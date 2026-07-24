package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"collector/internal/analytics"
	"collector/internal/spool"
	"collector/internal/store"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const syslogSubject = "collector.raw.syslog"

var (
	priPattern       = regexp.MustCompile(`^<([0-9]{1,3})>`)
	tracePattern     = regexp.MustCompile(`(?i)^(?:[A-Z][a-z]{2}\s+\d+\s+)?(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s+\[([A-Z ]+)\]\s*(.*)$`)
	componentPattern = regexp.MustCompile(`^([A-Za-z0-9_./ -]+?)(?::|\.)\s+(.*)$`)
	radiusPair       = regexp.MustCompile(`(?i)(Acct-Session-Id|Calling-Station-Id|Called-Station-Id|User-Name|xpgk-request-type|NAS-IP-Address)\s*(?:\(\d+\))?\s*[=:]\s*["']?([^"',;\s]+)`)
	radiusSession    = regexp.MustCompile(`(?i)Acct-Session-Id\s*(?:\(\d+\))?\s*[=:]\s*["']([^"']+)["']`)
)

type RawSyslog struct {
	EventID    uuid.UUID `json:"eventId"`
	DeviceID   uuid.UUID `json:"deviceId"`
	ReceivedAt time.Time `json:"receivedAt"`
	SourceIP   string    `json:"sourceIp"`
	SourcePort uint16    `json:"sourcePort"`
	Payload    []byte    `json:"payload"`
}

type SyslogReceiver struct {
	Addr  string
	Store *store.Store
	Spool *spool.Queue
}

func EnsureStreams(nc *nats.Conn) error {
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	if _, err = js.StreamInfo("SYSLOG"); err == nil {
		return nil
	}
	if !errors.Is(err, nats.ErrStreamNotFound) {
		return err
	}
	_, err = js.AddStream(&nats.StreamConfig{
		Name:       "SYSLOG",
		Subjects:   []string{syslogSubject},
		Storage:    nats.FileStorage,
		Retention:  nats.WorkQueuePolicy,
		MaxAge:     72 * time.Hour,
		MaxBytes:   20 << 30,
		Discard:    nats.DiscardOld,
		Duplicates: 72 * time.Hour,
	})
	return err
}

func (r *SyslogReceiver) Run(ctx context.Context) error {
	address, err := net.ResolveUDPAddr("udp", r.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetReadBuffer(16 << 20); err != nil {
		slog.Warn("unable to enlarge UDP receive buffer", "error", err)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	buffer := make([]byte, 64*1024)
	for {
		size, source, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Error("syslog read failed", "error", err)
			continue
		}
		deviceID, err := r.Store.DeviceBySourceIP(ctx, source.IP.String())
		if err != nil {
			slog.Warn("syslog from unknown source rejected", "source", source.IP)
			continue
		}
		record := RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: time.Now().UTC(),
			SourceIP: source.IP.String(), SourcePort: uint16(source.Port),
			Payload: append([]byte(nil), buffer[:size]...),
		}
		payload, _ := json.Marshal(record)
		if err := r.Spool.Enqueue(record.ReceivedAt, record.EventID.String(), payload); err != nil {
			slog.Error("syslog durable spool failed", "event", record.EventID, "error", err)
		}
	}
}

func RunSpoolPublisher(ctx context.Context, queue *spool.Queue, nc *nats.Conn) error {
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	for ctx.Err() == nil {
		items, err := queue.Peek(500)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		processed := make([][]byte, 0, len(items))
		for _, item := range items {
			var raw RawSyslog
			if err := json.Unmarshal(item.Data, &raw); err != nil {
				slog.Error("invalid durable spool record removed", "error", err)
				processed = append(processed, item.Key)
				continue
			}
			if _, err := js.Publish(syslogSubject, item.Data, nats.MsgId(raw.EventID.String())); err != nil {
				slog.Warn("NATS unavailable; retaining syslog spool", "error", err)
				break
			}
			processed = append(processed, item.Key)
		}
		if err := queue.Delete(processed); err != nil {
			return err
		}
	}
	return nil
}

func RunSyslogWorker(ctx context.Context, nc *nats.Conn, client *analytics.Client) error {
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	subscription, err := js.PullSubscribe(syslogSubject, "syslog-parser",
		nats.BindStream("SYSLOG"), nats.ManualAck(), nats.AckExplicit())
	if err != nil {
		return err
	}
	for ctx.Err() == nil {
		messages, err := subscription.Fetch(250, nats.MaxWait(time.Second))
		if errors.Is(err, nats.ErrTimeout) {
			continue
		}
		if err != nil {
			return err
		}
		for _, message := range messages {
			var raw RawSyslog
			if err := json.Unmarshal(message.Data, &raw); err != nil {
				_ = message.Term()
				continue
			}
			event := ParseSyslog(raw)
			if err := client.InsertSyslog(ctx, event); err != nil {
				slog.Error("syslog persistence failed", "event", raw.EventID, "error", err)
				_ = message.NakWithDelay(5 * time.Second)
				continue
			}
			if event.Category == "radius" {
				if err := client.InsertRadiusAndCorrelate(ctx, event); err != nil {
					slog.Error("RADIUS correlation failed", "event", raw.EventID, "error", err)
					_ = message.NakWithDelay(5 * time.Second)
					continue
				}
			}
			_ = message.Ack()
		}
	}
	return nil
}

func ParseSyslog(raw RawSyslog) analytics.SyslogEvent {
	text := strings.TrimSpace(string(raw.Payload))
	event := analytics.SyslogEvent{
		EventID: raw.EventID, DeviceID: raw.DeviceID, ReceivedAt: raw.ReceivedAt,
		SourceIP: net.ParseIP(raw.SourceIP), SourcePort: raw.SourcePort, Payload: raw.Payload,
		HeaderFormat: "eltex", ParseStatus: "partial", Category: "unknown",
		Message: text, Attributes: map[string]string{},
	}
	if match := priPattern.FindStringSubmatch(text); match != nil {
		value, _ := strconv.ParseUint(match[1], 10, 16)
		pri := uint16(value)
		facility := uint8(pri / 8)
		severity := uint8(pri % 8)
		event.PRI, event.Facility, event.Severity = &pri, &facility, &severity
		text = strings.TrimSpace(strings.TrimPrefix(text, match[0]))
		event.HeaderFormat = "rfc3164-or-pri"
	}
	if match := tracePattern.FindStringSubmatch(text); match != nil {
		event.Attributes["payload_severity"] = strings.TrimSpace(match[2])
		event.Message = strings.TrimSpace(match[3])
		if parsed := parsePayloadTime(match[1], raw.ReceivedAt); parsed != nil {
			event.EventTime = parsed
		}
		event.ParseStatus = "parsed"
	} else {
		event.Message = text
	}
	if match := componentPattern.FindStringSubmatch(event.Message); match != nil {
		event.Component = strings.TrimSpace(match[1])
		event.Message = strings.TrimSpace(match[2])
	}
	event.Category = classify(event.Component + " " + event.Message)
	if event.Category != "unknown" && event.ParseStatus == "partial" {
		event.ParseStatus = "parsed"
	}
	if event.Category == "radius" {
		for _, match := range radiusPair.FindAllStringSubmatch(text, -1) {
			event.Attributes[normalizeAttribute(match[1])] = strings.TrimSpace(match[2])
		}
		if match := radiusSession.FindStringSubmatch(text); match != nil {
			event.Attributes["acct_session_id"] = strings.TrimSpace(match[1])
		}
	}
	return event
}

func classify(value string) string {
	upper := strings.ToUpper(value)
	switch {
	case strings.Contains(upper, "RADIUS") || strings.Contains(upper, "ACCESS-REQUEST") || strings.Contains(upper, "ACCOUNTING-REQUEST"):
		return "radius"
	case strings.Contains(upper, "SS7") || strings.Contains(upper, "ISUP") || strings.Contains(upper, "IAM") || strings.Contains(upper, " RLC"):
		return "isup"
	case strings.Contains(upper, "Q.931") || strings.Contains(upper, "Q931") || strings.Contains(upper, "DSS1"):
		return "q931"
	case strings.Contains(upper, "SIP") || strings.Contains(upper, "INVITE") || strings.Contains(upper, "CALL-ID"):
		return "sip"
	case strings.Contains(upper, "IP-CONN") || strings.Contains(upper, "RTP") || strings.Contains(upper, "RTCP") || strings.Contains(upper, "CONN["):
		return "ip_connections"
	case strings.Contains(upper, "SM-VP") || strings.Contains(upper, " MSP"):
		return "ip_modules"
	case strings.Contains(upper, "ALARM") || strings.Contains(upper, "АВАР"):
		return "alarms"
	case strings.Contains(upper, "CONFIG") || strings.Contains(upper, "COMMAND") || strings.Contains(upper, "USERLOG"):
		return "config_history"
	case strings.Contains(upper, "AUTH") || strings.Contains(upper, "LOGIN") || strings.Contains(upper, "LOGOUT"):
		return "system_journal"
	case strings.Contains(upper, "CALL") || strings.Contains(upper, "PORT "):
		return "call_trace"
	default:
		return "unknown"
	}
}

func parsePayloadTime(value string, received time.Time) *time.Time {
	layout := "15:04:05"
	if strings.Contains(value, ".") {
		layout = "15:04:05.999999"
	}
	parsed, err := time.ParseInLocation(layout, value, received.Location())
	if err != nil {
		return nil
	}
	result := time.Date(received.Year(), received.Month(), received.Day(),
		parsed.Hour(), parsed.Minute(), parsed.Second(), parsed.Nanosecond(), received.Location()).UTC()
	if result.After(received.Add(12 * time.Hour)) {
		result = result.AddDate(0, 0, -1)
	}
	return &result
}

func normalizeAttribute(value string) string {
	return strings.ReplaceAll(strings.ToLower(value), "-", "_")
}

func ValidateSyslogAddress(value string) error {
	if _, err := net.ResolveUDPAddr("udp", value); err != nil {
		return fmt.Errorf("invalid syslog address: %w", err)
	}
	return nil
}
