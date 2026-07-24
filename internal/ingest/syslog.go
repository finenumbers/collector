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

const (
	syslogSubject    = "collector.raw.syslog"
	syslogDLQSubject = "collector.dlq.syslog"
)

var (
	priPattern        = regexp.MustCompile(`^<([0-9]{1,3})>`)
	eltexHostPattern  = regexp.MustCompile(`^<([^<>\s]{1,128})>\s+`)
	tracePattern      = regexp.MustCompile(`(?i)^(?:[A-Z][a-z]{2}\s+\d+\s+)?(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s+(?:\[([A-Z][A-Z0-9 _-]*)\]\s*)?(.*)$`)
	rfc3164Pattern    = regexp.MustCompile(`^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+([0-9]{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(.*)$`)
	rfc3164App        = regexp.MustCompile(`^([A-Za-z0-9_.-]+)(?:\[([0-9]+)\])?:\s*(.*)$`)
	callContext       = regexp.MustCompile(`^\[([A-Za-z0-9_-]+)\]\s*(.*)$`)
	callContextAny    = regexp.MustCompile(`\[(C[A-Za-z0-9_-]+)\]`)
	componentPattern  = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_./ -]{0,127}?)(?::|\.)\s*(.*)$`)
	radiusPair        = regexp.MustCompile(`(?i)\b([A-Za-z][A-Za-z0-9-]{1,63})\s*(?:\(\d+\))?\s*[=:]\s*(?:"([^"]*)"|'([^']*)'|([^,;\s]+))`)
	radiusSession     = regexp.MustCompile(`(?i)Acct-Session-Id\s*(?:\(\d+\))?\s*[=:]\s*["']([^"']+)["']`)
	radiusVSAPair     = regexp.MustCompile(`(?i)\b(xpgk-[a-z0-9-]+|in-trunkgroup-label|out-trunkgroup-label|h323-remote-id|h323-redirect-number|numplan)=([^,'"\s]+)`)
	radiusPacket      = regexp.MustCompile(`(?i)\b(Access-Request|Access-Accept|Access-Reject|Accounting-Request|Accounting-Response)\b`)
	radiusAttribute   = regexp.MustCompile(`(?i)^(?:User-Name|User-Password|Calling-Station-Id|Called-Station-Id|Acct-Session-Id|NAS-Port|NAS-Port-Type|Framed-IP-Address|Event-Timestamp|Acct-Delay-Time|Acct-Session-Time|Cisco-AVPair|Eltex-AVPair|h323-[A-Za-z0-9-]+)\s*(?:\([0-9]+\))?\s*[=:]`)
	radiusRequestID   = regexp.MustCompile(`(?i)\b(?:Request|Packet)\s+ID\s*\[?([0-9]{1,3})\]?`)
	radiusServer      = regexp.MustCompile(`(?i)\b(?:server|address)\s*[=:]?\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?)`)
	radiusLatency     = regexp.MustCompile(`(?i)\b(?:in|latency\s*[=:]?)\s*([0-9]+)\s*ms\b`)
	radiusRetry       = regexp.MustCompile(`(?i)\bretr(?:y|ies)\s*[=:]?\s*([0-9]+)\b`)
	q850CausePattern  = regexp.MustCompile(`(?i)\b(?:Q\.?850|disconnect-cause|release-cause)\s*[=:]\s*([0-9]{1,3})`)
	sipCallIDPattern  = regexp.MustCompile(`(?i)\bCall-ID\s*[=:]\s*["']?([^'"\s,;]+)`)
	globalCallPattern = regexp.MustCompile(`(?i)\b(?:Global[- ]Callref|GCR)\s*[=:]\s*["']?([^'"\s,;]+)`)
	systemAppPattern  = regexp.MustCompile(`(?i)\b(?:webapp|webspp)(?:\[[0-9]+\])?:\s*(?:WEBS|SEC)\s*:`)
	systemBodyPattern = regexp.MustCompile(`(?i)^\s*(?:WEBS|SEC)\s*:`)
	alarmPattern      = regexp.MustCompile(`(?i)(?:^|[\s:;,])ALARMS?(?:$|[\s:;,])|АВАР`)
	callPattern       = regexp.MustCompile(`(?i)(?:^|[\s:;,])CALL(?:$|[\s:;,])|(?:^|[\s:;,])PORT\s+[0-9]`)
)

type RawSyslog struct {
	EventID          uuid.UUID `json:"eventId"`
	DeviceID         uuid.UUID `json:"deviceId"`
	ReceivedAt       time.Time `json:"receivedAt"`
	SourceIP         string    `json:"sourceIp"`
	SourcePort       uint16    `json:"sourcePort"`
	Payload          []byte    `json:"payload"`
	Timezone         string    `json:"timezone,omitempty"`
	TimezoneRevision uint64    `json:"timezoneRevision,omitempty"`
}

type SyslogReceiver struct {
	Addr    string
	Store   *store.Store
	Spool   *spool.Queue
	Metrics *Metrics
}

func EnsureStreams(nc *nats.Conn) error {
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	if err := ensureStream(js, &nats.StreamConfig{
		Name:       "SYSLOG",
		Subjects:   []string{syslogSubject},
		Storage:    nats.FileStorage,
		Retention:  nats.WorkQueuePolicy,
		MaxBytes:   20 << 30,
		Discard:    nats.DiscardNew,
		Duplicates: 72 * time.Hour,
	}); err != nil {
		return err
	}
	return ensureStream(js, &nats.StreamConfig{
		Name:       "SYSLOG_DLQ",
		Subjects:   []string{syslogDLQSubject},
		Storage:    nats.FileStorage,
		Retention:  nats.LimitsPolicy,
		MaxBytes:   1 << 30,
		Discard:    nats.DiscardNew,
		Duplicates: 72 * time.Hour,
	})
}

func ensureStream(js nats.JetStreamContext, config *nats.StreamConfig) error {
	_, err := js.StreamInfo(config.Name)
	if err == nil {
		_, err = js.UpdateStream(config)
		return err
	}
	if !errors.Is(err, nats.ErrStreamNotFound) {
		return err
	}
	_, err = js.AddStream(config)
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
	type cachedDevice struct {
		id       uuid.UUID
		timezone string
		revision uint64
		expires  time.Time
	}
	const (
		maxBatch    = 256
		batchWindow = 2 * time.Millisecond
		cacheTTL    = 30 * time.Second
	)
	deviceCache := make(map[string]cachedDevice)
	rejectedLog := make(map[string]time.Time)
	pending := make([]spool.Entry, 0, maxBatch)
	var flushAt time.Time
	flush := func() error {
		for len(pending) > 0 {
			err := r.Spool.EnqueueBatch(pending)
			if err == nil {
				pending = pending[:0]
				flushAt = time.Time{}
				return nil
			}
			slog.Error("syslog durable spool batch failed; retrying without dropping datagrams",
				"count", len(pending), "error", err)
			r.Metrics.RecordSpoolError()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
		return nil
	}
	buffer := make([]byte, 64*1024)
	for {
		if len(pending) > 0 {
			_ = conn.SetReadDeadline(flushAt)
		} else {
			_ = conn.SetReadDeadline(time.Time{})
		}
		size, source, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				_ = flush()
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if err := flush(); err != nil && !errors.Is(err, context.Canceled) {
					return err
				}
				continue
			}
			slog.Error("syslog read failed", "error", err)
			continue
		}
		sourceIP := source.IP.String()
		if ipv4 := source.IP.To4(); ipv4 != nil {
			sourceIP = ipv4.String()
		}
		now := time.Now()
		deviceID := uuid.Nil
		timezone := ""
		var timezoneRevision uint64
		if cached, ok := deviceCache[sourceIP]; ok && now.Before(cached.expires) {
			deviceID = cached.id
			timezone = cached.timezone
			timezoneRevision = cached.revision
			err = nil
		} else {
			deviceID, err = r.Store.DeviceBySourceIP(ctx, sourceIP)
			if err == nil {
				device, deviceErr := r.Store.Device(ctx, deviceID)
				if deviceErr != nil {
					err = deviceErr
				} else {
					timezone = device.ActiveTimezone
					timezoneRevision = uint64(device.ActiveTimezoneRevision)
					deviceCache[sourceIP] = cachedDevice{
						id: deviceID, timezone: timezone, revision: timezoneRevision,
						expires: now.Add(cacheTTL),
					}
				}
			}
		}
		if err != nil || deviceID == uuid.Nil {
			r.Metrics.RecordRejected()
			if last := rejectedLog[sourceIP]; now.Sub(last) >= time.Minute {
				slog.Warn("syslog from unknown source rejected", "source", sourceIP, "source_port", source.Port)
				rejectedLog[sourceIP] = now
			}
			continue
		}
		record := RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now.UTC(),
			SourceIP: sourceIP, SourcePort: uint16(source.Port),
			Payload: append([]byte(nil), buffer[:size]...), Timezone: timezone,
			TimezoneRevision: timezoneRevision,
		}
		payload, _ := json.Marshal(record)
		pending = append(pending, spool.Entry{
			ReceivedAt: record.ReceivedAt, EventID: record.EventID.String(), Payload: payload,
		})
		r.Metrics.RecordAccepted()
		if len(pending) == 1 {
			flushAt = now.Add(batchWindow)
		}
		if len(pending) >= maxBatch {
			if err := flush(); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
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
				if quarantineErr := queue.Quarantine(item.Key, item.Data, err.Error()); quarantineErr != nil {
					return quarantineErr
				}
				slog.Error("invalid durable spool record moved to quarantine", "error", err)
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

type DeviceTimeConfigResolver interface {
	DeviceTimeConfig(context.Context, uuid.UUID) (store.DeviceTimeConfig, error)
}

func RunSyslogWorker(
	ctx context.Context,
	nc *nats.Conn,
	client *analytics.Client,
	timeResolver DeviceTimeConfigResolver,
) error {
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	subscription, err := js.PullSubscribe(syslogSubject, "syslog-parser",
		nats.BindStream("SYSLOG"), nats.ManualAck(), nats.AckExplicit())
	if err != nil {
		return err
	}
	type cachedTimeConfig struct {
		config  store.DeviceTimeConfig
		expires time.Time
	}
	timeConfigs := make(map[uuid.UUID]cachedTimeConfig)
	for ctx.Err() == nil {
		messages, err := subscription.Fetch(250, nats.MaxWait(time.Second))
		if errors.Is(err, nats.ErrTimeout) {
			continue
		}
		if err != nil {
			return err
		}
		type parsedMessage struct {
			message *nats.Msg
			event   analytics.SyslogEvent
		}
		parsed := make([]parsedMessage, 0, len(messages))
		events := make([]analytics.SyslogEvent, 0, len(messages))
		for _, message := range messages {
			var raw RawSyslog
			if err := json.Unmarshal(message.Data, &raw); err != nil {
				if _, publishErr := js.Publish(syslogDLQSubject, message.Data); publishErr != nil {
					slog.Error("invalid NATS envelope could not be quarantined", "error", publishErr)
					_ = message.NakWithDelay(5 * time.Second)
					continue
				}
				slog.Error("invalid NATS envelope moved to dead-letter stream", "error", err)
				_ = message.Term()
				continue
			}
			if timeResolver != nil {
				cached := timeConfigs[raw.DeviceID]
				if time.Now().After(cached.expires) {
					config, resolveErr := timeResolver.DeviceTimeConfig(ctx, raw.DeviceID)
					if resolveErr != nil {
						slog.Error("active device timezone resolution failed",
							"device", raw.DeviceID, "error", resolveErr)
						_ = message.NakWithDelay(5 * time.Second)
						continue
					}
					cached = cachedTimeConfig{config: config, expires: time.Now().Add(5 * time.Second)}
					timeConfigs[raw.DeviceID] = cached
				}
				raw.Timezone = cached.config.ActiveTimezone
				raw.TimezoneRevision = uint64(cached.config.ActiveTimezoneRevision)
			}
			event := ParseSyslog(raw)
			parsed = append(parsed, parsedMessage{message: message, event: event})
			events = append(events, event)
		}
		if err := client.InsertSyslogBatch(ctx, events); err != nil {
			slog.Error("syslog batch persistence failed", "count", len(events), "error", err)
			for _, item := range parsed {
				_ = item.message.NakWithDelay(5 * time.Second)
			}
			continue
		}
		successful := parsed
		successfulEvents := events
		if err := client.ProcessSyslogShadowDerivedBatch(ctx, successfulEvents); err != nil {
			slog.Error("Syslog shadow lifecycle batch failed", "error", err)
			for _, item := range successful {
				_ = item.message.NakWithDelay(5 * time.Second)
			}
			continue
		}
		if err := client.EnqueueDirtySyslogBuckets(ctx, successfulEvents); err != nil {
			slog.Error("Syslog dirty bucket enqueue failed", "error", err)
			for _, item := range successful {
				_ = item.message.NakWithDelay(5 * time.Second)
			}
			continue
		}
		for _, item := range successful {
			_ = item.message.Ack()
		}
	}
	return nil
}

func ParseSyslog(raw RawSyslog) analytics.SyslogEvent {
	location := time.UTC
	if raw.Timezone != "" {
		if parsed, err := time.LoadLocation(raw.Timezone); err == nil {
			location = parsed
		}
	}
	return ParseSyslogInLocation(raw, location)
}

func ParseSyslogInLocation(raw RawSyslog, location *time.Location) analytics.SyslogEvent {
	if location == nil {
		location = time.UTC
	}
	text := strings.TrimSpace(strings.Trim(string(raw.Payload), "\x00"))
	text = strings.TrimPrefix(text, "\ufeff")
	event := analytics.SyslogEvent{
		EventID: raw.EventID, DeviceID: raw.DeviceID, ReceivedAt: raw.ReceivedAt,
		SourceIP: net.ParseIP(raw.SourceIP), SourcePort: raw.SourcePort, Payload: raw.Payload,
		HeaderFormat: "eltex", ParseStatus: "partial", Category: "unknown",
		Message: text, Attributes: map[string]string{}, SourceTimezone: location.String(),
		TimezoneRevision: raw.TimezoneRevision,
	}
	if event.TimezoneRevision == 0 {
		event.TimezoneRevision = 1
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
	if match := eltexHostPattern.FindStringSubmatch(text); match != nil {
		event.Attributes["hostname"] = match[1]
		text = strings.TrimSpace(strings.TrimPrefix(text, match[0]))
		event.HeaderFormat = "eltex-trace"
	}
	if timestamp, severity, message, ok := parseEltexTrace(text, raw.ReceivedAt, location); ok {
		if severity != "" {
			event.Attributes["payload_severity"] = severity
		}
		event.Message = message
		event.EventTime = timestamp
		event.ParseStatus = "parsed"
	} else if timestamp, application, processID, message, ok := parseRFC3164(text, raw.ReceivedAt, location); ok {
		event.HeaderFormat = "rfc3164"
		event.EventTime = timestamp
		event.Message = message
		event.Attributes["application"] = application
		if processID != "" {
			event.Attributes["process_id"] = processID
		}
		event.ParseStatus = "parsed"
	} else {
		event.Message = text
		event.Attributes["parse_warning"] = "unrecognized_envelope"
	}
	if match := callContext.FindStringSubmatch(event.Message); match != nil {
		event.Attributes["call_context"] = match[1]
		event.Message = strings.TrimSpace(match[2])
	}
	if match := componentPattern.FindStringSubmatch(event.Message); match != nil {
		event.Component = strings.TrimSpace(match[1])
		event.Message = strings.TrimSpace(match[2])
	}
	event.Category = classify(event.Component, event.Attributes["application"], event.Message, string(raw.Payload))
	if event.Category == "radius" {
		extractRadiusAttributes(text, &event)
	}
	extractProtocolAttributes(text, &event)
	offsetTime := raw.ReceivedAt.In(location)
	if event.EventTime != nil {
		offsetTime = event.EventTime.In(location)
	}
	_, offsetSeconds := offsetTime.Zone()
	event.SourceUTCOffsetMinutes = int16(offsetSeconds / 60)
	return event
}

func classify(component, application, message, payload string) string {
	upperComponent := strings.ToUpper(strings.TrimSpace(component))
	upperApplication := strings.ToUpper(strings.TrimSpace(application))
	upperMessage := strings.ToUpper(message)
	upper := strings.ToUpper(strings.Join([]string{component, application, message, payload}, " "))
	isRadiusComponent := upperComponent == "RADIUS" || upperComponent == "RC" ||
		strings.Contains(upperComponent, "RADIUS")
	isSIPComponent := upperComponent == "SIP" || upperComponent == "SIPT" ||
		strings.Contains(upperComponent, "PBXIPC-SIP")
	switch {
	case upperApplication == "WEBAPP" || upperApplication == "WEBSPP" ||
		upperApplication == "WEBS" || upperApplication == "SEC" ||
		upperComponent == "WEBS" || upperComponent == "SEC" ||
		systemAppPattern.MatchString(payload) || systemBodyPattern.MatchString(message):
		return "system_journal"
	case isRadiusComponent || radiusPacket.MatchString(message) ||
		strings.Contains(upperMessage, "ACCS-REQUEST") ||
		strings.Contains(upperMessage, "ACCT-SESSION-ID") ||
		strings.Contains(upperMessage, "XPGK-") ||
		(upperComponent == "" && radiusAttribute.MatchString(strings.TrimSpace(message))) ||
		(!isSIPComponent && strings.Contains(upperMessage, "ANTIFRAUD")):
		return "radius"
	case strings.Contains(upper, "SS7") || strings.Contains(upper, "ISUP") ||
		strings.Contains(upper, "IAM-") || strings.Contains(upper, "RLC-"):
		return "isup"
	case strings.Contains(upper, "Q.931") || strings.Contains(upper, "Q931") || strings.Contains(upper, "DSS1"):
		return "q931"
	case isSIPComponent || strings.Contains(upper, "SIP") ||
		strings.Contains(upper, "INVITE") || strings.Contains(upper, "CALL-ID"):
		return "sip"
	case upperComponent == "H323" || strings.Contains(upperComponent, "H.323"):
		return "h323"
	case upperComponent == "RTP" || upperComponent == "RTCP" || upperComponent == "RTP-CREATE" ||
		strings.Contains(upperMessage, "RTP SESSION") || strings.Contains(upperMessage, "RTP STREAM"):
		return "rtp"
	case upperComponent == "HW" || strings.Contains(upperComponent, "HARDWARE"):
		return "hardware"
	case strings.Contains(upper, "IP-CONN") || strings.Contains(upper, "CONN["):
		return "ip_connections"
	case strings.Contains(upperComponent, "SM-VP") || strings.Contains(upperComponent, "SMVP") ||
		strings.Contains(upperComponent, "MSP"):
		return "ip_modules"
	case upperComponent == "IVR" || strings.HasPrefix(upperComponent, "IVR/"):
		return "ivr"
	case upperComponent == "IPNET" || strings.HasPrefix(upperComponent, "IPNET/"):
		return "ip_network"
	case upperComponent == "ALARM" || upperComponent == "ALARMS" || alarmPattern.MatchString(upper):
		return "alarms"
	case strings.Contains(upper, "CONFIG") || strings.Contains(upper, "COMMAND") || strings.Contains(upper, "USERLOG"):
		return "config_history"
	case strings.Contains(upper, "AUTHLOG") || upperComponent == "AUTH":
		return "auth_log"
	case strings.HasPrefix(eventCallContext(payload), "C") || callPattern.MatchString(upper):
		return "call_trace"
	case upperApplication != "":
		return "system_journal"
	default:
		return "unknown"
	}
}

func extractRadiusAttributes(text string, event *analytics.SyslogEvent) {
	lowerText := strings.ToLower(text)
	for _, match := range radiusPair.FindAllStringSubmatch(text, -1) {
		value := firstNonEmpty(match[2], match[3], match[4])
		event.Attributes[normalizeAttribute(match[1])] = strings.TrimSpace(value)
	}
	if match := radiusSession.FindStringSubmatch(text); match != nil {
		event.Attributes["acct_session_id"] = strings.TrimSpace(match[1])
	}
	for _, match := range radiusVSAPair.FindAllStringSubmatch(text, -1) {
		event.Attributes[normalizeAttribute(match[1])] = strings.TrimSpace(match[2])
	}
	if match := radiusPacket.FindStringSubmatch(text); match != nil {
		packetCode := strings.ToLower(match[1])
		event.Attributes["packet_code"] = packetCode
		if strings.HasSuffix(packetCode, "request") {
			event.Attributes["packet_direction"] = "request"
		} else {
			event.Attributes["packet_direction"] = "response"
		}
	}
	if event.Attributes["packet_code"] == "" {
		switch {
		case strings.Contains(lowerText, "radius server rejected"):
			event.Attributes["packet_code"] = "access-reject"
			event.Attributes["packet_direction"] = "response"
		case strings.Contains(lowerText, "got valid reply for accs"):
			event.Attributes["packet_code"] = "access-response"
			event.Attributes["packet_direction"] = "response"
		case strings.Contains(lowerText, "process queue"):
			event.Attributes["packet_direction"] = "request"
		}
	}
	if match := radiusRequestID.FindStringSubmatch(text); match != nil {
		event.Attributes["packet_identifier"] = match[1]
	}
	if match := radiusServer.FindStringSubmatch(text); match != nil {
		event.Attributes["server_address"] = match[1]
	}
	if match := radiusLatency.FindStringSubmatch(text); match != nil {
		event.Attributes["latency_ms"] = match[1]
	}
	if match := radiusRetry.FindStringSubmatch(text); match != nil {
		event.Attributes["retry"] = match[1]
	}
	requestType := strings.ToLower(event.Attributes["xpgk_request_type"])
	if requestType == "check_call" || requestType == "save_call" || requestType == "number" {
		event.Attributes["is_antifraud"] = "true"
	}
	packetCode := event.Attributes["packet_code"]
	switch {
	case requestType == "check_call" && packetCode == "access-accept":
		event.Attributes["decision"] = "accept"
	case requestType == "check_call" && packetCode == "access-reject":
		event.Attributes["decision"] = "reject"
	case strings.Contains(lowerText, "timeout"):
		event.Attributes["decision"] = "timeout_fail_open"
	case (requestType == "number" || requestType == "save_call") &&
		(packetCode == "access-accept" || packetCode == "access-reject"):
		event.Attributes["decision"] = "informational"
	}
	if strings.Contains(lowerText, "radius server rejected") {
		event.Attributes["result"] = "reject"
	}
	if packetCode == "accounting-request" {
		event.Attributes["accounting_status"] = "request"
	}
	if packetCode == "accounting-response" {
		event.Attributes["accounting_status"] = "complete"
	}
}

func extractProtocolAttributes(text string, event *analytics.SyslogEvent) {
	if match := q850CausePattern.FindStringSubmatch(text); match != nil {
		event.Attributes["q850_cause"] = match[1]
	}
	if match := sipCallIDPattern.FindStringSubmatch(text); match != nil {
		event.Attributes["sip_call_id"] = match[1]
	}
	if match := globalCallPattern.FindStringSubmatch(text); match != nil {
		event.Attributes["global_callref"] = match[1]
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parseEltexTrace(
	value string, received time.Time, location *time.Location,
) (*time.Time, string, string, bool) {
	match := tracePattern.FindStringSubmatch(value)
	if match == nil {
		return nil, "", "", false
	}
	severity := strings.TrimSpace(match[2])
	message := strings.TrimSpace(match[3])
	if strings.HasPrefix(strings.ToUpper(severity), "C") && strings.IndexFunc(severity, func(value rune) bool {
		return value >= '0' && value <= '9'
	}) >= 0 {
		message = "[" + severity + "] " + message
		severity = ""
	}
	// A plain RFC3164 body also starts with HH:MM:SS. Eltex trace is
	// distinguishable by microseconds, a severity, or a call-context bracket.
	if !strings.Contains(match[1], ".") && severity == "" && !strings.HasPrefix(message, "[") {
		return nil, "", "", false
	}
	return parsePayloadTime(match[1], received, location), severity, message, true
}

func eventCallContext(payload string) string {
	match := callContextAny.FindStringSubmatch(payload)
	if match == nil {
		return ""
	}
	return match[1]
}

func parseRFC3164(
	value string, received time.Time, location *time.Location,
) (*time.Time, string, string, string, bool) {
	match := rfc3164Pattern.FindStringSubmatch(value)
	if match == nil {
		return nil, "", "", "", false
	}
	remainder := strings.TrimSpace(match[4])
	appMatch := rfc3164App.FindStringSubmatch(remainder)
	if appMatch == nil {
		if _, after, found := strings.Cut(remainder, " "); found {
			appMatch = rfc3164App.FindStringSubmatch(strings.TrimSpace(after))
		}
	}
	if appMatch == nil {
		return nil, "", "", "", false
	}
	timestamp := parseRFC3164Time(match[1], match[2], match[3], received, location)
	application := appMatch[1]
	message := strings.TrimSpace(appMatch[3])
	if strings.EqualFold(application, "WEBS") || strings.EqualFold(application, "SEC") {
		message = application + ": " + message
		application = ""
	}
	return timestamp, application, appMatch[2], message, true
}

func parseRFC3164Time(
	month, day, clock string, received time.Time, location *time.Location,
) *time.Time {
	value := fmt.Sprintf("%s %s %s", month, day, clock)
	parsed, err := time.ParseInLocation("Jan 2 15:04:05", value, location)
	if err != nil {
		return nil
	}
	localReceived := received.In(location)
	result := time.Date(localReceived.Year(), parsed.Month(), parsed.Day(),
		parsed.Hour(), parsed.Minute(), parsed.Second(), 0, location).UTC()
	if result.After(received.Add(31 * 24 * time.Hour)) {
		result = result.AddDate(-1, 0, 0)
	}
	return &result
}

func parsePayloadTime(value string, received time.Time, location *time.Location) *time.Time {
	layout := "15:04:05"
	if strings.Contains(value, ".") {
		layout = "15:04:05.999999"
	}
	parsed, err := time.ParseInLocation(layout, value, location)
	if err != nil {
		return nil
	}
	localReceived := received.In(location)
	result := time.Date(localReceived.Year(), localReceived.Month(), localReceived.Day(),
		parsed.Hour(), parsed.Minute(), parsed.Second(), parsed.Nanosecond(), location).UTC()
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
