package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"sort"
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
	priPattern       = regexp.MustCompile(`^<([0-9]{1,3})>`)
	eltexHostPattern = regexp.MustCompile(`^<([^<>\s]{1,128})>\s+`)
	tracePattern     = regexp.MustCompile(`(?i)^(?:[A-Z][a-z]{2}\s+\d+\s+)?(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s+(?:\[([A-Z][A-Z0-9 _-]*)\]\s*)?(.*)$`)
	rfc3164Pattern   = regexp.MustCompile(`^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+([0-9]{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(.*)$`)
	rfc3164App       = regexp.MustCompile(`^([A-Za-z0-9_.-]+)(?:\[([0-9]+)\])?:\s*(.*)$`)
	callContext      = regexp.MustCompile(`^\[([A-Za-z0-9_-]+)\]\s*(.*)$`)
	callContextAny   = regexp.MustCompile(`\[(C[A-Za-z0-9_-]+)\]`)
	componentPattern = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_./ -]{0,127}?)(?::|\.)\s*(.*)$`)
	// After a false component split on HH:MM:SS, remainder looks like "MM:SS ..." / "MM:SS.ffffff ...".
	componentTimeRest   = regexp.MustCompile(`^\d{2}:\d{2}(?:\.\d{1,6})?(?:\s|$)`)
	portSIPTPattern     = regexp.MustCompile(`(?i)^(Port\s+SIPT)\s*:\s*(.*)$`)
	siptBracketPattern  = regexp.MustCompile(`(?i)^(SIPT?\[[0-9A-Fa-f]+\])\.\s*(.*)$`)
	radiusRejectedPat   = regexp.MustCompile(`(?i)^RADIUS\s+server\s+rejected:\s*(.*)$`)
	connComponentPat    = regexp.MustCompile(`(?i)^(Conn\[[0-9A-Fa-f]+\])\s*:\s*(.*)$`)
	siptInMessage       = regexp.MustCompile(`(?i)\bSIPT?\[[0-9A-Fa-f]+\]`)
	repeatedMessage     = regexp.MustCompile(`(?i)^last message repeated (\d+) times$`)
	radiusPair          = regexp.MustCompile(`(?i)\b([A-Za-z][A-Za-z0-9-]{1,63})\s*(?:\(\d+\))?\s*[=:]\s*(?:"([^"]*)"|'([^']*)'|([^,;\s]+))`)
	radiusSession       = regexp.MustCompile(`(?i)Acct-Session-Id\s*(?:\(\d+\))?\s*[=:]\s*["']([^"']+)["']`)
	radiusVSAPair       = regexp.MustCompile(`(?i)\b((?:xpgk|xpkg)-[a-z0-9-]+|in-trunkgroup-label|out-trunkgroup-label|h323-remote-id|h323-redirect-number|numplan)=([^,'"\s]+)`)
	radiusPacket        = regexp.MustCompile(`(?i)\b(Access-Request|Access-Accept|Access-Reject|Accounting-Request|Accounting-Response)\b`)
	radiusRequestAlias  = regexp.MustCompile(`(?i)\b(Accs-Request|Antifraud-Auth-Request)\b`)
	radiusAliasID       = regexp.MustCompile(`(?i)\b(?:Accs-Request|Antifraud-Auth-Request)\s*\[([0-9]{1,3})\]`)
	radiusReplyAlias    = regexp.MustCompile(`(?i)--\s*RADIUS\.\s*Accs-Reply\s*\[([0-9]{1,3})\]\s*--`)
	radiusProcReply     = regexp.MustCompile(`(?i)\bProc\s+Reply.*?\bRequest\s+ID\s*\[([0-9]{1,3})\]\s+Accs-Reply\s*\[(accept|reject)\]\.\s*Time\s*\[([0-9]+):([0-9]+)\]`)
	radiusAttribute     = regexp.MustCompile(`(?i)^(?:User-Name|User-Password|Calling-Station-Id|Called-Station-Id|Acct-Session-Id|NAS-Port|NAS-Port-Type|Framed-IP-Address|Event-Timestamp|Acct-Delay-Time|Acct-Session-Time|Cisco-AVPair|Eltex-AVPair|h323-[A-Za-z0-9-]+)\s*(?:\([0-9]+\))?\s*[=:]`)
	avpLinePattern      = regexp.MustCompile(`(?i)^[A-Za-z][A-Za-z0-9-]+\s*=\s*`)
	radiusRequestID     = regexp.MustCompile(`(?i)\b(?:Request|Packet)\s+ID\s*\[?([0-9]{1,3})\]?`)
	radiusResponse      = regexp.MustCompile(`(?i)\b(?:(?:RADIUS\s+)?server\s+rejected|got\s+valid\s+reply\s+for\s+accs)\b`)
	antifraudControlPat = regexp.MustCompile(`(?i)\b(?:ANTIFRAUD|RADIUS(?:[- ](?:profile|build|wait|config|control)))\b`)
	radiusServer        = regexp.MustCompile(`(?i)\b(?:server|address)\s*[=:]?\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?)`)
	radiusLatency       = regexp.MustCompile(`(?i)\b(?:in|latency\s*[=:]?)\s*([0-9]+)\s*ms\b`)
	bareCDRRejectDump   = regexp.MustCompile(`(?i)^server\s+rejected:\s*:0\s+\(replied\s+0\)$`)
	radiusRetry         = regexp.MustCompile(`(?i)\bretr(?:y|ies)\s*[=:]?\s*([0-9]+)\b`)
	q850CausePattern    = regexp.MustCompile(`(?i)\b(?:Q\.?850|disconnect-cause|release-cause)\s*[=:]\s*([0-9]{1,3})`)
	sipCallIDPattern    = regexp.MustCompile(`(?i)\bCall-ID\s*[=:]\s*["']?([^'"\s,;]+)`)
	globalCallPattern   = regexp.MustCompile(`(?i)\b(?:Global[- ]Callref|GCR)\s*[=:]\s*["']?([^'"\s,;]+)`)
	localCallrefPattern = regexp.MustCompile(`(?i)\bCallref\s*[=:]?\s*([0-9a-f]+)\b`)
	traceDirectionPat   = regexp.MustCompile(`(?i)(?:^|[.\s])(TX|RX)(?:[.\s]|$)`)
	sipMessagePat       = regexp.MustCompile(`(?i)\b(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|UPDATE|PRACK|INFO|REFER|NOTIFY|SUBSCRIBE|MESSAGE|SIP/2\.0\s+[1-6][0-9]{2})\b`)
	isupMessagePat      = regexp.MustCompile(`(?i)\b(IAM|ACM|ANM|REL|RLC|CPG)-?\b`)
	q931MessagePat      = regexp.MustCompile(`(?i)\b(SETUP|CALL\s+PROCEEDING|ALERTING|CONNECT|DISCONNECT|RELEASE(?:\s+COMPLETE)?)\b`)
	systemAppPattern    = regexp.MustCompile(`(?i)\b(?:webapp|webspp)(?:\[[0-9]+\])?:\s*(?:WEBS|SEC)\s*:`)
	systemBodyPattern   = regexp.MustCompile(`(?i)^\s*(?:WEBS|SEC)\s*:`)
	alarmPattern        = regexp.MustCompile(`(?i)(?:^|[\s:;,])ALARMS?(?:$|[\s:;,])|АВАР`)
	callPattern         = regexp.MustCompile(`(?i)(?:^|[\s:;,])CALL(?:$|[\s:;,])|(?:^|[\s:;,])PORT\s+[0-9]`)
	traceContinuation   = regexp.MustCompile(`(?i)^#+\s*(requestID|trunkID|Keep\s+alive\s+type|cause|connected\s+number|number)\b\s*[:=]?\s*['"]?([^'"]*)`)
	codecLinePattern    = regexp.MustCompile(`(?i)^a\[[0-9]+\]:`)
	hexOnlyPattern      = regexp.MustCompile(`(?i)^[0-9a-f]{8,}$`)
	digestLabelPat      = regexp.MustCompile(`(?i)^(Reply|Calculated|Calculating)\s+digest\b`)
	// Bare IPv4 lines from SIP HostIPlist / addr-list dumps (often tab-indented).
	ipv4OnlyPattern = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$`)
	// 3.410 bare RFC 4566 SDP fields (no ## prefix), often after `# SDP len (N): 'v=0`.
	// In particular, b= carries bandwidth information such as `b=AS:82`.
	sdpLinePattern  = regexp.MustCompile(`(?i)^[vosiuepcbtrzkam]=`)
	sdpQuotePattern = regexp.MustCompile(`^'`)
	configLinePat   = regexp.MustCompile(`(?i)^CONFIG:\s*(.*)$`)
	siptProcPattern = regexp.MustCompile(`(?i)^SIPT\s+Proc\b`)
	// 3.410 SS7/ISUP PDU dumps (dotted octets) and decode placeholders.
	dottedHexPattern    = regexp.MustCompile(`(?i)^[0-9a-f]{2}(\.[0-9a-f]{2}){3,}\.?$`)
	noOptionalParamsPat = regexp.MustCompile(`(?i)^\[No optional params\]$`)
)

var allowedComponents = map[string]struct{}{
	"SIP": {}, "SIPT": {}, "RADIUS": {}, "RC": {}, "ALARM": {}, "ALARMS": {},
	"ALARM-LED": {}, "SNMP": {}, "CDR": {}, "MSPC": {}, "MSP": {}, "WEBS": {}, "SEC": {},
	"SS7": {}, "ISUP": {}, "SS7/ISUP": {}, "H323": {}, "RTP": {}, "RTCP": {}, "RTP-CREATE": {},
	"HW": {}, "IVR": {}, "IPNET": {}, "AAA": {}, "AUTH": {},
}

type RawSyslog struct {
	EventID          uuid.UUID `json:"eventId"`
	DeviceID         uuid.UUID `json:"deviceId"`
	ReceivedAt       time.Time `json:"receivedAt"`
	SourceIP         string    `json:"sourceIp"`
	SourcePort       uint16    `json:"sourcePort"`
	Payload          []byte    `json:"payload"`
	Timezone         string    `json:"timezone,omitempty"`
	TimezoneRevision uint64    `json:"timezoneRevision,omitempty"`
	TemplateKey      string    `json:"templateKey,omitempty"`
	Firmware         string    `json:"firmware,omitempty"`
}

const (
	syslogDialect3232   = "3.23.2"
	syslogDialect3410   = "3.410"
	syslogDialectLegacy = "legacy-common"
)

func syslogDialect(raw RawSyslog) string {
	switch raw.TemplateKey {
	case "eltex-smg-1016m-3.23.2":
		return syslogDialect3232
	case "eltex-smg-1016m-3.410":
		return syslogDialect3410
	}
	switch raw.Firmware {
	case syslogDialect3232:
		return syslogDialect3232
	case syslogDialect3410:
		return syslogDialect3410
	default:
		return syslogDialectLegacy
	}
}

func allows3410Dialect(dialect string) bool {
	// Legacy envelopes predate template provenance; preserve their historical
	// superset behavior so replay never loses already recognized messages.
	return dialect != syslogDialect3232
}

type continuationParent struct {
	eventID     uuid.UUID
	anchorID    uuid.UUID
	receivedAt  time.Time
	sourceIP    string
	category    string
	component   string
	callContext string
}

type ContinuationAssembler struct {
	byCallSignal map[string]continuationParent
	byCallRadius map[string]continuationParent
	radiusBurst  map[uuid.UUID]continuationParent
	sipBurst     map[uuid.UUID]continuationParent
	isupBurst    map[uuid.UUID]continuationParent
}

func NewContinuationAssembler() *ContinuationAssembler {
	return &ContinuationAssembler{
		byCallSignal: make(map[string]continuationParent),
		byCallRadius: make(map[string]continuationParent),
		radiusBurst:  make(map[uuid.UUID]continuationParent),
		sipBurst:     make(map[uuid.UUID]continuationParent),
		isupBurst:    make(map[uuid.UUID]continuationParent),
	}
}

func continuationCallKey(deviceID uuid.UUID, callContext string) string {
	return deviceID.String() + "|" + callContext
}

func parentFresh(parent continuationParent, event *analytics.SyslogEvent, sourceIP string, window time.Duration) bool {
	return parent.sourceIP == sourceIP &&
		!event.ReceivedAt.Before(parent.receivedAt) &&
		event.ReceivedAt.Sub(parent.receivedAt) <= window
}

func compatibleSignalParent(parent continuationParent, kind string) bool {
	switch kind {
	case "isup_optional", "dotted_hex":
		return parent.category == "isup"
	case "sdp_line", "sdp_quote", "sdp", "codec", "host_ip":
		return parent.category == "sip"
	case "typed_hash", "hash_detail":
		return parent.category == "sip" || parent.category == "isup"
	default:
		return false
	}
}

func (a *ContinuationAssembler) nearestSignalBurst(
	event *analytics.SyslogEvent, sourceIP, kind string,
) (continuationParent, bool, string) {
	var selected continuationParent
	selectedOK := false
	selectedMethod := ""
	for _, candidate := range []struct {
		parent continuationParent
		ok     bool
		method string
	}{
		{a.sipBurst[event.DeviceID], a.sipBurst[event.DeviceID].eventID != uuid.Nil, "sip_burst"},
		{a.isupBurst[event.DeviceID], a.isupBurst[event.DeviceID].eventID != uuid.Nil, "isup_burst"},
	} {
		if !candidate.ok || !compatibleSignalParent(candidate.parent, kind) ||
			!parentFresh(candidate.parent, event, sourceIP, 2*time.Second) {
			continue
		}
		if !selectedOK || candidate.parent.receivedAt.After(selected.receivedAt) {
			selected, selectedOK, selectedMethod = candidate.parent, true, candidate.method
		}
	}
	return selected, selectedOK, selectedMethod
}

func (a *ContinuationAssembler) Assemble(events []analytics.SyslogEvent) {
	if a == nil {
		return
	}
	for index := range events {
		event := &events[index]
		sourceIP := ""
		if event.SourceIP != nil {
			sourceIP = event.SourceIP.String()
		}
		callContext := event.Attributes["call_context"]
		if event.Attributes["trace_continuation"] != "true" {
			parent := continuationParent{
				eventID: event.EventID, anchorID: event.EventID, receivedAt: event.ReceivedAt,
				sourceIP: sourceIP, category: event.Category,
				component: event.Component, callContext: callContext,
			}
			event.Attributes["construct_anchor_event_id"] = event.EventID.String()
			event.Attributes["construct_anchor"] = event.EventID.String()
			if callContext != "" {
				key := continuationCallKey(event.DeviceID, callContext)
				if event.Category == "radius" {
					a.byCallRadius[key] = parent
				} else {
					a.byCallSignal[key] = parent
				}
			}
			if event.Category == "radius" {
				a.radiusBurst[event.DeviceID] = parent
			}
			if event.Category == "sip" {
				a.sipBurst[event.DeviceID] = parent
			}
			if event.Category == "isup" {
				a.isupBurst[event.DeviceID] = parent
			}
			continue
		}
		kind := event.Attributes["fragment_kind"]
		radiusFragment := kind == "avp" || kind == "hex" || kind == "digest" || kind == "rc_fragment"
		signalFragment := compatibleSignalParent(
			continuationParent{category: "sip"}, kind,
		) || compatibleSignalParent(continuationParent{category: "isup"}, kind)
		parent, ok := continuationParent{}, false
		linkMethod := ""
		if callContext != "" {
			key := continuationCallKey(event.DeviceID, callContext)
			if radiusFragment {
				parent, ok = a.byCallRadius[key]
				linkMethod = "call_context_radius"
				if ok && !parentFresh(parent, event, sourceIP, 2*time.Second) {
					ok = false
				}
			} else {
				parent, ok = a.byCallSignal[key]
				linkMethod = "call_context_signal"
				if ok && (!compatibleSignalParent(parent, kind) ||
					!parentFresh(parent, event, sourceIP, 2*time.Second)) {
					ok = false
				}
			}
		}
		if !ok && radiusFragment {
			parent, ok = a.radiusBurst[event.DeviceID]
			linkMethod = "radius_burst"
			if !ok || parent.category != "radius" || !parentFresh(parent, event, sourceIP, 2*time.Second) {
				ok = false
			}
		}
		if !ok && signalFragment {
			parent, ok, linkMethod = a.nearestSignalBurst(event, sourceIP, kind)
		}
		if !ok && callContext == "" && !radiusFragment &&
			(!signalFragment || kind == "typed_hash") {
			parent, ok = a.radiusBurst[event.DeviceID]
			linkMethod = "radius_short_burst"
			if !ok || parent.category != "radius" ||
				!parentFresh(parent, event, sourceIP, 100*time.Millisecond) {
				ok = false
			}
		}
		if ok {
			event.Attributes["parent_event_id"] = parent.eventID.String()
			event.Attributes["construct_anchor_event_id"] = parent.anchorID.String()
			event.Attributes["construct_anchor"] = parent.anchorID.String()
			event.Attributes["fragment_link_method"] = linkMethod
			if strings.Contains(linkMethod, "burst") {
				event.Attributes["fragment_link_confidence"] = "0.7"
			} else {
				event.Attributes["fragment_link_confidence"] = "1"
			}
			event.Attributes["inherited_category"] = "true"
			event.Category = parent.category
			event.Attributes["classification_result"] = parent.category
			event.Attributes["classification_rule"] = "continuation_parent_context"
			event.Attributes["classification_confidence"] = event.Attributes["fragment_link_confidence"]
			event.Attributes["source_family"] = sourceFamilyForCategory(parent.category)
			event.Attributes["semantic_category"] = parent.category
			delete(event.Attributes, "unclassified_reason")
			if event.Component == "" {
				event.Component = parent.component
			}
		}
		// Keep sipBurst warm across SDP/hash fragments so bare a=/m= lines link
		// even when the preceding line was itself a continuation (# SDP len).
		if event.Category == "sip" {
			a.sipBurst[event.DeviceID] = continuationParent{
				eventID: event.EventID, anchorID: constructAnchorID(event), receivedAt: event.ReceivedAt,
				sourceIP: sourceIP, category: event.Category,
				component: event.Component, callContext: callContext,
			}
		}
		if event.Category == "isup" {
			a.isupBurst[event.DeviceID] = continuationParent{
				eventID: event.EventID, anchorID: constructAnchorID(event), receivedAt: event.ReceivedAt,
				sourceIP: sourceIP, category: event.Category,
				component: event.Component, callContext: callContext,
			}
		}
	}
}

func constructAnchorID(event *analytics.SyslogEvent) uuid.UUID {
	if value := event.Attributes["construct_anchor_event_id"]; value != "" {
		if parsed, err := uuid.Parse(value); err == nil {
			return parsed
		}
	}
	return event.EventID
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

func PurgeDeviceNATS(ctx context.Context, nc *nats.Conn, deviceID uuid.UUID) error {
	if nc == nil {
		return nil
	}
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	for _, stream := range []string{"SYSLOG", "SYSLOG_DLQ"} {
		info, err := js.StreamInfo(stream, nats.Context(ctx))
		if err != nil {
			return err
		}
		for sequence := info.State.FirstSeq; sequence <= info.State.LastSeq && sequence != 0; sequence++ {
			message, err := js.GetMsg(stream, sequence, nats.Context(ctx))
			if errors.Is(err, nats.ErrMsgNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			var raw RawSyslog
			if json.Unmarshal(message.Data, &raw) != nil || raw.DeviceID != deviceID {
				continue
			}
			if err := js.DeleteMsg(stream, sequence, nats.Context(ctx)); err != nil {
				return err
			}
		}
	}
	return nil
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

type deviceWriteLocker interface {
	LockDeviceWrites(uuid.UUID) func()
}

func RunSyslogWorker(
	ctx context.Context,
	nc *nats.Conn,
	client *analytics.Client,
	timeResolver DeviceTimeConfigResolver,
	syslogConstructsEnabled ...bool,
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
	continuations := NewContinuationAssembler()
	constructsEnabled := len(syslogConstructsEnabled) > 0 && syslogConstructsEnabled[0]
	var constructs *SyslogConstructAssembler
	if constructsEnabled {
		constructs = NewSyslogConstructAssembler()
	}
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
				raw.TemplateKey = cached.config.TemplateKey
				raw.Firmware = cached.config.Firmware
			}
			event := ParseSyslog(raw)
			parsed = append(parsed, parsedMessage{message: message, event: event})
			events = append(events, event)
		}
		continuations.Assemble(events)
		for index := range parsed {
			parsed[index].event = events[index]
		}
		retry := func() bool {
			release := lockSyslogDevices(timeResolver, events)
			defer release()
			activeParsed := make([]parsedMessage, 0, len(parsed))
			activeEvents := make([]analytics.SyslogEvent, 0, len(events))
			for index, item := range parsed {
				if timeResolver != nil {
					if _, configErr := timeResolver.DeviceTimeConfig(ctx, item.event.DeviceID); configErr != nil {
						if errors.Is(configErr, store.ErrDeviceDeleting) ||
							errors.Is(configErr, store.ErrNotFound) {
							_ = item.message.Term()
							continue
						}
						_ = item.message.NakWithDelay(5 * time.Second)
						continue
					}
				}
				activeParsed = append(activeParsed, item)
				activeEvents = append(activeEvents, events[index])
			}
			if len(activeEvents) == 0 {
				return false
			}
			if err := client.InsertSyslogBatch(ctx, activeEvents); err != nil {
				slog.Error("syslog batch persistence failed", "count", len(activeEvents), "error", err)
				for _, item := range activeParsed {
					_ = item.message.NakWithDelay(5 * time.Second)
				}
				return true
			}
			if constructsEnabled {
				constructRows, memberRows, fragmentLinks := constructs.Assemble(activeEvents)
				if err := client.InsertSyslogFragmentLinksBatch(ctx, fragmentLinks); err != nil {
					slog.Error("Syslog fragment link persistence failed", "error", err)
					for _, item := range activeParsed {
						_ = item.message.NakWithDelay(5 * time.Second)
					}
					return true
				}
				if err := client.InsertSyslogConstructsBatch(ctx, constructRows); err != nil {
					slog.Error("Syslog construct persistence failed", "error", err)
					for _, item := range activeParsed {
						_ = item.message.NakWithDelay(5 * time.Second)
					}
					return true
				}
				if err := client.InsertSyslogConstructMembersBatch(ctx, memberRows); err != nil {
					slog.Error("Syslog construct member persistence failed", "error", err)
					for _, item := range activeParsed {
						_ = item.message.NakWithDelay(5 * time.Second)
					}
					return true
				}
			}
			if err := client.ProcessSyslogShadowDerivedBatch(ctx, activeEvents); err != nil {
				slog.Error("Syslog shadow lifecycle batch failed", "error", err)
				for _, item := range activeParsed {
					_ = item.message.NakWithDelay(5 * time.Second)
				}
				return true
			}
			if err := client.EnqueueDirtySyslogBuckets(ctx, activeEvents); err != nil {
				slog.Error("Syslog dirty bucket enqueue failed", "error", err)
				for _, item := range activeParsed {
					_ = item.message.NakWithDelay(5 * time.Second)
				}
				return true
			}
			for _, item := range activeParsed {
				_ = item.message.Ack()
			}
			return false
		}()
		if retry {
			continue
		}
	}
	return nil
}

func lockSyslogDevices(resolver DeviceTimeConfigResolver, events []analytics.SyslogEvent) func() {
	locker, ok := resolver.(deviceWriteLocker)
	if !ok {
		return func() {}
	}
	unique := make(map[uuid.UUID]struct{}, len(events))
	for _, event := range events {
		unique[event.DeviceID] = struct{}{}
	}
	ids := make([]uuid.UUID, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool {
		return ids[left].String() < ids[right].String()
	})
	releases := make([]func(), 0, len(ids))
	for _, id := range ids {
		releases = append(releases, locker.LockDeviceWrites(id))
	}
	return func() {
		for index := len(releases) - 1; index >= 0; index-- {
			releases[index]()
		}
	}
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
	dialect := syslogDialect(raw)
	event.Attributes["firmware_scheme"] = dialect
	if raw.TemplateKey != "" {
		event.Attributes["template_key"] = raw.TemplateKey
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
	} else if message, ok := parseEltexConfig(text); ok {
		event.HeaderFormat = "eltex-config"
		event.Message = message
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
	} else if timestamp, message, count, ok := parseRepeatedMessage(text, raw.ReceivedAt, location); ok {
		event.HeaderFormat = "rfc3164"
		event.EventTime = timestamp
		event.Message = message
		event.Attributes["repeat_suppressed"] = "true"
		event.Attributes["repeat_count"] = count
		event.ParseStatus = "parsed"
	} else {
		event.Message = text
		event.Attributes["parse_warning"] = "unrecognized_envelope"
	}
	if match := callContext.FindStringSubmatch(event.Message); match != nil {
		event.Attributes["call_context"] = match[1]
		// Keep leading indentation so fragment detection can see Eltex detail lines.
		event.Message = strings.TrimRight(match[2], "\r\n")
	}
	if component, rest, ok := splitComponent(event.Message); ok {
		event.Component = component
		event.Message = rest
	}
	if bareCDRRejectDump.MatchString(strings.TrimSpace(event.Message)) {
		event.Component = "CDR"
		event.Category = "call_trace"
		event.Attributes["classification_result"] = event.Category
		setClassificationProvenance(&event)
		event.Attributes["intrinsic_kind"] = "cdr_dump_field"
		event.Attributes["semantic_category"] = "call_trace"
		event.Attributes["source_family"] = "cdr"
		offsetTime := raw.ReceivedAt.In(location)
		if event.EventTime != nil {
			offsetTime = event.EventTime.In(location)
		}
		_, offsetSeconds := offsetTime.Zone()
		event.SourceUTCOffsetMinutes = int16(offsetSeconds / 60)
		return event
	}
	eltexTraceContext := event.HeaderFormat == "eltex-trace"
	hostIPContext := eltexTraceContext && (raw.TemplateKey == "" ||
		raw.TemplateKey == "eltex-smg-1016m-3.23.2" ||
		raw.TemplateKey == "eltex-smg-1016m-3.410")
	extractTraceContinuation(&event, dialect, hostIPContext)
	if strings.TrimSpace(event.Message) == "" && event.Attributes["call_context"] != "" {
		event.Attributes["empty_body"] = "true"
		if event.Attributes["trace_continuation"] == "" {
			event.Attributes["trace_continuation"] = "true"
			event.Attributes["fragment_kind"] = "empty"
		}
	}
	event.Category = classify(
		event.Component, event.Attributes["application"], event.Message, string(raw.Payload), dialect,
		hostIPContext,
	)
	event.Attributes["classification_result"] = event.Category
	setClassificationProvenance(&event)
	if event.Category == "radius" {
		extractRadiusAttributes(text, &event)
	}
	extractProtocolAttributes(text, &event)
	extractConstructHints(&event)
	offsetTime := raw.ReceivedAt.In(location)
	if event.EventTime != nil {
		offsetTime = event.EventTime.In(location)
	}
	_, offsetSeconds := offsetTime.Zone()
	event.SourceUTCOffsetMinutes = int16(offsetSeconds / 60)
	return event
}

func classify(component, application, message, payload, dialect string, hostIPContext bool) string {
	upperComponent := strings.ToUpper(strings.TrimSpace(component))
	upperApplication := strings.ToUpper(strings.TrimSpace(application))
	upperMessage := strings.ToUpper(strings.TrimSpace(message))
	upperBody := strings.ToUpper(strings.Join([]string{component, application, message}, " "))
	trimmedMessage := strings.TrimSpace(message)
	sipComponent := isSIPComponentName(upperComponent) || siptInMessage.MatchString(component) ||
		siptInMessage.MatchString(message) || siptProcPattern.MatchString(trimmedMessage) ||
		strings.HasPrefix(upperMessage, "PBXIPC-SIP")
	radiusOperationContext := upperComponent == "RADIUS" ||
		strings.Contains(upperMessage, "RADIUS") ||
		radiusRequestAlias.MatchString(message)
	radiusEvidence := radiusPacket.MatchString(message) || radiusRequestAlias.MatchString(message) ||
		radiusReplyAlias.MatchString(message) || radiusProcReply.MatchString(message) ||
		radiusAttribute.MatchString(trimmedMessage) ||
		(!(allows3410Dialect(dialect) && isBareSDPLine(trimmedMessage)) &&
			avpLinePattern.MatchString(trimmedMessage)) ||
		strings.Contains(upperMessage, "ACCT-SESSION-ID") ||
		strings.Contains(upperMessage, "XPGK-") ||
		strings.Contains(upperMessage, "XPKG-") ||
		(radiusOperationContext && radiusRequestID.MatchString(message)) ||
		radiusResponse.MatchString(message)
	switch {
	case upperApplication == "WEBAPP" || upperApplication == "WEBSPP" ||
		upperApplication == "WEBS" || upperApplication == "SEC" ||
		upperComponent == "WEBS" || upperComponent == "SEC" ||
		systemAppPattern.MatchString(payload) || systemBodyPattern.MatchString(message):
		return "system_journal"
	case allows3410Dialect(dialect) && isBareSDPLine(trimmedMessage):
		return "sip"
	case noOptionalParamsPat.MatchString(trimmedMessage):
		return "isup"
	case allows3410Dialect(dialect) && isIsupDumpFragment(trimmedMessage):
		return "isup"
	case upperComponent == "CONFIG":
		return "config_history"
	case sipComponent && radiusEvidence:
		return "radius"
	case sipComponent:
		return "sip"
	case radiusEvidence:
		return "radius"
	case upperComponent == "SS7" || upperComponent == "ISUP" || upperComponent == "SS7/ISUP" ||
		strings.Contains(upperComponent, "SS7 ") || strings.HasPrefix(upperComponent, "SS7/"):
		return "isup"
	case !sipComponent && (strings.Contains(upperBody, "SS7") || strings.Contains(upperBody, "ISUP") ||
		strings.Contains(upperBody, "IAM-") || strings.Contains(upperBody, "RLC-")):
		return "isup"
	case strings.Contains(upperBody, "Q.931") || strings.Contains(upperBody, "Q931") ||
		strings.Contains(upperBody, "DSS1"):
		return "q931"
	case strings.Contains(upperBody, "SIP") || strings.Contains(upperMessage, "INVITE") ||
		strings.Contains(upperMessage, "CALL-ID"):
		return "sip"
	case upperComponent == "H323" || strings.Contains(upperComponent, "H.323"):
		return "h323"
	case upperComponent == "RTP" || upperComponent == "RTCP" || upperComponent == "RTP-CREATE" ||
		strings.Contains(upperMessage, "RTP SESSION") || strings.Contains(upperMessage, "RTP STREAM"):
		return "rtp"
	case upperComponent == "HW" || strings.Contains(upperComponent, "HARDWARE"):
		return "hardware"
	case strings.Contains(upperBody, "IP-CONN") || strings.Contains(upperBody, "CONN[") ||
		strings.HasPrefix(upperComponent, "CONN["):
		return "ip_connections"
	case strings.Contains(upperComponent, "SM-VP") || strings.Contains(upperComponent, "SMVP") ||
		strings.Contains(upperComponent, "MSP") || upperComponent == "MSPC":
		return "ip_modules"
	case upperComponent == "IVR" || strings.HasPrefix(upperComponent, "IVR/"):
		return "ivr"
	case upperComponent == "IPNET" || strings.HasPrefix(upperComponent, "IPNET/"):
		return "ip_network"
	case upperComponent == "CDR":
		return "system_journal"
	case upperComponent == "ALARM" || upperComponent == "ALARMS" ||
		upperComponent == "ALARM-LED" || strings.HasPrefix(upperComponent, "ALARM") ||
		alarmPattern.MatchString(upperBody):
		return "alarms"
	case upperComponent == "SNMP":
		if strings.Contains(upperMessage, "TRAP") || strings.Contains(upperBody, "ALARM-ID") {
			return "alarms"
		}
		return "system_journal"
	case strings.Contains(upperMessage, "LAST MESSAGE REPEATED"):
		return "system_journal"
	case strings.Contains(upperBody, "CONFIG") || strings.Contains(upperBody, "COMMAND") ||
		strings.Contains(upperBody, "USERLOG"):
		return "config_history"
	case strings.Contains(upperBody, "AUTHLOG") || upperComponent == "AUTH":
		return "auth_log"
	case strings.Contains(upperMessage, "SDP LEN") ||
		strings.HasPrefix(trimmedMessage, "# SDP") ||
		strings.HasPrefix(trimmedMessage, "##"):
		return "sip"
	case strings.HasPrefix(eventCallContext(payload), "C") || callPattern.MatchString(upperBody):
		return "call_trace"
	case strings.HasPrefix(trimmedMessage, "#") ||
		codecLinePattern.MatchString(trimmedMessage):
		return "call_trace"
	case hostIPContext && ipv4OnlyPattern.MatchString(trimmedMessage):
		// SIP HostIPlist / Interface addr-list continuation lines.
		return "sip"
	case upperApplication != "":
		return "system_journal"
	default:
		return "unknown"
	}
}

func setClassificationProvenance(event *analytics.SyslogEvent) {
	event.Attributes["transport_family"] = "syslog"
	switch event.HeaderFormat {
	case "eltex-trace":
		event.Attributes["header_family"] = "eltex_trace"
	case "eltex-config":
		event.Attributes["header_family"] = "eltex_config"
	case "rfc3164", "rfc3164-or-pri":
		event.Attributes["header_family"] = "rfc3164"
	default:
		event.Attributes["header_family"] = "unknown"
	}
	event.Attributes["source_family"] = sourceFamilyForCategory(event.Category)
	event.Attributes["semantic_category"] = event.Category

	trimmed := strings.TrimSpace(event.Message)
	switch {
	case event.Attributes["fragment_kind"] != "":
		event.Attributes["intrinsic_kind"] = event.Attributes["fragment_kind"]
	case antifraudControlPat.MatchString(strings.Join([]string{event.Component, event.Message}, " ")) &&
		event.Category != "radius":
		event.Attributes["intrinsic_kind"] = "antifraud_control"
		event.Attributes["semantic_category"] = "antifraud_control"
	case event.Category == "radius":
		event.Attributes["intrinsic_kind"] = "radius_packet"
	case event.Category == "sip", event.Category == "isup", event.Category == "q931":
		event.Attributes["intrinsic_kind"] = "signaling"
	case event.Category == "unknown":
		event.Attributes["intrinsic_kind"] = "unknown"
	default:
		event.Attributes["intrinsic_kind"] = "journal_event"
	}

	if event.Category == "unknown" {
		event.Attributes["classification_rule"] = "no_matching_rule"
		event.Attributes["classification_confidence"] = "0"
		switch {
		case trimmed == "":
			event.Attributes["unclassified_reason"] = "empty_message"
		case event.ParseStatus == "partial":
			event.Attributes["unclassified_reason"] = "unrecognized_envelope_and_body"
		default:
			event.Attributes["unclassified_reason"] = "no_category_evidence"
		}
		return
	}
	event.Attributes["classification_rule"] = "category_evidence:" + event.Category
	event.Attributes["classification_confidence"] = "1"
}

func sourceFamilyForCategory(category string) string {
	switch category {
	case "sip", "isup", "radius", "q931", "rtp", "h323":
		return category
	case "config_history":
		return "config"
	case "system_journal", "auth_log":
		return "system"
	case "unknown", "":
		return "unknown"
	default:
		return category
	}
}

func isBareSDPLine(trimmed string) bool {
	if trimmed == "" {
		return false
	}
	if sdpLinePattern.MatchString(trimmed) {
		return true
	}
	if trimmed == "'" || sdpQuotePattern.MatchString(trimmed) {
		return true
	}
	return false
}

func isIsupDumpFragment(trimmed string) bool {
	return noOptionalParamsPat.MatchString(trimmed) || dottedHexPattern.MatchString(trimmed)
}

func isSIPComponentName(upperComponent string) bool {
	return upperComponent == "SIP" || upperComponent == "SIPT" ||
		strings.HasPrefix(upperComponent, "PORT SIPT") ||
		strings.HasPrefix(upperComponent, "SIPT[") ||
		strings.HasPrefix(upperComponent, "SIP[") ||
		strings.HasPrefix(upperComponent, "SIPT PROC") ||
		strings.Contains(upperComponent, "PBXIPC-SIP")
}

func isAllowedComponent(component string) bool {
	upper := strings.ToUpper(strings.TrimSpace(component))
	if _, ok := allowedComponents[upper]; ok {
		return true
	}
	if upper == "CONFIG" {
		return true
	}
	if strings.HasPrefix(upper, "PORT SIPT") || strings.HasPrefix(upper, "SIPT[") ||
		strings.HasPrefix(upper, "SIP[") || strings.HasPrefix(upper, "CONN[") ||
		strings.HasPrefix(upper, "SIPT PROC") {
		return true
	}
	if strings.HasPrefix(upper, "IVR/") || strings.HasPrefix(upper, "IPNET/") ||
		strings.HasPrefix(upper, "SS7/") || strings.Contains(upper, "SM-VP") {
		return true
	}
	return false
}

func splitComponent(message string) (component, rest string, ok bool) {
	trimmedLeft := strings.TrimLeft(message, " \t")
	leading := message[:len(message)-len(trimmedLeft)]
	if match := radiusRejectedPat.FindStringSubmatch(trimmedLeft); match != nil {
		return "RADIUS", "server rejected: " + strings.TrimSpace(match[1]), true
	}
	if match := portSIPTPattern.FindStringSubmatch(trimmedLeft); match != nil {
		return match[1], strings.TrimSpace(match[2]), true
	}
	if match := siptBracketPattern.FindStringSubmatch(trimmedLeft); match != nil {
		return match[1], strings.TrimSpace(match[2]), true
	}
	if match := connComponentPat.FindStringSubmatch(trimmedLeft); match != nil {
		return match[1], strings.TrimSpace(match[2]), true
	}
	match := componentPattern.FindStringSubmatch(trimmedLeft)
	if match == nil {
		return "", "", false
	}
	component = strings.TrimSpace(match[1])
	rest = strings.TrimSpace(match[2])
	if componentTimeRest.MatchString(rest) {
		return "", "", false
	}
	if !isAllowedComponent(component) {
		return "", "", false
	}
	if leading != "" && rest != "" {
		// Preserve indent only for non-component detail; component lines are top-level.
		_ = leading
	}
	return component, rest, true
}

func parseRepeatedMessage(
	value string, received time.Time, location *time.Location,
) (*time.Time, string, string, bool) {
	match := rfc3164Pattern.FindStringSubmatch(value)
	if match == nil {
		return nil, "", "", false
	}
	remainder := strings.TrimSpace(match[4])
	rep := repeatedMessage.FindStringSubmatch(remainder)
	if rep == nil {
		return nil, "", "", false
	}
	return parseRFC3164Time(match[1], match[2], match[3], received, location), remainder, rep[1], true
}

func markTraceContinuation(event *analytics.SyslogEvent, kind string) {
	event.Attributes["trace_continuation"] = "true"
	event.Attributes["fragment_kind"] = kind
}

func extractTraceContinuation(event *analytics.SyslogEvent, dialect string, hostIPContext bool) {
	rawMessage := event.Message
	trimmed := strings.TrimSpace(rawMessage)
	indented := trimmed != "" && len(rawMessage) > 0 &&
		(rawMessage[0] == ' ' || rawMessage[0] == '\t')
	if match := traceContinuation.FindStringSubmatch(trimmed); match != nil {
		kind := strings.ToLower(strings.Join(strings.Fields(match[1]), "_"))
		value := strings.TrimSpace(match[2])
		markTraceContinuation(event, "typed_hash")
		event.Attributes["continuation_type"] = kind
		switch kind {
		case "requestid":
			event.Attributes["request_id"] = value
		case "trunkid":
			event.Attributes["trunk_id"] = value
		case "keep_alive_type":
			event.Attributes["keep_alive_type"] = value
		case "cause":
			event.Attributes["cause"] = value
		case "connected_number", "number":
			event.Attributes["number"] = value
		}
		return
	}
	switch {
	case strings.HasPrefix(trimmed, "##"):
		markTraceContinuation(event, "sdp")
	case strings.HasPrefix(trimmed, "#"):
		markTraceContinuation(event, "hash_detail")
	case codecLinePattern.MatchString(trimmed):
		markTraceContinuation(event, "codec")
	case allows3410Dialect(dialect) && sdpLinePattern.MatchString(trimmed):
		markTraceContinuation(event, "sdp_line")
	case allows3410Dialect(dialect) && (trimmed == "'" || sdpQuotePattern.MatchString(trimmed)):
		markTraceContinuation(event, "sdp_quote")
	case noOptionalParamsPat.MatchString(trimmed):
		markTraceContinuation(event, "isup_optional")
	case allows3410Dialect(dialect) && dottedHexPattern.MatchString(trimmed):
		markTraceContinuation(event, "dotted_hex")
	case hexOnlyPattern.MatchString(strings.ReplaceAll(trimmed, " ", "")):
		markTraceContinuation(event, "hex")
	case digestLabelPat.MatchString(trimmed):
		markTraceContinuation(event, "digest")
	case radiusAttribute.MatchString(trimmed) || avpLinePattern.MatchString(trimmed):
		markTraceContinuation(event, "avp")
	case strings.EqualFold(event.Component, "rc"):
		markTraceContinuation(event, "rc_fragment")
	case hostIPContext && ipv4OnlyPattern.MatchString(trimmed):
		markTraceContinuation(event, "host_ip")
		event.Attributes["host_ip"] = trimmed
	case indented:
		markTraceContinuation(event, "indented")
	}
}

func parseEltexConfig(value string) (string, bool) {
	match := configLinePat.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return "", false
	}
	return strings.TrimSpace(match[0]), true
}

func extractRadiusAttributes(text string, event *analytics.SyslogEvent) {
	lowerText := strings.ToLower(text)
	for _, match := range radiusPair.FindAllStringSubmatch(text, -1) {
		value := firstNonEmpty(match[2], match[3], match[4])
		key := normalizeAttribute(match[1])
		value = strings.TrimSpace(value)
		event.Attributes[key] = value
		if (key == "eltex_avpair" || key == "cisco_avpair") && strings.Contains(value, "=") {
			vsa := strings.SplitN(value, "=", 2)
			event.Attributes[normalizeAttribute(vsa[0])] = strings.TrimSpace(vsa[1])
		}
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
		case radiusRequestAlias.MatchString(text):
			event.Attributes["packet_code"] = "access-request"
			event.Attributes["packet_direction"] = "request"
			event.Attributes["packet_dump_anchor"] = "true"
		case radiusReplyAlias.MatchString(text):
			event.Attributes["packet_code"] = "access-response"
			event.Attributes["packet_direction"] = "response"
			event.Attributes["packet_dump_anchor"] = "true"
		case radiusProcReply.MatchString(text):
			match := radiusProcReply.FindStringSubmatch(text)
			event.Attributes["packet_identifier"] = match[1]
			event.Attributes["result"] = strings.ToLower(match[2])
			event.Attributes["packet_code"] = "access-" + strings.ToLower(match[2])
			event.Attributes["packet_direction"] = "response"
			event.Attributes["latency_ms"] = radiusReplyLatencyMS(match[3], match[4])
			event.Attributes["packet_status_event"] = "true"
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
	} else if match := radiusAliasID.FindStringSubmatch(text); match != nil {
		event.Attributes["packet_identifier"] = match[1]
	} else if match := radiusReplyAlias.FindStringSubmatch(text); match != nil {
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

func radiusReplyLatencyMS(seconds, fraction string) string {
	whole, wholeErr := strconv.ParseUint(seconds, 10, 64)
	part, partErr := strconv.ParseUint(fraction, 10, 64)
	if wholeErr != nil || partErr != nil {
		return ""
	}
	// Eltex releases have emitted both milliseconds and microseconds after the
	// separator. Values wider than three digits are therefore reduced to ms.
	if len(fraction) > 3 {
		part /= 1000
	}
	return strconv.FormatUint(whole*1000+part, 10)
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
	if match := localCallrefPattern.FindStringSubmatch(text); match != nil {
		event.Attributes["callref"] = strings.ToLower(match[1])
	}
}

func extractConstructHints(event *analytics.SyslogEvent) {
	text := strings.Join([]string{event.Component, event.Message}, " ")
	if match := traceDirectionPat.FindStringSubmatch(text); match != nil {
		event.Attributes["direction"] = strings.ToUpper(match[1])
	}
	var messageName string
	switch event.Category {
	case "sip":
		if match := sipMessagePat.FindStringSubmatch(text); match != nil {
			messageName = strings.ToUpper(strings.Join(strings.Fields(match[1]), " "))
		}
	case "isup":
		if match := isupMessagePat.FindStringSubmatch(text); match != nil {
			messageName = strings.ToUpper(match[1])
		}
	case "q931":
		if match := q931MessagePat.FindStringSubmatch(text); match != nil {
			messageName = strings.ToUpper(strings.Join(strings.Fields(match[1]), " "))
		}
	case "radius":
		messageName = firstNonEmpty(
			event.Attributes["packet_code"],
			event.Attributes["request_type"],
		)
	}
	if messageName != "" {
		event.Attributes["message_name"] = messageName
	}
	event.Attributes["protocol_message_kind"] = constructTypeForCategory(event.Category)
}

func constructTypeForCategory(category string) string {
	switch category {
	case "sip":
		return "sip_exchange"
	case "isup":
		return "isup_pdu"
	case "q931":
		return "q931_message"
	case "radius":
		return "radius_packet"
	default:
		return "single_event"
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
	// Keep leading indentation: SMG detail/addr-list lines are tab-prefixed.
	message := strings.TrimRight(match[3], "\r\n")
	if strings.HasPrefix(strings.ToUpper(severity), "C") && strings.IndexFunc(severity, func(value rune) bool {
		return value >= '0' && value <= '9'
	}) >= 0 {
		message = "[" + severity + "] " + message
		severity = ""
	}
	// A plain RFC3164 body also starts with HH:MM:SS. Eltex trace is
	// distinguishable by microseconds, a severity, or a call-context bracket.
	trimmedMessage := strings.TrimSpace(message)
	if !strings.Contains(match[1], ".") && severity == "" && !strings.HasPrefix(trimmedMessage, "[") {
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
	normalized := strings.ReplaceAll(strings.ToLower(value), "-", "_")
	if strings.HasPrefix(normalized, "xpkg_") {
		normalized = "xpgk_" + strings.TrimPrefix(normalized, "xpkg_")
	}
	return normalized
}

func ValidateSyslogAddress(value string) error {
	if _, err := net.ResolveUDPAddr("udp", value); err != nil {
		return fmt.Errorf("invalid syslog address: %w", err)
	}
	return nil
}
