package ingest

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"collector/internal/analytics"

	"github.com/google/uuid"
)

func TestParseEltexSyslog(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC),
		SourceIP:   "10.0.0.10", SourcePort: 514,
		Payload: []byte("<134>11:42:26.910465 [INFO] SS7/ISUP. ISUP-profile 00. Create call CIC=42"),
	}
	event := ParseSyslog(raw)
	if event.Category != "isup" {
		t.Fatalf("got category %q, want isup", event.Category)
	}
	if event.PRI == nil || *event.PRI != 134 || event.Facility == nil || *event.Facility != 16 {
		t.Fatalf("PRI not decoded: %#v", event)
	}
	if event.ParseStatus != "parsed" || event.EventTime == nil {
		t.Fatalf("trace envelope not parsed: %#v", event)
	}
}

func TestParseEltexTraceContinuations(t *testing.T) {
	deviceID := uuid.New()
	receivedAt := time.Date(2026, 7, 24, 16, 8, 10, 0, time.UTC)
	tests := []struct {
		payload string
		kind    string
		key     string
		value   string
	}{
		{`<14> <smg1016m> 16:08:10.545 [INFO] # requestID 05b7`, "requestid", "request_id", "05b7"},
		{`<14> <smg1016m> 16:08:10.545 [INFO] # trunkID 02`, "trunkid", "trunk_id", "02"},
		{`<14> <smg1016m> 16:08:10.546 [INFO] # Keep alive type '0'`, "keep_alive_type", "keep_alive_type", "0"},
		{`<14> <smg1016m> 16:08:10.610 [INFO] # cause 200`, "cause", "cause", "200"},
	}
	for _, test := range tests {
		event := ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: receivedAt,
			SourceIP: "5.227.161.181", SourcePort: 10003, Payload: []byte(test.payload),
		})
		if event.Category != "call_trace" || event.ParseStatus != "parsed" {
			t.Fatalf("%q classified as %#v", test.payload, event)
		}
		if event.Attributes["trace_continuation"] != "true" ||
			event.Attributes["continuation_type"] != test.kind ||
			event.Attributes[test.key] != test.value {
			t.Fatalf("%q attributes: %#v", test.payload, event.Attributes)
		}
	}
}

func TestContinuationAssemblerIsDeviceScopedAndConservative(t *testing.T) {
	firstDevice, secondDevice := uuid.New(), uuid.New()
	start := time.Date(2026, 7, 24, 16, 8, 10, 0, time.UTC)
	events := []analytics.SyslogEvent{
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: firstDevice, ReceivedAt: start,
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m> 16:08:10.500 [INFO] RADIUS. Access-Request`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: secondDevice, ReceivedAt: start.Add(10 * time.Millisecond),
			SourceIP: "5.227.161.188",
			Payload:  []byte(`<14> <smg1016m> 16:08:10.510 [INFO] # requestID 05b7`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: firstDevice, ReceivedAt: start.Add(20 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m> 16:08:10.520 [INFO] # requestID 05b7`),
		}),
	}
	NewContinuationAssembler().Assemble(events)
	if events[1].Category != "call_trace" || events[1].Attributes["parent_event_id"] != "" {
		t.Fatalf("second device inherited foreign context: %#v", events[1])
	}
	if events[2].Category != "radius" ||
		events[2].Attributes["parent_event_id"] != events[0].EventID.String() {
		t.Fatalf("same-device RADIUS continuation was not assembled: %#v", events[2])
	}
}

func TestParseRadiusAttributes(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "10.0.0.10",
		Payload:  []byte(`12:00:01.001 [INFO] RADIUS. Access-Request Acct-Session-Id="11000307 6a62" Calling-Station-Id=73832888803 xpgk-request-type=check_call`),
	}
	event := ParseSyslog(raw)
	if event.Category != "radius" {
		t.Fatalf("got category %q, want radius", event.Category)
	}
	if event.Attributes["calling_station_id"] != "73832888803" {
		t.Fatalf("attributes not extracted: %#v", event.Attributes)
	}
	if event.Attributes["xpgk_request_type"] != "check_call" {
		t.Fatalf("request type not extracted: %#v", event.Attributes)
	}
}

func TestParseCustomAntifraudWithoutRadiusKeyword(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "10.0.0.10",
		Payload: []byte(
			`12:00:01.001 [INFO] aaa. Access-Accept Acct-Session-Id="11000307 6a62" ` +
				`Calling-Station-Id="73832888803" xpgk-request-type="check_call" xpgk-dst-number-in=74951234567`,
		),
	}
	event := ParseSyslog(raw)
	if event.Category != "radius" {
		t.Fatalf("got category %q, want radius", event.Category)
	}
	if event.Attributes["acct_session_id"] != "11000307 6a62" {
		t.Fatalf("quoted session id not extracted: %#v", event.Attributes)
	}
	if event.Attributes["xpgk_dst_number_in"] != "74951234567" {
		t.Fatalf("Custom VSA not extracted: %#v", event.Attributes)
	}
}

func TestParseAccountingResponseWithoutRadiusKeyword(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "10.0.0.10",
		Payload:  []byte(`12:00:01.001 [INFO] aaa. Accounting-Response Acct-Session-Id="session-42"`),
	}
	if event := ParseSyslog(raw); event.Category != "radius" {
		t.Fatalf("got category %q, want radius", event.Category)
	}
}

func TestParseProductionEltexTraceEnvelope(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 8, 10, 55, 0, time.UTC),
		SourceIP:   "5.227.161.181", SourcePort: 10003,
		Payload: []byte(
			`<14> <smg1016m>  08:10:54.758569  [INFO] [C0270AD] SIP. Callref 03b8. New state 'SIPT_WAIT_MEDIA'`,
		),
	}
	event := ParseSyslog(raw)
	if event.Category != "sip" || event.Component != "SIP" {
		t.Fatalf("production trace not classified: %#v", event)
	}
	if event.ParseStatus != "parsed" || event.HeaderFormat != "eltex-trace" || event.EventTime == nil {
		t.Fatalf("production trace envelope not parsed: %#v", event)
	}
	if event.Attributes["hostname"] != "smg1016m" || event.Attributes["call_context"] != "C0270AD" {
		t.Fatalf("trace context not extracted: %#v", event.Attributes)
	}
	if event.SourcePort != 10003 {
		t.Fatalf("source port was not preserved: %d", event.SourcePort)
	}
}

func TestParseProductionAntifraudRequestAndVSA(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "5.227.161.181", SourcePort: 10003,
		Payload: []byte(
			`<14> <smg1016m> 08:10:54.784750 [INFO] [C0270AD] Cisco-AVPair = 'xpgk-request-type=number'`,
		),
	}
	event := ParseSyslog(raw)
	if event.Category != "radius" {
		t.Fatalf("got category %q, want radius: %#v", event.Category, event)
	}
	if event.Attributes["xpgk_request_type"] != "number" {
		t.Fatalf("nested Custom VSA not extracted: %#v", event.Attributes)
	}
}

func TestParseProductionRadiusAttributeContinuation(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "5.227.161.181", SourcePort: 10003,
		Payload: []byte(
			`<14> <smg1016m> 08:10:54.784750 [INFO] [C0270AD] Acct-Session-Id = '110003b8 6a631e0e 4db08414 16098401'`,
		),
	}
	event := ParseSyslog(raw)
	if event.Category != "radius" {
		t.Fatalf("got category %q, want radius", event.Category)
	}
	if event.Attributes["acct_session_id"] != "110003b8 6a631e0e 4db08414 16098401" {
		t.Fatalf("session id not extracted: %#v", event.Attributes)
	}
}

func TestParseRFC3164WebAppIntoSystemJournal(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 6, 43, 47, 0, time.UTC),
		SourceIP:   "10.0.0.10", SourcePort: 514,
		Payload: []byte(
			`<134>Jul 24 06:43:46 webapp[590]: WEBS: websDone[204] "/cfg/get_disk"`,
		),
	}
	event := ParseSyslog(raw)
	if event.Category != "system_journal" {
		t.Fatalf("got category %q, want system_journal", event.Category)
	}
	if event.ParseStatus != "parsed" || event.HeaderFormat != "rfc3164" {
		t.Fatalf("RFC3164 header not parsed: %#v", event)
	}
	if event.Component != "WEBS" || event.Message != `websDone[204] "/cfg/get_disk"` {
		t.Fatalf("webapp body not parsed: %#v", event)
	}
	if event.Attributes["application"] != "webapp" || event.Attributes["process_id"] != "590" {
		t.Fatalf("webapp attributes not extracted: %#v", event.Attributes)
	}
	if event.EventTime == nil || !event.EventTime.Equal(time.Date(2026, 7, 24, 6, 43, 46, 0, time.UTC)) {
		t.Fatalf("event time not parsed: %#v", event.EventTime)
	}
}

func TestParseProductionWebsppIntoSystemJournal(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 8, 10, 56, 0, time.UTC),
		SourceIP:   "5.227.161.181", SourcePort: 514,
		Payload: []byte(
			`<38>Jul 24 08:10:55 webspp[590]: SEC: User <operator> access </jx/alarm> successfully`,
		),
	}
	event := ParseSyslog(raw)
	if event.Category != "system_journal" || event.Component != "SEC" {
		t.Fatalf("webspp security event not classified: %#v", event)
	}
	if event.Attributes["application"] != "webspp" {
		t.Fatalf("webspp application not extracted: %#v", event.Attributes)
	}
}

func TestParseWebsppAlarmPathStaysInSystemJournal(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 8, 10, 56, 0, time.UTC),
		SourceIP:   "5.227.161.181", SourcePort: 514,
		Payload: []byte(
			`<38>Jul 24 08:10:55 webspp[590]: WEBS: search handler for "/jx/alarm" path`,
		),
	}
	event := ParseSyslog(raw)
	if event.Category != "system_journal" || event.Component != "WEBS" {
		t.Fatalf("WEBS alarm URL was misclassified: %#v", event)
	}
}

func TestParseBareRFC3164WebsWithoutSpace(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 8, 10, 56, 0, time.UTC),
		SourceIP:   "5.227.161.181", SourcePort: 514,
		Payload: []byte(`<38>Jul 24 08:10:55 WEBS:websDone[0] "(null)"`),
	}
	event := ParseSyslog(raw)
	if event.Category != "system_journal" || event.Component != "WEBS" ||
		event.ParseStatus != "parsed" {
		t.Fatalf("bare WEBS event not parsed: %#v", event)
	}
}

func TestParseEltexTraceWithoutSeverity(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 8, 10, 56, 0, time.UTC),
		SourceIP:   "5.227.161.181", SourcePort: 10003,
		Payload: []byte(
			`<14> <smg1016m> 08:10:54.784750 [C0270AD] SIP. INVITE sip:74951234567@example.net`,
		),
	}
	event := ParseSyslog(raw)
	if event.Category != "sip" || event.Component != "SIP" ||
		event.Attributes["call_context"] != "C0270AD" || event.ParseStatus != "parsed" {
		t.Fatalf("severity-less trace not parsed: %#v", event)
	}
}

func TestClassifiesEverySMGFunctionalSection(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		category string
	}{
		{"radius", `<14> <smg1016m> 08:10:54.1 [INFO] [C1] RADIUS. Access-Request`, "radius"},
		{"isup", `<14> <smg1016m> 08:10:54.1 [INFO] [C1] SS7/ISUP. IAM- received`, "isup"},
		{"q931", `<14> <smg1016m> 08:10:54.1 [INFO] [C1] Q.931. SETUP received`, "q931"},
		{"sip", `<14> <smg1016m> 08:10:54.1 [INFO] [C1] PBXIPC-SIP. INVITE received`, "sip"},
		{"ip connections", `<14> <smg1016m> 08:10:54.1 [INFO] [C1] IP-CONN. RTP connection opened`, "ip_connections"},
		{"ip modules", `<14> <smg1016m> 08:10:54.1 [INFO] SM-VP. DSP module ready`, "ip_modules"},
		{"h323", `<14> <smg1016m> 08:10:54.1 [INFO] H323. H.225 session opened`, "h323"},
		{"rtp", `<14> <smg1016m> 08:10:54.1 [INFO] RTP-CREATE. RTP stream allocated`, "rtp"},
		{"hardware", `<14> <smg1016m> 08:10:54.1 [INFO] HW. E1 stream initialized`, "hardware"},
		{"ivr", `<14> <smg1016m> 08:10:54.1 [INFO] IVR. Scenario started`, "ivr"},
		{"ipnet", `<14> <smg1016m> 08:10:54.1 [INFO] IPNET. Interface state changed`, "ip_network"},
		{"alarms", `<14> <smg1016m> 08:10:54.1 [WARN] ALARM. E1 link lost`, "alarms"},
		{"configuration", `<14> <smg1016m> 08:10:54.1 [INFO] CONFIG. User command committed`, "config_history"},
		{"auth log", `<14> <smg1016m> 08:10:54.1 [INFO] AUTH. Login accepted`, "auth_log"},
		{"call trace", `<14> <smg1016m> 08:10:54.1 [INFO] [C0270AD] Media resources allocated`, "call_trace"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := ParseSyslog(RawSyslog{
				EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
				SourceIP: "5.227.161.181", SourcePort: 10003, Payload: []byte(test.payload),
			})
			if event.Category != test.category {
				t.Fatalf("got %q, want %q: %#v", event.Category, test.category, event)
			}
		})
	}
}

func TestRadiusV5ExtractsDocumentedLifecycleFields(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "5.227.161.181", SourcePort: 10003,
		Payload: []byte(`<14> <smg1016m> 08:10:54.784750 [INFO] [C0270AD] RADIUS. ` +
			`Access-Reject Request ID [157] server=10.0.0.8:1812 in 165 ms ` +
			`Acct-Session-Id='session 42' Cisco-AVPair='xpgk-request-type=check_call' ` +
			`Event-Timestamp=1784898654 Q.850=21`),
	})
	for key, want := range map[string]string{
		"call_context":      "C0270AD",
		"packet_code":       "access-reject",
		"packet_direction":  "response",
		"packet_identifier": "157",
		"server_address":    "10.0.0.8:1812",
		"latency_ms":        "165",
		"acct_session_id":   "session 42",
		"xpgk_request_type": "check_call",
		"decision":          "reject",
		"q850_cause":        "21",
	} {
		if got := event.Attributes[key]; got != want {
			t.Errorf("%s=%q, want %q; all=%#v", key, got, want, event.Attributes)
		}
	}
}

func TestSIPCiscoAVPairIsNotMisclassifiedAsRadius(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "5.227.161.181",
		Payload: []byte(`<14> <smg1016m> 08:10:54.1 [INFO] [C1] SIP. ` +
			`Header Cisco-AVPair='diagnostic=value' in INVITE`),
	})
	if event.Category != "sip" {
		t.Fatalf("got %q, want sip: %#v", event.Category, event)
	}
}

func TestConfigurationUserNameIsNotMisclassifiedAsRadius(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "5.227.161.181",
		Payload:  []byte(`<14> <smg1016m> 08:10:54.1 [INFO] CONFIG. User-Name changed`),
	})
	if event.Category != "config_history" {
		t.Fatalf("got %q, want config_history: %#v", event.Category, event)
	}
}

func TestSyslogWallClockUsesDeviceTimezone(t *testing.T) {
	received := time.Date(2026, 7, 24, 11, 0, 1, 0, time.UTC)
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: received,
		SourceIP: "10.0.0.10", SourcePort: 10003, Timezone: "Asia/Novosibirsk",
		Payload: []byte("<14> <smg1016m> 18:00:00.500 [INFO] [CTZ] RADIUS. Access-Request"),
	})
	want := time.Date(2026, 7, 24, 11, 0, 0, 500_000_000, time.UTC)
	if event.EventTime == nil || !event.EventTime.Equal(want) {
		t.Fatalf("event time = %v, want %v", event.EventTime, want)
	}
	if event.SourceTimezone != "Asia/Novosibirsk" || event.SourceUTCOffsetMinutes != 420 {
		t.Fatalf("source time audit = %q/%d", event.SourceTimezone, event.SourceUTCOffsetMinutes)
	}
}

func TestSyslogTimezoneConversionAcrossUTCMidnight(t *testing.T) {
	received := time.Date(2026, 7, 23, 18, 30, 1, 0, time.UTC)
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: received,
		Timezone: "Asia/Novosibirsk",
		Payload:  []byte("<14> <smg1016m> 01:30:00.000 [INFO] [CTZ2] CALLS: setup"),
	})
	want := time.Date(2026, 7, 23, 18, 30, 0, 0, time.UTC)
	if event.EventTime == nil || !event.EventTime.Equal(want) {
		t.Fatalf("event time = %v, want %v", event.EventTime, want)
	}
}

func TestKnownBodyDoesNotHidePartialEnvelope(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "5.227.161.181", Payload: []byte(`SIP INVITE without an envelope`),
	})
	if event.Category != "sip" || event.ParseStatus != "partial" ||
		event.Attributes["parse_warning"] == "" {
		t.Fatalf("parse quality was hidden: %#v", event)
	}
}

func TestParseRFC3164SecurityAccessWithHostname(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 6, 43, 35, 0, time.UTC),
		SourceIP:   "10.0.0.10",
		Payload: []byte(
			`Jul 24 06:43:34 smg-1016m webapp[590]: SEC: User <d_pershin> access </cfg/get_disk> successfully from 90.189.221.79`,
		),
	}
	event := ParseSyslog(raw)
	if event.Category != "system_journal" || event.Component != "SEC" {
		t.Fatalf("security access not classified: %#v", event)
	}
	if event.Attributes["application"] != "webapp" || event.Attributes["process_id"] != "590" {
		t.Fatalf("webapp attributes not extracted: %#v", event.Attributes)
	}
}

func TestParseLastMessageRepeated(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 12, 32, 34, 0, time.UTC),
		SourceIP:   "5.227.161.181", SourcePort: 514,
		Payload: []byte(`<38>Jul 24 19:32:34 last message repeated 7 times`),
	})
	if event.ParseStatus != "parsed" || event.Category != "system_journal" {
		t.Fatalf("repeat not parsed: %#v", event)
	}
	if event.Component != "" {
		t.Fatalf("timestamp must not become component: %q", event.Component)
	}
	if event.Attributes["repeat_suppressed"] != "true" || event.Attributes["repeat_count"] != "7" {
		t.Fatalf("repeat attributes: %#v", event.Attributes)
	}
	if event.Attributes["parse_warning"] != "" {
		t.Fatalf("unexpected parse_warning: %#v", event.Attributes)
	}
}

func TestClassifyCDRRotateAndAlarmSideChannels(t *testing.T) {
	received := time.Date(2026, 7, 24, 12, 33, 50, 0, time.UTC)
	tests := []struct {
		payload   string
		category  string
		component string
	}{
		{
			payload:   `<14> <smg1016m>  19:33:50.716037  [INFO]  cdr: start new file '/mnt/sda/cdrs/billing.cdr'`,
			category:  "system_journal",
			component: "cdr",
		},
		{
			payload:   `<14> <smg1016m>  19:19:06.799809  [INFO]  alarm-led: set [green]<->[green] [0]`,
			category:  "alarms",
			component: "alarm-led",
		},
		{
			payload:   `<14> <smg1016m>  19:19:06.732672  [INFO]  SNMP: add trap for send res [0]. * TRAP * [0016] alarm-id[12] state[0] params [0][0][0]`,
			category:  "alarms",
			component: "SNMP",
		},
	}
	for _, test := range tests {
		event := ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: received,
			SourceIP: "5.227.161.181", Payload: []byte(test.payload),
		})
		if event.ParseStatus != "parsed" || event.Category != test.category ||
			event.Component != test.component {
			t.Fatalf("%q => status=%q category=%q component=%q, want parsed/%s/%s",
				test.payload, event.ParseStatus, event.Category, event.Component,
				test.category, test.component)
		}
	}
}

func TestUnrecognizedCorpus20260724HasNoUnknownOrPartial(t *testing.T) {
	path := filepath.Join("testdata", "syslog_unrecognized_20260724.txt")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer file.Close()
	received := time.Date(2026, 7, 24, 12, 30, 0, 0, time.UTC)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var total int
	for scanner.Scan() {
		payload := strings.TrimSpace(scanner.Text())
		if payload == "" {
			continue
		}
		total++
		event := ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: received,
			SourceIP: "5.227.161.181", SourcePort: 514, Payload: []byte(payload),
		})
		if event.ParseStatus == "partial" || event.Category == "unknown" {
			t.Fatalf("corpus line %d still unrecognized: status=%q category=%q component=%q message=%q payload=%q",
				total, event.ParseStatus, event.Category, event.Component, event.Message, payload)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	if total != 43 {
		t.Fatalf("corpus size = %d, want 43", total)
	}
}

func TestUnrecognizedCorpus3410HasNoUnknown(t *testing.T) {
	path := filepath.Join("testdata", "syslog_unrecognized_3410.txt")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer file.Close()
	deviceID := uuid.New()
	received := time.Date(2026, 7, 24, 20, 21, 55, 0, time.UTC)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var events []analytics.SyslogEvent
	for scanner.Scan() {
		payload := strings.TrimSpace(scanner.Text())
		if payload == "" {
			continue
		}
		events = append(events, ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID,
			ReceivedAt: received.Add(time.Duration(len(events)) * time.Millisecond),
			SourceIP:   "5.227.161.181", SourcePort: 514, Payload: []byte(payload),
		}))
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	if len(events) != 897 {
		t.Fatalf("corpus size = %d, want 897", len(events))
	}
	// Seed a SIP parent so sipBurst can attach orphan SDP fragments the way a
	// real 3.410 burst does (# SDP len / PBXIPC-SIP immediately before bare a=).
	seed := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: received.Add(-time.Millisecond),
		SourceIP: "5.227.161.181",
		Payload:  []byte(`<14> <smg1016m>  20:21:55.157000  [INFO] # SDP len (232): 'v=0`),
	})
	batch := append([]analytics.SyslogEvent{seed}, events...)
	NewContinuationAssembler().Assemble(batch)
	for i, event := range batch[1:] {
		if event.Category == "unknown" {
			t.Fatalf("corpus line %d still unknown: component=%q message=%q attrs=%#v payload=%q",
				i+1, event.Component, event.Message, event.Attributes, string(event.Payload))
		}
	}
}

func TestConfigWithoutTimestampIsParsed(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 20, 0, 0, 0, time.UTC),
		SourceIP:   "5.227.161.181",
		Payload:    []byte(`<14> <smg1016m> CONFIG: Configuration cmd:[CFG_SAVE] by WEBS/d.pershin`),
	})
	if event.ParseStatus != "parsed" || event.HeaderFormat != "eltex-config" {
		t.Fatalf("CONFIG envelope not parsed: %#v", event)
	}
	if event.Category != "config_history" || event.Component != "CONFIG" {
		t.Fatalf("CONFIG not config_history: category=%q component=%q", event.Category, event.Component)
	}
	if event.Attributes["parse_warning"] != "" {
		t.Fatalf("unexpected parse_warning: %#v", event.Attributes)
	}
}

func TestSIPTProcWithISUPStaysSIP(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 20, 21, 55, 0, time.UTC),
		SourceIP:   "5.227.161.181",
		Payload: []byte(
			`<14> <smg1016m>  20:21:55.008088  [INFO] [C000045] SIPT Proc. Fill ISUP Hop counter. Callref 0044. Converted SIP Max-Forwards to ISUP Hop counter: 69 => 30`,
		),
	})
	if event.Category != "sip" || !strings.HasPrefix(strings.ToUpper(event.Component), "SIPT PROC") {
		t.Fatalf("SIPT Proc+ISUP leaked to %q component=%q", event.Category, event.Component)
	}
}

func TestBareSDPLinesClassifyAsSIP(t *testing.T) {
	deviceID := uuid.New()
	start := time.Date(2026, 7, 24, 20, 21, 55, 0, time.UTC)
	events := []analytics.SyslogEvent{
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start,
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  20:21:55.157000  [INFO] PBXIPC-SIP. TX INVITE`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  20:21:55.157100  [INFO] # SDP len (232): 'v=0`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(2 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  20:21:55.157200  [INFO] a=rtpmap:8 PCMA/8000`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(3 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  20:21:55.157300  [INFO] m=audio 4000 RTP/AVP 8 101`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(4 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  20:21:55.157400  [INFO] '`),
		}),
	}
	if events[0].Category != "sip" {
		t.Fatalf("PBXIPC-SIP parent category=%q", events[0].Category)
	}
	if events[1].Category != "sip" || events[1].Attributes["fragment_kind"] != "hash_detail" {
		t.Fatalf("# SDP len not sip/hash_detail: %#v", events[1])
	}
	if events[2].Category != "sip" || events[2].Attributes["fragment_kind"] != "sdp_line" {
		t.Fatalf("a= not sdp_line: %#v", events[2])
	}
	if events[3].Category != "sip" || events[3].Attributes["fragment_kind"] != "sdp_line" {
		t.Fatalf("m= not sdp_line: %#v", events[3])
	}
	if events[4].Category != "sip" || events[4].Attributes["fragment_kind"] != "sdp_quote" {
		t.Fatalf("quote not sdp_quote: %#v", events[4])
	}
	NewContinuationAssembler().Assemble(events)
	for i := 1; i < len(events); i++ {
		if events[i].Attributes["parent_event_id"] == "" {
			t.Fatalf("event %d missing parent: %#v", i, events[i].Attributes)
		}
		if events[i].Category != "sip" {
			t.Fatalf("event %d category=%q after assemble", i, events[i].Category)
		}
	}
}

func TestKeepAliveCauseInheritsSIPBurst(t *testing.T) {
	deviceID := uuid.New()
	start := time.Date(2026, 7, 24, 20, 40, 27, 0, time.UTC)
	events := []analytics.SyslogEvent{
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start,
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  20:40:27.910000  [INFO] SIP. Keep Alive TX`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  20:40:27.911187  [INFO] 		# cause 200`),
		}),
	}
	if events[1].Attributes["fragment_kind"] != "typed_hash" {
		t.Fatalf("cause not typed_hash: %#v", events[1].Attributes)
	}
	NewContinuationAssembler().Assemble(events)
	if events[1].Category != "sip" || events[1].Attributes["parent_event_id"] != events[0].EventID.String() {
		t.Fatalf("keep-alive # cause did not inherit SIP: %#v", events[1])
	}
}

func TestClassifySIPWithIAMStaysSIP(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 13, 3, 39, 0, time.UTC),
		SourceIP:   "5.227.161.181",
		Payload: []byte(
			`<14> <smg1016m>  20:03:39.762663  [INFO] [C027A1F] SIP. TX. Callref 061d.   IAM- Initial Address Message`,
		),
	})
	if event.Category != "sip" || event.Component != "SIP" {
		t.Fatalf("SIP+IAM leaked out of sip: %#v", event)
	}
}

func TestClassifySIPTSeizeWithSS7CategoryStaysSIP(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 13, 3, 39, 0, time.UTC),
		SourceIP:   "5.227.161.181",
		Payload: []byte(
			`<14> <smg1016m>  20:03:39.608002  [INFO] [C027A1F] SIPT[32]. Seize  - calling SS7 category: '0A' (10) (from incoming port)`,
		),
	})
	if event.Category != "sip" || !strings.HasPrefix(strings.ToUpper(event.Component), "SIPT[") {
		t.Fatalf("SIPT seize leaked to %q component=%q", event.Category, event.Component)
	}
}

func TestBareCDRRejectedFieldIsNotRadius(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 13, 2, 40, 0, time.UTC),
		SourceIP:   "5.227.161.181",
		Payload: []byte(
			`<14> <smg1016m>  20:02:40.960163  [INFO] [C027A1E] 		 RADIUS server rejected: :0 (replied 0)`,
		),
	})
	if event.Category != "call_trace" || event.Component != "CDR" ||
		event.Attributes["intrinsic_kind"] != "cdr_dump_field" ||
		event.Attributes["packet_code"] != "" {
		t.Fatalf("bare CDR field became a reject packet: %#v", event)
	}
	if !strings.Contains(event.Message, "server rejected") {
		t.Fatalf("message lost rejected wording: %q", event.Message)
	}
}

func TestEmptyCallBodyMarked(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(),
		ReceivedAt: time.Date(2026, 7, 24, 13, 3, 39, 0, time.UTC),
		SourceIP:   "5.227.161.181",
		Payload:    []byte(`<14> <smg1016m>  20:03:39.765516  [INFO] [C027A1F] `),
	})
	if event.Attributes["empty_body"] != "true" || event.Attributes["call_context"] != "C027A1F" {
		t.Fatalf("empty body not marked: %#v", event.Attributes)
	}
}

func TestFragmentLinkerGroupsSIPDetailAndRadiusAVP(t *testing.T) {
	deviceID := uuid.New()
	start := time.Date(2026, 7, 24, 13, 3, 39, 762663000, time.UTC)
	events := []analytics.SyslogEvent{
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start,
			SourceIP: "5.227.161.181",
			Payload: []byte(
				`<14> <smg1016m>  20:03:39.762663  [INFO] [C027A1F] SIP. TX. Callref 061d.   IAM- Initial Address Message`,
			),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(1 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload: []byte(
				`<14> <smg1016m>  20:03:39.762663  [INFO] [C027A1F] 		# 	ISUP: used all the way`,
			),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(2 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload: []byte(
				`<14> <smg1016m>  20:03:39.764983  [INFO] [C027A1F] Port SIPT:061d. RADIUS: Request ID [063] process Antifraud-Auth-Request.`,
			),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(3 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload: []byte(
				`<14> <smg1016m>  20:03:39.765100  [INFO] [C027A1F] Cisco-AVPair                     = 'xpgk-request-type=number'`,
			),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(4 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload: []byte(
				`<14> <smg1016m>  20:03:39.765200  [INFO] [C027A1F] 		## a=ptime:20`,
			),
		}),
	}
	if events[0].Category != "sip" {
		t.Fatalf("parent SIP category=%q", events[0].Category)
	}
	if events[1].Attributes["trace_continuation"] != "true" || events[1].Attributes["fragment_kind"] != "hash_detail" {
		t.Fatalf("ISUP detail not marked fragment: %#v", events[1].Attributes)
	}
	if events[2].Category != "radius" {
		t.Fatalf("Port SIPT RADIUS not radius: %#v", events[2])
	}
	if events[3].Attributes["fragment_kind"] != "avp" {
		t.Fatalf("AVP not marked: %#v", events[3].Attributes)
	}
	if events[4].Attributes["fragment_kind"] != "sdp" {
		t.Fatalf("SDP not marked: %#v", events[4].Attributes)
	}
	NewContinuationAssembler().Assemble(events)
	if events[1].Category != "sip" || events[1].Attributes["parent_event_id"] != events[0].EventID.String() {
		t.Fatalf("ISUP detail did not inherit SIP parent: %#v", events[1])
	}
	if events[3].Category != "radius" || events[3].Attributes["parent_event_id"] != events[2].EventID.String() {
		t.Fatalf("AVP did not inherit RADIUS parent: %#v", events[3])
	}
	if events[4].Category != "sip" || events[4].Attributes["parent_event_id"] != events[0].EventID.String() {
		t.Fatalf("SDP should inherit SIP signal parent: %#v", events[4])
	}
}

func TestSIPHostIPListFragmentClassifiesAsSIP(t *testing.T) {
	deviceID := uuid.New()
	start := time.Date(2026, 7, 24, 13, 3, 59, 0, time.UTC)
	events := []analytics.SyslogEvent{
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start,
			SourceIP: "5.227.161.181",
			Payload: []byte(
				`<14> <smg1016m>  20:03:59.323892  [INFO]  SIP. proc cmd 'HostIPlist' [6] [0]`,
			),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload: []byte(
				`<14> <smg1016m>  20:03:59.324262  [INFO]  		95.163.183.222`,
			),
		}),
	}
	if events[0].Category != "sip" {
		t.Fatalf("HostIPlist parent category=%q", events[0].Category)
	}
	if events[1].Category != "sip" || events[1].Attributes["fragment_kind"] != "host_ip" {
		t.Fatalf("bare IP not classified as SIP host_ip: %#v", events[1])
	}
	if events[1].Attributes["host_ip"] != "95.163.183.222" {
		t.Fatalf("host_ip attr: %#v", events[1].Attributes)
	}
	NewContinuationAssembler().Assemble(events)
	if events[1].Attributes["parent_event_id"] != events[0].EventID.String() {
		t.Fatalf("host_ip did not link to SIP parent: %#v", events[1].Attributes)
	}
}

func TestContinuationAssemblerKeepsSeparateCallContexts(t *testing.T) {
	deviceID := uuid.New()
	start := time.Date(2026, 7, 24, 13, 0, 0, 0, time.UTC)
	events := []analytics.SyslogEvent{
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start,
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  20:00:00.000000  [INFO] [C000001] SIP. invite`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(5 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  20:00:00.005000  [INFO] [C000002] SIP. invite`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(10 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  20:00:00.010000  [INFO] [C000001] 		# 	ISUP: used all the way`),
		}),
	}
	NewContinuationAssembler().Assemble(events)
	if events[2].Attributes["parent_event_id"] != events[0].EventID.String() {
		t.Fatalf("call context C000001 linked to wrong parent: %#v", events[2].Attributes)
	}
}

func TestUnrecognizedCorpus3410ISUPHasNoUnknown(t *testing.T) {
	path := filepath.Join("testdata", "syslog_unrecognized_3410_isup.txt")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer file.Close()
	deviceID := uuid.New()
	received := time.Date(2026, 7, 25, 0, 6, 45, 0, time.UTC)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var events []analytics.SyslogEvent
	for scanner.Scan() {
		payload := strings.TrimSpace(scanner.Text())
		if payload == "" {
			continue
		}
		events = append(events, ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID,
			ReceivedAt: received.Add(time.Duration(len(events)) * time.Millisecond),
			SourceIP:   "5.227.161.181", SourcePort: 514, Payload: []byte(payload),
		}))
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	if len(events) != 1627 {
		t.Fatalf("corpus size = %d, want 1627", len(events))
	}
	seed := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: received.Add(-time.Millisecond),
		SourceIP: "5.227.161.181",
		Payload:  []byte(`<14> <smg1016m>  00:06:45.000000  [INFO] SS7/ISUP. IAM CIC=1`),
	})
	batch := append([]analytics.SyslogEvent{seed}, events...)
	NewContinuationAssembler().Assemble(batch)
	for i, event := range batch[1:] {
		if event.Category == "unknown" {
			t.Fatalf("corpus line %d still unknown: message=%q attrs=%#v",
				i+1, event.Message, event.Attributes)
		}
		if event.Category != "isup" {
			t.Fatalf("corpus line %d category=%q want isup message=%q",
				i+1, event.Category, event.Message)
		}
	}
}

func TestFirmwareDialectClassifiesBareSDPBandwidth(t *testing.T) {
	raw := RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "192.0.2.10", TemplateKey: "eltex-smg-1016m-3.410",
		Payload: []byte(`<14> <smg1016m> 11:01:25.269949 [INFO] b=AS:82`),
	}
	event := ParseSyslog(raw)
	if event.Category != "sip" || event.Attributes["fragment_kind"] != "sdp_line" ||
		event.Attributes["firmware_scheme"] != "3.410" {
		t.Fatalf("3.410 SDP bandwidth was not recognized: %#v", event)
	}

	raw.EventID = uuid.New()
	raw.TemplateKey = "eltex-smg-1016m-3.23.2"
	event = ParseSyslog(raw)
	if event.Category != "unknown" || event.Attributes["fragment_kind"] != "" ||
		event.Attributes["firmware_scheme"] != "3.23.2" {
		t.Fatalf("3.23.2 accepted a bare 3.410 SDP fragment: %#v", event)
	}
}

func TestFirmwareDialectKeepsWrappedSDPCommon(t *testing.T) {
	for _, template := range []string{
		"eltex-smg-1016m-3.23.2",
		"eltex-smg-1016m-3.410",
	} {
		event := ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
			SourceIP: "192.0.2.10", TemplateKey: template,
			Payload: []byte(`<14> <smg1016m> 11:01:25.269949 [INFO] [C42] ##b=AS:82`),
		})
		if event.Category != "sip" || event.Attributes["fragment_kind"] != "sdp" {
			t.Fatalf("%s wrapped SDP was not recognized: %#v", template, event)
		}
	}
}

func TestConfigKeyValueTakesPriorityOverGenericAVP(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "192.0.2.10", TemplateKey: "eltex-smg-1016m-3.410",
		Payload: []byte(`<14> <smg1016m> 11:01:25.269949 [INFO] CONFIG: mode=active`),
	})
	if event.Category != "config_history" {
		t.Fatalf("CONFIG key=value was misclassified: %#v", event)
	}
}

func FuzzParseSyslogDialectNeverPanics(f *testing.F) {
	for _, seed := range []string{
		`<14> <smg1016m> 11:01:25.269949 [INFO] b=AS:82`,
		`<14> <smg1016m> 11:01:25.270000 [INFO] [C42] ##a=sendrecv`,
		`<14> <smg1016m> 11:01:25.271000 [INFO] 01.02.03.04.05.06`,
		`<14> <smg1016m> CONFIG: mode=active`,
		`<134>Jul 26 11:01:25 webapp[42]: WEBS: request complete`,
	} {
		f.Add(seed, "eltex-smg-1016m-3.410")
	}
	f.Fuzz(func(t *testing.T, payload, template string) {
		if len(payload) > 64<<10 {
			t.Skip()
		}
		_ = ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
			SourceIP: "192.0.2.10", TemplateKey: template, Payload: []byte(payload),
		})
	})
}

func TestDottedHexAndNoOptionalParamsClassifyAsISUP(t *testing.T) {
	deviceID := uuid.New()
	start := time.Date(2026, 7, 25, 0, 6, 45, 0, time.UTC)
	events := []analytics.SyslogEvent{
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start,
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  00:06:45.000000  [INFO] SS7/ISUP. Release`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  00:06:45.601491  [INFO] 0B.C5.35.43.20.10.41.00.17.01.01.1E.`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(2 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  00:06:45.601859  [INFO] 		[No optional params]`),
		}),
	}
	if events[1].Category != "isup" || events[1].Attributes["fragment_kind"] != "dotted_hex" {
		t.Fatalf("dotted hex not isup/dotted_hex: %#v", events[1])
	}
	if events[2].Category != "isup" || events[2].Attributes["fragment_kind"] != "isup_optional" {
		t.Fatalf("optional params not isup/isup_optional: %#v", events[2])
	}
	NewContinuationAssembler().Assemble(events)
	if events[1].Attributes["parent_event_id"] != events[0].EventID.String() {
		t.Fatalf("dotted_hex did not link to ISUP parent: %#v", events[1].Attributes)
	}
	if events[2].Attributes["parent_event_id"] == "" || events[2].Category != "isup" {
		t.Fatalf("isup_optional did not stay under ISUP: %#v", events[2])
	}
}

func TestDottedHexDoesNotInheritRADIUS(t *testing.T) {
	deviceID := uuid.New()
	start := time.Date(2026, 7, 25, 0, 6, 45, 0, time.UTC)
	events := []analytics.SyslogEvent{
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start,
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  00:06:45.000000  [INFO] RADIUS. Access-Request`),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(10 * time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  00:06:45.010000  [INFO] 0B.C5.35.43.20.10.41.00.17.01.01.1E.`),
		}),
	}
	NewContinuationAssembler().Assemble(events)
	if events[1].Category != "isup" {
		t.Fatalf("dotted hex category=%q want isup", events[1].Category)
	}
	if events[1].Attributes["parent_event_id"] != "" {
		t.Fatalf("dotted hex must not inherit RADIUS parent: %#v", events[1].Attributes)
	}
}

func TestConstructHintsAndStableAnchor(t *testing.T) {
	deviceID := uuid.New()
	start := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	events := []analytics.SyslogEvent{
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start,
			SourceIP: "5.227.161.181",
			Payload: []byte(
				`<14> <smg1016m>  10:00:00.000000  [INFO] [C0A001] SIP. TX. Callref 061d. INVITE sip:74951234567@example.test SIP/2.0`,
			),
		}),
		ParseSyslog(RawSyslog{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(time.Millisecond),
			SourceIP: "5.227.161.181",
			Payload:  []byte(`<14> <smg1016m>  10:00:00.001000  [INFO] a=sendrecv`),
		}),
	}
	if events[0].Attributes["direction"] != "TX" ||
		events[0].Attributes["message_name"] != "INVITE" ||
		events[0].Attributes["callref"] != "061d" ||
		events[0].Attributes["protocol_message_kind"] != "sip_exchange" {
		t.Fatalf("construct hints: %#v", events[0].Attributes)
	}
	NewContinuationAssembler().Assemble(events)
	if events[0].Attributes["construct_anchor_event_id"] != events[0].EventID.String() {
		t.Fatalf("parent anchor: %#v", events[0].Attributes)
	}
	if events[1].Attributes["construct_anchor_event_id"] != events[0].EventID.String() {
		t.Fatalf("fragment anchor: %#v", events[1].Attributes)
	}
	if events[1].Attributes["fragment_link_method"] != "sip_burst" ||
		events[1].Attributes["fragment_link_confidence"] != "0.7" {
		t.Fatalf("fragment provenance: %#v", events[1].Attributes)
	}
}

func TestEltexAntifraudV15GoldenCorpus(t *testing.T) {
	type goldenCase struct {
		Name       string              `json:"name"`
		Template   string              `json:"template"`
		Payloads   []string            `json:"payloads"`
		Categories []string            `json:"categories"`
		Attributes []map[string]string `json:"attributes"`
	}
	data, err := os.ReadFile(filepath.Join("testdata", "syslog_eltex_antifraud_v15.json"))
	if err != nil {
		t.Fatalf("read golden corpus: %v", err)
	}
	var cases []goldenCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("decode golden corpus: %v", err)
	}
	for _, golden := range cases {
		t.Run(golden.Name, func(t *testing.T) {
			if len(golden.Payloads) != len(golden.Categories) ||
				len(golden.Payloads) != len(golden.Attributes) {
				t.Fatalf("invalid golden lengths: %#v", golden)
			}
			deviceID := uuid.New()
			start := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)
			events := make([]analytics.SyslogEvent, 0, len(golden.Payloads))
			for index, payload := range golden.Payloads {
				events = append(events, ParseSyslog(RawSyslog{
					EventID: uuid.New(), DeviceID: deviceID,
					ReceivedAt: start.Add(time.Duration(index) * time.Millisecond),
					SourceIP:   "192.0.2.10", SourcePort: 514,
					TemplateKey: golden.Template, Payload: []byte(payload),
				}))
			}
			NewContinuationAssembler().Assemble(events)
			for index := range events {
				if events[index].Category != golden.Categories[index] {
					t.Errorf("event %d category=%q want %q: %#v",
						index, events[index].Category, golden.Categories[index], events[index])
				}
				for key, want := range golden.Attributes[index] {
					if got := events[index].Attributes[key]; got != want {
						t.Errorf("event %d %s=%q want %q; attrs=%#v",
							index, key, got, want, events[index].Attributes)
					}
				}
				wantSource := sourceFamilyForCategory(golden.Categories[index])
				if events[index].Attributes["intrinsic_kind"] == "cdr_dump_field" {
					wantSource = "cdr"
				}
				if events[index].Attributes["source_family"] != wantSource ||
					events[index].Attributes["transport_family"] != "syslog" ||
					events[index].Attributes["header_family"] == "" {
					t.Errorf("event %d provenance=%#v want source=%q",
						index, events[index].Attributes, wantSource)
				}
			}
		})
	}
}

func TestCallAntiFraudV16GoldenSummary(t *testing.T) {
	var fixture struct {
		Template   string    `json:"template"`
		ReceivedAt time.Time `json:"receivedAt"`
		Payloads   []string  `json:"payloads"`
		CDR        struct {
			SetupTime       time.Time `json:"setupTime"`
			DurationSeconds uint64    `json:"durationSeconds"`
			Q850Cause       uint16    `json:"q850Cause"`
			RadiusSessionID string    `json:"radiusSessionId"`
			IncomingRoute   string    `json:"incomingRoute"`
			OutgoingRoute   string    `json:"outgoingRoute"`
		} `json:"cdr"`
	}
	data, err := os.ReadFile(filepath.Join("testdata", "call_antifraud_v16.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.MustParse("10000000-0000-0000-0000-000000000016")
	events := make([]analytics.SyslogEvent, 0, len(fixture.Payloads))
	for index, payload := range fixture.Payloads {
		events = append(events, ParseSyslog(RawSyslog{
			EventID:  uuid.NewSHA1(uuid.NameSpaceOID, []byte(payload)),
			DeviceID: deviceID, ReceivedAt: fixture.ReceivedAt.Add(time.Duration(index) * time.Millisecond),
			SourceIP: "192.0.2.16", SourcePort: 514, TemplateKey: fixture.Template,
			Payload: []byte(payload),
		}))
	}
	NewContinuationAssembler().Assemble(events)
	if fixture.CDR.SetupTime.IsZero() || fixture.CDR.DurationSeconds != 28 ||
		fixture.CDR.Q850Cause != 16 || fixture.CDR.IncomingRoute == "" ||
		fixture.CDR.OutgoingRoute == "" {
		t.Fatalf("golden CDR fact is incomplete: %#v", fixture.CDR)
	}
	if strings.ToLower(strings.Join(strings.Fields(fixture.CDR.RadiusSessionID), "")) !=
		events[1].Attributes["acct_session_id_normalized"] &&
		strings.ToLower(strings.Join(strings.Fields(fixture.CDR.RadiusSessionID), "")) !=
			strings.ToLower(strings.Join(strings.Fields(events[1].Attributes["acct_session_id"]), "")) {
		t.Fatalf("golden CDR does not retain inbound leg relationship")
	}
	last := events[len(events)-1]
	if last.Category != "call_trace" ||
		last.Attributes["intrinsic_kind"] != "cdr_dump_field" ||
		last.Attributes["packet_code"] != "" {
		t.Fatalf("bare CDR field became RADIUS reject: %#v", last)
	}
	got, err := json.MarshalIndent(analytics.CompactAntiFraudSummary(events), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "call_antifraud_v16_expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gotValue, wantValue any
	if json.Unmarshal(got, &gotValue) != nil || json.Unmarshal(want, &wantValue) != nil {
		t.Fatal("invalid compact summary JSON")
	}
	gotCanonical, _ := json.Marshal(gotValue)
	wantCanonical, _ := json.Marshal(wantValue)
	if string(gotCanonical) != string(wantCanonical) {
		t.Fatalf("compact summary mismatch:\ngot  %s\nwant %s", got, want)
	}
}

func TestTrueRadiusRejectStillParses(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "192.0.2.16",
		Payload: []byte(`<14> <smg1016m> 22:30:31.000000 [INFO] [CREJ] ` +
			`RADIUS server rejected: server=192.0.2.44 Request ID [070]`),
	})
	if event.Category != "radius" || event.Attributes["packet_code"] != "access-reject" ||
		event.Attributes["packet_identifier"] != "070" ||
		event.Attributes["server_address"] != "192.0.2.44" {
		t.Fatalf("true reject evidence was lost: %#v", event)
	}
}

func TestEltexAntifraudV15CorpusAudit(t *testing.T) {
	type goldenCase struct {
		Template string   `json:"template"`
		Payloads []string `json:"payloads"`
	}
	type auditReport struct {
		Total            int            `json:"total"`
		Categories       map[string]int `json:"categories"`
		UnknownReasons   map[string]int `json:"unknown_reasons"`
		SourceConfusions int            `json:"source_confusions"`
		Coverage         map[string]int `json:"coverage"`
	}
	corpusData, err := os.ReadFile(filepath.Join(
		"testdata", "syslog_eltex_antifraud_v15.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var corpus []goldenCase
	if err := json.Unmarshal(corpusData, &corpus); err != nil {
		t.Fatal(err)
	}
	report := auditReport{
		Categories: make(map[string]int), UnknownReasons: make(map[string]int),
		Coverage: make(map[string]int),
	}
	for _, fixture := range corpus {
		deviceID := uuid.New()
		events := make([]analytics.SyslogEvent, 0, len(fixture.Payloads))
		for index, payload := range fixture.Payloads {
			events = append(events, ParseSyslog(RawSyslog{
				EventID: uuid.New(), DeviceID: deviceID,
				ReceivedAt: time.Date(2026, 7, 27, 10, 0, 0, index, time.UTC),
				SourceIP:   "192.0.2.10", SourcePort: 514,
				TemplateKey: fixture.Template, Payload: []byte(payload),
			}))
		}
		NewContinuationAssembler().Assemble(events)
		for _, event := range events {
			report.Total++
			report.Categories[event.Category]++
			if reason := event.Attributes["unclassified_reason"]; reason != "" {
				report.UnknownReasons[reason]++
			}
			if event.Attributes["source_family"] != sourceFamilyForCategory(event.Category) &&
				event.Attributes["intrinsic_kind"] != "cdr_dump_field" {
				report.SourceConfusions++
			}
			if event.Attributes["source_family"] != "" {
				report.Coverage["producer_provenance"]++
			}
			if event.Attributes["transport_family"] == "syslog" {
				report.Coverage["transport_provenance"]++
			}
			switch event.Attributes["fragment_kind"] {
			case "host_ip", "isup_optional", "hash_detail":
				report.Coverage[event.Attributes["fragment_kind"]]++
			}
			if event.Attributes["intrinsic_kind"] == "antifraud_control" {
				report.Coverage["antifraud_control"]++
			}
			if event.Attributes["packet_code"] == "access-request" {
				report.Coverage["access_request_alias"]++
			}
			if event.Attributes["packet_code"] == "access-reject" {
				report.Coverage["access_reject_response"]++
			}
			if operationType := event.Attributes["xpgk_request_type"]; operationType != "" {
				report.Coverage["operation_"+operationType]++
			}
		}
	}
	expectedData, err := os.ReadFile(filepath.Join(
		"testdata", "syslog_eltex_antifraud_v15_audit.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var expected auditReport
	if err := json.Unmarshal(expectedData, &expected); err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(report)
	wantJSON, _ := json.Marshal(expected)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("corpus audit drifted:\ngot  %s\nwant %s", gotJSON, wantJSON)
	}
}

func TestClassificationProvenanceAndConservativeBareIP(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "192.0.2.10", TemplateKey: "eltex-smg-1016m-3.23.2",
		Payload: []byte("192.0.2.23"),
	})
	if event.Category != "unknown" || event.Attributes["fragment_kind"] != "" {
		t.Fatalf("unenveloped IPv4 must not become SIP: %#v", event)
	}
	for key, want := range map[string]string{
		"source_family":             "unknown",
		"transport_family":          "syslog",
		"header_family":             "unknown",
		"intrinsic_kind":            "unknown",
		"classification_rule":       "no_matching_rule",
		"classification_confidence": "0",
		"unclassified_reason":       "unrecognized_envelope_and_body",
	} {
		if got := event.Attributes[key]; got != want {
			t.Errorf("%s=%q want %q; attrs=%#v", key, got, want, event.Attributes)
		}
	}

	known := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "192.0.2.10",
		Payload:  []byte(`<14> <smg1016m> 10:00:00.000000 [INFO] SIP. INVITE sip:user@example.test`),
	})
	for _, key := range []string{
		"source_family", "transport_family", "header_family", "intrinsic_kind",
		"classification_rule", "classification_confidence",
	} {
		if known.Attributes[key] == "" {
			t.Errorf("known event missing %s: %#v", key, known.Attributes)
		}
	}
	if known.Attributes["unclassified_reason"] != "" {
		t.Errorf("known event has unclassified reason: %#v", known.Attributes)
	}
	if known.Attributes["source_family"] != "sip" ||
		known.Attributes["header_family"] != "eltex_trace" {
		t.Errorf("producer/header provenance was conflated: %#v", known.Attributes)
	}
}
