package ingest

import (
	"bufio"
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
		payload  string
		category string
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
