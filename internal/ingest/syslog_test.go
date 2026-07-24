package ingest

import (
	"testing"
	"time"

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
