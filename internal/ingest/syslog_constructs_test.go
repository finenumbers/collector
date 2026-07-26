package ingest

import (
	"testing"
	"time"

	"collector/internal/analytics"

	"github.com/google/uuid"
)

func TestSyslogConstructAssemblerIsStableAcrossBatches(t *testing.T) {
	deviceID := uuid.New()
	start := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	parent := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start,
		SourceIP: "10.0.0.10",
		Payload: []byte(
			`<14> <smg1016m> 10:00:00.000000 [INFO] [C100001] SIP. TX. Callref 01ab. INVITE sip:100@example.test SIP/2.0`,
		),
	})
	child := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: start.Add(time.Millisecond),
		SourceIP: "10.0.0.10",
		Payload:  []byte(`<14> <smg1016m> 10:00:00.001000 [INFO] a=sendrecv`),
	})
	continuations := NewContinuationAssembler()
	continuations.Assemble([]analytics.SyslogEvent{parent})
	childBatch := []analytics.SyslogEvent{child}
	continuations.Assemble(childBatch)
	child = childBatch[0]

	assembler := NewSyslogConstructAssembler()
	parentConstructs, parentMembers, _ := assembler.Assemble([]analytics.SyslogEvent{parent})
	childConstructs, childMembers, links := assembler.Assemble([]analytics.SyslogEvent{child})
	if len(parentConstructs) != 1 || len(childConstructs) != 1 {
		t.Fatalf("construct counts parent=%d child=%d", len(parentConstructs), len(childConstructs))
	}
	if parentConstructs[0].ConstructID != childConstructs[0].ConstructID {
		t.Fatalf("batch boundary split construct: %s != %s",
			parentConstructs[0].ConstructID, childConstructs[0].ConstructID)
	}
	if len(parentMembers) != 1 || len(childMembers) != 1 ||
		parentMembers[0].Ordinal != 0 || childMembers[0].Ordinal != 1 {
		t.Fatalf("member ordinals: parent=%#v child=%#v", parentMembers, childMembers)
	}
	if len(links) != 1 || links[0].LinkMethod != "sip_burst" || links[0].Confidence != 0.7 {
		t.Fatalf("link provenance: %#v", links)
	}
	if childConstructs[0].MemberCount != 2 || childConstructs[0].GroupingMethod != "heuristic" {
		t.Fatalf("updated construct: %#v", childConstructs[0])
	}
}

func TestSyslogConstructAssemblerRetryIsIdempotent(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "10.0.0.10",
		Payload:  []byte(`<14> <smg1016m> 10:00:00.000000 [INFO] CONFIG: Configuration saved`),
	})
	NewContinuationAssembler().Assemble([]analytics.SyslogEvent{event})
	assembler := NewSyslogConstructAssembler()
	first, firstMembers, _ := assembler.Assemble([]analytics.SyslogEvent{event})
	second, secondMembers, _ := assembler.Assemble([]analytics.SyslogEvent{event})
	if len(first) != 1 || len(second) != 1 || first[0].ConstructID != second[0].ConstructID {
		t.Fatalf("retry changed construct: first=%#v second=%#v", first, second)
	}
	if second[0].MemberCount != 1 || secondMembers[0].Ordinal != firstMembers[0].Ordinal {
		t.Fatalf("retry duplicated member: construct=%#v member=%#v", second[0], secondMembers[0])
	}
}

func TestSyslogConstructAssemblerSeparatesTimezoneRevisions(t *testing.T) {
	event := ParseSyslog(RawSyslog{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		SourceIP: "10.0.0.10",
		Payload:  []byte(`<14> <smg1016m> 10:00:00.000000 [INFO] CONFIG: Configuration saved`),
	})
	event.TimezoneRevision = 1
	assembler := NewSyslogConstructAssembler()
	first, _, _ := assembler.Assemble([]analytics.SyslogEvent{event})
	event.TimezoneRevision = 2
	second, _, _ := assembler.Assemble([]analytics.SyslogEvent{event})
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("construct counts first=%d second=%d", len(first), len(second))
	}
	if first[0].TimezoneRevision != 1 || second[0].TimezoneRevision != 2 {
		t.Fatalf("revision state leaked: first=%#v second=%#v", first[0], second[0])
	}
	if second[0].MemberCount != 1 {
		t.Fatalf("revision replay duplicated members: %#v", second[0])
	}
}
