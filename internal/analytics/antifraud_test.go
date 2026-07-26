package analytics

import (
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAntifraudAssemblerCombinesFragmentsAndRejectDecision(t *testing.T) {
	deviceID := uuid.New()
	now := time.Now().UTC()
	transaction := &AntifraudTransaction{
		TransactionID: uuid.New(), DeviceID: deviceID, FirstEventAt: now,
		Attributes: make(map[string]string), ParserVersion: SyslogParserVersion,
	}
	request := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now,
		Attributes: map[string]string{
			"call_context": "C0273CA", "packet_code": "access-request",
			"packet_direction": "request", "packet_identifier": "157",
			"acct_session_id": "110003b8 6A63", "xpgk_request_type": "check_call",
			"calling_station_id": "73832888803", "called_station_id": "74951234567",
		},
	}
	identifier := uint8(157)
	mergeAntifraudEvent(transaction, request, now, &identifier, nil, 0, nil)
	response := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now.Add(165 * time.Millisecond),
		Attributes: map[string]string{
			"call_context": "C0273CA", "packet_code": "access-reject",
			"packet_direction": "response", "result": "reject", "latency_ms": "165",
		},
	}
	latency := uint32(165)
	mergeAntifraudEvent(transaction, response, response.ReceivedAt, &identifier, &latency, 0, nil)
	if transaction.Decision != "reject" || transaction.DecisionReason != "Access-Reject" {
		t.Fatalf("incorrect decision: %#v", transaction)
	}
	if transaction.Q850Cause == nil || *transaction.Q850Cause != 21 {
		t.Fatalf("reject must map to Q.850 21: %#v", transaction.Q850Cause)
	}
	if transaction.Completeness != "complete" || transaction.IsAntifraud != 1 {
		t.Fatalf("lifecycle not completed: %#v", transaction)
	}
	if len(transaction.RawEventIDs) != 2 ||
		transaction.AcctSessionIDNormalized != "110003b86a63" {
		t.Fatalf("fragments not assembled: %#v", transaction)
	}
}

func TestCanonicalRadiusTimePrefersEmbeddedTimestamp(t *testing.T) {
	received := time.Date(2026, 7, 27, 1, 0, 0, 0, time.UTC)
	embedded := received.Add(-17 * time.Minute)
	event := SyslogEvent{
		ReceivedAt: received, SourceTimezone: "UTC",
		Attributes: map[string]string{
			"event_timestamp": strconv.FormatInt(embedded.Unix(), 10),
			"acct_delay_time": "30",
		},
	}
	canonical, occurredAt := canonicalizeRadiusEvent(event)
	if !occurredAt.Equal(embedded) ||
		canonical.Attributes["correlation_time_source"] != "event_timestamp" {
		t.Fatalf("canonical time=%v attributes=%v", occurredAt, canonical.Attributes)
	}
}

func TestCanonicalRadiusTimeAppliesAccountingDelay(t *testing.T) {
	received := time.Date(2026, 7, 27, 1, 0, 0, 0, time.UTC)
	eventTime := received.Add(-time.Minute)
	event := SyslogEvent{
		ReceivedAt: received, EventTime: &eventTime,
		Attributes: map[string]string{"acct_delay_time": "45"},
	}
	canonical, occurredAt := canonicalizeRadiusEvent(event)
	if !occurredAt.Equal(eventTime.Add(-45*time.Second)) ||
		canonical.Attributes["correlation_time_source"] != "event_time_minus_acct_delay" {
		t.Fatalf("canonical time=%v attributes=%v", occurredAt, canonical.Attributes)
	}
}

func TestAntifraudIdentityUsesCanonicalOccurrenceWindow(t *testing.T) {
	deviceID := uuid.New()
	occurredAt := time.Date(2026, 7, 27, 0, 29, 59, 0, time.UTC)
	first := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID,
		ReceivedAt: occurredAt.Add(time.Minute),
		Attributes: map[string]string{"call_context": "C-CANONICAL"},
	}
	second := first
	second.EventID = uuid.New()
	second.ReceivedAt = occurredAt.Add(31 * time.Minute)
	if antifraudTransactionID(first, occurredAt) != antifraudTransactionID(second, occurredAt) {
		t.Fatal("receive-time drift split one canonical lifecycle")
	}
}

func TestLifecyclePreservesFirstCanonicalTimeProvenance(t *testing.T) {
	firstAt := time.Date(2026, 7, 27, 1, 0, 0, 0, time.UTC)
	transaction := &AntifraudTransaction{
		TransactionID: uuid.New(), DeviceID: uuid.New(), Attributes: map[string]string{},
	}
	first := SyslogEvent{
		EventID: uuid.New(), Attributes: map[string]string{
			"correlation_time_source": "event_timestamp",
			"correlation_time_utc":    firstAt.Format(time.RFC3339Nano),
		},
	}
	mergeAntifraudEvent(transaction, first, firstAt, nil, nil, 0, nil)
	later := SyslogEvent{
		EventID: uuid.New(), Attributes: map[string]string{
			"correlation_time_source": "received_at",
			"correlation_time_utc":    firstAt.Add(time.Minute).Format(time.RFC3339Nano),
		},
	}
	mergeAntifraudEvent(transaction, later, firstAt.Add(time.Minute), nil, nil, 0, nil)
	if got := transaction.Attributes["correlation_time_source"]; got != "event_timestamp" {
		t.Fatalf("first-event provenance was overwritten: %q", got)
	}
}

func TestAntifraudTimeoutIsFailOpenOnlyForCheckCall(t *testing.T) {
	transaction := &AntifraudTransaction{
		TransactionID: uuid.New(), DeviceID: uuid.New(), FirstEventAt: time.Now().UTC(),
		RequestType: "check_call", IsAntifraud: 1, Attributes: make(map[string]string),
	}
	event := SyslogEvent{
		EventID: uuid.New(), DeviceID: transaction.DeviceID, ReceivedAt: time.Now().UTC(),
		Attributes: map[string]string{"decision": "timeout_fail_open"},
	}
	mergeAntifraudEvent(transaction, event, event.ReceivedAt, nil, nil, 0, nil)
	if transaction.Decision != "timeout_fail_open" ||
		transaction.DecisionReason != "RADIUS timeout, documented fail-open" {
		t.Fatalf("timeout semantics lost: %#v", transaction)
	}
}

func TestAntifraudTransactionIDUsesDeviceAndCallContext(t *testing.T) {
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	device := uuid.New()
	first := SyslogEvent{
		EventID: uuid.New(), DeviceID: device,
		Attributes: map[string]string{"call_context": "C0273CA"},
	}
	second := first
	second.EventID = uuid.New()
	if antifraudTransactionID(first, now) != antifraudTransactionID(second, now.Add(time.Minute)) {
		t.Fatal("same device/day/call context must assemble into one lifecycle")
	}
	other := second
	other.DeviceID = uuid.New()
	if antifraudTransactionID(first, now) == antifraudTransactionID(other, now) {
		t.Fatal("different devices must never share a lifecycle")
	}
}
