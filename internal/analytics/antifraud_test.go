package analytics

import (
	"strconv"
	"strings"
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
	if transaction.Decision != "verification_reject" ||
		transaction.DecisionReason != "Access-Reject" {
		t.Fatalf("incorrect decision: %#v", transaction)
	}
	if transaction.Q850Cause != nil {
		t.Fatalf("reject must not synthesize Q.850: %#v", transaction.Q850Cause)
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
	if transaction.Decision != "verification_fail_open" ||
		transaction.DecisionReason != "RADIUS timeout, documented fail-open" {
		t.Fatalf("timeout semantics lost: %#v", transaction)
	}
}

func TestProjectionKeepsOperationTypesDistinctAndVSAOrder(t *testing.T) {
	deviceID := uuid.New()
	now := time.Date(2026, 7, 27, 1, 0, 0, 0, time.UTC)
	events := make([]SyslogEvent, 0)
	for index, operationType := range []string{"number", "save_call", "check_call"} {
		anchor := uuid.New()
		request := SyslogEvent{
			EventID: anchor, DeviceID: deviceID,
			ReceivedAt: now.Add(time.Duration(index) * time.Second), Category: "radius",
			Payload: []byte(`Eltex-AVPair="xpgk-request-type=` + operationType +
				`" Eltex-AVPair="xpgk-src-number-in=100" Eltex-AVPair="xpgk-src-number-in=200"`),
			Attributes: map[string]string{
				"construct_anchor_event_id": anchor.String(), "call_context": "C-SHARED",
				"acct_session_id": "shared session", "packet_code": "access-request",
				"packet_direction": "request", "packet_identifier": strconv.Itoa(40 + index),
				"xpgk_request_type": operationType,
			},
		}
		response := request
		response.EventID = uuid.New()
		response.ReceivedAt = request.ReceivedAt.Add(100 * time.Millisecond)
		response.Payload = []byte("Access-Accept")
		response.Attributes = map[string]string{
			"construct_anchor_event_id": response.EventID.String(),
			"call_context":              "C-SHARED",
			"packet_code":               "access-accept",
			"packet_direction":          "response",
			"packet_identifier":         strconv.Itoa(40 + index),
		}
		events = append(events, request, response)
	}
	projection := buildAntiFraudProjection(events, nil)
	if len(projection.Operations) != 3 {
		t.Fatalf("operations=%d want 3: %#v", len(projection.Operations), projection.Operations)
	}
	types := map[string]string{}
	for _, operation := range projection.Operations {
		types[operation.OperationType] = operation.TerminalState
	}
	if types["number"] != "informational" || types["save_call"] != "informational" ||
		types["check_call"] != "verification_accept" {
		t.Fatalf("operation semantics were conflated: %#v", types)
	}
	if len(projection.Calls) != 1 {
		t.Fatalf("same session produced %d calls", len(projection.Calls))
	}
	requestPacket := projection.Packets[0]
	var values []string
	for index, key := range requestPacket.AttributeKeys {
		if key == "xpgk_src_number_in" {
			values = append(values, requestPacket.AttributeValues[index])
		}
	}
	if strings.Join(values, ",") != "100,200" {
		t.Fatalf("repeated VSA order lost: keys=%v values=%v",
			requestPacket.AttributeKeys, requestPacket.AttributeValues)
	}
}

func TestProjectionRejectAndTimeoutSemantics(t *testing.T) {
	deviceID := uuid.New()
	now := time.Now().UTC()
	makePair := func(operationType, responseCode string, timeout bool) []SyslogEvent {
		request := SyslogEvent{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now, Category: "radius",
			Attributes: map[string]string{
				"call_context": "C-" + operationType, "packet_direction": "request",
				"packet_code": "access-request", "xpgk_request_type": operationType,
			},
		}
		if timeout {
			request.Attributes["decision"] = "timeout_fail_open"
			return []SyslogEvent{request}
		}
		response := SyslogEvent{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now.Add(time.Millisecond),
			Category: "radius", Attributes: map[string]string{
				"call_context": "C-" + operationType, "packet_direction": "response",
				"packet_code": responseCode,
			},
		}
		return []SyslogEvent{request, response}
	}
	number := buildAntiFraudProjection(makePair("number", "access-reject", false), nil)
	check := buildAntiFraudProjection(makePair("check_call", "access-reject", false), nil)
	timeout := buildAntiFraudProjection(makePair("check_call", "", true), nil)
	if number.Operations[0].TerminalState != "informational" {
		t.Fatalf("number reject controls passage: %#v", number.Operations[0])
	}
	if check.Operations[0].TerminalState != "verification_reject" ||
		check.Operations[0].Q850Cause != nil {
		t.Fatalf("check reject semantics: %#v", check.Operations[0])
	}
	if timeout.Operations[0].TerminalState != "verification_fail_open" {
		t.Fatalf("timeout semantics: %#v", timeout.Operations[0])
	}
}

func TestProjectionResponseOnlyAndIdempotentRetry(t *testing.T) {
	event := SyslogEvent{
		EventID: uuid.New(), DeviceID: uuid.New(), ReceivedAt: time.Now().UTC(),
		Category: "radius", Attributes: map[string]string{
			"call_context": "C-ONLY", "packet_direction": "response",
			"packet_code": "access-reject",
		},
	}
	first := buildAntiFraudProjection([]SyslogEvent{event}, nil)
	second := buildAntiFraudProjection([]SyslogEvent{event, event}, nil)
	if first.Operations[0].TerminalState != "incomplete_response" {
		t.Fatalf("response-only state: %#v", first.Operations)
	}
	if len(second.Packets) != 1 || second.Packets[0].PacketID != first.Packets[0].PacketID {
		t.Fatalf("duplicate event was not idempotent: %#v", second.Packets)
	}
}

func TestProjectionRetryUsesOutstandingOperation(t *testing.T) {
	deviceID := uuid.New()
	now := time.Now().UTC()
	request := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now, Category: "radius",
		Attributes: map[string]string{
			"call_context": "C-RETRY", "packet_direction": "request",
			"packet_code": "access-request", "packet_identifier": "17",
			"xpgk_request_type": "check_call",
		},
	}
	retry := request
	retry.EventID = uuid.New()
	retry.ReceivedAt = now.Add(time.Second)
	retry.Attributes = map[string]string{
		"call_context": "C-RETRY", "packet_direction": "request",
		"packet_code": "access-request", "packet_identifier": "17",
		"xpgk_request_type": "check_call", "retry": "1",
	}
	response := request
	response.EventID = uuid.New()
	response.ReceivedAt = now.Add(2 * time.Second)
	response.Attributes = map[string]string{
		"call_context": "C-RETRY", "packet_direction": "response",
		"packet_code": "access-accept", "packet_identifier": "17",
	}
	projection := buildAntiFraudProjection([]SyslogEvent{request, retry, response}, nil)
	if len(projection.Operations) != 1 || len(projection.Packets) != 3 {
		t.Fatalf("retry split operation: packets=%d operations=%d",
			len(projection.Packets), len(projection.Operations))
	}
	for _, packet := range projection.Packets {
		if packet.OperationID == nil ||
			*packet.OperationID != projection.Operations[0].OperationID {
			t.Fatalf("packet is not linked to one operation: %#v", projection)
		}
	}
}

func TestPublicRadiusRedaction(t *testing.T) {
	attributes := map[string]string{
		"user_password": "secret", "Password": "also-secret", "user_name": "alice",
	}
	public := sanitizePublicAttributes(attributes)
	if public["user_password"] != "" || public["Password"] != "" ||
		public["user_name"] != "alice" {
		t.Fatalf("attribute redaction failed: %#v", public)
	}
	payload := redactPublicPayload(`User-Password = "secret" Calling-Station-Id=100`)
	if strings.Contains(payload, "secret") || !strings.Contains(payload, "[REDACTED]") {
		t.Fatalf("payload redaction failed: %s", payload)
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
