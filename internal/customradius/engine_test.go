package customradius

import (
	"encoding/json"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	testDevice = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	testBase   = time.Date(2026, 10, 25, 0, 59, 59, 0, time.UTC)
)

func raw(sequence int, offset time.Duration, payload string) RawEvent {
	return RawEvent{
		EventID:  uuid.NewSHA1(stableNamespace, []byte(payload+"#"+string(rune(sequence)))),
		DeviceID: testDevice, ReceivedAt: testBase.Add(offset), SourceIP: "192.0.2.10",
		SourcePort: 514, Transport: "udp", Payload: []byte(payload),
	}
}

func enabled() Config {
	return Config{Enabled: true, ResponseTimeout: 3 * time.Second}
}

func mergeSessionEventsForTest(existing, additions []RawEvent) []RawEvent {
	merged := make([]RawEvent, 0, len(existing)+len(additions))
	seen := make(map[uuid.UUID]struct{}, len(existing)+len(additions))
	appendEvent := func(event RawEvent) {
		if event.EventID != uuid.Nil {
			if _, exists := seen[event.EventID]; exists {
				return
			}
			seen[event.EventID] = struct{}{}
		}
		merged = append(merged, event)
	}
	for _, event := range existing {
		appendEvent(event)
	}
	for _, event := range additions {
		appendEvent(event)
	}
	return merged
}

func TestAllFamiliesAndSemantics(t *testing.T) {
	events := []RawEvent{
		raw(1, 0, "[C1] Access-Request [7] Cisco-AVPair='xpgk-request-type=number' Acct-Session-Id=' S-1 '"),
		raw(2, time.Millisecond, "[C1] Access-Accept [7]"),
		raw(3, time.Second, "[C1] Access-Request [8] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id='s-1'"),
		raw(4, time.Second+time.Millisecond, "[C1] Access-Reject [8]"),
		raw(5, 2*time.Second, "[C1] Accounting-Request [9] Acct-Session-Id='S-1' Acct-Status-Type=Start"),
		raw(6, 2*time.Second+time.Millisecond, "[C1] Accounting-Response [9]"),
	}
	result := BuildAtCutoff(enabled(), events, testBase.Add(10*time.Second))
	if len(result.Packets) != 6 {
		t.Fatalf("packets=%d, want 6", len(result.Packets))
	}
	want := []Decision{
		DecisionInfoOnly, DecisionInfoOnly, DecisionDeny, DecisionDeny,
		DecisionAcknowledgement, DecisionAcknowledgement,
	}
	for index := range result.Packets {
		if result.Packets[index].Decision != want[index] {
			t.Errorf("packet %d decision=%q, want %q", index, result.Packets[index].Decision, want[index])
		}
		if !result.Packets[index].IsAntifraud {
			t.Errorf("packet %d was not inherited/detected as AntiFraud", index)
		}
	}
	if len(result.Calls) != 1 || result.Calls[0].Status != CallBlocked {
		t.Fatalf("calls=%+v, want one blocked call", result.Calls)
	}
	if result.Calls[0].Key.AcctSessionID != "s-1" ||
		result.Calls[0].Key.AcctSessionIDDisplay != " S-1 " {
		t.Fatalf("session normalization/display lost: %+v", result.Calls[0].Key)
	}
}

func TestDisabledProducesNothing(t *testing.T) {
	result := BuildAtCutoff(Config{Enabled: false}, []RawEvent{
		raw(1, 0, "Antifraud-Auth-Request [1] Password=do-not-retain"),
	}, testBase)
	if len(result.Packets)+len(result.Calls)+len(result.Unmatched) != 0 {
		t.Fatalf("disabled engine returned derived data: %+v", result)
	}
}

func TestConservativeDetectionAndFalseCDRGuard(t *testing.T) {
	result := BuildAtCutoff(enabled(), []RawEvent{
		raw(1, 0, "Access-Request [1] Calling-Station-Id=100 Called-Station-Id=200 Acct-Session-Id=s"),
		raw(2, time.Second, "RADIUS server rejected: :0 (replied 0)"),
		raw(3, 2*time.Second, "Access-Request [2] Some-Custom-Hint=yes Acct-Session-Id=x"),
	}, testBase.Add(10*time.Second))
	for _, packet := range result.Packets {
		if packet.IsAntifraud {
			t.Fatalf("generic/strong enrichment created false call: %+v", packet)
		}
	}
	if len(result.Calls) != 0 {
		t.Fatalf("false Custom calls: %+v", result.Calls)
	}
	foundGuard := false
	for _, fact := range result.Unmatched {
		if fact.Explanation.Code == "custom.event.unmatched" && fact.Provenance.EventID == raw(2, time.Second, "RADIUS server rejected: :0 (replied 0)").EventID {
			foundGuard = true
		}
	}
	if !foundGuard {
		t.Fatal("CDR guard event provenance was not preserved")
	}
}

func TestTokenizerOrderingVendorSplitAndRedaction(t *testing.T) {
	eventID := uuid.New()
	result := Tokenize([]byte(
		`Cisco-AVPair='xpkg-request-type=check_call', User-Password="secret\"x" `+
			`Calling-Station-Id=100 Cisco-AVPair='xpgk-tag=a=b' Calling-Station-Id=101`), eventID)
	if len(result.Attributes) != 5 {
		t.Fatalf("attributes=%d: %+v", len(result.Attributes), result.Attributes)
	}
	if result.Attributes[0].Name != "xpgk-request-type" ||
		result.Attributes[0].Value != "check_call" ||
		result.Attributes[3].Value != "a=b" {
		t.Fatalf("vendor split/normalization failed: %+v", result.Attributes)
	}
	if !result.Attributes[1].Redacted || result.Attributes[1].Value != "" ||
		result.Attributes[1].RawValue != "" {
		t.Fatalf("secret survived tokenization: %+v", result.Attributes[1])
	}
	if result.Attributes[2].Value != "100" || result.Attributes[4].Value != "101" {
		t.Fatalf("repeated attribute order lost: %+v", result.Attributes)
	}
	if len(result.Warnings) == 0 || result.Warnings[0].Code != "custom.attribute.xpkg_normalized" {
		t.Fatalf("xpkg warning missing: %+v", result.Warnings)
	}
}

func TestMalformedQuoteAndPacketIDRange(t *testing.T) {
	event := raw(1, 0, "Access-Request [256] Cisco-AVPair='xpgk-request-type=check_call")
	envelope := DecodeEnvelope(event)
	if envelope.Identifier != nil {
		t.Fatalf("invalid identifier accepted: %d", *envelope.Identifier)
	}
	codes := make(map[string]bool)
	for _, warning := range envelope.Warnings {
		codes[warning.Code] = true
	}
	if !codes["custom.packet.invalid_identifier"] || !codes["custom.attribute.malformed_quote"] {
		t.Fatalf("warnings=%+v", envelope.Warnings)
	}
}

func TestAssemblySupersededHeaderClosesPriorAnchor(t *testing.T) {
	result := BuildAtCutoff(enabled(), []RawEvent{
		raw(1, 0, "[C1] Access-Request [1]"),
		raw(2, time.Millisecond, "[C1] Access-Request [2]"),
		raw(3, 2*time.Millisecond, "[C1] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=s2"),
	}, testBase)
	if len(result.Unmatched) != 0 {
		t.Fatalf("superseded anchor left unmatched facts: %+v", result.Unmatched)
	}
	if result.Packets[0].IsAntifraud || !result.Packets[1].IsAntifraud {
		t.Fatalf("attribute did not attach to current anchor: %+v", result.Packets)
	}
}

func TestAssemblyKeepsConcurrentContextsSeparate(t *testing.T) {
	result := BuildAtCutoff(enabled(), []RawEvent{
		raw(1, 0, "[C1] Access-Request [1]"),
		raw(2, time.Millisecond, "[C2] Access-Request [2]"),
		raw(3, 2*time.Millisecond, "[C1] Cisco-AVPair='xpgk-request-type=number' Acct-Session-Id=s1"),
		raw(4, 3*time.Millisecond, "[C2] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=s2"),
	}, testBase)
	if len(result.Unmatched) != 0 || !result.Packets[0].IsAntifraud || !result.Packets[1].IsAntifraud {
		t.Fatalf("concurrent contexts crossed or orphaned: %+v", result)
	}
}

func TestRetransmissionGroupingAndIDLessAmbiguity(t *testing.T) {
	request := "Access-Request [4] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=s1"
	result := BuildAtCutoff(enabled(), []RawEvent{
		raw(1, 0, request),
		raw(2, time.Millisecond, request),
		raw(3, 2*time.Millisecond, "Access-Accept [4]"),
		raw(4, time.Second, "Access-Request Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=s2"),
		raw(5, time.Second+time.Millisecond, "Access-Request Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=s3"),
		raw(6, time.Second+2*time.Millisecond, "Access-Accept"),
	}, testBase.Add(2*time.Second))
	if len(result.Packets[0].AttemptIDs) != 2 || result.Packets[2].Status != PacketPaired {
		t.Fatalf("retry grouping failed: %+v", result.Packets[:3])
	}
	if result.Packets[5].Status != PacketAmbiguous {
		t.Fatalf("ID-less ambiguous response status=%q", result.Packets[5].Status)
	}
}

func TestStrictCallIdentity(t *testing.T) {
	result := BuildAtCutoff(enabled(), []RawEvent{
		raw(1, 0, "Antifraud-Auth-Request [1] Acct-Session-Id=s1 h323-conf-id=H Calling-Station-Id=10 Called-Station-Id=20"),
		raw(2, time.Second, "Antifraud-Auth-Request [2] Acct-Session-Id=s2 h323-conf-id=h Calling-Station-Id=10 Called-Station-Id=20"),
		raw(3, 2*time.Second, "Antifraud-Auth-Request [3] h323-conf-id=H"),
		raw(4, 3*time.Second, "Antifraud-Auth-Request [4] Acct-Session-Id=s3 h323-conf-id=unique"),
		raw(5, 4*time.Second, "Antifraud-Auth-Request [5] h323-conf-id=UNIQUE"),
	}, testBase.Add(5*time.Second))
	// Shared h323 H merges s1+s2+lone-H; unique merges s3+UNIQUE → 2 logical calls.
	if len(result.Calls) != 2 {
		t.Fatalf("calls=%d, want 2 logical h323 calls: %+v", len(result.Calls), result.Calls)
	}
	var shared *Call
	for index := range result.Calls {
		if result.Calls[index].Key.H323ConfID == "h" {
			shared = &result.Calls[index]
		}
	}
	if shared == nil || len(shared.AcctSessionIDs) != 2 {
		t.Fatalf("shared h323 call missing session legs: %+v", result.Calls)
	}
}

func TestTimeoutAndLateReconciliation(t *testing.T) {
	events := []RawEvent{
		raw(1, 0, "Access-Request [9] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=s"),
	}
	pending := BuildAtCutoff(enabled(), events, testBase.Add(time.Second))
	if pending.Packets[0].Decision != "" || pending.Packets[0].Status != PacketPending {
		t.Fatalf("premature fallback: %+v", pending.Packets[0])
	}
	fallback := BuildAtCutoff(enabled(), events, testBase.Add(4*time.Second))
	if fallback.Packets[0].Decision != DecisionUnavailableFallback {
		t.Fatalf("missing fallback: %+v", fallback.Packets[0])
	}
	reconciled := BuildAtCutoff(enabled(), append(events,
		raw(2, 2*time.Second, "Access-Accept [9]")), testBase.Add(4*time.Second))
	if reconciled.Packets[0].Decision != DecisionAllow ||
		reconciled.Packets[0].Status != PacketPaired {
		t.Fatalf("late evidence did not recompute: %+v", reconciled.Packets)
	}
}

func TestDeterminismBatchRestartDSTAndJSONSecrecy(t *testing.T) {
	events := []RawEvent{
		raw(1, time.Hour, "Antifraud-Auth-Request [1] Cisco-AVPair='xpgk-request-type=number' Acct-Session-Id=dst Password=hidden"),
		raw(2, time.Hour+time.Millisecond, "Access-Accept [1]"),
	}
	baseline := BuildAtCutoff(enabled(), events, testBase.Add(2*time.Hour))
	for seed := int64(0); seed < 20; seed++ {
		shuffled := append([]RawEvent(nil), events...)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		restarted := NewEngine(enabled()).ProcessAtCutoff(shuffled, testBase.Add(2*time.Hour))
		if !reflect.DeepEqual(baseline, restarted) {
			t.Fatalf("seed %d changed deterministic result", seed)
		}
	}
	encoded, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "hidden") || strings.Contains(string(encoded), string(events[0].Payload)) {
		t.Fatalf("public DTO leaked raw/secret data: %s", encoded)
	}
}

func TestCopiedNeutralFixtureForms(t *testing.T) {
	data, err := os.ReadFile("testdata/eltex_radius_neutral.json")
	if err != nil {
		t.Fatal(err)
	}
	var payloads []string
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatal(err)
	}
	wantKinds := []EnvelopeKind{
		EnvelopeHeader, EnvelopeHeader, EnvelopeAttributes, EnvelopeAttributes,
		EnvelopeAttributes, EnvelopeAttributes, EnvelopeOther,
	}
	for index, payload := range payloads {
		envelope := DecodeEnvelope(raw(index, time.Duration(index)*time.Millisecond, payload))
		if envelope.Kind != wantKinds[index] {
			t.Errorf("%q kind=%q, want %q", payload, envelope.Kind, wantKinds[index])
		}
	}
}

func TestProductionV16RawFixtureAssembly(t *testing.T) {
	data, err := os.ReadFile("testdata/call_antifraud_v16_raw.json")
	if err != nil {
		t.Fatal(err)
	}
	var payloads []string
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatal(err)
	}
	events := make([]RawEvent, 0, len(payloads))
	for index, payload := range payloads {
		events = append(events, raw(100+index, time.Duration(index)*time.Millisecond, payload))
	}
	result := BuildAtCutoff(enabled(), events, testBase.Add(time.Minute))
	if len(result.Packets) != 4 {
		t.Fatalf("packets=%d, want four request/reply packets: %+v", len(result.Packets), result.Packets)
	}
	if len(result.Calls) != 1 {
		t.Fatalf("calls=%d, want one logical h323 call: %+v", len(result.Calls), result.Calls)
	}
	if len(result.Calls[0].AcctSessionIDs) != 2 {
		t.Fatalf("session legs=%v, want session-a and session-b", result.Calls[0].AcctSessionIDs)
	}
	for _, packet := range result.Packets {
		if packet.Status != PacketPaired || packet.Decision != DecisionInfoOnly {
			t.Errorf("fixture packet not paired consistently: %+v", packet)
		}
	}
	if result.Packets[1].RadiusType != "access-accept" ||
		result.Packets[1].ResponseLatencyMillis == nil ||
		*result.Packets[1].ResponseLatencyMillis != 111 {
		t.Fatalf("production Proc Reply was not status enrichment: %+v", result.Packets[1])
	}
	// Context-only "RADIUS server rejected" attaches when a unique logical call owns [C…].
	if len(result.Calls[0].Unmatched) != 1 {
		t.Fatalf("unmatched facts on logical call=%+v, want the rejected-line provenance",
			result.Calls[0].Unmatched)
	}
}

func TestProductionHeaderOrdersAndProcReply(t *testing.T) {
	request := DecodeEnvelope(raw(1, 0,
		"[C1] RADIUS. Request ID [063] process Antifraud-Auth-Request"))
	if request.Kind != EnvelopeHeader || request.Direction != DirectionRequest ||
		request.Identifier == nil || *request.Identifier != 63 || !request.ExplicitAF {
		t.Fatalf("request-ID-first header not decoded: %+v", request)
	}
	alternate := DecodeEnvelope(raw(2, time.Millisecond,
		"[C1] RADIUS. Antifraud-Auth-Request [064]"))
	if alternate.Identifier == nil || *alternate.Identifier != 64 {
		t.Fatalf("alternate request header not decoded: %+v", alternate)
	}
	status := DecodeEnvelope(raw(3, 2*time.Millisecond,
		"[C1] RADIUS. Proc Reply. Request ID [068] Accs-Reply [reject]. Time [1:007]"))
	if status.Kind != EnvelopeStatus || status.RadiusType != "access-reject" ||
		status.Identifier == nil || *status.Identifier != 68 ||
		status.ResponseLatencyMillis == nil || *status.ResponseLatencyMillis != 1007 {
		t.Fatalf("production Proc Reply not decoded as status: %+v", status)
	}
}

func TestIdentifierReusePairsOnlyOutstandingGroups(t *testing.T) {
	events := []RawEvent{
		raw(1, 0, "[C1] Access-Request [7] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=s"),
		raw(2, time.Millisecond, "[C1] Access-Accept [7]"),
		raw(3, 10*time.Minute, "[C1] Access-Request [7] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=s"),
		raw(4, 10*time.Minute+time.Millisecond, "[C1] Access-Reject [7]"),
	}
	result := BuildAtCutoff(enabled(), events, testBase.Add(11*time.Minute))
	if result.Packets[0].Decision != DecisionAllow || result.Packets[2].Decision != DecisionDeny {
		t.Fatalf("identifier reuse paired to consumed request: %+v", result.Packets)
	}
	if len(result.Packets[0].AttemptIDs) != 1 || len(result.Packets[2].AttemptIDs) != 1 {
		t.Fatalf("identifier reuse collapsed into retries: %+v", result.Packets)
	}
}

func TestConcurrentCallsWithSameIdentifierPairByContext(t *testing.T) {
	result := BuildAtCutoff(enabled(), []RawEvent{
		raw(1, 0, "[C1] Access-Request [7] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=s1"),
		raw(2, time.Millisecond, "[C2] Access-Request [7] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=s2"),
		raw(3, 2*time.Millisecond, "[C2] Access-Reject [7]"),
		raw(4, 3*time.Millisecond, "[C1] Access-Accept [7]"),
	}, testBase.Add(time.Second))
	if len(result.Calls) != 2 ||
		result.Packets[0].Decision != DecisionAllow ||
		result.Packets[1].Decision != DecisionDeny {
		t.Fatalf("concurrent same-ID calls crossed: %+v", result)
	}
}

func TestRetrySemanticsPropagateToEveryAttempt(t *testing.T) {
	request := "[C1] Access-Request [4] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=retry"
	result := BuildAtCutoff(enabled(), []RawEvent{
		raw(1, 0, request),
		raw(2, time.Millisecond, request),
		raw(3, 2*time.Millisecond, "[C1] Access-Reject [4]"),
	}, testBase.Add(time.Second))
	for _, index := range []int{0, 1} {
		packet := result.Packets[index]
		if packet.Decision != DecisionDeny || packet.Confidence != ConfidenceHigh ||
			len(packet.AttemptIDs) != 2 || packet.ResponseID == nil {
			t.Fatalf("attempt %d lacks complete response semantics: %+v", index, packet)
		}
	}
}

func TestCrossHourSessionRecomputeAndDeadline(t *testing.T) {
	initial := []RawEvent{
		raw(1, 0, "[C1] Access-Request [1] Cisco-AVPair='xpgk-request-type=number' Acct-Session-Id=long"),
		raw(2, time.Millisecond, "[C1] Access-Accept [1]"),
	}
	later := []RawEvent{
		raw(3, 2*time.Hour, "[C2] Accounting-Request [2] Acct-Session-Id=long Acct-Status-Type=Start"),
		raw(4, 2*time.Hour+time.Millisecond, "[C2] Accounting-Response [2]"),
		raw(5, 5*time.Hour, "[C3] Accounting-Request [3] Acct-Session-Id=long Acct-Status-Type=Stop Acct-Session-Time=10800"),
		raw(6, 5*time.Hour+time.Millisecond, "[C3] Accounting-Response [3]"),
	}
	merged := mergeSessionEventsForTest(initial, later)
	merged = mergeSessionEventsForTest(merged, later)
	result := BuildAtCutoff(enabled(), merged, testBase.Add(6*time.Hour))
	if len(merged) != 6 || len(result.Calls) != 1 ||
		result.Calls[0].Status != CallCompleted ||
		result.Calls[0].Accounting.SessionDuration == nil ||
		*result.Calls[0].Accounting.SessionDuration != 10800 {
		t.Fatalf("cross-hour recompute failed: merged=%d result=%+v", len(merged), result)
	}
	reversed := append([]RawEvent(nil), merged...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	if other := BuildAtCutoff(enabled(), reversed, testBase.Add(6*time.Hour)); !reflect.DeepEqual(result, other) {
		t.Fatal("multi-hour build depended on input batch order")
	}

	pendingEvents := []RawEvent{
		raw(20, 7*time.Hour, "[C4] Access-Request [20] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=late"),
	}
	before := BuildAtCutoff(enabled(), pendingEvents, testBase.Add(7*time.Hour+time.Second))
	wantDeadline := pendingEvents[0].ReceivedAt.Add(enabled().ResponseTimeout)
	if before.NextDeadline == nil || !before.NextDeadline.Equal(wantDeadline) ||
		before.Packets[0].Decision != "" {
		t.Fatalf("next deadline missing before cutoff: %+v", before)
	}
	atDeadline := BuildAtCutoff(enabled(), pendingEvents, wantDeadline)
	if atDeadline.NextDeadline != nil ||
		atDeadline.Packets[0].Decision != DecisionUnavailableFallback {
		t.Fatalf("explicit cutoff did not trigger timeout: %+v", atDeadline)
	}
}

func TestContextOnlyUnmatchedRequiresUniqueAuthoritativeCall(t *testing.T) {
	shared := BuildAtCutoff(enabled(), []RawEvent{
		raw(1, 0, "[C1] Antifraud-Auth-Request [1] Acct-Session-Id=s1"),
		raw(2, time.Millisecond, "[C1] Antifraud-Auth-Request [2] Acct-Session-Id=s2"),
		raw(3, 2*time.Millisecond, "[C1] unrelated context fact"),
	}, testBase.Add(time.Second))
	for _, call := range shared.Calls {
		if len(call.Unmatched) != 0 {
			t.Fatal("shared context fact attached to multiple authoritative calls")
		}
	}
	unique := BuildAtCutoff(enabled(), []RawEvent{
		raw(4, 0, "[C2] Antifraud-Auth-Request [4] Acct-Session-Id=only"),
		raw(5, time.Millisecond, "[C2] unrelated context fact"),
	}, testBase.Add(time.Second))
	if len(unique.Calls) != 1 || len(unique.Calls[0].Unmatched) != 1 {
		t.Fatalf("unique context fact was not attached: %+v", unique)
	}
}

func TestGoldenIndication(t *testing.T) {
	result := BuildAtCutoff(enabled(), []RawEvent{
		raw(81, 0, "Antifraud-Auth-Request [81] Cisco-AVPair='xpgk-request-type=number' Acct-Session-Id=golden"),
		raw(82, time.Millisecond, "Access-Accept [81]"),
	}, testBase.Add(time.Second))
	type goldenPacket struct {
		IsAntifraud bool         `json:"is_antifraud"`
		Family      Family       `json:"family"`
		RadiusType  string       `json:"radius_type"`
		Phase       Phase        `json:"phase"`
		Decision    Decision     `json:"decision"`
		Confidence  Confidence   `json:"confidence"`
		Status      PacketStatus `json:"status"`
		Session     string       `json:"session"`
	}
	type goldenResult struct {
		Packets    []goldenPacket `json:"packets"`
		CallStatus CallStatus     `json:"call_status"`
		Indicators []string       `json:"indicators"`
	}
	actual := goldenResult{Packets: make([]goldenPacket, 0, len(result.Packets))}
	for _, packet := range result.Packets {
		actual.Packets = append(actual.Packets, goldenPacket{
			IsAntifraud: packet.IsAntifraud, Family: packet.Family,
			RadiusType: packet.RadiusType, Phase: packet.Phase, Decision: packet.Decision,
			Confidence: packet.Confidence, Status: packet.Status,
			Session: packet.CallKey.AcctSessionID,
		})
	}
	actual.CallStatus = result.Calls[0].Status
	actual.Indicators = result.Calls[0].Indicators
	actualJSON, err := json.MarshalIndent(actual, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := os.ReadFile("testdata/golden_indication.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected any
	var normalizedActual any
	if err := json.Unmarshal(expectedJSON, &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(actualJSON, &normalizedActual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalizedActual, expected) {
		t.Fatalf("golden mismatch\nactual: %s\nexpected: %s", actualJSON, expectedJSON)
	}
}

func TestEltexSummaryWithoutSessionNeverFormsCall(t *testing.T) {
	// Summary-only Eltex AF lines (clg/cld + [C…]) assemble a packet for
	// diagnostics but must not invent a Call without Acct-Session-Id/h323.
	events := []RawEvent{
		raw(1, 0, "[C02AB7E] Port SIPT:0779. Accs-Request for Antifraud: check TG(i/o): 2(ext)/3(ext), USE_AF 1"),
		raw(2, time.Millisecond, "[C02AB7E] Port SIPT:0779. RADIUS: Accs-Request [antifraud_out]"),
		raw(3, 2*time.Millisecond, "[C02AB7E] Port SIPT:0779. RADIUS: Prepare Antifraud-Auth-Request."),
		raw(4, 3*time.Millisecond, "[C02AB7E] Port SIPT:0779. RADIUS: Antifraud-Auth-Request clg <73833777762>, cld <79237008480>"),
		raw(5, 4*time.Millisecond, "[C02AB7E] Port SIPT:0779. RADIUS: Request ID [121] process Antifraud-Auth-Request."),
		raw(6, 5*time.Millisecond, "[C02AB7E] -- RADIUS. Antifraud-Auth-Request [121] --"),
		raw(7, 6*time.Millisecond, "[C02AB7E] RADIUS: Request ID [121] process reply: ignore for not antifraud verify stage."),
		raw(8, 20*time.Millisecond, "[C02AB7E] RADIUS. Proc Reply. Request ID [121] Accs-Reply [accept]. Time [0:070]"),
	}
	result := BuildAtCutoff(enabled(), events, testBase.Add(time.Second))
	if len(result.Calls) != 0 {
		t.Fatalf("context/clg alone formed calls=%d: %+v", len(result.Calls), result.Calls)
	}
	var request *Packet
	for index := range result.Packets {
		packet := &result.Packets[index]
		if packet.Direction == DirectionRequest && packet.IsAntifraud {
			request = packet
			break
		}
	}
	if request == nil || request.Identifier == nil || *request.Identifier != 121 {
		t.Fatalf("assembly should still merge AF request 121: %+v", result.Packets)
	}
	if request.CallKey.Calling != "73833777762" || request.CallKey.Called != "79237008480" {
		t.Fatalf("clg/cld should remain participants only: %+v", request.CallKey)
	}
	if request.CallKey.AcctSessionID != "" || request.CallKey.H323ConfID != "" {
		t.Fatalf("summary fixture unexpectedly gained session/h323: %+v", request.CallKey)
	}
	if !hasExplanation(request.Explanations, "custom.classify.missing_request_type") {
		t.Fatalf("missing xpgk-request-type should leave family unclassified: %+v", request.Explanations)
	}
	if request.Family != FamilyUnknown {
		t.Fatalf("family=%q, want unknown without xpgk-request-type", request.Family)
	}
}

func TestNumbersAloneNeverFormCallIdentity(t *testing.T) {
	result := BuildAtCutoff(enabled(), []RawEvent{
		raw(1, 0, "[C1] Antifraud-Auth-Request clg <100>, cld <200>"),
		raw(2, time.Millisecond, "[C1] Antifraud-Auth-Request clg <100>, cld <200>"),
	}, testBase.Add(time.Second))
	if len(result.Calls) != 0 {
		t.Fatalf("calling/called alone formed calls: %+v", result.Calls)
	}
}

func TestAttributeDumpWithSessionFormsIndicationCall(t *testing.T) {
	result := BuildAtCutoff(enabled(), []RawEvent{
		raw(1, 0, "[C1] RADIUS. -- RADIUS. Accs-Request [068] --"),
		raw(2, time.Millisecond, "\tAcct-Session-Id = \"0600000f 6a666058 66cb3590 505c7af3\" Eltex-AVPair=\"h323-conf-id=0600000f 6a666058 66cb3590 505c7af3\" Eltex-AVPair=\"xpgk-request-type=number\" Eltex-AVPair=\"xpgk-src-number-in=9586786161\" Eltex-AVPair=\"xpgk-dst-number-in=8435999999\""),
		raw(3, 100*time.Millisecond, "[C1] RADIUS. Proc Reply. Request ID [068] Accs-Reply [accept]. Time [0:100]"),
	}, testBase.Add(time.Second))
	if len(result.Calls) != 1 {
		t.Fatalf("calls=%d, want 1 session call: %+v", len(result.Calls), result.Calls)
	}
	call := result.Calls[0]
	if call.Key.AcctSessionID != "0600000f6a66605866cb3590505c7af3" {
		t.Fatalf("session key=%q", call.Key.AcctSessionID)
	}
	if call.Key.AcctSessionIDDisplay == "" {
		t.Fatal("display session must retain original spacing")
	}
	var request *Packet
	for index := range result.Packets {
		if result.Packets[index].Direction == DirectionRequest && result.Packets[index].IsAntifraud {
			request = &result.Packets[index]
			break
		}
	}
	if request == nil || request.Family != FamilyIndication {
		t.Fatalf("dump should classify indication: %+v", request)
	}
}

func FuzzTokenizerNeverLeaksRecognizedSecrets(f *testing.F) {
	f.Add(`Password="secret" Cisco-AVPair='xpgk-request-type=number'`)
	f.Add(`CHAP-Password=abc Authorization=Bearer`)
	f.Add(`Cisco-AVPair='private-key=abc'`)
	f.Fuzz(func(t *testing.T, input string) {
		result := Tokenize([]byte(input), uuid.Nil)
		for _, attribute := range result.Attributes {
			if isSecretName(attribute.Name) &&
				(!attribute.Redacted || attribute.Value != "" || attribute.RawValue != "") {
				t.Fatalf("recognized secret retained: %+v", attribute)
			}
		}
	})
}
