package customradius

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type callAccumulator struct {
	identity      string
	packetIndexes []int
}

func aggregateCalls(packets []Packet, unmatched []UnmatchedFact) ([]Call, []UnmatchedFact) {
	requestByID := make(map[uuid.UUID]int)
	for index := range packets {
		packet := &packets[index]
		if !packet.IsAntifraud {
			continue
		}
		if packet.Direction == DirectionRequest {
			requestByID[packet.ID] = index
		}
	}

	accumulators := make(map[string]*callAccumulator)
	callUnmatched := make([]UnmatchedFact, 0)
	for index := range packets {
		packet := &packets[index]
		if !packet.IsAntifraud {
			continue
		}
		identity := logicalCallIdentity(*packet)
		if identity == "" && packet.RequestID != nil {
			if requestIndex, exists := requestByID[*packet.RequestID]; exists {
				identity = logicalCallIdentity(packets[requestIndex])
				if identity != "" {
					mergeCallKey(&packet.CallKey, packets[requestIndex].CallKey)
				}
			}
		}
		if identity == "" {
			packet.Status = PacketAmbiguous
			packet.Explanations = append(packet.Explanations, explanation(
				"custom.call.missing_or_ambiguous_key",
				"The packet had no h323-conf-id or Acct-Session-Id for a logical call."))
			for _, source := range packet.Provenance {
				callUnmatched = append(callUnmatched, UnmatchedFact{
					Provenance: source, Reason: "ambiguous_call_identity",
					Explanation: explanation("custom.call.ambiguous",
						"The event could not be assigned to a logical Custom call."),
				})
			}
			continue
		}
		accumulator := accumulators[identity]
		if accumulator == nil {
			accumulator = &callAccumulator{identity: identity}
			accumulators[identity] = accumulator
		}
		accumulator.packetIndexes = append(accumulator.packetIndexes, index)
	}

	identities := make([]string, 0, len(accumulators))
	for identity := range accumulators {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	calls := make([]Call, 0, len(identities))
	for _, identity := range identities {
		calls = append(calls, buildCall(identity, accumulators[identity].packetIndexes, packets))
	}
	contextOwners := make(map[string][]int)
	for callIndex := range calls {
		seen := make(map[string]struct{})
		for _, packet := range calls[callIndex].Packets {
			if packet.CallContext == "" {
				continue
			}
			key := packetContextKey(packet)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			contextOwners[key] = append(contextOwners[key], callIndex)
		}
	}
	for _, fact := range unmatched {
		owners := contextOwners[unmatchedContextKey(fact)]
		if fact.CallContext != "" && len(owners) == 1 {
			call := &calls[owners[0]]
			if call.Key.AcctSessionID != "" {
				call.Unmatched = append(call.Unmatched, fact.Provenance)
			}
		}
	}
	return calls, callUnmatched
}

func packetContextKey(packet Packet) string {
	if len(packet.Provenance) == 0 {
		return ""
	}
	source := packet.Provenance[0]
	return source.DeviceID.String() + "\x00" + source.SourceIP + "\x00" + packet.CallContext
}

func unmatchedContextKey(fact UnmatchedFact) string {
	return fact.Provenance.DeviceID.String() + "\x00" + fact.Provenance.SourceIP +
		"\x00" + fact.CallContext
}

// logicalCallIdentity groups Eltex legs that share h323-conf-id into one call.
// Without h323, identity falls back to Acct-Session-Id. Numbers/[C…] never key a call.
func logicalCallIdentity(packet Packet) string {
	if packet.CallKey.H323ConfID != "" {
		return "h323:" + packet.CallKey.H323ConfID
	}
	if packet.CallKey.AcctSessionID != "" {
		return "session:" + packet.CallKey.AcctSessionID
	}
	return ""
}

func buildCall(identity string, indexes []int, packets []Packet) Call {
	sort.SliceStable(indexes, func(left, right int) bool {
		a, b := packets[indexes[left]], packets[indexes[right]]
		if a.FirstSeenAt.Equal(b.FirstSeenAt) {
			return a.ID.String() < b.ID.String()
		}
		return a.FirstSeenAt.Before(b.FirstSeenAt)
	})
	first := packets[indexes[0]]
	device := uuid.Nil
	if len(first.Provenance) > 0 {
		device = first.Provenance[0].DeviceID
	}
	call := Call{
		ID:           stableID("call", device.String(), identity),
		Key:          first.CallKey,
		Participants: Participants{Calling: first.CallKey.Calling, Called: first.CallKey.Called},
		Indicators:   []string{}, Phases: []PacketPhase{}, Attributes: []Attribute{},
		Packets: make([]Packet, 0, len(indexes)), Unmatched: []EventProvenance{},
		Orphans: []uuid.UUID{}, Explanations: []Explanation{},
		Status: CallPending,
	}
	indicatorSet := make(map[string]struct{})
	attributeSet := make(map[string]struct{})
	sessionSet := make(map[string]struct{})
	for _, index := range indexes {
		packet := packets[index]
		call.Packets = append(call.Packets, packet)
		mergeCallKey(&call.Key, packet.CallKey)
		if packet.CallKey.AcctSessionID != "" {
			sessionSet[packet.CallKey.AcctSessionID] = struct{}{}
		}
		if call.Participants.Calling == "" {
			call.Participants.Calling = packet.CallKey.Calling
		}
		if call.Participants.Called == "" {
			call.Participants.Called = packet.CallKey.Called
		}
		if indicator := attributeValue(packet.Attributes, "xpgk-request-type"); indicator != "" {
			indicatorSet[indicator] = struct{}{}
		}
		for _, attribute := range packet.Attributes {
			key := attribute.Name + "\x00" + attribute.Value + "\x00" + strconv.FormatBool(attribute.Redacted)
			if _, exists := attributeSet[key]; exists {
				continue
			}
			attributeSet[key] = struct{}{}
			call.Attributes = append(call.Attributes, attribute)
		}
		if packet.Direction == DirectionRequest {
			call.Phases = append(call.Phases, PacketPhase{
				Phase: packet.Phase, RequestID: uuidPointer(packet.ID), ResponseID: packet.ResponseID,
			})
		}
		if packet.Status == PacketOrphan || packet.Status == PacketAmbiguous {
			call.Orphans = append(call.Orphans, packet.ID)
		}
		applyAccounting(&call.Accounting, packet)
		applyRouting(&call.Routing, packet)
	}
	for indicator := range indicatorSet {
		call.Indicators = append(call.Indicators, indicator)
	}
	sort.Strings(call.Indicators)
	for session := range sessionSet {
		call.AcctSessionIDs = append(call.AcctSessionIDs, session)
	}
	sort.Strings(call.AcctSessionIDs)
	if call.Key.AcctSessionID == "" && len(call.AcctSessionIDs) > 0 {
		call.Key.AcctSessionID = call.AcctSessionIDs[0]
	}
	call.Status = overallStatus(call.Packets)
	finalizeCallOutcome(&call)
	call.Explanations = append(call.Explanations, statusExplanation(call.Status))
	return call
}

func mergeCallKey(destination *CallKey, source CallKey) {
	if destination.AcctSessionID == "" {
		destination.AcctSessionID = source.AcctSessionID
		destination.AcctSessionIDDisplay = source.AcctSessionIDDisplay
	}
	if destination.H323ConfID == "" {
		destination.H323ConfID = source.H323ConfID
		destination.H323ConfIDDisplay = source.H323ConfIDDisplay
	}
	if destination.Context == "" {
		destination.Context = source.Context
		destination.ContextDisplay = source.ContextDisplay
	}
	if destination.Calling == "" {
		destination.Calling = source.Calling
	}
	if destination.Called == "" {
		destination.Called = source.Called
	}
}

func applyAccounting(accounting *Accounting, packet Packet) {
	if packet.Family != FamilyAccounting || packet.Direction != DirectionRequest {
		return
	}
	eventTime := packet.FirstSeenAt
	if value := firstAttributeValue(packet.Attributes, "event-timestamp"); value != "" {
		if parsed, ok := parseAttributeTime(value); ok {
			eventTime = parsed
			copy := parsed
			accounting.EventTimestamp = &copy
		}
	}
	switch packet.Phase {
	case PhaseStart:
		copy := eventTime
		accounting.StartTime = &copy
	case PhaseEnd:
		copy := eventTime
		accounting.StopTime = &copy
	}
	if value := firstAttributeValue(packet.Attributes, "acct-terminate-cause"); value != "" {
		accounting.TerminateCause = value
	}
	if value := firstAttributeValue(packet.Attributes, "acct-session-time"); value != "" {
		if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && seconds >= 0 {
			accounting.SessionDuration = &seconds
		}
	}
	if value := firstAttributeValue(packet.Attributes, "acct-delay-time"); value != "" {
		if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && seconds >= 0 {
			accounting.DelayTimeSec = &seconds
		}
	}
	if value := firstAttributeValue(packet.Attributes, "h323-setup-time"); value != "" {
		if parsed, ok := parseAttributeTime(value); ok {
			copy := parsed
			accounting.SetupTime = &copy
		}
	}
	if value := firstAttributeValue(packet.Attributes, "h323-connect-time"); value != "" {
		if parsed, ok := parseAttributeTime(value); ok {
			copy := parsed
			accounting.ConnectTime = &copy
		}
	}
	if value := firstAttributeValue(packet.Attributes, "h323-disconnect-time"); value != "" {
		if parsed, ok := parseAttributeTime(value); ok {
			copy := parsed
			accounting.DisconnectTime = &copy
		}
	}
	if value := firstAttributeValue(packet.Attributes, "h323-disconnect-cause"); value != "" {
		if cause := parseQ850Cause(value); cause != nil {
			accounting.DisconnectCauseQ850 = cause
		}
	}
}

func applyRouting(routing *Routing, packet Packet) {
	set := func(dst *string, names ...string) {
		if *dst != "" {
			return
		}
		for _, name := range names {
			if value := firstAttributeValue(packet.Attributes, name); value != "" {
				*dst = value
				return
			}
		}
	}
	set(&routing.OriginatingIP, "xpgk-origination-gateway-ip")
	set(&routing.TerminationIP, "xpgk-termination-gateway-ip")
	set(&routing.SrcNumberIn, "xpgk-src-number-in")
	set(&routing.DstNumberIn, "xpgk-dst-number-in")
	set(&routing.SrcNumberOut, "xpgk-src-number-out")
	set(&routing.DstNumberOut, "xpgk-dst-number-out")
	set(&routing.RedirectNumber, "h323-redirect-number")
	set(&routing.RemoteID, "h323-remote-id")
	set(&routing.OutTrunkgroupLabel, "out-trunkgroup-label")
	set(&routing.InTrunkgroupLabel, "in-trunkgroup-label")
	set(&routing.CallOrigin, "h323-call-origin")
	set(&routing.CallType, "h323-call-type")
	set(&routing.NASPort, "nas-port")
	set(&routing.NASPortType, "nas-port-type")
	set(&routing.FramedIPAddress, "framed-ip-address")
}

func finalizeCallOutcome(call *Call) {
	call.VerificationResult = "absent"
	var hasCheck bool
	var sawAccept, sawReject, sawUnavailable, sawAmbiguous bool
	for _, packet := range call.Packets {
		requestType := firstAttributeValue(packet.Attributes, "xpgk-request-type")
		isVerification := packet.Family == FamilyVerification || requestType == "check_call"
		isIndication := packet.Family == FamilyIndication ||
			requestType == "number" || requestType == "save_call"
		if isIndication && packet.Direction == DirectionRequest &&
			(packet.Status == PacketPaired || packet.Decision == DecisionInfoOnly) {
			if packet.ResponseID != nil || packet.Status == PacketPaired {
				call.IndicationAcked = true
			}
		}
		if isIndication && packet.Direction == DirectionResponse &&
			(packet.RadiusType == "access-accept" || packet.RadiusType == "access-response" ||
				packet.Decision == DecisionInfoOnly) {
			call.IndicationAcked = true
		}
		if packet.Family == FamilyAccounting && packet.Direction == DirectionRequest &&
			packet.Status == PacketPaired {
			call.AccountingAcked = true
		}
		if packet.Family == FamilyAccounting && packet.Direction == DirectionResponse {
			call.AccountingAcked = true
		}
		if !isVerification {
			continue
		}
		hasCheck = true
		if packet.Status == PacketAmbiguous {
			sawAmbiguous = true
		}
		switch packet.Decision {
		case DecisionDeny:
			sawReject = true
		case DecisionAllow:
			sawAccept = true
		case DecisionUnavailableFallback:
			sawUnavailable = true
		}
		if packet.Direction == DirectionRequest &&
			(packet.Status == PacketPending || packet.Decision == DecisionUnavailableFallback) {
			sawUnavailable = true
		}
	}
	switch {
	case !hasCheck:
		call.VerificationResult = "absent"
		call.FinalDecision = "not_applicable"
	case sawReject:
		call.VerificationResult = "reject"
		call.FinalDecision = "blocked"
	case sawUnavailable && !sawAccept:
		call.VerificationResult = "no_response"
		call.FinalDecision = "unavailable"
	case sawAccept:
		call.VerificationResult = "accept"
		call.FinalDecision = "allowed"
	case sawAmbiguous:
		call.VerificationResult = "no_response"
		call.FinalDecision = "unknown"
	default:
		call.VerificationResult = "no_response"
		call.FinalDecision = "unknown"
	}
}

func parseQ850Cause(value string) *int64 {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(trimmed), "0x") {
		trimmed = trimmed[2:]
		base = 16
	}
	parsed, err := strconv.ParseInt(trimmed, base, 64)
	if err != nil || parsed < 0 {
		return nil
	}
	return &parsed
}

func parseAttributeTime(value string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339, "Jan 2 2006 15:04:05 MST",
		"2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05",
	} {
		if parsed, err := time.Parse(layout, strings.TrimSpace(value)); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func overallStatus(packets []Packet) CallStatus {
	for _, packet := range packets {
		if packet.Decision == DecisionDeny {
			return CallBlocked
		}
	}
	for _, packet := range packets {
		// Indication timeouts also set packet DecisionUnavailableFallback (fail-open
		// pairing), but call-level unavailable is only meaningful for check_call.
		if packet.Decision == DecisionUnavailableFallback && isVerificationPacket(packet) {
			return CallUnavailable
		}
	}
	for _, packet := range packets {
		if packet.Status == PacketAmbiguous || packet.Status == PacketOrphan {
			return CallIndeterminate
		}
	}
	for _, packet := range packets {
		if packet.Decision == DecisionAllow && isVerificationPacket(packet) {
			return CallVerified
		}
	}
	for _, packet := range packets {
		if packet.Family == FamilyAccounting && packet.Phase == PhaseEnd {
			return CallCompleted
		}
	}
	for _, packet := range packets {
		if packet.Family == FamilyAccounting &&
			(packet.Phase == PhaseStart || packet.Phase == PhaseMid) {
			return CallOpen
		}
	}
	return CallPending
}

func isVerificationPacket(packet Packet) bool {
	if packet.Family == FamilyVerification {
		return true
	}
	return firstAttributeValue(packet.Attributes, "xpgk-request-type") == "check_call"
}

func statusExplanation(status CallStatus) Explanation {
	text := map[CallStatus]string{
		CallBlocked:       "A verification response denied the call.",
		CallUnavailable:   "A required response timed out and fallback was used.",
		CallIndeterminate: "Ambiguous or orphan evidence prevents a definitive result.",
		CallVerified:      "A verification response allowed the call.",
		CallCompleted:     "Accounting contains an end phase.",
		CallOpen:          "Accounting contains an open phase without an end phase.",
		CallPending:       "The call is awaiting definitive Custom evidence.",
	}[status]
	return explanation("custom.call.status."+string(status), text)
}

func sortResult(packets []Packet, calls []Call, unmatched []UnmatchedFact) {
	sort.SliceStable(packets, func(left, right int) bool {
		if packets[left].FirstSeenAt.Equal(packets[right].FirstSeenAt) {
			return packets[left].ID.String() < packets[right].ID.String()
		}
		return packets[left].FirstSeenAt.Before(packets[right].FirstSeenAt)
	})
	sort.SliceStable(calls, func(left, right int) bool {
		return calls[left].ID.String() < calls[right].ID.String()
	})
	sort.SliceStable(unmatched, func(left, right int) bool {
		a, b := unmatched[left].Provenance, unmatched[right].Provenance
		if a.ReceivedAt.Equal(b.ReceivedAt) {
			return a.EventID.String() < b.EventID.String()
		}
		return a.ReceivedAt.Before(b.ReceivedAt)
	})
}
