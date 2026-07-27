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
	h323Sessions := make(map[string]map[string]struct{})
	requestByID := make(map[uuid.UUID]int)
	for index := range packets {
		packet := &packets[index]
		if !packet.IsAntifraud {
			continue
		}
		if packet.Direction == DirectionRequest {
			requestByID[packet.ID] = index
		}
		if packet.CallKey.H323ConfID != "" && packet.CallKey.AcctSessionID != "" {
			if h323Sessions[packet.CallKey.H323ConfID] == nil {
				h323Sessions[packet.CallKey.H323ConfID] = make(map[string]struct{})
			}
			h323Sessions[packet.CallKey.H323ConfID][packet.CallKey.AcctSessionID] = struct{}{}
		}
	}

	accumulators := make(map[string]*callAccumulator)
	callUnmatched := make([]UnmatchedFact, 0)
	for index := range packets {
		packet := &packets[index]
		if !packet.IsAntifraud {
			continue
		}
		identity := ""
		if packet.CallKey.AcctSessionID != "" {
			identity = "session:" + packet.CallKey.AcctSessionID
		} else if packet.RequestID != nil {
			if requestIndex, exists := requestByID[*packet.RequestID]; exists {
				identity = callIdentityForPacket(packets[requestIndex], h323Sessions)
				if identity != "" {
					packet.CallKey = packets[requestIndex].CallKey
				}
			}
		} else {
			identity = callIdentityForPacket(*packet, h323Sessions)
		}
		if identity == "" {
			packet.Status = PacketAmbiguous
			packet.Explanations = append(packet.Explanations, explanation(
				"custom.call.missing_or_ambiguous_key",
				"The packet had no authoritative session or uniquely mapped H323 identity."))
			for _, source := range packet.Provenance {
				callUnmatched = append(callUnmatched, UnmatchedFact{
					Provenance: source, Reason: "ambiguous_call_identity",
					Explanation: explanation("custom.call.ambiguous",
						"The event could not be assigned to a strict Custom call."),
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

func callIdentityForPacket(packet Packet, h323Sessions map[string]map[string]struct{}) string {
	if packet.CallKey.AcctSessionID != "" {
		return "session:" + packet.CallKey.AcctSessionID
	}
	if packet.CallKey.H323ConfID == "" {
		return ""
	}
	sessions := h323Sessions[packet.CallKey.H323ConfID]
	if len(sessions) > 1 {
		return ""
	}
	for session := range sessions {
		return "session:" + session
	}
	// Lone h323 is allowed only as a provisional key; never calling/called or [C…].
	return "h323:" + packet.CallKey.H323ConfID
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
	for _, index := range indexes {
		packet := packets[index]
		call.Packets = append(call.Packets, packet)
		mergeCallKey(&call.Key, packet.CallKey)
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
	}
	for indicator := range indicatorSet {
		call.Indicators = append(call.Indicators, indicator)
	}
	sort.Strings(call.Indicators)
	call.Status = overallStatus(call.Packets)
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
		if packet.Decision == DecisionUnavailableFallback {
			return CallUnavailable
		}
	}
	for _, packet := range packets {
		if packet.Status == PacketAmbiguous || packet.Status == PacketOrphan {
			return CallIndeterminate
		}
	}
	for _, packet := range packets {
		if packet.Decision == DecisionAllow {
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
