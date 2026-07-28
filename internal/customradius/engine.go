package customradius

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// LessEventID compares canonical UUID string order without allocating.
// For standard UUID layout this matches id.String() lexicographic order.
func LessEventID(left, right uuid.UUID) bool {
	return bytes.Compare(left[:], right[:]) < 0
}

var stableNamespace = uuid.MustParse("9d07d95f-2abc-5ff4-9ee7-c865d190e93d")

type Engine struct {
	config Config
}

func NewEngine(config Config) *Engine {
	return &Engine{config: config.normalized()}
}

// BuildAtCutoff evaluates timeout state at the supplied deterministic cutoff.
func BuildAtCutoff(config Config, events []RawEvent, cutoff time.Time) Result {
	return NewEngine(config).ProcessAtCutoff(events, cutoff)
}

type packetBuilder struct {
	packet  Packet
	device  uuid.UUID
	ip      string
	port    uint16
	members int
	bytes   int
	closed  bool
}

type decodedEvent struct {
	raw      RawEvent
	envelope Envelope
}

// ProcessAtCutoff recomputes the complete projection at an explicit cutoff.
func (engine *Engine) ProcessAtCutoff(events []RawEvent, cutoff time.Time) Result {
	if engine == nil || !engine.config.Enabled {
		return Result{Packets: []Packet{}, Calls: []Call{}, Unmatched: []UnmatchedFact{}}
	}
	config := engine.config.normalized()
	ordered := append([]RawEvent(nil), events...)
	sort.SliceStable(ordered, func(left, right int) bool {
		if ordered[left].ReceivedAt.Equal(ordered[right].ReceivedAt) {
			return LessEventID(ordered[left].EventID, ordered[right].EventID)
		}
		return ordered[left].ReceivedAt.Before(ordered[right].ReceivedAt)
	})

	decoded := make([]decodedEvent, 0, len(ordered))
	for _, event := range ordered {
		decoded = append(decoded, decodedEvent{raw: event, envelope: DecodeEnvelope(event)})
	}
	builders, unmatched := assemble(decoded, config)
	packets := make([]Packet, 0, len(builders))
	for _, builder := range builders {
		finalizePacket(&builder.packet)
		packets = append(packets, builder.packet)
	}
	nextDeadline := classifyAndPair(
		packets, cutoff, config.ResponseTimeout, config.PairingHorizon, config.RetryHorizon,
	)
	calls, callUnmatched := aggregateCalls(packets, unmatched)
	unmatched = append(unmatched, callUnmatched...)
	sortResult(packets, calls, unmatched)
	return Result{
		Packets: packets, Calls: calls, Unmatched: unmatched, NextDeadline: nextDeadline,
	}
}

func assemble(events []decodedEvent, config Config) ([]packetBuilder, []UnmatchedFact) {
	builders := make([]packetBuilder, 0)
	unmatched := make([]UnmatchedFact, 0)
	for _, item := range events {
		envelope := item.envelope
		switch envelope.Kind {
		case EnvelopeHeader:
			if mergeIndex := mergeableBuilder(builders, item); mergeIndex >= 0 {
				mergeHeaderIntoBuilder(&builders[mergeIndex], item, config)
				continue
			}
			closeSupersededBuilders(builders, item)
			packet := Packet{
				RadiusType: envelope.RadiusType, Direction: envelope.Direction,
				Identifier: envelope.Identifier, Attributes: cloneAttributes(envelope.Attributes),
				Provenance:  []EventProvenance{envelope.Provenance},
				Warnings:    append([]Explanation(nil), envelope.Warnings...),
				CallContext: envelope.CallContext, Component: envelope.Component, Server: envelope.Server,
				FirstSeenAt: item.raw.ReceivedAt, LastSeenAt: item.raw.ReceivedAt,
				Status: PacketPending, Family: FamilyUnknown, Phase: PhaseUnknown,
				Confidence: ConfidenceLow,
			}
			if envelope.ExplicitAF {
				packet.Explanations = append(packet.Explanations, explanation(
					"custom.detect.explicit_header", "An explicit Antifraud request header identified this packet."))
			}
			packet.ID = stableID("packet", eventIDString(item.raw.EventID), packet.RadiusType,
				identifierString(packet.Identifier))
			if len(item.raw.Payload) > config.MaxBytes {
				packet.Attributes = nil
				packet.Warnings = append(packet.Warnings, explanation(
					"custom.assembly.bound_exceeded",
					"The anchor exceeded the packet byte bound; its attributes were not retained."))
			}
			builders = append(builders, packetBuilder{
				packet: packet, device: item.raw.DeviceID, ip: item.raw.SourceIP,
				port: item.raw.SourcePort, members: 1, bytes: len(item.raw.Payload),
			})
		case EnvelopeAttributes, EnvelopeStatus:
			candidates := compatibleBuilders(builders, item, config.AssemblyIdle)
			if len(candidates) > 1 {
				portMatches := make([]int, 0, len(candidates))
				for _, candidate := range candidates {
					if builders[candidate].port == item.raw.SourcePort {
						portMatches = append(portMatches, candidate)
					}
				}
				if len(portMatches) == 1 {
					candidates = portMatches
				}
			}
			if len(candidates) == 0 && envelope.Kind == EnvelopeStatus &&
				envelope.Direction == DirectionResponse {
				// Eltex "Proc Reply" is a status line without a prior Access-Accept
				// header; promote it to a response packet so classifyAndPair can
				// match the outstanding request by identifier + call context.
				packet := Packet{
					RadiusType: envelope.RadiusType, Direction: DirectionResponse,
					Identifier: envelope.Identifier, Attributes: cloneAttributes(envelope.Attributes),
					Provenance:  []EventProvenance{envelope.Provenance},
					Warnings:    append([]Explanation(nil), envelope.Warnings...),
					CallContext: envelope.CallContext, Component: envelope.Component, Server: envelope.Server,
					ResponseLatencyMillis: envelope.ResponseLatencyMillis,
					FirstSeenAt:           item.raw.ReceivedAt, LastSeenAt: item.raw.ReceivedAt,
					Status: PacketPending, Family: FamilyUnknown, Phase: PhaseUnknown,
					Confidence: ConfidenceLow,
				}
				packet.ID = stableID("packet", eventIDString(item.raw.EventID), packet.RadiusType,
					identifierString(packet.Identifier))
				builders = append(builders, packetBuilder{
					packet: packet, device: item.raw.DeviceID, ip: item.raw.SourceIP,
					port: item.raw.SourcePort, members: 1, bytes: len(item.raw.Payload),
				})
				continue
			}
			if len(candidates) != 1 {
				reason := "no_compatible_anchor"
				code := "custom.assembly.orphan"
				text := "The event had no unique compatible open packet anchor."
				if len(candidates) > 1 {
					reason, code = "ambiguous_anchor", "custom.assembly.ambiguous"
					text = "Competing packet anchors prevented deterministic attachment."
				}
				unmatched = append(unmatched, unmatchedFact(envelope, reason, code, text))
				continue
			}
			builder := &builders[candidates[0]]
			if builder.members+1 > config.MaxMembers || builder.bytes+len(item.raw.Payload) > config.MaxBytes {
				builder.packet.Warnings = append(builder.packet.Warnings, explanation(
					"custom.assembly.bound_exceeded", "The packet assembly member or byte bound was reached."))
				unmatched = append(unmatched, unmatchedFact(envelope, "assembly_bound",
					"custom.assembly.bound_exceeded", "The event exceeded a bounded packet assembly."))
				continue
			}
			builder.members++
			builder.bytes += len(item.raw.Payload)
			builder.packet.LastSeenAt = item.raw.ReceivedAt
			builder.packet.Provenance = append(builder.packet.Provenance, envelope.Provenance)
			builder.packet.Attributes = append(builder.packet.Attributes, cloneAttributes(envelope.Attributes)...)
			builder.packet.Warnings = append(builder.packet.Warnings, envelope.Warnings...)
			if envelope.CallContext != "" && builder.packet.CallContext == "" {
				builder.packet.CallContext = envelope.CallContext
			}
			if envelope.Server != "" && builder.packet.Server == "" {
				builder.packet.Server = envelope.Server
			}
			if envelope.Component != "" && builder.packet.Component == "" {
				builder.packet.Component = envelope.Component
			}
			if envelope.Kind == EnvelopeStatus && builder.packet.Direction == DirectionResponse {
				builder.packet.RadiusType = envelope.RadiusType
				builder.packet.ResponseLatencyMillis = envelope.ResponseLatencyMillis
			}
		default:
			unmatched = append(unmatched, unmatchedFact(envelope, "not_radius_packet",
				"custom.event.unmatched", "The raw event did not form a Custom RADIUS packet fact."))
		}
	}
	return builders, unmatched
}

func closeSupersededBuilders(builders []packetBuilder, item decodedEvent) {
	for index := range builders {
		builder := &builders[index]
		if builder.closed || builder.device != item.raw.DeviceID || builder.ip != item.raw.SourceIP {
			continue
		}
		existingContext := builder.packet.CallContext
		newContext := item.envelope.CallContext
		sameLane := existingContext != "" && newContext != "" && existingContext == newContext
		if existingContext == "" && newContext == "" {
			sameLane = builder.port == item.raw.SourcePort
		}
		if sameLane {
			builder.closed = true
		}
	}
}

// mergeableBuilder finds an open same-lane request that can absorb another AF
// header (clg/cld line, Request-ID line, banner) instead of superseding it.
// Fresh retries that repeat the same numeric ID with session attributes stay
// separate so AttemptIDs remain accurate.
func mergeableBuilder(builders []packetBuilder, item decodedEvent) int {
	if item.envelope.Direction != DirectionRequest {
		return -1
	}
	found := -1
	for index := range builders {
		builder := &builders[index]
		if builder.closed || builder.device != item.raw.DeviceID || builder.ip != item.raw.SourceIP {
			continue
		}
		if builder.packet.Direction != DirectionRequest {
			continue
		}
		existingContext := builder.packet.CallContext
		newContext := item.envelope.CallContext
		if existingContext == "" || newContext == "" || existingContext != newContext {
			continue
		}
		if builder.packet.Identifier != nil && item.envelope.Identifier != nil &&
			*builder.packet.Identifier != *item.envelope.Identifier {
			continue
		}
		if builder.packet.Identifier != nil && item.envelope.Identifier != nil &&
			hasSessionOrRequestTypeAttrs(builder.packet.Attributes) &&
			hasSessionOrRequestTypeAttrs(item.envelope.Attributes) {
			continue
		}
		if found >= 0 {
			return -1
		}
		found = index
	}
	return found
}

func hasSessionOrRequestTypeAttrs(attributes []Attribute) bool {
	for _, attribute := range attributes {
		switch attribute.Name {
		case "acct-session-id", "h323-conf-id", "xpgk-request-type":
			return true
		}
	}
	return false
}

func mergeHeaderIntoBuilder(builder *packetBuilder, item decodedEvent, config Config) {
	envelope := item.envelope
	builder.members++
	builder.bytes += len(item.raw.Payload)
	builder.packet.LastSeenAt = item.raw.ReceivedAt
	builder.packet.Provenance = append(builder.packet.Provenance, envelope.Provenance)
	if len(item.raw.Payload) <= config.MaxBytes {
		builder.packet.Attributes = append(
			builder.packet.Attributes, cloneAttributes(envelope.Attributes)...,
		)
	}
	builder.packet.Warnings = append(builder.packet.Warnings, envelope.Warnings...)
	if envelope.Identifier != nil && builder.packet.Identifier == nil {
		builder.packet.Identifier = envelope.Identifier
	}
	if envelope.ExplicitAF && !hasExplanation(builder.packet.Explanations, "custom.detect.explicit_header") {
		builder.packet.Explanations = append(builder.packet.Explanations, explanation(
			"custom.detect.explicit_header", "An explicit Antifraud request header identified this packet."))
	}
	if envelope.CallContext != "" && builder.packet.CallContext == "" {
		builder.packet.CallContext = envelope.CallContext
	}
	if envelope.Component != "" && builder.packet.Component == "" {
		builder.packet.Component = envelope.Component
	}
	if envelope.Server != "" && builder.packet.Server == "" {
		builder.packet.Server = envelope.Server
	}
	if envelope.RadiusType != "" {
		builder.packet.RadiusType = envelope.RadiusType
	}
}

func compatibleBuilders(builders []packetBuilder, item decodedEvent, idle time.Duration) []int {
	candidates := make([]int, 0)
	for index := range builders {
		builder := &builders[index]
		if builder.closed || builder.device != item.raw.DeviceID || builder.ip != item.raw.SourceIP {
			continue
		}
		if item.raw.ReceivedAt.Before(builder.packet.FirstSeenAt) ||
			item.raw.ReceivedAt.Sub(builder.packet.LastSeenAt) > idle {
			continue
		}
		context := item.envelope.CallContext
		if context != "" && builder.packet.CallContext != "" && context != builder.packet.CallContext {
			continue
		}
		if item.envelope.Component != "" && builder.packet.Component != "" &&
			item.envelope.Component != builder.packet.Component {
			continue
		}
		if item.envelope.Kind == EnvelopeStatus {
			if builder.packet.Direction != DirectionResponse {
				continue
			}
			if item.envelope.Identifier != nil && builder.packet.Identifier != nil &&
				*item.envelope.Identifier != *builder.packet.Identifier {
				continue
			}
		}
		candidates = append(candidates, index)
	}
	return candidates
}

func finalizePacket(packet *Packet) {
	packet.CallKey = extractCallKey(packet.Attributes)
	if packet.CallContext != "" {
		packet.CallKey.Context = normalizeIdentity(packet.CallContext)
		packet.CallKey.ContextDisplay = packet.CallContext
	}
	requestType := attributeValue(packet.Attributes, "xpgk-request-type")
	switch requestType {
	case "number", "save_call":
		packet.Family = FamilyIndication
	case "check_call":
		packet.Family = FamilyVerification
	default:
		if strings.HasPrefix(packet.RadiusType, "accounting-") {
			packet.Family = FamilyAccounting
		}
	}
	if packet.Family == FamilyAccounting {
		switch strings.ToLower(attributeValue(packet.Attributes, "acct-status-type")) {
		case "start", "1":
			packet.Phase = PhaseStart
		case "interim-update", "interim", "3":
			packet.Phase = PhaseMid
		case "stop", "2":
			packet.Phase = PhaseEnd
		}
	}
}

func classifyAndPair(
	packets []Packet,
	cutoff time.Time,
	timeout time.Duration,
	pairingHorizon time.Duration,
	retryHorizon time.Duration,
) *time.Time {
	knownSessions := make(map[string]struct{})
	for index := range packets {
		packet := &packets[index]
		if packet.Direction != DirectionRequest {
			continue
		}
		requestType := attributeValue(packet.Attributes, "xpgk-request-type")
		explicit := hasExplanation(packet.Explanations, "custom.detect.explicit_header")
		strong := hasStrongCustomAttributeSet(*packet)
		switch {
		case requestType == "number" || requestType == "save_call":
			packet.IsAntifraud = true
			packet.Family = FamilyIndication
			packet.Explanations = append(packet.Explanations, explanation(
				"custom.detect.request_type", "xpgk-request-type identified an indication packet."))
		case requestType == "check_call":
			packet.IsAntifraud = true
			packet.Family = FamilyVerification
			packet.Explanations = append(packet.Explanations, explanation(
				"custom.detect.request_type", "xpgk-request-type identified a verification packet."))
		case packet.Family == FamilyAccounting && hasAccountingCustomEvidence(*packet):
			packet.IsAntifraud = true
			packet.Explanations = append(packet.Explanations, explanation(
				"custom.detect.accounting_attrs", "Accounting carried Custom AntiFraud attributes."))
		case strings.HasPrefix(packet.RadiusType, "access-") && (explicit || strong):
			packet.IsAntifraud = true
			// Without xpgk-request-type do not invent indication/verification.
			packet.Explanations = append(packet.Explanations, explanation(
				"custom.classify.missing_request_type",
				"AntiFraud access lacked xpgk-request-type; family left unclassified."))
		}
		if packet.IsAntifraud && packet.CallKey.AcctSessionID != "" {
			knownSessions[packet.CallKey.AcctSessionID] = struct{}{}
		}
	}
	for index := range packets {
		packet := &packets[index]
		if packet.Direction == DirectionRequest && packet.Family == FamilyAccounting &&
			!packet.IsAntifraud && packet.CallKey.AcctSessionID != "" {
			_, packet.IsAntifraud = knownSessions[packet.CallKey.AcctSessionID]
			if packet.IsAntifraud {
				packet.Explanations = append(packet.Explanations, explanation(
					"custom.detect.known_session", "Accounting matched an exact known Custom session."))
			}
		}
	}

	groups := matchAttemptGroups(packets, pairingHorizon, retryHorizon)
	for groupIndex := range groups {
		group := &groups[groupIndex]
		attempts := make([]uuid.UUID, 0, len(group.indexes))
		for _, requestIndex := range group.indexes {
			attempts = append(attempts, packets[requestIndex].ID)
		}
		for _, requestIndex := range group.indexes {
			packets[requestIndex].AttemptIDs = append([]uuid.UUID(nil), attempts...)
		}
		if group.responseIndex < 0 {
			continue
		}
		response := &packets[group.responseIndex]
		request := &packets[group.indexes[0]]
		response.IsAntifraud = request.IsAntifraud
		response.Family = request.Family
		response.Phase = request.Phase
		response.Status = PacketPaired
		request.Status = PacketPaired
		request.ResponseID = uuidPointer(response.ID)
		response.RequestID = uuidPointer(request.ID)
		response.AttemptIDs = append([]uuid.UUID(nil), attempts...)
		applyDecision(request, response)
		for _, requestIndex := range group.indexes {
			attempt := &packets[requestIndex]
			attempt.ResponseID = uuidPointer(response.ID)
			attempt.Status = PacketPaired
			attempt.Decision = request.Decision
			attempt.Confidence = request.Confidence
			if requestIndex != group.indexes[0] {
				attempt.Explanations = append(attempt.Explanations, explanation(
					"custom.pair.unique",
					"A unique compatible response was paired with this request attempt."))
			}
		}
	}
	var nextDeadline *time.Time
	for groupIndex := range groups {
		group := &groups[groupIndex]
		if group.responseIndex >= 0 {
			continue
		}
		lastSeen := packets[group.indexes[0]].LastSeenAt
		for _, requestIndex := range group.indexes[1:] {
			if packets[requestIndex].LastSeenAt.After(lastSeen) {
				lastSeen = packets[requestIndex].LastSeenAt
			}
		}
		deadline := lastSeen.Add(timeout)
		isAntifraud := packets[group.indexes[0]].IsAntifraud
		for _, requestIndex := range group.indexes {
			packet := &packets[requestIndex]
			packet.Status = PacketPending
			if isAntifraud && !cutoff.Before(deadline) {
				packet.Decision = DecisionUnavailableFallback
				packet.Explanations = append(packet.Explanations, explanation(
					"custom.response.timeout",
					"No unique response arrived before the retry group's configured timeout."))
			}
		}
		if isAntifraud && cutoff.Before(deadline) &&
			(nextDeadline == nil || deadline.Before(*nextDeadline)) {
			copy := deadline
			nextDeadline = &copy
		}
	}
	return nextDeadline
}

type attemptGroup struct {
	indexes       []int
	key           string
	lastAttemptAt time.Time
	responseIndex int
	consumed      bool
}

func matchAttemptGroups(
	packets []Packet, pairingHorizon, retryHorizon time.Duration,
) []attemptGroup {
	groups := make([]attemptGroup, 0)
	latestByKey := make(map[string]int)
	for index := range packets {
		packet := &packets[index]
		if packet.Direction == DirectionRequest {
			identity := authoritativeIdentity(*packet)
			key := identity + "|" + canonicalRequestFingerprint(*packet)
			if identity != "" {
				if groupIndex, exists := latestByKey[key]; exists {
					group := &groups[groupIndex]
					if !group.consumed &&
						!packet.FirstSeenAt.After(group.lastAttemptAt.Add(retryHorizon)) {
						group.indexes = append(group.indexes, index)
						group.lastAttemptAt = packet.FirstSeenAt
						continue
					}
				}
			}
			groups = append(groups, attemptGroup{
				indexes: []int{index}, key: key, lastAttemptAt: packet.FirstSeenAt,
				responseIndex: -1,
			})
			if identity != "" {
				latestByKey[key] = len(groups) - 1
			}
			continue
		}
		if packet.Direction != DirectionResponse {
			continue
		}
		candidates := make([]int, 0)
		for groupIndex := range groups {
			group := &groups[groupIndex]
			if group.consumed || packet.FirstSeenAt.After(group.lastAttemptAt.Add(pairingHorizon)) {
				continue
			}
			request := packets[group.indexes[0]]
			if pairCompatible(request, *packet) {
				candidates = append(candidates, groupIndex)
			}
		}
		if len(candidates) == 1 {
			group := &groups[candidates[0]]
			group.consumed = true
			group.responseIndex = index
			continue
		}
		packet.Status = PacketOrphan
		if len(candidates) > 1 {
			packet.Status = PacketAmbiguous
			packet.Explanations = append(packet.Explanations, explanation(
				"custom.pair.ambiguous", "More than one outstanding request prevented response pairing."))
		} else {
			packet.Explanations = append(packet.Explanations, explanation(
				"custom.pair.orphan_response",
				"No unconsumed compatible request was found inside the pairing horizon."))
		}
	}
	return groups
}

func pairCompatible(request, response Packet) bool {
	if request.FirstSeenAt.After(response.FirstSeenAt) {
		return false
	}
	if request.FirstSeenAt.Equal(response.FirstSeenAt) &&
		firstEventID(request) >= firstEventID(response) {
		return false
	}
	if request.Identifier != nil && response.Identifier != nil && *request.Identifier != *response.Identifier {
		return false
	}
	if response.Identifier != nil && request.Identifier == nil {
		return false
	}
	requestFamily := radiusProtocolFamily(request.RadiusType)
	if requestFamily == "" || requestFamily != radiusProtocolFamily(response.RadiusType) {
		return false
	}
	if conflicts(request.CallKey, response.CallKey) ||
		(request.CallContext != "" && response.CallContext != "" && request.CallContext != response.CallContext) ||
		(request.Component != "" && response.Component != "" && request.Component != response.Component) ||
		(request.Server != "" && response.Server != "" && request.Server != response.Server) {
		return false
	}
	return true
}

func firstEventID(packet Packet) string {
	if len(packet.Provenance) == 0 {
		return ""
	}
	return packet.Provenance[0].EventID.String()
}

func applyDecision(request, response *Packet) {
	switch request.Family {
	case FamilyAccounting:
		request.Decision, response.Decision = DecisionAcknowledgement, DecisionAcknowledgement
	case FamilyVerification:
		if response.RadiusType == "access-reject" {
			request.Decision, response.Decision = DecisionDeny, DecisionDeny
		} else if response.RadiusType == "access-accept" || response.RadiusType == "access-response" {
			request.Decision, response.Decision = DecisionAllow, DecisionAllow
		}
	case FamilyIndication:
		request.Decision, response.Decision = DecisionInfoOnly, DecisionInfoOnly
	}
	if request.Identifier != nil && response.Identifier != nil {
		request.Confidence, response.Confidence = ConfidenceHigh, ConfidenceHigh
	} else {
		request.Confidence, response.Confidence = ConfidenceMedium, ConfidenceMedium
	}
	request.Explanations = append(request.Explanations, explanation(
		"custom.pair.unique", "A unique compatible response was paired with this request."))
	response.Explanations = append(response.Explanations, explanation(
		"custom.pair.unique", "A unique compatible request was paired with this response."))
}

func hasAccountingCustomEvidence(packet Packet) bool {
	return hasStrongCustomAttributeSet(packet)
}

// hasStrongCustomAttributeSet reports Custom AntiFraud attributes beyond a bare
// ExplicitAF header or clg/cld summary. Generic RADIUS keys alone (session id,
// calling/called) are not enough — that would invent AF from ordinary Access.
func hasStrongCustomAttributeSet(packet Packet) bool {
	for _, attribute := range packet.Attributes {
		name := attribute.Name
		switch {
		case name == "xpgk-request-type",
			name == "h323-conf-id",
			name == "h323-call-origin",
			name == "h323-call-type",
			name == "h323-remote-id",
			name == "in-trunkgroup-label",
			name == "out-trunkgroup-label",
			strings.HasPrefix(name, "xpgk-"),
			strings.HasPrefix(name, "h323-"),
			strings.Contains(name, "antifraud"),
			strings.HasPrefix(name, "custom-"):
			return true
		}
	}
	return false
}

func extractCallKey(attributes []Attribute) CallKey {
	sessionDisplay := firstAttributeRawValue(attributes, "acct-session-id")
	h323Display := firstAttributeRawValue(attributes, "h323-conf-id")
	return CallKey{
		AcctSessionID: normalizeIdentity(sessionDisplay), AcctSessionIDDisplay: sessionDisplay,
		H323ConfID: normalizeIdentity(h323Display), H323ConfIDDisplay: h323Display,
		Calling: firstAttributeValue(attributes, "calling-station-id", "calling-number"),
		Called:  firstAttributeValue(attributes, "called-station-id", "called-number"),
	}
}

func normalizeIdentity(value string) string {
	// Compact form must match CDR radius_session_id_normalized and reconciliation.
	return strings.ToLower(strings.Join(strings.Fields(value), ""))
}

func attributeValue(attributes []Attribute, names ...string) string {
	return strings.ToLower(strings.TrimSpace(firstAttributeValue(attributes, names...)))
}

func firstAttributeValue(attributes []Attribute, names ...string) string {
	for _, attribute := range attributes {
		for _, name := range names {
			if attribute.Name == name && !attribute.Redacted {
				return strings.TrimSpace(attribute.Value)
			}
		}
	}
	return ""
}

func firstAttributeRawValue(attributes []Attribute, names ...string) string {
	for _, attribute := range attributes {
		for _, name := range names {
			if attribute.Name == name && !attribute.Redacted {
				return attribute.RawValue
			}
		}
	}
	return ""
}

func authoritativeIdentity(packet Packet) string {
	if packet.CallKey.AcctSessionID != "" {
		return "session:" + packet.CallKey.AcctSessionID
	}
	if packet.CallKey.H323ConfID != "" {
		return "h323:" + packet.CallKey.H323ConfID
	}
	return ""
}

func canonicalRequestFingerprint(packet Packet) string {
	parts := []string{
		packet.RadiusType, identifierString(packet.Identifier), packet.CallContext,
		packet.Component, packet.Server,
	}
	for _, attribute := range packet.Attributes {
		if attribute.Redacted {
			parts = append(parts, attribute.Name+"=<redacted>")
		} else {
			parts = append(parts, attribute.Name+"="+attribute.Value)
		}
	}
	sum := sha1.Sum([]byte(strings.Join(parts, "\x1f")))
	return fmt.Sprintf("%x", sum[:])
}

func radiusProtocolFamily(radiusType string) string {
	if strings.HasPrefix(radiusType, "access-") {
		return "access"
	}
	if strings.HasPrefix(radiusType, "accounting-") {
		return "accounting"
	}
	return ""
}

func conflicts(left, right CallKey) bool {
	if left.AcctSessionID != "" && right.AcctSessionID != "" &&
		left.AcctSessionID != right.AcctSessionID {
		return true
	}
	if left.H323ConfID != "" && right.H323ConfID != "" && left.H323ConfID != right.H323ConfID {
		return true
	}
	return false
}

func identifierString(identifier *uint8) string {
	if identifier == nil {
		return ""
	}
	return strconv.Itoa(int(*identifier))
}

func stableID(parts ...string) uuid.UUID {
	return uuid.NewSHA1(stableNamespace, []byte(strings.Join(parts, "\x00")))
}

func uuidPointer(value uuid.UUID) *uuid.UUID {
	copy := value
	return &copy
}

func explanation(code, text string) Explanation {
	return Explanation{Code: code, Text: text}
}

func hasExplanation(explanations []Explanation, code string) bool {
	for _, item := range explanations {
		if item.Code == code {
			return true
		}
	}
	return false
}

func unmatchedFact(envelope Envelope, reason, code, text string) UnmatchedFact {
	return UnmatchedFact{
		Provenance: envelope.Provenance, Reason: reason,
		Attributes: cloneAttributes(envelope.Attributes), Explanation: explanation(code, text),
		CallContext: envelope.CallContext, Component: envelope.Component,
	}
}

func cloneAttributes(attributes []Attribute) []Attribute {
	return append([]Attribute(nil), attributes...)
}
