package analytics

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const antifraudResponseWindow = 30 * time.Second

var (
	publicSecretPattern = regexp.MustCompile(`(?i)\b(?:user-?password|password)\s*(?:\(\d+\))?\s*([=:])\s*(?:"[^"]*"|'[^']*'|[^,;\s]+)`)
	radiusPublicPair    = regexp.MustCompile(`(?i)\b([A-Za-z][A-Za-z0-9-]{1,63})\s*(?:\(\d+\))?\s*[=:]\s*(?:"([^"]*)"|'([^']*)'|([^,;\s]+))`)
	vsaPublicPair       = regexp.MustCompile(`(?i)^((?:xpgk|xpkg)-[a-z0-9-]+|in-trunkgroup-label|out-trunkgroup-label|h323-[a-z0-9-]+|numplan)=(.*)$`)
)

type AntiFraudPacket struct {
	DeviceID, PacketID, CallID, AnchorID uuid.UUID
	OperationID                          *uuid.UUID
	Revision                             uint64
	UpdatedAt, OccurredAt                time.Time
	Direction, Code                      string
	Identifier                           *uint8
	Retry                                uint16
	Completeness, TerminalReason         string
	AttributeKeys, AttributeValues       []string
	Attributes                           map[string]string
	RawEventIDs                          []uuid.UUID
	ParserVersion                        string
}

type AntiFraudOperation struct {
	DeviceID, OperationID, CallID uuid.UUID
	Revision                      uint64
	UpdatedAt                     time.Time
	FirstEventAt, LastEventAt     time.Time
	OperationType                 string
	Occurrence                    uint32
	CallContext                   string
	SessionRaw                    string
	Session                       string
	RequestPacketID               *uuid.UUID
	RequestIdentifier             *uint8
	ResponsePacketID              *uuid.UUID
	TerminalState, TerminalReason string
	Decision                      string
	Q850Cause                     *uint16
	RawEventIDs                   []uuid.UUID
	ParserVersion                 string
}

type antiFraudCall struct {
	DeviceID, CallID          uuid.UUID
	Revision                  uint64
	UpdatedAt                 time.Time
	FirstEventAt, LastEventAt time.Time
	IdentityKind              string
	IdentityValue             string
	SessionRaw, Session       string
	H323ConfID                string
	CallContexts              []string
	LegSessions               []string
	LegSessionsNormalized     []string
	RawEventIDs               []uuid.UUID
	ParserVersion             string
}

type antiFraudProjection struct {
	Packets    []AntiFraudPacket
	Operations []AntiFraudOperation
	Calls      []antiFraudCall
}

type CompactAntiFraudProjection struct {
	Packets      int                         `json:"packets"`
	Operations   []CompactAntiFraudOperation `json:"operations"`
	Calls        int                         `json:"calls"`
	BogusRejects int                         `json:"bogusRejects"`
}

type CompactAntiFraudOperation struct {
	Type               string  `json:"type"`
	Session            string  `json:"session"`
	RequestIdentifier  *uint8  `json:"requestIdentifier"`
	ResponseIdentifier *uint8  `json:"responseIdentifier"`
	ResponseCode       string  `json:"responseCode"`
	LatencyMS          *uint32 `json:"latencyMs"`
	TerminalState      string  `json:"terminalState"`
	TerminalReason     string  `json:"terminalReason"`
}

// CompactAntiFraudSummary is a deterministic acceptance-test representation of
// the projection. It intentionally contains no UUIDs or wall-clock update times.
func CompactAntiFraudSummary(events []SyslogEvent) CompactAntiFraudProjection {
	projection := buildAntiFraudProjection(events, nil)
	result := CompactAntiFraudProjection{
		Packets: len(projection.Packets), Calls: len(projection.Calls),
		Operations: make([]CompactAntiFraudOperation, 0, len(projection.Operations)),
	}
	packets := make(map[uuid.UUID]AntiFraudPacket, len(projection.Packets))
	for _, packet := range projection.Packets {
		packets[packet.PacketID] = packet
		if packet.Code == "access-reject" &&
			packet.Attributes["intrinsic_kind"] == "cdr_dump_field" {
			result.BogusRejects++
		}
	}
	for _, operation := range projection.Operations {
		item := CompactAntiFraudOperation{
			Type: operation.OperationType, Session: operation.Session,
			RequestIdentifier: operation.RequestIdentifier,
			TerminalState:     operation.TerminalState, TerminalReason: operation.TerminalReason,
		}
		if operation.ResponsePacketID != nil {
			response := packets[*operation.ResponsePacketID]
			item.ResponseIdentifier = response.Identifier
			item.ResponseCode = response.Code
			item.LatencyMS = parseUint32Attribute(response.Attributes["latency_ms"])
		}
		result.Operations = append(result.Operations, item)
	}
	sort.Slice(result.Operations, func(i, j int) bool {
		if result.Operations[i].Type != result.Operations[j].Type {
			return result.Operations[i].Type < result.Operations[j].Type
		}
		return result.Operations[i].Session < result.Operations[j].Session
	})
	return result
}

func sanitizePublicAttributes(attributes map[string]string) map[string]string {
	result := make(map[string]string, len(attributes))
	for key, value := range attributes {
		normalized := strings.ReplaceAll(strings.ToLower(key), "-", "_")
		if normalized == "password" || normalized == "user_password" {
			continue
		}
		result[key] = value
	}
	return result
}

func redactPublicPayload(payload string) string {
	return publicSecretPattern.ReplaceAllString(payload, "User-Password$1[REDACTED]")
}

func sanitizeEventPresentation(row *EventRow) {
	row.RawPayload = redactPublicPayload(row.RawPayload)
	row.Attributes = sanitizePublicAttributes(row.Attributes)
}

func normalizePublicAttribute(key string) string {
	key = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "-", "_")
	if strings.HasPrefix(key, "xpkg_") {
		key = "xpgk_" + strings.TrimPrefix(key, "xpkg_")
	}
	return key
}

func orderedPublicRadiusAttributes(payload []byte) ([]string, []string) {
	matches := radiusPublicPair.FindAllStringSubmatch(string(payload), -1)
	keys := make([]string, 0, len(matches))
	values := make([]string, 0, len(matches))
	for _, match := range matches {
		value := ""
		for _, candidate := range match[2:] {
			if candidate != "" {
				value = strings.TrimSpace(candidate)
				break
			}
		}
		key := normalizePublicAttribute(match[1])
		if key == "password" || key == "user_password" {
			continue
		}
		if (key == "eltex_avpair" || key == "cisco_avpair") && vsaPublicPair.MatchString(value) {
			vsa := vsaPublicPair.FindStringSubmatch(value)
			key, value = normalizePublicAttribute(vsa[1]), strings.TrimSpace(vsa[2])
		}
		keys, values = append(keys, key), append(values, value)
	}
	return keys, values
}

func antiFraudAnchor(event SyslogEvent) uuid.UUID {
	for _, key := range []string{"construct_anchor_event_id", "parent_event_id"} {
		if value, err := uuid.Parse(event.Attributes[key]); err == nil {
			return value
		}
	}
	return event.EventID
}

func antiFraudCallIdentity(attributes map[string]string, anchor uuid.UUID) (string, string) {
	if confID := normalizeCorrelationValue(attributes["h323_conf_id"]); confID != "" {
		return "h323_conf_id", confID
	}
	if session := normalizeCorrelationValue(attributes["acct_session_id"]); session != "" {
		return "acct_session_id", session
	}
	if contextValue := normalizeCorrelationValue(attributes["call_context"]); contextValue != "" {
		return "call_context", contextValue
	}
	return "packet_anchor", anchor.String()
}

func antiFraudCallID(deviceID uuid.UUID, kind, value string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf(
		"%s|antifraud-call|%s|%s", deviceID, kind, value,
	)))
}

func antiFraudPacketID(event SyslogEvent, revision uint64, identity string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf(
		"%s|%d|%s|%s|packet", event.DeviceID, revision, SyslogParserVersion, identity,
	)))
}

func projectionOperationType(packet AntiFraudPacket) string {
	requestType := strings.ToLower(packet.Attributes["xpgk_request_type"])
	switch requestType {
	case "number", "save_call", "check_call":
		return requestType
	}
	if strings.HasPrefix(packet.Code, "accounting-") {
		return "accounting"
	}
	return ""
}

func buildAntiFraudProjection(events []SyslogEvent, existing []AntiFraudOperation) antiFraudProjection {
	return buildAntiFraudProjectionWithPackets(events, existing, nil)
}

func buildAntiFraudProjectionWithPackets(
	events []SyslogEvent, existing []AntiFraudOperation, persisted []AntiFraudPacket,
) antiFraudProjection {
	type packetKey struct {
		device   uuid.UUID
		revision uint64
		anchor   uuid.UUID
	}
	sortedEvents := append([]SyslogEvent(nil), events...)
	sort.SliceStable(sortedEvents, func(i, j int) bool {
		left, leftAt := canonicalizeRadiusEvent(sortedEvents[i])
		right, rightAt := canonicalizeRadiusEvent(sortedEvents[j])
		_ = left
		_ = right
		if !leftAt.Equal(rightAt) {
			return leftAt.Before(rightAt)
		}
		return sortedEvents[i].EventID.String() < sortedEvents[j].EventID.String()
	})
	grouped := make(map[packetKey][]SyslogEvent)
	order := make([]packetKey, 0)
	basePackets := make(map[packetKey]AntiFraudPacket)
	candidates := make([]AntiFraudPacket, 0, len(persisted)+len(events))
	for _, packet := range persisted {
		key := packetKey{packet.DeviceID, packet.Revision, packet.AnchorID}
		basePackets[key] = packet
		candidates = append(candidates, packet)
	}
	for _, event := range sortedEvents {
		if event.Category != "radius" || event.Attributes["intrinsic_kind"] == "cdr_dump_field" {
			continue
		}
		revision := event.TimezoneRevision
		if revision == 0 {
			revision = 1
		}
		direction := strings.ToLower(event.Attributes["packet_direction"])
		code := strings.ToLower(event.Attributes["packet_code"])
		if direction == "" {
			if strings.HasSuffix(code, "request") {
				direction = "request"
			} else if code != "" {
				direction = "response"
			}
		}
		identifier := event.Attributes["packet_identifier"]
		anchor := antiFraudAnchor(event)
		key := packetKey{event.DeviceID, revision, anchor}
		if event.Attributes["packet_status_event"] == "true" {
			if matched, ok := closestProjectionPacket(
				event, direction, identifier, candidates,
			); ok {
				key = packetKey{matched.DeviceID, matched.Revision, matched.AnchorID}
			} else {
				// A status trace is evidence for a packet, never a packet itself.
				continue
			}
		}
		if code == "" && direction == "" {
			if _, inBatch := grouped[key]; !inBatch {
				if _, persisted := basePackets[key]; !persisted {
					// Control/status rows may enrich a known anchored packet, but
					// cannot create standalone packets.
					continue
				}
			}
		}
		if _, ok := grouped[key]; !ok {
			order = append(order, key)
		}
		grouped[key] = append(grouped[key], event)
		if code != "" && event.Attributes["packet_status_event"] != "true" {
			_, occurredAt := canonicalizeRadiusEvent(event)
			candidates = append(candidates, AntiFraudPacket{
				DeviceID: event.DeviceID, Revision: revision, AnchorID: key.anchor,
				OccurredAt: occurredAt, Direction: direction,
				Identifier: parseUint8Attribute(identifier),
				Attributes: map[string]string{"call_context": event.Attributes["call_context"]},
			})
		}
	}

	result := antiFraudProjection{}
	for _, key := range order {
		members := grouped[key]
		packet, exists := basePackets[key]
		if !exists {
			packet = AntiFraudPacket{
				DeviceID: key.device, Revision: key.revision, AnchorID: key.anchor,
				PacketID:   antiFraudPacketID(members[0], key.revision, key.anchor.String()),
				Attributes: make(map[string]string), Completeness: "packet",
				ParserVersion: SyslogParserVersion,
			}
		} else {
			packet.AttributeKeys = append([]string(nil), packet.AttributeKeys...)
			packet.AttributeValues = append([]string(nil), packet.AttributeValues...)
			packet.RawEventIDs = append([]uuid.UUID(nil), packet.RawEventIDs...)
			packet.Attributes = cloneStringMap(packet.Attributes)
		}
		packet.UpdatedAt = time.Now().UTC()
		for _, member := range members {
			if containsUUID(packet.RawEventIDs, member.EventID) {
				continue
			}
			canonical, occurredAt := canonicalizeRadiusEvent(member)
			if packet.OccurredAt.IsZero() || occurredAt.Before(packet.OccurredAt) {
				packet.OccurredAt = occurredAt
			}
			packet.RawEventIDs = appendUniqueUUID(packet.RawEventIDs, member.EventID)
			for attrKey, value := range sanitizePublicAttributes(canonical.Attributes) {
				if value != "" {
					packet.Attributes[attrKey] = value
				}
			}
			keys, values := orderedPublicRadiusAttributes(member.Payload)
			packet.AttributeKeys = append(packet.AttributeKeys, keys...)
			packet.AttributeValues = append(packet.AttributeValues, values...)
		}
		packet.Direction = strings.ToLower(packet.Attributes["packet_direction"])
		packet.Code = strings.ToLower(packet.Attributes["packet_code"])
		if packet.Direction == "" {
			if strings.HasSuffix(packet.Code, "request") {
				packet.Direction = "request"
			} else if packet.Code != "" {
				packet.Direction = "response"
			}
		}
		packet.Identifier = parseUint8Attribute(packet.Attributes["packet_identifier"])
		packet.Retry = valueOrZero(parseUint16Attribute(packet.Attributes["retry"]))
		kind, identity := antiFraudCallIdentity(packet.Attributes, packet.AnchorID)
		packet.CallID = antiFraudCallID(packet.DeviceID, kind, identity)
		result.Packets = append(result.Packets, packet)
	}

	result.Operations = make([]AntiFraudOperation, 0, len(result.Packets))
	occurrences := make(map[string]uint32)
	outstanding := make([]*AntiFraudOperation, 0)
	existingIDs := make(map[uuid.UUID]bool)
	existingByID := make(map[uuid.UUID]*AntiFraudOperation)
	existingRequests := make(map[uuid.UUID]*AntiFraudOperation)
	existingResponses := make(map[uuid.UUID]*AntiFraudOperation)
	for index := range existing {
		item := existing[index]
		existingIDs[item.OperationID] = true
		key := item.CallID.String() + "|" + item.OperationType
		if item.Occurrence > occurrences[key] {
			occurrences[key] = item.Occurrence
		}
		copy := item
		existingByID[item.OperationID] = &copy
		if item.RequestPacketID != nil {
			existingRequests[*item.RequestPacketID] = existingByID[item.OperationID]
		}
		if item.ResponsePacketID != nil {
			existingResponses[*item.ResponsePacketID] = existingByID[item.OperationID]
		}
		if item.TerminalState == "outstanding" {
			outstanding = append(outstanding, existingByID[item.OperationID])
		}
	}
	updatedExisting := make(map[uuid.UUID]*AntiFraudOperation)
	for index := range result.Packets {
		packet := &result.Packets[index]
		operationType := projectionOperationType(*packet)
		if packet.Direction != "response" && operationType != "" {
			operationID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(packet.PacketID.String()+"|operation"))
			if packet.OperationID != nil {
				if operation := existingByID[*packet.OperationID]; operation != nil {
					updateOperationFromRequestPacket(operation, packet, operationType)
					updatedExisting[operation.OperationID] = operation
					continue
				}
			}
			if operation := existingRequests[packet.PacketID]; operation != nil {
				packet.OperationID = &operation.OperationID
				updateOperationFromRequestPacket(operation, packet, operationType)
				updatedExisting[operation.OperationID] = operation
				continue
			}
			if packet.Retry > 0 {
				candidates := compatibleRetryOperations(*packet, operationType, outstanding)
				if len(candidates) == 1 {
					operation := candidates[0]
					packet.OperationID = &operation.OperationID
					packet.CallID = operation.CallID
					operation.UpdatedAt = time.Now().UTC()
					operation.LastEventAt = packet.OccurredAt
					for _, eventID := range packet.RawEventIDs {
						operation.RawEventIDs = appendUniqueUUID(operation.RawEventIDs, eventID)
					}
					if existingIDs[operation.OperationID] {
						updatedExisting[operation.OperationID] = operation
					}
					continue
				}
			}
			key := packet.CallID.String() + "|" + operationType
			occurrences[key]++
			operation := AntiFraudOperation{
				DeviceID: packet.DeviceID, Revision: packet.Revision,
				OperationID: operationID, CallID: packet.CallID, UpdatedAt: packet.UpdatedAt,
				FirstEventAt: packet.OccurredAt, LastEventAt: packet.OccurredAt,
				OperationType: operationType, Occurrence: occurrences[key],
				CallContext:     packet.Attributes["call_context"],
				SessionRaw:      packet.Attributes["acct_session_id"],
				Session:         normalizeCorrelationValue(packet.Attributes["acct_session_id"]),
				RequestPacketID: &packet.PacketID, TerminalState: "outstanding",
				RequestIdentifier: packet.Identifier,
				RawEventIDs:       append([]uuid.UUID(nil), packet.RawEventIDs...),
				ParserVersion:     SyslogParserVersion,
			}
			if operationType == "check_call" &&
				(packet.Attributes["decision"] == "timeout_fail_open" ||
					packet.Attributes["result"] == "timeout") {
				operation.TerminalState = "verification_fail_open"
				operation.TerminalReason = "timeout_or_unavailable"
				operation.Decision = "verification_fail_open"
			}
			packet.OperationID = &operationID
			result.Operations = append(result.Operations, operation)
			outstanding = append(outstanding, &result.Operations[len(result.Operations)-1])
		}
	}
	for index := range result.Packets {
		packet := &result.Packets[index]
		if packet.Direction != "response" {
			continue
		}
		if packet.Code == "access-response" && packet.Attributes["result"] == "" {
			// Eltex reply headers identify a packet but do not contain its
			// terminal result. A later Proc Reply event updates this same packet.
			continue
		}
		if operation := existingResponses[packet.PacketID]; operation != nil {
			packet.OperationID = &operation.OperationID
			packet.CallID = operation.CallID
			continue
		}
		candidates := compatibleOutstandingOperations(*packet, outstanding)
		if len(candidates) == 1 {
			applyOperationResponse(candidates[0], packet)
			if existingIDs[candidates[0].OperationID] {
				updatedExisting[candidates[0].OperationID] = candidates[0]
			}
			continue
		}
		reason := "incomplete_response"
		if len(candidates) > 1 {
			reason = "ambiguous_response"
		}
		operationID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(packet.PacketID.String()+"|response-only"))
		packet.OperationID = &operationID
		result.Operations = append(result.Operations, AntiFraudOperation{
			DeviceID: packet.DeviceID, Revision: packet.Revision, OperationID: operationID,
			CallID: packet.CallID, UpdatedAt: packet.UpdatedAt, FirstEventAt: packet.OccurredAt,
			LastEventAt: packet.OccurredAt, OperationType: projectionOperationType(*packet),
			CallContext:      packet.Attributes["call_context"],
			SessionRaw:       packet.Attributes["acct_session_id"],
			Session:          normalizeCorrelationValue(packet.Attributes["acct_session_id"]),
			ResponsePacketID: &packet.PacketID, TerminalState: reason, TerminalReason: reason,
			RawEventIDs:   append([]uuid.UUID(nil), packet.RawEventIDs...),
			ParserVersion: SyslogParserVersion,
		})
		packet.TerminalReason = reason
	}
	for _, operation := range updatedExisting {
		result.Operations = append(result.Operations, *operation)
	}
	result.Calls = projectionCalls(result.Packets)
	return result
}

func updateOperationFromRequestPacket(
	operation *AntiFraudOperation, packet *AntiFraudPacket, operationType string,
) {
	packet.OperationID = &operation.OperationID
	operation.UpdatedAt = time.Now().UTC()
	if packet.OccurredAt.After(operation.LastEventAt) {
		operation.LastEventAt = packet.OccurredAt
	}
	operation.CallID = packet.CallID
	operation.OperationType = prefer(operation.OperationType, operationType)
	operation.CallContext = prefer(
		operation.CallContext, packet.Attributes["call_context"],
	)
	operation.SessionRaw = prefer(
		operation.SessionRaw, packet.Attributes["acct_session_id"],
	)
	operation.Session = normalizeCorrelationValue(operation.SessionRaw)
	for _, eventID := range packet.RawEventIDs {
		operation.RawEventIDs = appendUniqueUUID(operation.RawEventIDs, eventID)
	}
}

func closestProjectionPacket(
	event SyslogEvent, direction, identifier string, candidates []AntiFraudPacket,
) (AntiFraudPacket, bool) {
	_, occurredAt := canonicalizeRadiusEvent(event)
	contextValue := event.Attributes["call_context"]
	eventIdentifier := parseUint8Attribute(identifier)
	var selected AntiFraudPacket
	found := false
	for _, candidate := range candidates {
		if candidate.DeviceID != event.DeviceID ||
			candidate.Revision != max(event.TimezoneRevision, uint64(1)) ||
			candidate.Direction != direction ||
			eventIdentifier == nil || candidate.Identifier == nil ||
			*candidate.Identifier != *eventIdentifier ||
			(contextValue != "" && candidate.Attributes["call_context"] != contextValue) ||
			candidate.OccurredAt.After(occurredAt) ||
			occurredAt.Sub(candidate.OccurredAt) > antifraudResponseWindow {
			continue
		}
		if !found || candidate.OccurredAt.After(selected.OccurredAt) ||
			(candidate.OccurredAt.Equal(selected.OccurredAt) &&
				candidate.AnchorID.String() < selected.AnchorID.String()) {
			selected, found = candidate, true
		}
	}
	return selected, found
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func containsUUID(values []uuid.UUID, candidate uuid.UUID) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func compatibleRetryOperations(
	packet AntiFraudPacket, operationType string, operations []*AntiFraudOperation,
) []*AntiFraudOperation {
	contextValue := packet.Attributes["call_context"]
	result := make([]*AntiFraudOperation, 0)
	for _, operation := range operations {
		if operation.DeviceID != packet.DeviceID || operation.Revision != packet.Revision ||
			operation.TerminalState != "outstanding" || operation.OperationType != operationType ||
			operation.LastEventAt.After(packet.OccurredAt) {
			continue
		}
		delta := packet.OccurredAt.Sub(operation.LastEventAt)
		if delta > antifraudResponseWindow ||
			(contextValue != "" && operation.CallContext != contextValue) ||
			(packet.Identifier != nil && operation.RequestIdentifier != nil &&
				*packet.Identifier != *operation.RequestIdentifier) {
			continue
		}
		result = append(result, operation)
	}
	return result
}

func compatibleOutstandingOperations(
	packet AntiFraudPacket, operations []*AntiFraudOperation,
) []*AntiFraudOperation {
	contextValue := packet.Attributes["call_context"]
	result := make([]*AntiFraudOperation, 0)
	for _, operation := range operations {
		if operation.DeviceID != packet.DeviceID || operation.Revision != packet.Revision ||
			operation.TerminalState != "outstanding" || operation.LastEventAt.After(packet.OccurredAt) {
			continue
		}
		delta := packet.OccurredAt.Sub(operation.LastEventAt)
		if delta > antifraudResponseWindow ||
			(contextValue != "" && operation.CallContext != contextValue) {
			continue
		}
		if packet.Identifier != nil && operation.RequestIdentifier != nil &&
			*packet.Identifier != *operation.RequestIdentifier {
			continue
		}
		result = append(result, operation)
	}
	return result
}

func applyOperationResponse(operation *AntiFraudOperation, packet *AntiFraudPacket) {
	operation.UpdatedAt = time.Now().UTC()
	operation.LastEventAt = packet.OccurredAt
	operation.ResponsePacketID = &packet.PacketID
	operation.RawEventIDs = append(operation.RawEventIDs, packet.RawEventIDs...)
	packet.OperationID = &operation.OperationID
	packet.CallID = operation.CallID
	if packet.Attributes["acct_session_id"] == "" && operation.Session != "" {
		packet.Attributes["acct_session_id"] = operation.SessionRaw
		if packet.Attributes["acct_session_id"] == "" {
			packet.Attributes["acct_session_id"] = operation.Session
		}
	}
	if packet.Attributes["call_context"] == "" {
		packet.Attributes["call_context"] = operation.CallContext
	}
	switch operation.OperationType {
	case "number", "save_call":
		operation.TerminalState = "response_received"
		operation.TerminalReason = "no_block_evidence"
		operation.Decision = "neutral"
	case "check_call":
		switch packet.Code {
		case "access-accept":
			operation.TerminalState, operation.Decision = "verification_accept", "verification_accept"
		case "access-reject":
			operation.TerminalState, operation.Decision = "verification_reject", "verification_reject"
		default:
			operation.TerminalState, operation.Decision = "verification_fail_open", "verification_fail_open"
			operation.TerminalReason = "timeout_or_unavailable"
		}
	case "accounting":
		if packet.Code == "accounting-response" {
			operation.TerminalState = "accounting_complete"
		} else {
			operation.TerminalState, operation.TerminalReason = "accounting_incomplete", "unexpected_response"
		}
	default:
		operation.TerminalState, operation.TerminalReason = "incomplete_response", "unknown_operation"
	}
	if cause := parseUint16Attribute(packet.Attributes["q850_cause"]); cause != nil {
		operation.Q850Cause = cause
	}
}

func projectionCalls(packets []AntiFraudPacket) []antiFraudCall {
	result := make(map[uuid.UUID]*antiFraudCall)
	for _, packet := range packets {
		if packet.OperationID == nil {
			continue
		}
		item := result[packet.CallID]
		kind, identity := antiFraudCallIdentity(packet.Attributes, packet.AnchorID)
		if item == nil {
			item = &antiFraudCall{
				DeviceID: packet.DeviceID, CallID: packet.CallID, Revision: packet.Revision,
				UpdatedAt: packet.UpdatedAt, FirstEventAt: packet.OccurredAt,
				LastEventAt: packet.OccurredAt, IdentityKind: kind, IdentityValue: identity,
				SessionRaw: packet.Attributes["acct_session_id"],
				Session:    normalizeCorrelationValue(packet.Attributes["acct_session_id"]),
				H323ConfID: packet.Attributes["h323_conf_id"], ParserVersion: SyslogParserVersion,
			}
			result[packet.CallID] = item
		}
		if packet.OccurredAt.Before(item.FirstEventAt) {
			item.FirstEventAt = packet.OccurredAt
		}
		if packet.OccurredAt.After(item.LastEventAt) {
			item.LastEventAt = packet.OccurredAt
		}
		if contextValue := packet.Attributes["call_context"]; contextValue != "" {
			item.CallContexts = appendUniqueString(item.CallContexts, contextValue)
		}
		if session := packet.Attributes["acct_session_id"]; session != "" {
			item.LegSessions = appendUniqueString(item.LegSessions, session)
			item.LegSessionsNormalized = appendUniqueString(
				item.LegSessionsNormalized, normalizeCorrelationValue(session),
			)
		}
		for _, eventID := range packet.RawEventIDs {
			item.RawEventIDs = appendUniqueUUID(item.RawEventIDs, eventID)
		}
	}
	calls := make([]antiFraudCall, 0, len(result))
	for _, item := range result {
		calls = append(calls, *item)
	}
	return calls
}

func appendUniqueString(values []string, candidate string) []string {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func (c *Client) processAntiFraudProjection(ctx context.Context, events []SyslogEvent) error {
	existing, err := c.loadProjectionOperations(ctx, events)
	if err != nil {
		return err
	}
	persistedPackets, err := c.loadProjectionPackets(ctx, events)
	if err != nil {
		return err
	}
	projection := buildAntiFraudProjectionWithPackets(events, existing, persistedPackets)
	if len(projection.Packets) == 0 {
		return nil
	}
	if err := c.insertProjectionCalls(ctx, projection.Calls); err != nil {
		return err
	}
	if err := c.insertProjectionPackets(ctx, projection.Packets); err != nil {
		return err
	}
	return c.insertProjectionOperations(ctx, projection.Operations)
}

func (c *Client) loadProjectionPackets(
	ctx context.Context, events []SyslogEvent,
) ([]AntiFraudPacket, error) {
	if len(events) == 0 {
		return nil, nil
	}
	deviceID := events[0].DeviceID
	revision := events[0].TimezoneRevision
	if revision == 0 {
		revision = 1
	}
	_, firstAt := canonicalizeRadiusEvent(events[0])
	from, to := firstAt.Add(-antifraudResponseWindow), firstAt.Add(antifraudResponseWindow)
	for _, event := range events[1:] {
		if event.DeviceID != deviceID {
			return nil, nil
		}
		_, occurredAt := canonicalizeRadiusEvent(event)
		if occurredAt.Add(-antifraudResponseWindow).Before(from) {
			from = occurredAt.Add(-antifraudResponseWindow)
		}
		if occurredAt.Add(antifraudResponseWindow).After(to) {
			to = occurredAt.Add(antifraudResponseWindow)
		}
	}
	rows, err := c.Conn.Query(ctx, `SELECT packet_id,updated_at,occurred_at,call_id,
			operation_id,construct_anchor_event_id,direction,packet_code,
			packet_identifier,retry,completeness,terminal_reason,attribute_keys,
			attribute_values,attributes,raw_event_ids
		FROM collector.current_antifraud_packets
		WHERE device_id=? AND timezone_revision=? AND parser_version=?
		  AND occurred_at>=? AND occurred_at<=?`,
		deviceID, revision, SyslogParserVersion, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]AntiFraudPacket, 0)
	for rows.Next() {
		item := AntiFraudPacket{
			DeviceID: deviceID, Revision: revision, ParserVersion: SyslogParserVersion,
		}
		if err := rows.Scan(
			&item.PacketID, &item.UpdatedAt, &item.OccurredAt, &item.CallID,
			&item.OperationID, &item.AnchorID, &item.Direction, &item.Code,
			&item.Identifier, &item.Retry, &item.Completeness, &item.TerminalReason,
			&item.AttributeKeys, &item.AttributeValues, &item.Attributes, &item.RawEventIDs,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (c *Client) loadProjectionOperations(
	ctx context.Context, events []SyslogEvent,
) ([]AntiFraudOperation, error) {
	if len(events) == 0 {
		return nil, nil
	}
	deviceID := events[0].DeviceID
	revision := events[0].TimezoneRevision
	if revision == 0 {
		revision = 1
	}
	from, to := events[0].ReceivedAt.Add(-antifraudResponseWindow), events[0].ReceivedAt.Add(antifraudResponseWindow)
	for _, event := range events[1:] {
		if event.DeviceID != deviceID {
			return nil, nil // multi-device ingest batches are not cross-paired
		}
		if event.ReceivedAt.Before(from) {
			from = event.ReceivedAt.Add(-antifraudResponseWindow)
		}
		if event.ReceivedAt.After(to) {
			to = event.ReceivedAt.Add(antifraudResponseWindow)
		}
	}
	rows, err := c.Conn.Query(ctx, `SELECT o.operation_id,o.updated_at,o.first_event_at,
		o.last_event_at,o.call_id,o.operation_type,o.occurrence,o.call_context,
		o.acct_session_id,o.acct_session_id_normalized,o.request_packet_id,p.packet_identifier,
		o.response_packet_id,o.terminal_state,o.terminal_reason,o.decision,
		o.q850_cause,o.raw_event_ids
		FROM collector.current_antifraud_operations AS o
		LEFT JOIN collector.current_antifraud_packets AS p
		  ON p.device_id=o.device_id AND p.timezone_revision=o.timezone_revision
		 AND p.parser_version=o.parser_version AND p.packet_id=o.request_packet_id
		WHERE o.device_id=? AND o.timezone_revision=? AND o.parser_version=?
		  AND o.last_event_at>=? AND o.last_event_at<=?`,
		deviceID, revision, SyslogParserVersion, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]AntiFraudOperation, 0)
	for rows.Next() {
		item := AntiFraudOperation{
			DeviceID: deviceID, Revision: revision, ParserVersion: SyslogParserVersion,
		}
		if err := rows.Scan(
			&item.OperationID, &item.UpdatedAt, &item.FirstEventAt, &item.LastEventAt,
			&item.CallID, &item.OperationType, &item.Occurrence, &item.CallContext,
			&item.SessionRaw, &item.Session, &item.RequestPacketID, &item.RequestIdentifier,
			&item.ResponsePacketID,
			&item.TerminalState, &item.TerminalReason, &item.Decision,
			&item.Q850Cause, &item.RawEventIDs,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (c *Client) insertProjectionCalls(ctx context.Context, calls []antiFraudCall) error {
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.antifraud_calls
		(device_id,timezone_revision,parser_version,call_id,updated_at,first_event_at,
		 last_event_at,identity_kind,identity_value,acct_session_id,
		 acct_session_id_normalized,h323_conf_id,call_contexts,raw_event_ids,
		 leg_session_ids,leg_session_ids_normalized)`)
	if err != nil {
		return err
	}
	for _, item := range calls {
		if err := batch.Append(
			item.DeviceID, item.Revision, item.ParserVersion, item.CallID, item.UpdatedAt,
			item.FirstEventAt, item.LastEventAt, item.IdentityKind, item.IdentityValue,
			item.SessionRaw, item.Session, item.H323ConfID, item.CallContexts, item.RawEventIDs,
			item.LegSessions, item.LegSessionsNormalized,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *Client) insertProjectionPackets(ctx context.Context, packets []AntiFraudPacket) error {
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.antifraud_packets
		(device_id,timezone_revision,parser_version,packet_id,updated_at,occurred_at,
		 call_id,operation_id,construct_anchor_event_id,direction,packet_code,
		 packet_identifier,retry,completeness,terminal_reason,attribute_keys,
		 attribute_values,attributes,raw_event_ids)`)
	if err != nil {
		return err
	}
	for _, item := range packets {
		if err := batch.Append(
			item.DeviceID, item.Revision, item.ParserVersion, item.PacketID, item.UpdatedAt,
			item.OccurredAt, item.CallID, item.OperationID, item.AnchorID, item.Direction,
			item.Code, item.Identifier, item.Retry, item.Completeness, item.TerminalReason,
			item.AttributeKeys, item.AttributeValues, item.Attributes, item.RawEventIDs,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *Client) insertProjectionOperations(
	ctx context.Context, operations []AntiFraudOperation,
) error {
	if len(operations) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.antifraud_operations
		(device_id,timezone_revision,parser_version,operation_id,updated_at,first_event_at,
		 last_event_at,call_id,operation_type,occurrence,call_context,
		 acct_session_id,acct_session_id_normalized,request_packet_id,response_packet_id,terminal_state,
		 terminal_reason,decision,q850_cause,raw_event_ids)`)
	if err != nil {
		return err
	}
	for _, item := range operations {
		if err := batch.Append(
			item.DeviceID, item.Revision, item.ParserVersion, item.OperationID, item.UpdatedAt,
			item.FirstEventAt, item.LastEventAt, item.CallID, item.OperationType,
			item.Occurrence, item.CallContext, item.SessionRaw, item.Session, item.RequestPacketID,
			item.ResponsePacketID, item.TerminalState, item.TerminalReason, item.Decision,
			item.Q850Cause, item.RawEventIDs,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *Client) reconcileOperationCDRs(
	ctx context.Context, bucket DirtyCorrelationBucket,
) error {
	from := bucket.Bucket.UTC().Add(-10 * time.Minute)
	to := bucket.Bucket.UTC().Add(24*time.Hour + 10*time.Minute)
	rows, err := c.Conn.Query(ctx, `SELECT o.operation_id,o.first_event_at,
			o.acct_session_id_normalized,ifNull(c.h323_conf_id_normalized,'')
		FROM collector.current_antifraud_operations AS o
		LEFT JOIN collector.current_antifraud_calls AS c
		  ON c.device_id=o.device_id AND c.timezone_revision=o.timezone_revision
		 AND c.parser_version=o.parser_version AND c.call_id=o.call_id
		WHERE o.device_id=? AND o.timezone_revision=? AND o.parser_version=?
		  AND o.first_event_at>=? AND o.first_event_at<?`,
		bucket.DeviceID, bucket.Revision, SyslogParserVersion, from, to)
	if err != nil {
		return err
	}
	type operation struct {
		id      uuid.UUID
		at      time.Time
		session string
		h323    string
	}
	operations := make([]operation, 0)
	for rows.Next() {
		var item operation
		if err := rows.Scan(&item.id, &item.at, &item.session, &item.h323); err != nil {
			rows.Close()
			return err
		}
		operations = append(operations, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	cdrRows, err := c.Conn.Query(ctx, `SELECT c.record_id,t.setup_time,
			c.radius_session_id_normalized
		FROM collector.cdr_records AS c FINAL
		ANY INNER JOIN
		(
			SELECT record_id,argMax(setup_time_utc,interpreted_at) AS setup_time
			FROM collector.cdr_time_facts
			WHERE device_id=? AND timezone_revision=?
			GROUP BY record_id
		) AS t ON t.record_id=c.record_id
		WHERE c.device_id=? AND t.setup_time>=? AND t.setup_time<?`,
		bucket.DeviceID, bucket.Revision, bucket.DeviceID, from, to)
	if err != nil {
		return err
	}
	type cdr struct {
		id      uuid.UUID
		at      time.Time
		session string
	}
	cdrs := make([]cdr, 0)
	for cdrRows.Next() {
		var item cdr
		if err := cdrRows.Scan(&item.id, &item.at, &item.session); err != nil {
			cdrRows.Close()
			return err
		}
		cdrs = append(cdrs, item)
	}
	if err := cdrRows.Close(); err != nil {
		return err
	}
	if len(operations) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.antifraud_operation_cdr_links
		(device_id,timezone_revision,parser_version,operation_id,updated_at,cdr_record_id,
		 state,method,time_delta_ms,reason)`)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, operation := range operations {
		candidates := make([]cdr, 0)
		method := "exact_acct_session"
		for _, candidate := range cdrs {
			if operationCDRMatchMethod(operation.session, operation.h323, candidate.session) ==
				"exact_acct_session" {
				candidates = append(candidates, candidate)
			}
		}
		if len(candidates) == 0 && operation.h323 != "" {
			method = "exact_h323_conf_id"
			for _, candidate := range cdrs {
				if operationCDRMatchMethod(operation.session, operation.h323, candidate.session) ==
					"exact_h323_conf_id" {
					candidates = append(candidates, candidate)
				}
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			left := absDuration(candidates[i].at.Sub(operation.at))
			right := absDuration(candidates[j].at.Sub(operation.at))
			if left != right {
				return left < right
			}
			return candidates[i].id.String() < candidates[j].id.String()
		})
		var recordID *uuid.UUID
		state, selectedMethod, reason := "unlinked", "", "no_session_match"
		var delta int64
		if len(candidates) > 0 {
			delta = candidates[0].at.Sub(operation.at).Milliseconds()
			if len(candidates) == 1 {
				id := candidates[0].id
				recordID = &id
				state, selectedMethod, reason = "linked", method, ""
			} else {
				state, selectedMethod = "ambiguous", method
				if method == "exact_h323_conf_id" {
					reason = "ambiguous_h323_conf_id_collision"
				} else {
					reason = "ambiguous_session_collision"
				}
			}
		}
		if err := batch.Append(
			bucket.DeviceID, bucket.Revision, SyslogParserVersion, operation.id, now,
			recordID, state, selectedMethod, delta, reason,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func operationCDRMatchMethod(operationSession, callH323, cdrSession string) string {
	if operationSession != "" && operationSession == cdrSession {
		return "exact_acct_session"
	}
	if callH323 != "" && callH323 == cdrSession {
		return "exact_h323_conf_id"
	}
	return ""
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
