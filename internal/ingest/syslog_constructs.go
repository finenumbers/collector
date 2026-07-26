package ingest

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"collector/internal/analytics"

	"github.com/google/uuid"
)

type syslogConstructState struct {
	value          analytics.SyslogConstruct
	lastReceivedAt time.Time
}

type syslogConstructEventResult struct {
	constructID uuid.UUID
	member      analytics.SyslogConstructMember
	link        *analytics.SyslogFragmentLink
	receivedAt  time.Time
}

type syslogConstructStateKey struct {
	constructID uuid.UUID
	revision    uint64
}

type syslogConstructEventKey struct {
	eventID  uuid.UUID
	revision uint64
}

// SyslogConstructAssembler creates a durable readable projection without changing
// the one-datagram-per-event raw contract. It is intentionally stateful across
// batches; stable anchor IDs make replay output independent of batch boundaries.
type SyslogConstructAssembler struct {
	states map[syslogConstructStateKey]*syslogConstructState
	events map[syslogConstructEventKey]syslogConstructEventResult
}

func NewSyslogConstructAssembler() *SyslogConstructAssembler {
	return &SyslogConstructAssembler{
		states: make(map[syslogConstructStateKey]*syslogConstructState),
		events: make(map[syslogConstructEventKey]syslogConstructEventResult),
	}
}

func (a *SyslogConstructAssembler) Assemble(
	events []analytics.SyslogEvent,
) ([]analytics.SyslogConstruct, []analytics.SyslogConstructMember, []analytics.SyslogFragmentLink) {
	if a == nil || len(events) == 0 {
		return nil, nil, nil
	}
	a.prune(events)
	changed := make(map[syslogConstructStateKey]struct{})
	members := make([]analytics.SyslogConstructMember, 0, len(events))
	links := make([]analytics.SyslogFragmentLink, 0)
	for index := range events {
		event := &events[index]
		eventKey := syslogConstructEventKey{
			eventID: event.EventID, revision: event.TimezoneRevision,
		}
		if previous, ok := a.events[eventKey]; ok {
			members = append(members, previous.member)
			if previous.link != nil {
				links = append(links, *previous.link)
			}
			changed[syslogConstructStateKey{
				constructID: previous.constructID, revision: event.TimezoneRevision,
			}] = struct{}{}
			continue
		}

		anchorID := constructAnchorID(event)
		constructID := stableConstructID(event.DeviceID, anchorID)
		stateKey := syslogConstructStateKey{
			constructID: constructID, revision: event.TimezoneRevision,
		}
		state := a.states[stateKey]
		if state == nil {
			state = &syslogConstructState{
				value: newSyslogConstruct(*event, constructID, anchorID),
			}
			a.states[stateKey] = state
		}
		state.lastReceivedAt = event.ReceivedAt
		updateSyslogConstruct(&state.value, *event)
		member := analytics.SyslogConstructMember{
			DeviceID:         event.DeviceID,
			TimezoneRevision: event.TimezoneRevision,
			GroupingVersion:  analytics.SyslogGroupingVersion,
			ConstructID:      constructID,
			EventID:          event.EventID,
			Ordinal:          state.value.MemberCount - 1,
			Role:             constructMemberRole(*event),
			Technical:        isTechnicalConstructEvent(*event),
			LinkedAt:         time.Now().UTC(),
		}
		var link *analytics.SyslogFragmentLink
		if parentID, err := uuid.Parse(event.Attributes["parent_event_id"]); err == nil {
			confidence := parseConstructConfidence(event.Attributes["fragment_link_confidence"])
			item := analytics.SyslogFragmentLink{
				DeviceID:         event.DeviceID,
				TimezoneRevision: event.TimezoneRevision,
				GroupingVersion:  analytics.SyslogGroupingVersion,
				ChildEventID:     event.EventID,
				ParentEventID:    parentID,
				LinkMethod:       firstNonEmpty(event.Attributes["fragment_link_method"], "parent_event_id"),
				FragmentKind:     event.Attributes["fragment_kind"],
				Confidence:       confidence,
				LinkedAt:         member.LinkedAt,
			}
			link = &item
			links = append(links, item)
		}
		a.events[eventKey] = syslogConstructEventResult{
			constructID: constructID, member: member, link: link,
			receivedAt: event.ReceivedAt,
		}
		members = append(members, member)
		changed[stateKey] = struct{}{}
	}
	constructs := make([]analytics.SyslogConstruct, 0, len(changed))
	for key := range changed {
		constructs = append(constructs, a.states[key].value)
	}
	return constructs, members, links
}

func (a *SyslogConstructAssembler) prune(events []analytics.SyslogEvent) {
	watermark := events[0].ReceivedAt
	for index := 1; index < len(events); index++ {
		if events[index].ReceivedAt.After(watermark) {
			watermark = events[index].ReceivedAt
		}
	}
	cutoff := watermark.Add(-10 * time.Second)
	for key, state := range a.states {
		if state.lastReceivedAt.Before(cutoff) {
			delete(a.states, key)
		}
	}
	for key, result := range a.events {
		if result.receivedAt.Before(cutoff) {
			delete(a.events, key)
		}
	}
}

func stableConstructID(deviceID, anchorID uuid.UUID) uuid.UUID {
	key := fmt.Sprintf("%s|%s|%s", deviceID, analytics.SyslogGroupingVersion, anchorID)
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(key))
}

func newSyslogConstruct(
	event analytics.SyslogEvent, constructID, anchorID uuid.UUID,
) analytics.SyslogConstruct {
	occurredAt := event.ReceivedAt
	if event.EventTime != nil {
		occurredAt = *event.EventTime
	}
	continuation := event.Attributes["trace_continuation"] == "true"
	method, reason, confidence := constructGrouping(event)
	title := constructTitle(event)
	attributes := map[string]string{
		"anchor_event_id": anchorID.String(),
	}
	for _, key := range []string{
		"sip_call_id", "global_callref", "callref", "q850_cause",
		"acct_session_id", "packet_identifier", "request_type",
	} {
		if value := event.Attributes[key]; value != "" {
			attributes[key] = value
		}
	}
	completeness := "complete"
	if continuation && anchorID == event.EventID {
		completeness = "fragment"
	}
	return analytics.SyslogConstruct{
		DeviceID:         event.DeviceID,
		TimezoneRevision: event.TimezoneRevision,
		GroupingVersion:  analytics.SyslogGroupingVersion,
		ConstructID:      constructID,
		UpdatedAt:        time.Now().UTC(),
		StartedAt:        occurredAt,
		EndedAt:          occurredAt,
		ConstructType:    firstNonEmpty(event.Attributes["protocol_message_kind"], constructTypeForCategory(event.Category)),
		Category:         event.Category,
		Direction:        event.Attributes["direction"],
		Title:            title,
		Summary:          strings.TrimSpace(event.Message),
		CallContext:      event.Attributes["call_context"],
		MessageName:      event.Attributes["message_name"],
		Completeness:     completeness,
		GroupingMethod:   method,
		GroupingReason:   reason,
		Confidence:       confidence,
		SearchableText:   constructSearchText(event, title),
		Attributes:       attributes,
	}
}

func updateSyslogConstruct(construct *analytics.SyslogConstruct, event analytics.SyslogEvent) {
	occurredAt := event.ReceivedAt
	if event.EventTime != nil {
		occurredAt = *event.EventTime
	}
	if occurredAt.Before(construct.StartedAt) {
		construct.StartedAt = occurredAt
	}
	if occurredAt.After(construct.EndedAt) {
		construct.EndedAt = occurredAt
	}
	construct.UpdatedAt = time.Now().UTC()
	construct.MemberCount++
	if isTechnicalConstructEvent(event) {
		construct.HiddenCount++
	}
	if construct.CallContext == "" {
		construct.CallContext = event.Attributes["call_context"]
	}
	if construct.Direction == "" {
		construct.Direction = event.Attributes["direction"]
	}
	if construct.MessageName == "" {
		construct.MessageName = event.Attributes["message_name"]
	}
	for _, key := range []string{
		"sip_call_id", "global_callref", "callref", "q850_cause",
		"acct_session_id", "packet_identifier", "request_type",
	} {
		if value := event.Attributes[key]; value != "" {
			construct.Attributes[key] = value
		}
	}
	if construct.Summary == "" || construct.Completeness == "fragment" {
		if event.Attributes["trace_continuation"] != "true" {
			construct.Summary = strings.TrimSpace(event.Message)
			construct.Title = constructTitle(event)
			construct.Completeness = "complete"
		}
	}
	method, reason, confidence := constructGrouping(event)
	if method == "heuristic" && construct.GroupingMethod != "heuristic" {
		construct.GroupingMethod = method
		construct.GroupingReason = reason
		construct.Confidence = confidence
	}
	appendText := strings.TrimSpace(event.Message)
	if appendText != "" && !strings.Contains(construct.SearchableText, appendText) {
		if len(construct.SearchableText)+len(appendText) < 32*1024 {
			construct.SearchableText += " " + appendText
		}
	}
}

func constructGrouping(event analytics.SyslogEvent) (method, reason string, confidence float32) {
	linkMethod := event.Attributes["fragment_link_method"]
	if strings.Contains(linkMethod, "burst") {
		return "heuristic", linkMethod, parseConstructConfidence(
			event.Attributes["fragment_link_confidence"],
		)
	}
	if linkMethod != "" {
		return "deterministic", linkMethod, 1
	}
	return "deterministic", "anchor_event", 1
}

func parseConstructConfidence(value string) float32 {
	if parsed, err := strconv.ParseFloat(value, 32); err == nil && parsed > 0 && parsed <= 1 {
		return float32(parsed)
	}
	return 1
}

func constructTitle(event analytics.SyslogEvent) string {
	name := event.Attributes["message_name"]
	direction := event.Attributes["direction"]
	if name != "" && direction != "" {
		return direction + " " + name
	}
	if name != "" {
		return name
	}
	if event.Component != "" {
		return event.Component
	}
	switch event.Category {
	case "sip":
		return "SIP message"
	case "isup":
		return "ISUP PDU"
	case "q931":
		return "Q.931 message"
	case "radius":
		return "RADIUS packet"
	default:
		return event.Category
	}
}

func constructSearchText(event analytics.SyslogEvent, title string) string {
	values := []string{
		title, event.Message, event.Category, event.Component,
		event.Attributes["call_context"], event.Attributes["sip_call_id"],
		event.Attributes["global_callref"], event.Attributes["callref"],
		event.Attributes["acct_session_id"],
	}
	return strings.TrimSpace(strings.Join(values, " "))
}

func constructMemberRole(event analytics.SyslogEvent) string {
	if event.Attributes["trace_continuation"] != "true" {
		return "anchor"
	}
	switch event.Attributes["fragment_kind"] {
	case "sdp", "sdp_line", "sdp_quote", "codec", "host_ip":
		return "sdp"
	case "avp", "typed_hash", "hash_detail", "isup_optional":
		return "parameter"
	case "hex", "dotted_hex", "digest":
		return "raw_dump"
	case "empty":
		return "technical"
	default:
		return "body"
	}
}

func isTechnicalConstructEvent(event analytics.SyslogEvent) bool {
	if event.Attributes["empty_body"] == "true" {
		return true
	}
	switch event.Attributes["fragment_kind"] {
	case "hex", "dotted_hex", "digest", "empty":
		return true
	default:
		return false
	}
}
