package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"collector/internal/redact"
	"collector/internal/workload"

	"github.com/google/uuid"
)

const (
	maxCallDetailPackets  = 500
	maxCallDetailMembers  = 5000
	maxCallAttributes     = 200
	maxCallAttributeBytes = 1024
	maxCallCardJSONBytes  = 2 << 20
)

type CoverageSummary struct {
	State           string         `json:"state"`
	Method          string         `json:"method,omitempty"`
	Reason          string         `json:"reason,omitempty"`
	DeltaMS         *int64         `json:"deltaMs,omitempty"`
	Ambiguous       bool           `json:"ambiguous"`
	AmbiguityReason string         `json:"ambiguityReason,omitempty"`
	Evidence        map[string]any `json:"evidence,omitempty"`
	LinkedCDRIDs    []uuid.UUID    `json:"linkedCdrIds"`
	UpdatedAt       *time.Time     `json:"updatedAt,omitempty"`
}

type AntifraudCallRow struct {
	CallID           uuid.UUID       `json:"callId"`
	FirstSeenAt      time.Time       `json:"firstSeenAt"`
	LastSeenAt       time.Time       `json:"lastSeenAt"`
	AcctSessionID    string          `json:"acctSessionId"`
	H323ConfID       string          `json:"h323ConfId"`
	Calling          string          `json:"calling"`
	Called           string          `json:"called"`
	Status           string          `json:"status"`
	Phases           []string        `json:"phases"`
	PacketCount      uint64          `json:"packetCount"`
	ExplanationCodes []string        `json:"explanationCodes"`
	Coverage         CoverageSummary `json:"coverage"`
	SortTime         time.Time       `json:"-"`
}

type AntifraudCallCursor struct {
	SortTime time.Time
	CallID   uuid.UUID
}

type AntifraudCallPage struct {
	Items   []AntifraudCallRow
	HasMore bool
}

type OrderedAttribute struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

type PacketMember struct {
	EventID    uuid.UUID `json:"eventId"`
	ReceivedAt time.Time `json:"receivedAt"`
	SourceIP   string    `json:"sourceIp"`
	SourcePort uint16    `json:"sourcePort"`
}

type AntifraudPacket struct {
	PacketID         uuid.UUID          `json:"packetId"`
	FirstSeenAt      time.Time          `json:"firstSeenAt"`
	LastSeenAt       time.Time          `json:"lastSeenAt"`
	Family           string             `json:"family"`
	RadiusType       string             `json:"radiusType"`
	Direction        string             `json:"direction"`
	Phase            string             `json:"phase"`
	Decision         string             `json:"decision"`
	Confidence       string             `json:"confidence"`
	Status           string             `json:"status"`
	RequestID        *uuid.UUID         `json:"requestId,omitempty"`
	ResponseID       *uuid.UUID         `json:"responseId,omitempty"`
	AttemptIDs       []uuid.UUID        `json:"attemptIds"`
	Attributes       []OrderedAttribute `json:"attributes"`
	ExplanationCodes []string           `json:"explanationCodes"`
	Warnings         any                `json:"warnings,omitempty"`
	OrphanReason     string             `json:"orphanReason,omitempty"`
	AmbiguityReason  string             `json:"ambiguityReason,omitempty"`
	Members          []PacketMember     `json:"members"`
}

type AntifraudExchange struct {
	ExchangeID       uuid.UUID   `json:"exchangeId"`
	RequestID        uuid.UUID   `json:"requestId"`
	ResponseID       *uuid.UUID  `json:"responseId,omitempty"`
	AttemptIDs       []uuid.UUID `json:"attemptIds"`
	Status           string      `json:"status"`
	Decision         string      `json:"decision"`
	ExplanationCodes []string    `json:"explanationCodes"`
	OccurredAt       time.Time   `json:"occurredAt"`
}

type CDRFacts struct {
	RecordID            uuid.UUID  `json:"recordId"`
	SetupTime           *time.Time `json:"setupTime,omitempty"`
	ConnectTime         *time.Time `json:"connectTime,omitempty"`
	DisconnectTime      *time.Time `json:"disconnectTime,omitempty"`
	DurationMS          *uint64    `json:"durationMs,omitempty"`
	ReleaseCause        *uint16    `json:"releaseCause,omitempty"`
	ReleaseInfo         string     `json:"releaseInfo,omitempty"`
	IncomingCgPN        string     `json:"incomingCgpn,omitempty"`
	OutgoingCgPN        string     `json:"outgoingCgpn,omitempty"`
	IncomingCdPN        string     `json:"incomingCdpn,omitempty"`
	OutgoingCdPN        string     `json:"outgoingCdpn,omitempty"`
	IncomingDescription string     `json:"incomingDescription,omitempty"`
	OutgoingDescription string     `json:"outgoingDescription,omitempty"`
	RadiusSessionID     string     `json:"radiusSessionId,omitempty"`
	UniqueTag           string     `json:"uniqueTag,omitempty"`
	SourceTimezone      string     `json:"sourceTimezone,omitempty"`
}

type AntifraudCallDetail struct {
	AntifraudCallRow
	SnapshotID             uuid.UUID           `json:"-"`
	ContractKey            string              `json:"-"`
	AccountingStart        *time.Time          `json:"accountingStart,omitempty"`
	AccountingStop         *time.Time          `json:"accountingStop,omitempty"`
	SessionDurationSeconds *int64              `json:"sessionDurationSeconds,omitempty"`
	Attributes             []OrderedAttribute  `json:"attributes"`
	Unmatched              any                 `json:"unmatched,omitempty"`
	OrphanPacketIDs        []uuid.UUID         `json:"orphanPacketIds"`
	Packets                []AntifraudPacket   `json:"packets"`
	Exchanges              []AntifraudExchange `json:"exchanges"`
	LinkedCDRs             []CDRFacts          `json:"linkedCdrs"`
	Truncated              bool                `json:"truncated"`
	Warnings               []string            `json:"warnings"`
}

type CallCard struct {
	CDR       CDRFacts             `json:"cdr"`
	Coverage  CoverageSummary      `json:"coverage"`
	Antifraud *AntifraudCallDetail `json:"antifraud,omitempty"`
}

func (c *Client) ListAntifraudCallsPage(
	ctx context.Context, deviceID uuid.UUID, search string, limit uint64,
	cursor *AntifraudCallCursor, timeRange *TimeRange,
) (AntifraudCallPage, error) {
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return AntifraudCallPage{}, err
	}
	defer release()
	if search != "" && timeRange == nil && !c.admittedAs(ctx, workload.Export) {
		return AntifraudCallPage{}, ErrSearchRequiresRange
	}
	if limit == 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT call.call_id,call.first_seen_at,call.last_seen_at,call.acct_session_id,
		call.h323_conf_id,call.calling,call.called,call.status,call.explanation_codes,
		ifNull(packet_summary.phases,[]),ifNull(packet_summary.packet_count,0),
		ifNull(assignment.method,''),ifNull(assignment.reason,''),assignment.delta_ms,
		ifNull(assignment.ambiguous,0),ifNull(assignment.ambiguity_reason,''),
		ifNull(assignment.evidence,'{}'),ifNull(assignment.cdr_ids,[])
		FROM collector.custom_antifraud_calls_current call
		LEFT JOIN (
			SELECT device_id,call_id,any(method) method,any(reason) reason,any(delta_ms) delta_ms,
				max(ambiguous) ambiguous,any(ambiguity_reason) ambiguity_reason,
				any(matched_evidence_json) evidence,groupUniqArray(cdr_id) cdr_ids
			FROM collector.cdr_antifraud_assignments_current GROUP BY device_id,call_id
		) assignment ON assignment.device_id=call.device_id AND assignment.call_id=call.call_id
		LEFT JOIN (
			SELECT links.device_id,links.snapshot_id,links.call_id,
				groupUniqArray(packet.phase) phases,count() packet_count
			FROM collector.custom_antifraud_call_packets_current links
			INNER JOIN collector.custom_radius_packets_current packet
				ON packet.device_id=links.device_id AND packet.snapshot_id=links.snapshot_id
				AND packet.packet_id=links.packet_id
			WHERE links.deleted=0 GROUP BY links.device_id,links.snapshot_id,links.call_id
		) packet_summary ON packet_summary.device_id=call.device_id
			AND packet_summary.snapshot_id=call.snapshot_id AND packet_summary.call_id=call.call_id
		WHERE call.device_id=?`
	args := []any{deviceID}
	if timeRange != nil {
		query += ` AND call.first_seen_at>=? AND call.first_seen_at<?`
		args = append(args, timeRange.From, timeRange.To)
	}
	if search != "" {
		query += ` AND (positionCaseInsensitiveUTF8(call.acct_session_id,?)>0
			OR positionCaseInsensitiveUTF8(call.h323_conf_id,?)>0
			OR positionCaseInsensitiveUTF8(call.calling,?)>0
			OR positionCaseInsensitiveUTF8(call.called,?)>0
			OR positionCaseInsensitiveUTF8(call.status,?)>0)`
		for range 5 {
			args = append(args, search)
		}
	}
	if cursor != nil {
		query += ` AND (call.first_seen_at<? OR (call.first_seen_at=? AND call.call_id<?))`
		args = append(args, cursor.SortTime, cursor.SortTime, cursor.CallID)
	}
	query += ` ORDER BY call.first_seen_at DESC,call.call_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return AntifraudCallPage{}, err
	}
	defer rows.Close()
	items := make([]AntifraudCallRow, 0, limit+1)
	for rows.Next() {
		var item AntifraudCallRow
		var evidence string
		if err := rows.Scan(
			&item.CallID, &item.FirstSeenAt, &item.LastSeenAt, &item.AcctSessionID,
			&item.H323ConfID, &item.Calling, &item.Called, &item.Status,
			&item.ExplanationCodes, &item.Phases, &item.PacketCount,
			&item.Coverage.Method, &item.Coverage.Reason, &item.Coverage.DeltaMS,
			&item.Coverage.Ambiguous, &item.Coverage.AmbiguityReason, &evidence,
			&item.Coverage.LinkedCDRIDs,
		); err != nil {
			return AntifraudCallPage{}, err
		}
		item.SortTime = item.FirstSeenAt
		item.Coverage.State = "unmatched"
		if len(item.Coverage.LinkedCDRIDs) > 0 {
			item.Coverage.State = "matched"
		}
		item.Coverage.Evidence = safeJSONObject(evidence)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return AntifraudCallPage{}, err
	}
	hasMore := uint64(len(items)) > limit
	if hasMore {
		items = items[:limit]
	}
	return AntifraudCallPage{Items: items, HasMore: hasMore}, nil
}

func (c *Client) AntifraudCallDetail(
	ctx context.Context, deviceID, callID uuid.UUID,
) (AntifraudCallDetail, error) {
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return AntifraudCallDetail{}, err
	}
	defer release()
	var detail AntifraudCallDetail
	var attributes, unmatched string
	err = c.Conn.QueryRow(ctx, `SELECT snapshot_id,contract_key,call_id,first_seen_at,last_seen_at,acct_session_id,
		h323_conf_id,calling,called,status,explanation_codes,accounting_start,accounting_stop,
		session_duration_seconds,ordered_attributes_json,unmatched_provenance_json,orphan_packet_ids
		FROM collector.custom_antifraud_calls_current WHERE device_id=? AND call_id=? LIMIT 1`,
		deviceID, callID).Scan(
		&detail.SnapshotID, &detail.ContractKey, &detail.CallID, &detail.FirstSeenAt,
		&detail.LastSeenAt, &detail.AcctSessionID,
		&detail.H323ConfID, &detail.Calling, &detail.Called, &detail.Status,
		&detail.ExplanationCodes, &detail.AccountingStart, &detail.AccountingStop,
		&detail.SessionDurationSeconds, &attributes, &unmatched, &detail.OrphanPacketIDs,
	)
	if err != nil {
		return detail, err
	}
	detail.SortTime = detail.FirstSeenAt
	detail.Attributes = safeOrderedAttributes(attributes)
	detail.Unmatched = safeJSONValue(unmatched)
	if err := c.loadAntifraudPackets(ctx, deviceID, callID, &detail); err != nil {
		return detail, err
	}
	if err := c.loadAntifraudExchanges(ctx, deviceID, &detail); err != nil {
		return detail, err
	}
	if err := c.loadCallCoverage(ctx, deviceID, callID, &detail.Coverage); err != nil {
		return detail, err
	}
	if len(detail.Coverage.LinkedCDRIDs) > 0 {
		detail.LinkedCDRs, err = c.loadCDRFacts(ctx, deviceID, detail.Coverage.LinkedCDRIDs)
		if err != nil {
			return detail, err
		}
	}
	boundCallDetail(&detail)
	return detail, nil
}

func (c *Client) loadAntifraudExchanges(
	ctx context.Context, deviceID uuid.UUID, detail *AntifraudCallDetail,
) error {
	rows, err := c.Conn.Query(ctx, `SELECT exchange_id,request_id,response_id,attempt_ids,
		status,decision,explanation_codes,occurred_at
		FROM collector.custom_radius_exchanges_current
		WHERE device_id=? AND snapshot_id=? AND contract_key=? AND deleted=0
		ORDER BY occurred_at,exchange_id LIMIT ?`,
		deviceID, detail.SnapshotID, detail.ContractKey, maxCallDetailPackets+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item AntifraudExchange
		if err := rows.Scan(
			&item.ExchangeID, &item.RequestID, &item.ResponseID, &item.AttemptIDs,
			&item.Status, &item.Decision, &item.ExplanationCodes, &item.OccurredAt,
		); err != nil {
			return err
		}
		detail.Exchanges = append(detail.Exchanges, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(detail.Exchanges) > maxCallDetailPackets {
		detail.Exchanges = detail.Exchanges[:maxCallDetailPackets]
		detail.Truncated = true
		detail.Warnings = append(detail.Warnings, "exchange list truncated at 500 items")
	}
	return nil
}

func (c *Client) loadAntifraudPackets(
	ctx context.Context, deviceID, callID uuid.UUID, detail *AntifraudCallDetail,
) error {
	rows, err := c.Conn.Query(ctx, `SELECT packet.packet_id,packet.first_seen_at,packet.last_seen_at,
		packet.family,packet.radius_type,packet.direction,packet.phase,packet.decision,
		packet.confidence,packet.status,packet.request_id,packet.response_id,
		exchange.attempt_ids,packet.ordered_attributes_json,packet.explanation_codes,
		packet.warnings_json,packet.orphan_reason,packet.ambiguity_reason,count() OVER()
		FROM collector.custom_antifraud_call_packets_current links
		INNER JOIN collector.custom_radius_packets_current packet
			ON packet.device_id=links.device_id AND packet.snapshot_id=links.snapshot_id
			AND packet.packet_id=links.packet_id
		LEFT JOIN collector.custom_radius_exchanges_current exchange
			ON exchange.device_id=packet.device_id AND exchange.snapshot_id=packet.snapshot_id
			AND exchange.request_id=packet.packet_id AND exchange.deleted=0
		WHERE links.device_id=? AND links.call_id=? AND links.deleted=0
		ORDER BY links.packet_order LIMIT ?`, deviceID, callID, maxCallDetailPackets+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var packet AntifraudPacket
		var attributes, warnings string
		var fullPacketCount uint64
		if err := rows.Scan(
			&packet.PacketID, &packet.FirstSeenAt, &packet.LastSeenAt, &packet.Family,
			&packet.RadiusType, &packet.Direction, &packet.Phase, &packet.Decision,
			&packet.Confidence, &packet.Status, &packet.RequestID, &packet.ResponseID,
			&packet.AttemptIDs, &attributes, &packet.ExplanationCodes, &warnings,
			&packet.OrphanReason, &packet.AmbiguityReason, &fullPacketCount,
		); err != nil {
			return err
		}
		packet.Attributes = safeOrderedAttributes(attributes)
		packet.Warnings = safeJSONValue(warnings)
		detail.Packets = append(detail.Packets, packet)
		detail.PacketCount = fullPacketCount
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(detail.Packets) > maxCallDetailPackets {
		detail.Packets = detail.Packets[:maxCallDetailPackets]
		detail.Truncated = true
		detail.Warnings = append(detail.Warnings, "packet list truncated at 500 items")
	}
	phaseSet := map[string]struct{}{}
	packetIDs := make([]uuid.UUID, 0, len(detail.Packets))
	for index := range detail.Packets {
		packet := &detail.Packets[index]
		phaseSet[packet.Phase] = struct{}{}
		packetIDs = append(packetIDs, packet.PacketID)
	}
	members, membersTruncated, err := c.loadPacketMembers(ctx, deviceID, packetIDs)
	if err != nil {
		return err
	}
	if membersTruncated {
		detail.Truncated = true
		detail.Warnings = append(detail.Warnings, "packet member list truncated at 5000 items")
	}
	for index := range detail.Packets {
		detail.Packets[index].Members = members[detail.Packets[index].PacketID]
	}
	for phase := range phaseSet {
		detail.Phases = append(detail.Phases, phase)
	}
	return nil
}

func (c *Client) loadPacketMembers(
	ctx context.Context, deviceID uuid.UUID, packetIDs []uuid.UUID,
) (map[uuid.UUID][]PacketMember, bool, error) {
	result := make(map[uuid.UUID][]PacketMember, len(packetIDs))
	if len(packetIDs) == 0 {
		return result, false, nil
	}
	rows, err := c.Conn.Query(ctx, `SELECT packet_id,event_id,received_at,toString(source_ip),source_port
		FROM collector.custom_radius_packet_members_current
		WHERE device_id=? AND packet_id IN ? AND deleted=0
		ORDER BY packet_id,member_order LIMIT ?`,
		deviceID, packetIDs, maxCallDetailMembers+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var packetID uuid.UUID
		var item PacketMember
		if err := rows.Scan(
			&packetID, &item.EventID, &item.ReceivedAt, &item.SourceIP, &item.SourcePort,
		); err != nil {
			return nil, false, err
		}
		count++
		if count > maxCallDetailMembers {
			continue
		}
		result[packetID] = append(result[packetID], item)
	}
	return result, count > maxCallDetailMembers, rows.Err()
}

func (c *Client) loadCallCoverage(
	ctx context.Context, deviceID, callID uuid.UUID, coverage *CoverageSummary,
) error {
	var evidence string
	err := c.Conn.QueryRow(ctx, `SELECT any(method),any(reason),any(delta_ms),max(ambiguous),
		any(ambiguity_reason),any(matched_evidence_json),groupUniqArray(cdr_id),max(assigned_at)
		FROM collector.cdr_antifraud_assignments_current WHERE device_id=? AND call_id=?`,
		deviceID, callID).Scan(
		&coverage.Method, &coverage.Reason, &coverage.DeltaMS, &coverage.Ambiguous,
		&coverage.AmbiguityReason, &evidence, &coverage.LinkedCDRIDs, &coverage.UpdatedAt,
	)
	if err != nil {
		return err
	}
	coverage.State = "unmatched"
	if len(coverage.LinkedCDRIDs) > 0 {
		coverage.State = "matched"
	}
	coverage.Evidence = safeJSONObject(evidence)
	return nil
}

func (c *Client) CallCard(
	ctx context.Context, deviceID, recordID uuid.UUID, antifraudEnabled bool,
) (CallCard, error) {
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return CallCard{}, err
	}
	defer release()
	facts, err := c.loadCDRFacts(ctx, deviceID, []uuid.UUID{recordID})
	if err != nil {
		return CallCard{}, err
	}
	if len(facts) == 0 {
		return CallCard{}, errors.New("call not found")
	}
	card := CallCard{CDR: facts[0], Coverage: CoverageSummary{
		State: "not_applicable", Reason: "device_disabled", LinkedCDRIDs: []uuid.UUID{},
	}}
	if !antifraudEnabled {
		return card, nil
	}
	var callID *uuid.UUID
	var evidence string
	err = c.Conn.QueryRow(ctx, `SELECT state,method,reason,delta_ms,ambiguous,ambiguity_reason,
		matched_evidence_json,matched_call_id,updated_at
		FROM collector.cdr_antifraud_coverage_current WHERE device_id=? AND cdr_id=? LIMIT 1`,
		deviceID, recordID).Scan(
		&card.Coverage.State, &card.Coverage.Method, &card.Coverage.Reason,
		&card.Coverage.DeltaMS, &card.Coverage.Ambiguous, &card.Coverage.AmbiguityReason,
		&evidence, &callID, &card.Coverage.UpdatedAt,
	)
	if err != nil {
		card.Coverage.State, card.Coverage.Reason = "expected", "awaiting_custom_call"
		return card, nil
	}
	card.Coverage.Evidence = safeJSONObject(evidence)
	card.Coverage.LinkedCDRIDs = []uuid.UUID{recordID}
	if callID != nil {
		detail, detailErr := c.AntifraudCallDetail(ctx, deviceID, *callID)
		if detailErr != nil {
			return CallCard{}, detailErr
		}
		card.Antifraud = &detail
	}
	return card, nil
}

func (c *Client) loadCDRFacts(
	ctx context.Context, deviceID uuid.UUID, ids []uuid.UUID,
) ([]CDRFacts, error) {
	if len(ids) == 0 {
		return []CDRFacts{}, nil
	}
	rows, err := c.Conn.Query(ctx, `SELECT c.record_id,coalesce(t.setup_time,c.setup_time),
		coalesce(t.connect_time,c.connect_time),coalesce(t.disconnect_time,c.disconnect_time),
		c.duration_ms,c.release_cause,c.release_info,c.incoming_cgpn,c.outgoing_cgpn,
		c.incoming_cdpn,c.outgoing_cdpn,c.incoming_description,c.outgoing_description,
		c.radius_session_id,c.unique_tag,if(t.source_timezone='',c.source_timezone,t.source_timezone)
		FROM collector.cdr_records c FINAL
		LEFT JOIN collector.cdr_time_interpretations t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		WHERE c.device_id=? AND c.record_id IN ? ORDER BY c.record_id`, deviceID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]CDRFacts, 0, len(ids))
	for rows.Next() {
		var item CDRFacts
		if err := rows.Scan(
			&item.RecordID, &item.SetupTime, &item.ConnectTime, &item.DisconnectTime,
			&item.DurationMS, &item.ReleaseCause, &item.ReleaseInfo, &item.IncomingCgPN,
			&item.OutgoingCgPN, &item.IncomingCdPN, &item.OutgoingCdPN,
			&item.IncomingDescription, &item.OutgoingDescription, &item.RadiusSessionID,
			&item.UniqueTag, &item.SourceTimezone,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func safeOrderedAttributes(raw string) []OrderedAttribute {
	value := safeJSONValue(raw)
	result := make([]OrderedAttribute, 0)
	switch attributes := value.(type) {
	case []any:
		for _, entry := range attributes {
			if len(result) >= maxCallAttributes {
				result = append(result, OrderedAttribute{
					Name: "__warning__", Value: "attributes truncated at 200 items",
				})
				break
			}
			if object, ok := entry.(map[string]any); ok {
				name, _ := object["name"].(string)
				if name == "" {
					name, _ = object["key"].(string)
				}
				result = append(result, OrderedAttribute{Name: name, Value: redactValue(name, object["value"])})
			}
		}
	case map[string]any:
		names := make([]string, 0, len(attributes))
		for name := range attributes {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			item := attributes[name]
			if len(result) >= maxCallAttributes {
				result = append(result, OrderedAttribute{
					Name: "__warning__", Value: "attributes truncated at 200 items",
				})
				break
			}
			result = append(result, OrderedAttribute{Name: name, Value: redactValue(name, item)})
		}
	}
	return result
}

func safeJSONObject(raw string) map[string]any {
	value, _ := safeJSONValue(raw).(map[string]any)
	if value == nil {
		return map[string]any{}
	}
	return redactObject(value)
}

func safeJSONValue(raw string) any {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var value any
	if json.Unmarshal([]byte(raw), &value) != nil {
		return nil
	}
	return redactAny(value)
}

func redactAny(value any) any {
	switch item := value.(type) {
	case map[string]any:
		return redactObject(item)
	case []any:
		size := min(len(item), maxCallAttributes)
		result := make([]any, size)
		for index := range result {
			result[index] = redactAny(item[index])
		}
		if len(item) > size {
			result = append(result, "[TRUNCATED]")
		}
		return result
	case string:
		if len(item) > maxCallAttributeBytes {
			return item[:maxCallAttributeBytes] + "[TRUNCATED]"
		}
		return item
	default:
		return value
	}
}

func redactObject(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		if len(result) >= maxCallAttributes {
			result["__warning__"] = "object truncated at 200 fields"
			break
		}
		result[key] = redactValue(key, item)
	}
	return result
}

func redactValue(key string, value any) any {
	if redact.SecretName(key) {
		return redact.Replacement
	}
	return redactAny(value)
}

func boundCallDetail(detail *AntifraudCallDetail) {
	size := jsonSize(detail)
	for index := len(detail.Packets) - 1; index >= 0 && size > maxCallCardJSONBytes; index-- {
		if len(detail.Packets[index].Members) != 0 {
			size -= max(jsonSize(detail.Packets[index].Members)-2, 0)
			detail.Packets[index].Members = nil
			detail.Truncated = true
		}
	}
	for index := len(detail.Packets) - 1; index >= 0 && size > maxCallCardJSONBytes; index-- {
		if len(detail.Packets[index].Attributes) != 0 {
			size -= max(jsonSize(detail.Packets[index].Attributes)-2, 0)
			detail.Packets[index].Attributes = nil
			detail.Truncated = true
		}
	}
	size = jsonSize(detail)
	for len(detail.Exchanges) > 0 && size > maxCallCardJSONBytes {
		detail.Exchanges = detail.Exchanges[:len(detail.Exchanges)-1]
		detail.Truncated = true
		size = jsonSize(detail)
	}
	for len(detail.Packets) > 0 && size > maxCallCardJSONBytes {
		detail.Packets = detail.Packets[:len(detail.Packets)-1]
		detail.Truncated = true
		size = jsonSize(detail)
	}
	if detail.Truncated && !containsString(detail.Warnings, "response truncated to 2097152 JSON bytes") {
		detail.Warnings = append(detail.Warnings, "response truncated to 2097152 JSON bytes")
	}
}

func jsonSize(value any) int {
	encoded, _ := json.Marshal(value)
	return len(encoded)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
