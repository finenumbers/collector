package analytics

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
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

// ErrAntifraudCallNotFound is returned when the active projection has no call row.
var ErrAntifraudCallNotFound = errors.New("antifraud call not found")

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

type ChainCompleteness struct {
	State             string   `json:"state"`
	MissingStages     []string `json:"missingStages,omitempty"`
	MissingResponses  []string `json:"missingResponses,omitempty"`
	Notes             []string `json:"notes,omitempty"`
}

type CallParticipants struct {
	CallingNumber string `json:"callingNumber,omitempty"`
	CalledNumber  string `json:"calledNumber,omitempty"`
}

type CallAccounting struct {
	SetupTime           *time.Time `json:"setupTime,omitempty"`
	ConnectTime         *time.Time `json:"connectTime,omitempty"`
	DisconnectTime      *time.Time `json:"disconnectTime,omitempty"`
	EventTimestamp      *time.Time `json:"eventTimestamp,omitempty"`
	DisconnectCause     string     `json:"disconnectCause,omitempty"`
	DisconnectCauseQ850 *int64     `json:"disconnectCauseQ850,omitempty"`
	SessionTimeSec      *int64     `json:"sessionTimeSec,omitempty"`
	DelayTimeSec        *int64     `json:"delayTimeSec,omitempty"`
}

type CallRouting struct {
	OriginatingIP      string `json:"originatingIp,omitempty"`
	TerminationIP      string `json:"terminationIp,omitempty"`
	SrcNumberIn        string `json:"srcNumberIn,omitempty"`
	DstNumberIn        string `json:"dstNumberIn,omitempty"`
	SrcNumberOut       string `json:"srcNumberOut,omitempty"`
	DstNumberOut       string `json:"dstNumberOut,omitempty"`
	RedirectNumber     string `json:"redirectNumber,omitempty"`
	RemoteID           string `json:"remoteId,omitempty"`
	OutTrunkgroupLabel string `json:"outTrunkgroupLabel,omitempty"`
	InTrunkgroupLabel  string `json:"inTrunkgroupLabel,omitempty"`
	CallOrigin         string `json:"callOrigin,omitempty"`
	CallType           string `json:"callType,omitempty"`
	NASPort            string `json:"nasPort,omitempty"`
	NASPortType        string `json:"nasPortType,omitempty"`
	FramedIPAddress    string `json:"framedIpAddress,omitempty"`
}

type TimelineEvent struct {
	TS              time.Time  `json:"ts"`
	Phase           string     `json:"phase"`
	RadiusType      string     `json:"radiusType"`
	XpgkRequestType string     `json:"xpgkRequestType,omitempty"`
	AcctStatusType  string     `json:"acctStatusType,omitempty"`
	Decision        string     `json:"decision,omitempty"`
	Summary         string     `json:"summary"`
	PacketID        uuid.UUID  `json:"packetId"`
}

type AntifraudCallRow struct {
	CallID              uuid.UUID         `json:"callId"`
	FirstSeenAt         time.Time         `json:"firstSeenAt"`
	LastSeenAt          time.Time         `json:"lastSeenAt"`
	AcctSessionID       string            `json:"acctSessionId"`
	AcctSessionIDs      []string          `json:"acctSessionIds,omitempty"`
	H323ConfID          string            `json:"h323ConfId"`
	Calling             string            `json:"calling"`
	Called              string            `json:"called"`
	Status              string            `json:"status"`
	RadiusOutcome       string            `json:"radiusOutcome"`
	Phases              []string          `json:"phases"`
	PacketCount         uint64            `json:"packetCount"`
	ExplanationCodes    []string          `json:"explanationCodes"`
	Coverage            CoverageSummary   `json:"coverage"`
	ChainCompleteness   ChainCompleteness `json:"chainCompleteness"`
	SortTime            time.Time         `json:"-"`
	storedCoverageState string            `json:"-"`
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
	RecordID               uuid.UUID  `json:"recordId"`
	SetupTime              *time.Time `json:"setupTime,omitempty"`
	ConnectTime            *time.Time `json:"connectTime,omitempty"`
	DisconnectTime         *time.Time `json:"disconnectTime,omitempty"`
	DurationMS             *uint64    `json:"durationMs,omitempty"`
	ReleaseCause           *uint16    `json:"releaseCause,omitempty"`
	ReleaseInfo            string     `json:"releaseInfo,omitempty"`
	IncomingCgPN           string     `json:"incomingCgpn,omitempty"`
	OutgoingCgPN           string     `json:"outgoingCgpn,omitempty"`
	IncomingCdPN           string     `json:"incomingCdpn,omitempty"`
	OutgoingCdPN           string     `json:"outgoingCdpn,omitempty"`
	IncomingDescription    string     `json:"incomingDescription,omitempty"`
	OutgoingDescription    string     `json:"outgoingDescription,omitempty"`
	RadiusSessionID        string     `json:"radiusSessionId,omitempty"`
	UniqueTag              string     `json:"uniqueTag,omitempty"`
	SourceTimezone         string     `json:"sourceTimezone,omitempty"`
	VoipmonitorCDRID       string     `json:"voipmonitorCdrId,omitempty"`
	VoipmonitorCallID      string     `json:"voipmonitorCallId,omitempty"`
	VoipmonitorCardURL     string     `json:"voipmonitorCardUrl,omitempty"`
	VoipmonitorMatchStatus string     `json:"voipmonitorMatchStatus,omitempty"`
	VoipmonitorMatchMethod string     `json:"voipmonitorMatchMethod,omitempty"`
	VoipmonitorMatchScore  uint8      `json:"voipmonitorMatchScore,omitempty"`
}

type AntifraudCallDetail struct {
	AntifraudCallRow
	SnapshotID             uuid.UUID           `json:"-"`
	ContractKey            string              `json:"-"`
	Participants           CallParticipants    `json:"participants"`
	RequestTypes           []string            `json:"requestTypes,omitempty"`
	IndicationAcked        bool                `json:"indicationAcked"`
	VerificationResult     string              `json:"verificationResult,omitempty"`
	AccountingAcked        bool                `json:"accountingAcked"`
	FinalDecision          string              `json:"finalDecision,omitempty"`
	DurationSec            *int64              `json:"durationSec,omitempty"`
	DisconnectCauseQ850    *int64              `json:"disconnectCauseQ850,omitempty"`
	Timeline               []TimelineEvent     `json:"timeline"`
	Accounting             CallAccounting      `json:"accounting"`
	Routing                CallRouting         `json:"routing,omitempty"`
	AccountingStart        *time.Time          `json:"accountingStart,omitempty"`
	AccountingStop         *time.Time          `json:"accountingStop,omitempty"`
	SessionDurationSeconds *int64              `json:"sessionDurationSeconds,omitempty"`
	Attributes             []OrderedAttribute  `json:"attributes"`
	Unmatched              any                 `json:"unmatched,omitempty"`
	OrphanPacketIDs        []uuid.UUID         `json:"orphanPacketIds"`
	Packets                []AntifraudPacket   `json:"packets"`
	RawPackets             []AntifraudPacket   `json:"rawPackets"`
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
	const maxPage = 1000
	if limit == 0 || limit > maxPage {
		limit = 100
	}
	query := `SELECT call.call_id,call.first_seen_at,call.last_seen_at,call.acct_session_id,
		call.acct_session_ids,call.h323_conf_id,call.calling,call.called,call.status,call.coverage_state,call.explanation_codes,
		ifNull(packet_summary.families,[]),ifNull(packet_summary.packet_count,0),
		ifNull(packet_summary.unpaired,0),ifNull(packet_summary.fallback,0),
		ifNull(packet_summary.rejects,0),ifNull(packet_summary.accepts,0),
		ifNull(assignment.method,''),ifNull(assignment.reason,''),assignment.delta_ms,
		ifNull(assignment.ambiguous,0),ifNull(assignment.ambiguity_reason,''),
		ifNull(assignment.evidence,'{}'),ifNull(assignment.cdr_ids,[])
		FROM collector.custom_antifraud_calls_current call
		LEFT JOIN (
			SELECT device_id,call_id,any(method) method,any(reason) reason,any(delta_ms) delta_ms,
				max(ambiguous) ambiguous,any(ambiguity_reason) ambiguity_reason,
				any(matched_evidence_json) evidence,groupUniqArray(cdr_id) cdr_ids
			FROM collector.cdr_antifraud_assignments_current
			WHERE device_id=? GROUP BY device_id,call_id
		) assignment ON assignment.device_id=call.device_id AND assignment.call_id=call.call_id
		LEFT JOIN (
			SELECT links.device_id,links.snapshot_id,links.call_id,
				groupUniqArray(packet.family) families,count() packet_count,
				countIf(packet.direction='request' AND packet.status IN ('pending','orphan','ambiguous')) unpaired,
				countIf(packet.decision='unavailable_fallback') fallback,
				countIf(lower(packet.decision)='deny' OR lower(packet.radius_type)='access-reject') rejects,
				countIf(lower(packet.decision)='allow'
					OR lower(packet.radius_type) IN ('access-accept','access-response')) accepts
			FROM collector.custom_antifraud_call_packets_current links
			INNER JOIN collector.custom_radius_packets_current packet
				ON packet.device_id=links.device_id AND packet.snapshot_id=links.snapshot_id
				AND packet.packet_id=links.packet_id
			WHERE links.deleted=0 AND links.device_id=?
			GROUP BY links.device_id,links.snapshot_id,links.call_id
		) packet_summary ON packet_summary.device_id=call.device_id
			AND packet_summary.snapshot_id=call.snapshot_id AND packet_summary.call_id=call.call_id
		WHERE call.device_id=?`
	args := []any{deviceID, deviceID, deviceID}
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
	items := make([]AntifraudCallRow, 0, maxPage+1)
	now := time.Now().UTC()
	for rows.Next() {
		var item AntifraudCallRow
		var evidence string
		var families []string
		var unpaired, fallback, rejects, accepts uint64
		if err := rows.Scan(
			&item.CallID, &item.FirstSeenAt, &item.LastSeenAt, &item.AcctSessionID,
			&item.AcctSessionIDs, &item.H323ConfID, &item.Calling, &item.Called, &item.Status,
			&item.storedCoverageState, &item.ExplanationCodes, &families, &item.PacketCount,
			&unpaired, &fallback, &rejects, &accepts,
			&item.Coverage.Method, &item.Coverage.Reason, &item.Coverage.DeltaMS,
			&item.Coverage.Ambiguous, &item.Coverage.AmbiguityReason, &evidence,
			&item.Coverage.LinkedCDRIDs,
		); err != nil {
			return AntifraudCallPage{}, err
		}
		item.SortTime = item.FirstSeenAt
		item.Phases = orderedFamilies(families)
		item.RadiusOutcome = radiusOutcomeFromSummary(rejects > 0, accepts > 0)
		item.ChainCompleteness = chainCompletenessFromSummary(item.Phases, unpaired, fallback, item.Status)
		item.Coverage.State = deriveAFCoverageState(len(item.Coverage.LinkedCDRIDs) > 0,
			item.Coverage.Ambiguous, item.FirstSeenAt, now)
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
	err = c.Conn.QueryRow(ctx, `SELECT call.snapshot_id,call.contract_key,call.call_id,call.first_seen_at,call.last_seen_at,call.acct_session_id,
		call.acct_session_ids,call.h323_conf_id,call.calling,call.called,call.status,call.coverage_state,call.explanation_codes,call.accounting_start,call.accounting_stop,
		call.session_duration_seconds,call.ordered_attributes_json,call.unmatched_provenance_json,call.orphan_packet_ids
		FROM collector.custom_antifraud_calls AS call FINAL
		INNER JOIN (
			SELECT device_id,bucket_start,argMax(snapshot_id,projection_seq) AS snapshot_id,
				argMax(marker,projection_seq) AS marker
			FROM collector.custom_projection_state
			WHERE device_id=?
			GROUP BY device_id,bucket_start
		) AS state ON state.device_id=call.device_id AND state.bucket_start=call.bucket_start
			AND state.snapshot_id=call.snapshot_id
		WHERE call.device_id=? AND call.call_id=? AND call.deleted=0 AND state.marker='active'
		LIMIT 1`,
		deviceID, deviceID, callID).Scan(
		&detail.SnapshotID, &detail.ContractKey, &detail.CallID, &detail.FirstSeenAt,
		&detail.LastSeenAt, &detail.AcctSessionID, &detail.AcctSessionIDs,
		&detail.H323ConfID, &detail.Calling, &detail.Called, &detail.Status,
		&detail.storedCoverageState, &detail.ExplanationCodes, &detail.AccountingStart, &detail.AccountingStop,
		&detail.SessionDurationSeconds, &attributes, &unmatched, &detail.OrphanPacketIDs,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return detail, ErrAntifraudCallNotFound
		}
		return detail, err
	}
	detail.SortTime = detail.FirstSeenAt
	detail.Attributes = safeOrderedAttributes(attributes)
	detail.Unmatched = safeJSONValue(unmatched)
	// Keep the call shell visible when dense-SMG packet/CDR enrichment fails;
	// list→card previously mapped every secondary error to a false "not found".
	if err := c.loadAntifraudPackets(ctx, deviceID, callID, &detail); err != nil {
		detail.Warnings = append(detail.Warnings,
			"packets unavailable: "+redact.Text(err.Error()))
	}
	if err := c.loadAntifraudExchanges(ctx, deviceID, &detail); err != nil {
		detail.Warnings = append(detail.Warnings,
			"exchanges unavailable: "+redact.Text(err.Error()))
	}
	if err := c.loadCallCoverage(ctx, deviceID, callID, &detail.Coverage); err != nil {
		detail.Warnings = append(detail.Warnings,
			"coverage unavailable: "+redact.Text(err.Error()))
	} else {
		detail.Coverage.State = deriveAFCoverageState(len(detail.Coverage.LinkedCDRIDs) > 0,
			detail.Coverage.Ambiguous, detail.FirstSeenAt, time.Now().UTC())
		if len(detail.Coverage.LinkedCDRIDs) > 0 {
			detail.LinkedCDRs, err = c.loadCDRFacts(ctx, deviceID, detail.Coverage.LinkedCDRIDs)
			if err != nil {
				detail.Warnings = append(detail.Warnings,
					"linked CDR unavailable: "+redact.Text(err.Error()))
				detail.LinkedCDRs = nil
			}
		}
	}
	enrichAntifraudDetail(&detail)
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
		WHERE links.device_id=? AND links.snapshot_id=? AND links.call_id=? AND links.deleted=0
		ORDER BY links.packet_order LIMIT ?`, deviceID, detail.SnapshotID, callID, maxCallDetailPackets+1)
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
	families := make([]string, 0, len(detail.Packets))
	packetIDs := make([]uuid.UUID, 0, len(detail.Packets))
	for index := range detail.Packets {
		packet := &detail.Packets[index]
		families = append(families, packet.Family)
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
	detail.Phases = orderedFamilies(families)
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
			// Keep CDR facts + matched coverage visible when AF detail fails.
			if card.Coverage.Reason == "" {
				card.Coverage.Reason = "antifraud_detail_unavailable"
			} else if !strings.Contains(card.Coverage.Reason, "antifraud_detail_unavailable") {
				card.Coverage.Reason = card.Coverage.Reason + ";antifraud_detail_unavailable"
			}
			return card, nil
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	links, err := c.loadVoipmonitorLinkMap(ctx, deviceID, "eltex_smg", ids)
	if err != nil {
		return nil, err
	}
	for index := range result {
		if link, ok := links[result[index].RecordID]; ok {
			result[index].VoipmonitorCDRID = link.VoipmonitorCDRID
			result[index].VoipmonitorCallID = link.VoipmonitorCallID
			result[index].VoipmonitorCardURL = link.VoipmonitorCardURL
			result[index].VoipmonitorMatchStatus = link.MatchStatus
			result[index].VoipmonitorMatchMethod = link.MatchMethod
			result[index].VoipmonitorMatchScore = link.MatchScore
		}
	}
	return result, nil
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

func orderedFamilies(families []string) []string {
	order := []string{"indication", "verification", "accounting"}
	seen := map[string]struct{}{}
	for _, family := range families {
		family = strings.ToLower(strings.TrimSpace(family))
		if family == "" || family == "unknown" {
			continue
		}
		seen[family] = struct{}{}
	}
	result := make([]string, 0, len(order))
	for _, family := range order {
		if _, ok := seen[family]; ok {
			result = append(result, family)
		}
	}
	return result
}

func deriveAFCoverageState(matched, ambiguous bool, firstSeen, now time.Time) string {
	if matched {
		return "matched"
	}
	if ambiguous {
		return "ambiguous"
	}
	age := now.Sub(firstSeen)
	switch {
	case age < 5*time.Minute:
		return "awaiting_cdr"
	case age < 10*time.Minute:
		return "expected"
	case age < 30*time.Minute:
		return "late"
	default:
		return "missing"
	}
}

func radiusOutcomeFromSummary(hasReject, hasAccept bool) string {
	switch {
	case hasReject:
		return "reject"
	case hasAccept:
		return "accept"
	default:
		return "no_response"
	}
}

func radiusOutcomeFromPackets(packets []AntifraudPacket) string {
	var hasReject, hasAccept bool
	for _, packet := range packets {
		radiusType := strings.ToLower(packet.RadiusType)
		decision := strings.ToLower(packet.Decision)
		if decision == "deny" || radiusType == "access-reject" {
			hasReject = true
		}
		if decision == "allow" || radiusType == "access-accept" || radiusType == "access-response" {
			hasAccept = true
		}
	}
	return radiusOutcomeFromSummary(hasReject, hasAccept)
}

func chainCompletenessFromSummary(
	phases []string, unpaired, fallback uint64, status string,
) ChainCompleteness {
	has := map[string]bool{}
	for _, phase := range phases {
		has[phase] = true
	}
	missing := make([]string, 0, 3)
	for _, stage := range []string{"indication", "verification", "accounting"} {
		if !has[stage] {
			missing = append(missing, stage)
		}
	}
	completeness := ChainCompleteness{MissingStages: missing}
	switch {
	case len(missing) == 0 && unpaired == 0 && fallback == 0:
		completeness.State = "complete"
	case len(phases) == 0 || (len(phases) == 1 && unpaired > 0):
		completeness.State = "minimal"
	default:
		completeness.State = "partial"
	}
	if unpaired > 0 {
		completeness.MissingResponses = append(completeness.MissingResponses, "unpaired_requests")
		completeness.Notes = append(completeness.Notes, "есть запросы без ответа")
	}
	if fallback > 0 || status == "unavailable_fallback" {
		completeness.Notes = append(completeness.Notes, "сработал unavailable_fallback")
	}
	return completeness
}

func enrichAntifraudDetail(detail *AntifraudCallDetail) {
	detail.Participants = CallParticipants{
		CallingNumber: detail.Calling, CalledNumber: detail.Called,
	}
	detail.Accounting = CallAccounting{
		SetupTime: detail.AccountingStart, DisconnectTime: detail.AccountingStop,
		SessionTimeSec: detail.SessionDurationSeconds,
	}
	detail.Timeline = buildTimeline(detail.Packets)
	detail.RawPackets = detail.Packets
	requestTypes := map[string]struct{}{}
	var unpaired, fallback uint64
	var hasCheck, sawAccept, sawReject, sawUnavailable, sawAmbiguous bool
	for _, packet := range detail.Packets {
		if packet.Direction == "request" &&
			(packet.Status == "pending" || packet.Status == "orphan" || packet.Status == "ambiguous") {
			unpaired++
		}
		if packet.Decision == "unavailable_fallback" {
			fallback++
		}
		requestType := attributeString(packet.Attributes, "xpgk-request-type")
		if requestType != "" {
			requestTypes[requestType] = struct{}{}
		}
		family := strings.ToLower(packet.Family)
		isVerification := family == "verification" || requestType == "check_call"
		isIndication := family == "indication" || requestType == "number" || requestType == "save_call"
		if isIndication && (packet.Status == "paired" || packet.Decision == "info_only" ||
			packet.RadiusType == "access-accept" || packet.RadiusType == "access-response") {
			detail.IndicationAcked = true
		}
		if family == "accounting" && (packet.Status == "paired" || packet.Direction == "response") {
			detail.AccountingAcked = true
		}
		if isVerification {
			hasCheck = true
			if packet.Status == "ambiguous" {
				sawAmbiguous = true
			}
			switch packet.Decision {
			case "deny":
				sawReject = true
			case "allow":
				sawAccept = true
			case "unavailable_fallback":
				sawUnavailable = true
			}
			if packet.Direction == "request" &&
				(packet.Status == "pending" || packet.Decision == "unavailable_fallback") {
				sawUnavailable = true
			}
		}
		if cause := attributeString(packet.Attributes, "acct-terminate-cause"); cause != "" {
			detail.Accounting.DisconnectCause = cause
		}
		if delay := attributeInt64(packet.Attributes, "acct-delay-time"); delay != nil {
			detail.Accounting.DelayTimeSec = delay
		}
		if setup := attributeTime(packet.Attributes, "h323-setup-time"); setup != nil {
			detail.Accounting.SetupTime = setup
		}
		if connect := attributeTime(packet.Attributes, "h323-connect-time"); connect != nil {
			detail.Accounting.ConnectTime = connect
		}
		if disconnect := attributeTime(packet.Attributes, "h323-disconnect-time"); disconnect != nil {
			detail.Accounting.DisconnectTime = disconnect
		}
		if eventTS := attributeTime(packet.Attributes, "event-timestamp"); eventTS != nil {
			detail.Accounting.EventTimestamp = eventTS
		}
		if q850 := attributeQ850(packet.Attributes, "h323-disconnect-cause"); q850 != nil {
			detail.Accounting.DisconnectCauseQ850 = q850
			detail.DisconnectCauseQ850 = q850
		}
		if session := attributeInt64(packet.Attributes, "acct-session-time"); session != nil {
			detail.Accounting.SessionTimeSec = session
			detail.SessionDurationSeconds = session
		}
		fillRouting(&detail.Routing, packet.Attributes)
	}
	for requestType := range requestTypes {
		detail.RequestTypes = append(detail.RequestTypes, requestType)
	}
	sort.Strings(detail.RequestTypes)
	detail.DurationSec = detail.Accounting.SessionTimeSec
	if detail.DurationSec == nil {
		detail.DurationSec = detail.SessionDurationSeconds
	}
	switch {
	case !hasCheck:
		detail.VerificationResult = "absent"
		detail.FinalDecision = "not_applicable"
	case sawReject:
		detail.VerificationResult = "reject"
		detail.FinalDecision = "blocked"
	case sawUnavailable && !sawAccept:
		detail.VerificationResult = "no_response"
		detail.FinalDecision = "unavailable"
	case sawAccept:
		detail.VerificationResult = "accept"
		detail.FinalDecision = "allowed"
	case sawAmbiguous:
		detail.VerificationResult = "no_response"
		detail.FinalDecision = "unknown"
	default:
		detail.VerificationResult = "no_response"
		detail.FinalDecision = "unknown"
	}
	detail.RadiusOutcome = radiusOutcomeFromPackets(detail.Packets)
	detail.ChainCompleteness = chainCompletenessFromSummary(detail.Phases, unpaired, fallback, detail.Status)
}

func fillRouting(routing *CallRouting, attributes []OrderedAttribute) {
	set := func(dst *string, name string) {
		if *dst != "" {
			return
		}
		if value := attributeString(attributes, name); value != "" {
			*dst = value
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

func buildTimeline(packets []AntifraudPacket) []TimelineEvent {
	byID := make(map[uuid.UUID]AntifraudPacket, len(packets))
	ordered := append([]AntifraudPacket(nil), packets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].FirstSeenAt.Equal(ordered[j].FirstSeenAt) {
			return ordered[i].PacketID.String() < ordered[j].PacketID.String()
		}
		return ordered[i].FirstSeenAt.Before(ordered[j].FirstSeenAt)
	})
	for _, packet := range ordered {
		byID[packet.PacketID] = packet
	}
	usedResponses := map[uuid.UUID]struct{}{}
	events := make([]TimelineEvent, 0, len(ordered))
	for _, packet := range ordered {
		if packet.Direction != "request" {
			continue
		}
		phase := timelinePhase(packet)
		xpgk := attributeString(packet.Attributes, "xpgk-request-type")
		acct := attributeString(packet.Attributes, "acct-status-type")
		responseLabel := ""
		decision := packet.Decision
		if packet.ResponseID != nil {
			if response, ok := byID[*packet.ResponseID]; ok {
				usedResponses[*packet.ResponseID] = struct{}{}
				responseLabel = displayRadiusType(response.RadiusType)
				if response.Decision != "" {
					decision = response.Decision
				}
			}
		}
		summary := ""
		switch {
		case xpgk != "":
			summary = xpgk
		case acct != "":
			summary = acct
		default:
			summary = displayRadiusType(packet.RadiusType)
		}
		if responseLabel != "" {
			summary += " -> " + responseLabel
		} else if packet.Status == "pending" || decision == "unavailable_fallback" {
			summary += " -> no_response"
		}
		events = append(events, TimelineEvent{
			TS: packet.FirstSeenAt, Phase: phase, RadiusType: packet.RadiusType,
			XpgkRequestType: xpgk, AcctStatusType: acct, Decision: decision,
			Summary: summary, PacketID: packet.PacketID,
		})
	}
	for _, packet := range ordered {
		if packet.Direction != "response" {
			continue
		}
		if _, used := usedResponses[packet.PacketID]; used {
			continue
		}
		phase := timelinePhase(packet)
		events = append(events, TimelineEvent{
			TS: packet.FirstSeenAt, Phase: phase, RadiusType: packet.RadiusType,
			Decision: packet.Decision, Summary: displayRadiusType(packet.RadiusType) + " (orphan)",
			PacketID: packet.PacketID,
		})
	}
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].TS.Equal(events[j].TS) {
			return events[i].PacketID.String() < events[j].PacketID.String()
		}
		return events[i].TS.Before(events[j].TS)
	})
	return events
}

func displayRadiusType(radiusType string) string {
	switch strings.ToLower(radiusType) {
	case "access-request":
		return "Access-Request"
	case "access-accept", "access-response":
		// Eltex Custom often logs a generic Access-Response for Accept.
		return "Access-Accept"
	case "access-reject":
		return "Access-Reject"
	case "accounting-request":
		return "Accounting-Request"
	case "accounting-response":
		return "Accounting-Response"
	default:
		if radiusType == "" {
			return "RADIUS"
		}
		return radiusType
	}
}

func timelinePhase(packet AntifraudPacket) string {
	switch strings.ToLower(packet.Family) {
	case "indication", "verification", "accounting":
		return strings.ToLower(packet.Family)
	default:
		if strings.HasPrefix(strings.ToLower(packet.RadiusType), "accounting") {
			return "accounting"
		}
		return "unknown"
	}
}

func attributeString(attributes []OrderedAttribute, name string) string {
	want := strings.ToLower(name)
	for _, attribute := range attributes {
		if strings.ToLower(attribute.Name) == want {
			switch typed := attribute.Value.(type) {
			case string:
				return typed
			default:
				encoded, _ := json.Marshal(typed)
				return strings.Trim(string(encoded), `"`)
			}
		}
	}
	return ""
}

func attributeInt64(attributes []OrderedAttribute, name string) *int64 {
	raw := strings.TrimSpace(attributeString(attributes, name))
	if raw == "" {
		return nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil
	}
	return &value
}

func attributeQ850(attributes []OrderedAttribute, name string) *int64 {
	raw := strings.TrimSpace(attributeString(attributes, name))
	if raw == "" {
		return nil
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(raw), "0x") {
		raw = raw[2:]
		base = 16
	}
	value, err := strconv.ParseInt(raw, base, 64)
	if err != nil || value < 0 {
		return nil
	}
	return &value
}

func attributeTime(attributes []OrderedAttribute, name string) *time.Time {
	raw := strings.TrimSpace(attributeString(attributes, name))
	if raw == "" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339, "Jan 2 2006 15:04:05 MST",
		"2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05",
	} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return &parsed
		}
	}
	return nil
}
