package analytics

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrCallCDRNotFound = errors.New("call CDR not found")

type CallAntiFraudSummary struct {
	ProjectionStatus string                          `json:"projectionStatus"`
	ParserVersion    string                          `json:"parserVersion"`
	Building         bool                            `json:"building"`
	CDR              CallAntiFraudCDR                `json:"cdr"`
	Call             *CallAntiFraudIdentity          `json:"call,omitempty"`
	Operations       []CallAntiFraudSummaryOperation `json:"operations"`
	OverallStatus    string                          `json:"overallStatus"`
	Warnings         []string                        `json:"warnings"`
}

type CallAntiFraudCDR struct {
	RecordID            uuid.UUID  `json:"recordId"`
	SetupTime           *time.Time `json:"setupTime"`
	DurationMS          *uint64    `json:"durationMs"`
	Q850Cause           *uint16    `json:"q850Cause"`
	IncomingNumber      string     `json:"incomingNumber"`
	IncomingDestination string     `json:"incomingDestination"`
	OutgoingNumber      string     `json:"outgoingNumber"`
	OutgoingDestination string     `json:"outgoingDestination"`
	IncomingRoute       string     `json:"incomingRoute"`
	OutgoingRoute       string     `json:"outgoingRoute"`
	RadiusSessionID     string     `json:"radiusSessionId"`
}

type CallAntiFraudIdentity struct {
	CallID                  uuid.UUID `json:"callId"`
	IdentityKind            string    `json:"identityKind"`
	IdentityValue           string    `json:"identityValue"`
	H323ConfID              string    `json:"h323ConfId"`
	CallContexts            []string  `json:"callContexts"`
	LegSessionIDs           []string  `json:"legSessionIds"`
	LegSessionIDsNormalized []string  `json:"legSessionIdsNormalized"`
}

type CallAntiFraudSummaryOperation struct {
	OperationID         uuid.UUID         `json:"operationId"`
	OccurredAt          time.Time         `json:"occurredAt"`
	Type                string            `json:"type"`
	LegDirection        string            `json:"legDirection"`
	LegSessionID        string            `json:"legSessionId"`
	CallContext         string            `json:"callContext"`
	SrcNumberIn         string            `json:"srcNumberIn"`
	DstNumberIn         string            `json:"dstNumberIn"`
	SrcNumberOut        string            `json:"srcNumberOut"`
	DstNumberOut        string            `json:"dstNumberOut"`
	RequestIdentifier   *uint8            `json:"requestIdentifier"`
	RequestCode         string            `json:"requestCode"`
	ResponseIdentifier  *uint8            `json:"responseIdentifier"`
	ResponseCode        string            `json:"responseCode"`
	LatencyMS           *uint32           `json:"latencyMs"`
	Retries             uint16            `json:"retries"`
	TerminalState       string            `json:"terminalState"`
	TerminalReason      string            `json:"terminalReason"`
	CorrelationState    string            `json:"correlationState"`
	CorrelationMethod   string            `json:"correlationMethod"`
	CorrelationEvidence map[string]string `json:"correlationEvidence"`
}

func (c *Client) CallAntiFraudSummary(
	ctx context.Context, deviceID, recordID uuid.UUID,
) (CallAntiFraudSummary, error) {
	result := CallAntiFraudSummary{
		ParserVersion: SyslogParserVersion, OverallStatus: "neutral",
		Operations: []CallAntiFraudSummaryOperation{}, Warnings: []string{},
	}
	if err := c.Conn.QueryRow(ctx, `SELECT record_id,setup_time,duration_ms,release_cause,
			incoming_cgpn,incoming_cdpn,outgoing_cgpn,outgoing_cdpn,
			incoming_description,outgoing_description,radius_session_id
		FROM collector.cdr_records FINAL WHERE device_id=? AND record_id=? LIMIT 1`,
		deviceID, recordID).Scan(
		&result.CDR.RecordID, &result.CDR.SetupTime, &result.CDR.DurationMS,
		&result.CDR.Q850Cause, &result.CDR.IncomingNumber, &result.CDR.IncomingDestination,
		&result.CDR.OutgoingNumber, &result.CDR.OutgoingDestination,
		&result.CDR.IncomingRoute, &result.CDR.OutgoingRoute, &result.CDR.RadiusSessionID,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) ||
			strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return result, ErrCallCDRNotFound
		}
		return result, err
	}
	revision, err := c.ActiveDeviceRevision(ctx, deviceID)
	if err != nil {
		return result, err
	}
	if revision == 0 {
		revision = 1
	}
	active, err := c.hasOperationProjection(ctx, deviceID, revision)
	if err != nil {
		return result, err
	}
	if !active {
		result.ProjectionStatus = "building"
		result.Building = true
		result.Warnings = append(result.Warnings, "AntiFraud v16 projection is building")
		return result, nil
	}
	result.ProjectionStatus = "active"
	query := `WITH links AS
		(
			SELECT operation_id,
				latest.1 AS cdr_record_id,latest.2 AS state,latest.3 AS method,
				latest.4 AS reason,latest.5 AS delta
			FROM
			(
				SELECT operation_id,argMax(
					tuple(cdr_record_id,state,method,reason,time_delta_ms),
					tuple(updated_at,state,method,reason)
				) AS latest
				FROM collector.antifraud_operation_cdr_links
				WHERE device_id=? AND timezone_revision=? AND parser_version=?
				GROUP BY operation_id
			)
			WHERE latest.2='linked' AND latest.1 IS NOT NULL
		),
		packet_stats AS
		(
			SELECT operation_id,toUInt16(greatest(
				toInt64(max(retry)),
				greatest(toInt64(countIf(direction='request'))-1,0)
			)) AS retries
			FROM collector.current_antifraud_packets
			WHERE device_id=? AND timezone_revision=? AND parser_version=?
				AND operation_id IS NOT NULL
			GROUP BY operation_id
		)
		SELECT o.operation_id,o.first_event_at,o.operation_type,
			if(o.acct_session_id='',o.acct_session_id_normalized,o.acct_session_id),
			o.call_context,ifNull(req.attributes['xpgk_src_number_in'],''),
			ifNull(req.attributes['xpgk_dst_number_in'],''),
			ifNull(req.attributes['xpgk_src_number_out'],''),
			ifNull(req.attributes['xpgk_dst_number_out'],''),
			req.packet_identifier,ifNull(req.packet_code,''),resp.packet_identifier,
			ifNull(resp.packet_code,''),toUInt32OrNull(resp.attributes['latency_ms']),
			ifNull(ps.retries,0),o.terminal_state,o.terminal_reason,
			ifNull(l.state,'unlinked'),ifNull(l.method,''),ifNull(l.reason,''),
			ifNull(l.delta,0),ifNull(req.attributes['h323_call_origin'],''),
			c.call_id,c.identity_kind,c.identity_value,c.h323_conf_id,c.call_contexts,
			c.leg_session_ids,c.leg_session_ids_normalized
		FROM collector.current_antifraud_operations AS o
		INNER JOIN links AS l ON l.operation_id=o.operation_id AND l.cdr_record_id=?
		LEFT JOIN packet_stats AS ps ON ps.operation_id=o.operation_id
		LEFT JOIN collector.current_antifraud_packets AS req
		  ON req.device_id=o.device_id AND req.timezone_revision=o.timezone_revision
		 AND req.parser_version=o.parser_version AND req.packet_id=o.request_packet_id
		LEFT JOIN collector.current_antifraud_packets AS resp
		  ON resp.device_id=o.device_id AND resp.timezone_revision=o.timezone_revision
		 AND resp.parser_version=o.parser_version AND resp.packet_id=o.response_packet_id
		INNER JOIN collector.current_antifraud_calls AS c
		  ON c.device_id=o.device_id AND c.timezone_revision=o.timezone_revision
		 AND c.parser_version=o.parser_version AND c.call_id=o.call_id
		WHERE o.device_id=? AND o.timezone_revision=? AND o.parser_version=?
		ORDER BY o.first_event_at,o.occurrence,o.operation_id`
	rows, err := c.Conn.Query(ctx, query,
		deviceID, revision, SyslogParserVersion,
		deviceID, revision, SyslogParserVersion, recordID,
		deviceID, revision, SyslogParserVersion,
	)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var item CallAntiFraudSummaryOperation
		var reason, origin string
		var call CallAntiFraudIdentity
		var delta int64
		if err := rows.Scan(
			&item.OperationID, &item.OccurredAt, &item.Type, &item.LegSessionID,
			&item.CallContext, &item.SrcNumberIn, &item.DstNumberIn, &item.SrcNumberOut,
			&item.DstNumberOut, &item.RequestIdentifier, &item.RequestCode,
			&item.ResponseIdentifier, &item.ResponseCode, &item.LatencyMS, &item.Retries,
			&item.TerminalState, &item.TerminalReason, &item.CorrelationState,
			&item.CorrelationMethod, &reason, &delta, &origin, &call.CallID,
			&call.IdentityKind, &call.IdentityValue, &call.H323ConfID, &call.CallContexts,
			&call.LegSessionIDs, &call.LegSessionIDsNormalized,
		); err != nil {
			return result, err
		}
		item.LegDirection = antiFraudLegDirection(origin, item.CorrelationMethod)
		item.CorrelationEvidence = map[string]string{
			"method": item.CorrelationMethod, "reason": reason,
			"timeDeltaMs": strconv.FormatInt(delta, 10),
		}
		result.Call = &call
		result.Operations = append(result.Operations, item)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if len(result.Operations) == 0 {
		result.Warnings = append(result.Warnings, "No active v16 AntiFraud operations linked to this CDR")
	}
	result.OverallStatus, result.Warnings = callAntiFraudOverallStatus(
		result.Operations, result.Warnings,
	)
	return result, nil
}

func callAntiFraudOverallStatus(
	operations []CallAntiFraudSummaryOperation, warnings []string,
) (string, []string) {
	failOpen := false
	ambiguousResponse := false
	for _, operation := range operations {
		if operation.TerminalState == "verification_reject" {
			return "blocked", warnings
		}
		if operation.TerminalState == "verification_fail_open" {
			failOpen = true
		}
		if operation.TerminalState == "ambiguous_response" {
			ambiguousResponse = true
		}
	}
	if failOpen {
		return "fail_open", append(warnings, "Verification failed open; no block evidence")
	}
	if ambiguousResponse {
		warnings = append(warnings, "Ambiguous RADIUS response was not paired")
	}
	return "neutral", warnings
}

func antiFraudLegDirection(origin, method string) string {
	switch strings.ToLower(origin) {
	case "originate", "originating", "outbound":
		return "outbound"
	case "answer", "terminating", "inbound":
		return "inbound"
	}
	if method == "exact_h323_conf_id" {
		return "outbound"
	}
	if method == "exact_acct_session" {
		return "inbound"
	}
	return "unknown"
}
