package analytics

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type AntifraudTransaction struct {
	TransactionID           uuid.UUID
	DeviceID                uuid.UUID
	UpdatedAt               time.Time
	FirstEventAt            time.Time
	LastEventAt             time.Time
	CallContext             string
	AcctSessionID           string
	AcctSessionIDNormalized string
	PacketIdentifier        *uint8
	RequestType             string
	RequestCode             string
	ResponseCode            string
	Decision                string
	DecisionReason          string
	ServerAddress           string
	Retries                 uint16
	LatencyMS               *uint32
	CallingStationID        string
	CalledStationID         string
	SrcNumberIn             string
	DstNumberIn             string
	SrcNumberOut            string
	DstNumberOut            string
	InTrunkgroupLabel       string
	OutTrunkgroupLabel      string
	AccountingStatus        string
	Q850Cause               *uint16
	IsAntifraud             uint8
	Completeness            string
	Attributes              map[string]string
	RawEventIDs             []uuid.UUID
	ParserVersion           string
}

type AntifraudRow struct {
	TransactionID      uuid.UUID         `json:"transactionId"`
	FirstEventAt       time.Time         `json:"firstEventAt"`
	LastEventAt        time.Time         `json:"lastEventAt"`
	CallContext        string            `json:"callContext"`
	AcctSessionID      string            `json:"acctSessionId"`
	RequestType        string            `json:"requestType"`
	RequestCode        string            `json:"requestCode"`
	ResponseCode       string            `json:"responseCode"`
	Decision           string            `json:"decision"`
	DecisionReason     string            `json:"decisionReason"`
	ServerAddress      string            `json:"serverAddress"`
	Retries            uint16            `json:"retries"`
	LatencyMS          *uint32           `json:"latencyMs"`
	CallingStationID   string            `json:"callingStationId"`
	CalledStationID    string            `json:"calledStationId"`
	SrcNumberIn        string            `json:"srcNumberIn"`
	DstNumberIn        string            `json:"dstNumberIn"`
	SrcNumberOut       string            `json:"srcNumberOut"`
	DstNumberOut       string            `json:"dstNumberOut"`
	InTrunkgroupLabel  string            `json:"inTrunkgroupLabel"`
	OutTrunkgroupLabel string            `json:"outTrunkgroupLabel"`
	AccountingStatus   string            `json:"accountingStatus"`
	Q850Cause          *uint16           `json:"q850Cause"`
	Completeness       string            `json:"completeness"`
	Attributes         map[string]string `json:"attributes"`
	LinkedRecordIDs    []uuid.UUID       `json:"linkedRecordIds"`
	LegCount           uint64            `json:"legCount"`
}

type AntifraudCursor struct {
	LastEventAt   time.Time
	TransactionID uuid.UUID
}

type AntifraudPage struct {
	Items   []AntifraudRow
	HasMore bool
}

type ReplaySyslogRow struct {
	EventID    uuid.UUID
	DeviceID   uuid.UUID
	ReceivedAt time.Time
	SourceIP   net.IP
	SourcePort uint16
	Payload    []byte
}

func (c *Client) ProcessSyslogDerived(ctx context.Context, event SyslogEvent) error {
	if event.Category == "radius" {
		if err := c.processRadiusEvent(ctx, event); err != nil {
			return err
		}
	}
	return c.correlateExactProtocolEvent(ctx, event)
}

func (c *Client) InsertRadiusAndCorrelate(ctx context.Context, event SyslogEvent) error {
	return c.processRadiusEvent(ctx, event)
}

func (c *Client) processRadiusEvent(ctx context.Context, event SyslogEvent) error {
	occurredAt := event.ReceivedAt
	if event.EventTime != nil {
		occurredAt = *event.EventTime
	}
	transactionID := antifraudTransactionID(event, occurredAt)
	packetIdentifier := parseUint8Attribute(event.Attributes["packet_identifier"])
	latency := parseUint32Attribute(event.Attributes["latency_ms"])
	delay := parseUint32Attribute(event.Attributes["acct_delay_time"])
	eventTimestamp := parseRadiusEventTimestamp(event.Attributes["event_timestamp"])
	q850 := parseUint16Attribute(event.Attributes["q850_cause"])
	retry := uint16(0)
	if parsed := parseUint16Attribute(event.Attributes["retry"]); parsed != nil {
		retry = *parsed
	}
	sessionID := event.Attributes["acct_session_id"]
	normalized := normalizeCorrelationValue(sessionID)
	requestType := strings.ToLower(event.Attributes["xpgk_request_type"])
	packetCode := strings.ToLower(event.Attributes["packet_code"])
	direction := event.Attributes["packet_direction"]
	result := event.Attributes["result"]
	if result == "" {
		switch packetCode {
		case "access-accept":
			result = "accept"
		case "access-reject":
			result = "reject"
		case "accounting-response":
			result = "complete"
		}
	}
	isAntifraud := requestType == "number" || requestType == "save_call" ||
		requestType == "check_call" || event.Attributes["is_antifraud"] == "true"
	completeness := "fragment"
	if packetCode != "" {
		completeness = "packet"
	}
	if err := c.Conn.Exec(ctx, `INSERT INTO collector.radius_events
		(event_id,device_id,transaction_id,call_context,is_antifraud,occurred_at,direction,
		 packet_code,packet_identifier,request_type,server_address,acct_session_id,
		 acct_session_id_normalized,calling_station_id,called_station_id,result,decision,
		 decision_reason,event_timestamp,acct_delay_seconds,accounting_status,completeness,
		 retry,latency_ms,attributes,raw_event_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		event.EventID, event.DeviceID, transactionID, event.Attributes["call_context"],
		boolToUInt8(isAntifraud), occurredAt, direction, packetCode, packetIdentifier,
		requestType, event.Attributes["server_address"], sessionID, normalized,
		event.Attributes["calling_station_id"], event.Attributes["called_station_id"],
		result, event.Attributes["decision"], event.Attributes["decision_reason"],
		eventTimestamp, delay, event.Attributes["accounting_status"], completeness,
		retry, latency, event.Attributes, event.EventID); err != nil {
		return err
	}

	c.antifraudMu.Lock()
	defer c.antifraudMu.Unlock()
	transaction := c.antifraudActive[transactionID]
	if transaction == nil {
		loaded, err := c.loadAntifraudTransaction(ctx, transactionID)
		if err != nil {
			return err
		}
		transaction = loaded
		if transaction == nil {
			transaction = &AntifraudTransaction{
				TransactionID: transactionID, DeviceID: event.DeviceID,
				FirstEventAt: occurredAt, Attributes: make(map[string]string),
				ParserVersion: SyslogParserVersion,
			}
		}
		c.antifraudActive[transactionID] = transaction
	}
	mergeAntifraudEvent(transaction, event, occurredAt, packetIdentifier, latency, retry, q850)
	if err := c.insertAntifraudTransaction(ctx, transaction); err != nil {
		return err
	}
	return c.linkAntifraudTransaction(ctx, transaction)
}

func mergeAntifraudEvent(
	transaction *AntifraudTransaction,
	event SyslogEvent,
	occurredAt time.Time,
	packetIdentifier *uint8,
	latency *uint32,
	retry uint16,
	q850 *uint16,
) {
	if transaction.FirstEventAt.IsZero() || occurredAt.Before(transaction.FirstEventAt) {
		transaction.FirstEventAt = occurredAt
	}
	if occurredAt.After(transaction.LastEventAt) {
		transaction.LastEventAt = occurredAt
	}
	transaction.UpdatedAt = time.Now().UTC()
	transaction.CallContext = prefer(transaction.CallContext, event.Attributes["call_context"])
	transaction.AcctSessionID = prefer(transaction.AcctSessionID, event.Attributes["acct_session_id"])
	transaction.AcctSessionIDNormalized = normalizeCorrelationValue(transaction.AcctSessionID)
	if packetIdentifier != nil {
		transaction.PacketIdentifier = packetIdentifier
	}
	transaction.RequestType = prefer(transaction.RequestType, strings.ToLower(event.Attributes["xpgk_request_type"]))
	packetCode := strings.ToLower(event.Attributes["packet_code"])
	if strings.HasSuffix(packetCode, "request") {
		transaction.RequestCode = packetCode
	} else if packetCode != "" {
		transaction.ResponseCode = packetCode
	}
	transaction.ServerAddress = prefer(transaction.ServerAddress, event.Attributes["server_address"])
	if retry > transaction.Retries {
		transaction.Retries = retry
	}
	if latency != nil {
		transaction.LatencyMS = latency
	}
	transaction.CallingStationID = prefer(transaction.CallingStationID, event.Attributes["calling_station_id"])
	transaction.CalledStationID = prefer(transaction.CalledStationID, event.Attributes["called_station_id"])
	transaction.SrcNumberIn = prefer(transaction.SrcNumberIn, event.Attributes["xpgk_src_number_in"])
	transaction.DstNumberIn = prefer(transaction.DstNumberIn, event.Attributes["xpgk_dst_number_in"])
	transaction.SrcNumberOut = prefer(transaction.SrcNumberOut, event.Attributes["xpgk_src_number_out"])
	transaction.DstNumberOut = prefer(transaction.DstNumberOut, event.Attributes["xpgk_dst_number_out"])
	transaction.InTrunkgroupLabel = prefer(transaction.InTrunkgroupLabel, event.Attributes["in_trunkgroup_label"])
	transaction.OutTrunkgroupLabel = prefer(transaction.OutTrunkgroupLabel, event.Attributes["out_trunkgroup_label"])
	transaction.AccountingStatus = prefer(transaction.AccountingStatus, event.Attributes["accounting_status"])
	if q850 != nil {
		transaction.Q850Cause = q850
	}
	for key, value := range event.Attributes {
		if value != "" {
			transaction.Attributes[key] = value
		}
	}
	transaction.RawEventIDs = appendUniqueUUID(transaction.RawEventIDs, event.EventID)
	transaction.IsAntifraud = boolToUInt8(
		transaction.IsAntifraud == 1 ||
			transaction.RequestType == "number" ||
			transaction.RequestType == "save_call" ||
			transaction.RequestType == "check_call" ||
			event.Attributes["is_antifraud"] == "true",
	)
	resolveAntifraudDecision(transaction, event)
	resolveAntifraudCompleteness(transaction)
}

func resolveAntifraudDecision(transaction *AntifraudTransaction, event SyslogEvent) {
	explicit := event.Attributes["decision"]
	if explicit == "timeout_fail_open" && transaction.RequestType != "check_call" {
		explicit = ""
	}
	if explicit != "" {
		transaction.Decision = explicit
	}
	if transaction.RequestType == "check_call" {
		switch {
		case transaction.ResponseCode == "access-accept":
			transaction.Decision = "accept"
			transaction.DecisionReason = "Access-Accept"
		case transaction.ResponseCode == "access-reject" ||
			event.Attributes["result"] == "reject":
			transaction.Decision = "reject"
			transaction.DecisionReason = "Access-Reject"
			if transaction.Q850Cause == nil {
				cause := uint16(21)
				transaction.Q850Cause = &cause
			}
		case explicit == "timeout_fail_open":
			transaction.DecisionReason = "RADIUS timeout, documented fail-open"
		}
	} else if (transaction.RequestType == "number" || transaction.RequestType == "save_call") &&
		transaction.ResponseCode != "" {
		transaction.Decision = "informational"
		transaction.DecisionReason = "registration response does not control call passage"
	}
}

func resolveAntifraudCompleteness(transaction *AntifraudTransaction) {
	switch {
	case transaction.IsAntifraud == 0:
		transaction.Completeness = "radius_only"
	case transaction.RequestType == "check_call" && transaction.Decision != "":
		transaction.Completeness = "complete"
	case (transaction.RequestType == "number" || transaction.RequestType == "save_call") &&
		transaction.ResponseCode != "":
		transaction.Completeness = "complete"
	case transaction.AccountingStatus == "complete":
		transaction.Completeness = "complete"
	default:
		transaction.Completeness = "incomplete"
	}
}

func (c *Client) loadAntifraudTransaction(
	ctx context.Context, transactionID uuid.UUID,
) (*AntifraudTransaction, error) {
	row := c.Conn.QueryRow(ctx, `SELECT transaction_id,device_id,updated_at,first_event_at,last_event_at,
		call_context,acct_session_id,acct_session_id_normalized,packet_identifier,request_type,
		request_code,response_code,decision,decision_reason,server_address,retries,latency_ms,
		calling_station_id,called_station_id,src_number_in,dst_number_in,src_number_out,dst_number_out,
		in_trunkgroup_label,out_trunkgroup_label,accounting_status,q850_cause,is_antifraud,
		completeness,attributes,raw_event_ids,parser_version
		FROM collector.antifraud_transactions FINAL WHERE transaction_id=? LIMIT 1`, transactionID)
	var result AntifraudTransaction
	if err := row.Scan(
		&result.TransactionID, &result.DeviceID, &result.UpdatedAt, &result.FirstEventAt,
		&result.LastEventAt, &result.CallContext, &result.AcctSessionID,
		&result.AcctSessionIDNormalized, &result.PacketIdentifier, &result.RequestType,
		&result.RequestCode, &result.ResponseCode, &result.Decision, &result.DecisionReason,
		&result.ServerAddress, &result.Retries, &result.LatencyMS, &result.CallingStationID,
		&result.CalledStationID, &result.SrcNumberIn, &result.DstNumberIn,
		&result.SrcNumberOut, &result.DstNumberOut, &result.InTrunkgroupLabel,
		&result.OutTrunkgroupLabel, &result.AccountingStatus, &result.Q850Cause,
		&result.IsAntifraud, &result.Completeness, &result.Attributes,
		&result.RawEventIDs, &result.ParserVersion,
	); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (c *Client) insertAntifraudTransaction(ctx context.Context, item *AntifraudTransaction) error {
	return c.Conn.Exec(ctx, `INSERT INTO collector.antifraud_transactions
		(transaction_id,device_id,updated_at,first_event_at,last_event_at,call_context,
		 acct_session_id,acct_session_id_normalized,packet_identifier,request_type,request_code,
		 response_code,decision,decision_reason,server_address,retries,latency_ms,
		 calling_station_id,called_station_id,src_number_in,dst_number_in,src_number_out,
		 dst_number_out,in_trunkgroup_label,out_trunkgroup_label,accounting_status,q850_cause,
		 is_antifraud,completeness,attributes,raw_event_ids,parser_version)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		item.TransactionID, item.DeviceID, item.UpdatedAt, item.FirstEventAt, item.LastEventAt,
		item.CallContext, item.AcctSessionID, item.AcctSessionIDNormalized, item.PacketIdentifier,
		item.RequestType, item.RequestCode, item.ResponseCode, item.Decision, item.DecisionReason,
		item.ServerAddress, item.Retries, item.LatencyMS, item.CallingStationID,
		item.CalledStationID, item.SrcNumberIn, item.DstNumberIn, item.SrcNumberOut,
		item.DstNumberOut, item.InTrunkgroupLabel, item.OutTrunkgroupLabel,
		item.AccountingStatus, item.Q850Cause, item.IsAntifraud, item.Completeness,
		item.Attributes, item.RawEventIDs, item.ParserVersion)
}

func (c *Client) linkAntifraudTransaction(ctx context.Context, item *AntifraudTransaction) error {
	if item.AcctSessionIDNormalized == "" || len(item.RawEventIDs) == 0 {
		return nil
	}
	if err := c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
		(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
		SELECT c.device_id,c.record_id,arrayJoin(?),'exact_acct_session',toFloat32(1.0),
			map('acct_session_id',c.radius_session_id_normalized),'smg-3.410-v5',now64(3)
		FROM collector.cdr_records c
		WHERE c.device_id=? AND c.radius_session_id_normalized=?`,
		item.RawEventIDs, item.DeviceID, item.AcctSessionIDNormalized); err != nil {
		return err
	}
	if item.CallContext == "" {
		return nil
	}
	return c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
		(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
		SELECT c.device_id,c.record_id,e.event_id,'call_context_transaction',toFloat32(0.98),
			map('call_context',?,'acct_session_id',?),'smg-3.410-v5',now64(3)
		FROM collector.cdr_records c
		CROSS JOIN collector.raw_syslog e
		WHERE c.device_id=? AND c.radius_session_id_normalized=?
			AND e.device_id=c.device_id AND e.attributes['call_context']=?`,
		item.CallContext, item.AcctSessionIDNormalized, item.DeviceID,
		item.AcctSessionIDNormalized, item.CallContext)
}

func (c *Client) correlateExactProtocolEvent(ctx context.Context, event SyslogEvent) error {
	occurredAt := event.ReceivedAt
	if event.EventTime != nil {
		occurredAt = *event.EventTime
	}
	if callContext := event.Attributes["call_context"]; callContext != "" {
		if err := c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
			(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
			SELECT c.device_id,c.record_id,?,'call_context_transaction',toFloat32(0.98),
				map('call_context',?,'acct_session_id',t.acct_session_id_normalized),
				'smg-3.410-v5',now64(3)
			FROM collector.antifraud_transactions AS t FINAL
			INNER JOIN collector.cdr_records c
				ON c.device_id=t.device_id
				AND c.radius_session_id_normalized=t.acct_session_id_normalized
			WHERE t.device_id=? AND t.call_context=?
				AND t.acct_session_id_normalized!=''`,
			event.EventID, callContext, event.DeviceID, callContext); err != nil {
			return err
		}
	}
	if callID := event.Attributes["sip_call_id"]; callID != "" {
		if err := c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
			(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
			SELECT device_id,record_id,?,'exact_sip_call_id',toFloat32(1.0),
				map('sip_call_id',?),'smg-3.410-v5',now64(3)
			FROM collector.cdr_records
			WHERE device_id=? AND (incoming_sip_call_id=? OR outgoing_sip_call_id=?)
				AND ? BETWEEN coalesce(setup_time,ingested_at)-INTERVAL 5 MINUTE
					AND coalesce(disconnect_time,setup_time,ingested_at)+INTERVAL 5 MINUTE`,
			event.EventID, callID, event.DeviceID, callID, callID, occurredAt); err != nil {
			return err
		}
	}
	if globalCallref := event.Attributes["global_callref"]; globalCallref != "" {
		return c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
			(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
			SELECT device_id,record_id,?,'exact_global_callref',toFloat32(1.0),
				map('global_callref',?),'smg-3.410-v5',now64(3)
			FROM collector.cdr_records WHERE device_id=? AND global_callref=?`,
			event.EventID, globalCallref, event.DeviceID, globalCallref)
	}
	return nil
}

func (c *Client) correlateCDRExactEvidence(ctx context.Context, record CDRRecord) error {
	for _, callID := range []string{record.IncomingSIPCallID, record.OutgoingSIPCallID} {
		if callID == "" {
			continue
		}
		if err := c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
			(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
			SELECT device_id,?,event_id,'exact_sip_call_id',toFloat32(1.0),
				map('sip_call_id',?),'smg-3.410-v5',now64(3)
			FROM collector.raw_syslog
			WHERE device_id=? AND attributes['sip_call_id']=?
				AND received_at BETWEEN coalesce(?,?)-INTERVAL 5 MINUTE
					AND coalesce(?,?,?)+INTERVAL 5 MINUTE`,
			record.RecordID, callID, record.DeviceID, callID, record.SetupTime,
			record.IngestedAt, record.DisconnectTime, record.SetupTime, record.IngestedAt); err != nil {
			return err
		}
	}
	if record.GlobalCallref != "" {
		if err := c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
			(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
			SELECT device_id,?,event_id,'exact_global_callref',toFloat32(1.0),
				map('global_callref',?),'smg-3.410-v5',now64(3)
			FROM collector.raw_syslog
			WHERE device_id=? AND attributes['global_callref']=?`,
			record.RecordID, record.GlobalCallref, record.DeviceID, record.GlobalCallref); err != nil {
			return err
		}
	}
	if record.RejectingRadiusServer != "" {
		if err := c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
			(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
			SELECT device_id,?,event_id,'cdr_radius_rejected',toFloat32(0.99),
				map('rejecting_radius_server',?),'smg-3.410-v5',now64(3)
			FROM collector.raw_syslog
			WHERE device_id=? AND category='radius'
				AND (attributes['server_address']=?
					OR positionCaseInsensitive(payload,?)>0)
				AND received_at BETWEEN coalesce(?,?)-INTERVAL 5 MINUTE
					AND coalesce(?,?,?)+INTERVAL 5 MINUTE`,
			record.RecordID, record.RejectingRadiusServer, record.DeviceID,
			record.RejectingRadiusServer, record.RejectingRadiusServer,
			record.SetupTime, record.IngestedAt, record.DisconnectTime,
			record.SetupTime, record.IngestedAt); err != nil {
			return err
		}
	}
	return c.insertCorrelationCandidates(ctx, record)
}

func (c *Client) insertCorrelationCandidates(ctx context.Context, record CDRRecord) error {
	if record.RadiusSessionIDNormalized != "" {
		return nil
	}
	numbers := []string{
		record.IncomingCgPN, record.OutgoingCgPN, record.IncomingCdPN, record.OutgoingCdPN,
	}
	hasNumber := false
	for _, number := range numbers {
		hasNumber = hasNumber || number != ""
	}
	if !hasNumber {
		return nil
	}
	return c.Conn.Exec(ctx, `INSERT INTO collector.call_correlation_candidates
		(device_id,cdr_record_id,transaction_id,method,confidence,ambiguity,
		 candidate_reason,evidence,created_at)
		SELECT device_id,?,transaction_id,'candidate_number_time',toFloat32(0.5),1,
			'number and time overlap are diagnostic only',
			map('incoming_cgpn',?,'outgoing_cgpn',?,'incoming_cdpn',?,
				'outgoing_cdpn',?,'call_context',call_context),now64(3)
		FROM collector.antifraud_transactions FINAL
		WHERE device_id=?
			AND last_event_at BETWEEN coalesce(?,?)-INTERVAL 5 MINUTE
				AND coalesce(?,?,?)+INTERVAL 5 MINUTE
			AND (
				(calling_station_id!='' AND calling_station_id IN (?,?,?,?))
				OR (called_station_id!='' AND called_station_id IN (?,?,?,?))
				OR (src_number_in!='' AND src_number_in IN (?,?,?,?))
				OR (dst_number_in!='' AND dst_number_in IN (?,?,?,?))
			)`,
		record.RecordID, numbers[0], numbers[1], numbers[2], numbers[3],
		record.DeviceID, record.SetupTime, record.IngestedAt, record.DisconnectTime,
		record.SetupTime, record.IngestedAt,
		numbers[0], numbers[1], numbers[2], numbers[3],
		numbers[0], numbers[1], numbers[2], numbers[3],
		numbers[0], numbers[1], numbers[2], numbers[3],
		numbers[0], numbers[1], numbers[2], numbers[3])
}

func (c *Client) ListAntifraudPage(
	ctx context.Context,
	deviceID uuid.UUID,
	search string,
	limit uint64,
	cursor *AntifraudCursor,
) (AntifraudPage, error) {
	if limit == 0 || limit > 50000 {
		limit = 200
	}
	query := `SELECT t.transaction_id,t.first_event_at,t.last_event_at,t.call_context,
		t.acct_session_id,t.request_type,t.request_code,t.response_code,t.decision,
		t.decision_reason,t.server_address,t.retries,t.latency_ms,t.calling_station_id,
		t.called_station_id,t.src_number_in,t.dst_number_in,t.src_number_out,t.dst_number_out,
		t.in_trunkgroup_label,t.out_trunkgroup_label,t.accounting_status,t.q850_cause,
		t.completeness,t.attributes,ifNull(c.record_ids,[]),ifNull(c.leg_count,0)
		FROM collector.antifraud_transactions AS t FINAL
		LEFT JOIN (
			SELECT device_id,radius_session_id_normalized,groupArray(record_id) AS record_ids,
				count() AS leg_count
			FROM collector.cdr_records
			GROUP BY device_id,radius_session_id_normalized
		) c ON c.device_id=t.device_id
			AND c.radius_session_id_normalized=t.acct_session_id_normalized
		WHERE t.device_id=? AND t.is_antifraud=1`
	args := []any{deviceID}
	if search != "" {
		query += ` AND (positionCaseInsensitive(t.acct_session_id,?)>0
			OR positionCaseInsensitive(t.calling_station_id,?)>0
			OR positionCaseInsensitive(t.called_station_id,?)>0
			OR positionCaseInsensitive(toString(t.attributes),?)>0)`
		for range 4 {
			args = append(args, search)
		}
	}
	if cursor != nil {
		query += ` AND (t.last_event_at < ? OR (t.last_event_at=? AND t.transaction_id<?))`
		args = append(args, cursor.LastEventAt, cursor.LastEventAt, cursor.TransactionID)
	}
	query += ` ORDER BY t.last_event_at DESC,t.transaction_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return AntifraudPage{}, err
	}
	defer rows.Close()
	items := make([]AntifraudRow, 0, limit)
	for rows.Next() {
		var item AntifraudRow
		if err := rows.Scan(
			&item.TransactionID, &item.FirstEventAt, &item.LastEventAt, &item.CallContext,
			&item.AcctSessionID, &item.RequestType, &item.RequestCode, &item.ResponseCode,
			&item.Decision, &item.DecisionReason, &item.ServerAddress, &item.Retries,
			&item.LatencyMS, &item.CallingStationID, &item.CalledStationID,
			&item.SrcNumberIn, &item.DstNumberIn, &item.SrcNumberOut, &item.DstNumberOut,
			&item.InTrunkgroupLabel, &item.OutTrunkgroupLabel, &item.AccountingStatus,
			&item.Q850Cause, &item.Completeness, &item.Attributes, &item.LinkedRecordIDs,
			&item.LegCount,
		); err != nil {
			return AntifraudPage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return AntifraudPage{}, err
	}
	hasMore := uint64(len(items)) > limit
	if hasMore {
		items = items[:limit]
	}
	return AntifraudPage{Items: items, HasMore: hasMore}, nil
}

func (c *Client) AntifraudTimeline(
	ctx context.Context, deviceID, transactionID uuid.UUID,
) ([]TimelineRow, error) {
	rows, err := c.Conn.Query(ctx, `SELECT e.event_id,e.received_at,e.category,e.component,
		e.message,e.payload,e.parse_status,e.attributes,'antifraud_transaction',toFloat32(1.0)
		FROM collector.antifraud_transactions AS t FINAL
		ARRAY JOIN t.raw_event_ids AS linked_event_id
		INNER JOIN collector.raw_syslog e
			ON e.device_id=t.device_id AND e.event_id=linked_event_id
		WHERE t.device_id=? AND t.transaction_id=?
		ORDER BY e.received_at,e.event_id`, deviceID, transactionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TimelineRow, 0)
	for rows.Next() {
		var item TimelineRow
		if err := rows.Scan(
			&item.EventID, &item.ReceivedAt, &item.Category, &item.Component,
			&item.Message, &item.RawPayload, &item.Status, &item.Attributes,
			&item.Method, &item.Confidence,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (c *Client) NextSyslogReplayBatch(
	ctx context.Context, parserVersion string, limit uint64,
) ([]ReplaySyslogRow, error) {
	rows, err := c.Conn.Query(ctx, `SELECT r.event_id,any(r.device_id),any(r.received_at),
		any(r.source_ip),any(r.source_port),any(r.payload)
		FROM collector.raw_syslog r
		LEFT JOIN collector.syslog_reprocess_ledger l
			ON l.event_id=r.event_id AND l.parser_version=?
		WHERE l.event_id=toUUID('00000000-0000-0000-0000-000000000000')
		GROUP BY r.event_id ORDER BY any(r.received_at) LIMIT ?`, parserVersion, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ReplaySyslogRow, 0, limit)
	for rows.Next() {
		var item ReplaySyslogRow
		var payload string
		if err := rows.Scan(
			&item.EventID, &item.DeviceID, &item.ReceivedAt, &item.SourceIP,
			&item.SourcePort, &payload,
		); err != nil {
			return nil, err
		}
		item.Payload = []byte(payload)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (c *Client) MarkSyslogReprocessed(
	ctx context.Context, eventID uuid.UUID, parserVersion string,
) error {
	return c.Conn.Exec(ctx, `INSERT INTO collector.syslog_reprocess_ledger
		(event_id,parser_version,processed_at) VALUES(?,?,now64(3))`, eventID, parserVersion)
}

func (c *Client) MarkSyslogReprocessedBatch(
	ctx context.Context, eventIDs []uuid.UUID, parserVersion string,
) error {
	if len(eventIDs) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.syslog_reprocess_ledger
		(event_id,parser_version,processed_at)`)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, eventID := range eventIDs {
		if err := batch.Append(eventID, parserVersion, now); err != nil {
			return err
		}
	}
	return batch.Send()
}

func antifraudTransactionID(event SyslogEvent, occurredAt time.Time) uuid.UUID {
	key := ""
	if contextValue := event.Attributes["call_context"]; contextValue != "" {
		key = "context:" + contextValue
	} else if session := normalizeCorrelationValue(event.Attributes["acct_session_id"]); session != "" {
		key = "session:" + session
	} else if requestID := event.Attributes["packet_identifier"]; requestID != "" {
		key = fmt.Sprintf("request:%s:%s", requestID, occurredAt.UTC().Truncate(10*time.Minute))
	} else {
		key = "event:" + event.EventID.String()
	}
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte(event.DeviceID.String()+"|"+occurredAt.UTC().Format("2006-01-02")+"|"+key))
}

func normalizeCorrelationValue(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), ""))
}

func parseUint8Attribute(value string) *uint8 {
	parsed, err := strconv.ParseUint(value, 10, 8)
	if err != nil {
		return nil
	}
	result := uint8(parsed)
	return &result
}

func parseUint16Attribute(value string) *uint16 {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return nil
	}
	result := uint16(parsed)
	return &result
}

func parseUint32Attribute(value string) *uint32 {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return nil
	}
	result := uint32(parsed)
	return &result
}

func parseRadiusEventTimestamp(value string) *time.Time {
	if value == "" {
		return nil
	}
	if epoch, err := strconv.ParseInt(value, 10, 64); err == nil {
		result := time.Unix(epoch, 0).UTC()
		return &result
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			result := parsed.UTC()
			return &result
		}
	}
	return nil
}

func prefer(current, candidate string) string {
	if candidate != "" {
		return candidate
	}
	return current
}

func appendUniqueUUID(values []uuid.UUID, candidate uuid.UUID) []uuid.UUID {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func boolToUInt8(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}
