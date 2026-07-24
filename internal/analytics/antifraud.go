package analytics

import (
	"context"
	"fmt"
	"net"
	"sort"
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
	TimezoneRevision        uint64
}

type AntifraudRow struct {
	TransactionID          uuid.UUID         `json:"transactionId"`
	FirstEventAt           time.Time         `json:"firstEventAt"`
	LastEventAt            time.Time         `json:"lastEventAt"`
	CallContext            string            `json:"callContext"`
	AcctSessionID          string            `json:"acctSessionId"`
	RequestType            string            `json:"requestType"`
	RequestCode            string            `json:"requestCode"`
	ResponseCode           string            `json:"responseCode"`
	Decision               string            `json:"decision"`
	DecisionReason         string            `json:"decisionReason"`
	ServerAddress          string            `json:"serverAddress"`
	Retries                uint16            `json:"retries"`
	LatencyMS              *uint32           `json:"latencyMs"`
	CallingStationID       string            `json:"callingStationId"`
	CalledStationID        string            `json:"calledStationId"`
	SrcNumberIn            string            `json:"srcNumberIn"`
	DstNumberIn            string            `json:"dstNumberIn"`
	SrcNumberOut           string            `json:"srcNumberOut"`
	DstNumberOut           string            `json:"dstNumberOut"`
	InTrunkgroupLabel      string            `json:"inTrunkgroupLabel"`
	OutTrunkgroupLabel     string            `json:"outTrunkgroupLabel"`
	AccountingStatus       string            `json:"accountingStatus"`
	Q850Cause              *uint16           `json:"q850Cause"`
	Completeness           string            `json:"completeness"`
	Attributes             map[string]string `json:"attributes"`
	LinkedRecordIDs        []uuid.UUID       `json:"linkedRecordIds"`
	LegCount               uint64            `json:"legCount"`
	CDRSetupTime           *time.Time        `json:"cdrSetupTime"`
	CorrelationMethod      string            `json:"correlationMethod"`
	CorrelationConfidence  float32           `json:"correlationConfidence"`
	CorrelationTimeDeltaMS int64             `json:"correlationTimeDeltaMs"`
	AmbiguityReason        string            `json:"ambiguityReason"`
	CDRSessionID           string            `json:"cdrSessionId"`
	CorrelationState       string            `json:"correlationState"`
	MatchedFields          []string          `json:"matchedFields"`
	SourceTimezone         string            `json:"sourceTimezone"`
	FirstEventLocal        string            `json:"firstEventLocal"`
	LastEventLocal         string            `json:"lastEventLocal"`
	CDRSetupLocal          string            `json:"cdrSetupLocal"`
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
	EventID        uuid.UUID
	DeviceID       uuid.UUID
	ReceivedAt     time.Time
	SourceIP       net.IP
	SourcePort     uint16
	Payload        []byte
	SourceTimezone string
	ReceivedAtUS   int64
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
	packetTransactionID := antifraudPacketTransactionID(event, occurredAt, transactionID)
	packetIdentifier := parseUint8Attribute(event.Attributes["packet_identifier"])
	latency := parseUint32Attribute(event.Attributes["latency_ms"])
	delay := parseUint32Attribute(event.Attributes["acct_delay_time"])
	eventTimestamp := parseRadiusEventTimestamp(
		event.Attributes["event_timestamp"], event.SourceTimezone,
	)
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
		(event_id,device_id,transaction_id,packet_transaction_id,call_context,is_antifraud,occurred_at,direction,
		 packet_code,packet_identifier,request_type,server_address,acct_session_id,
		 acct_session_id_normalized,calling_station_id,called_station_id,result,decision,
		 decision_reason,event_timestamp,acct_delay_seconds,accounting_status,completeness,
		 parser_version,retry,latency_ms,attributes,raw_event_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		event.EventID, event.DeviceID, transactionID, packetTransactionID,
		event.Attributes["call_context"],
		boolToUInt8(isAntifraud), occurredAt, direction, packetCode, packetIdentifier,
		requestType, event.Attributes["server_address"], sessionID, normalized,
		event.Attributes["calling_station_id"], event.Attributes["called_station_id"],
		result, event.Attributes["decision"], event.Attributes["decision_reason"],
		eventTimestamp, delay, event.Attributes["accounting_status"], completeness,
		SyslogParserVersion, retry, latency, event.Attributes, event.EventID); err != nil {
		return err
	}

	shard := &c.antifraudShards[int(transactionID[0])%len(c.antifraudShards)]
	shard.Lock()
	c.antifraudMu.Lock()
	transaction := c.antifraudActive[transactionID]
	c.antifraudMu.Unlock()
	shard.Unlock()
	if transaction == nil {
		loaded, err := c.loadAntifraudTransaction(ctx, transactionID)
		if err != nil {
			return err
		}
		shard.Lock()
		c.antifraudMu.Lock()
		transaction = c.antifraudActive[transactionID]
		if transaction == nil {
			transaction = loaded
			if transaction == nil {
				transaction = &AntifraudTransaction{
					TransactionID: transactionID, DeviceID: event.DeviceID,
					FirstEventAt: occurredAt, Attributes: make(map[string]string),
					ParserVersion: SyslogParserVersion,
				}
			}
			c.antifraudActive[transactionID] = transaction
			c.pruneAntifraudCacheLocked(transactionID)
		}
		c.antifraudMu.Unlock()
	} else {
		shard.Lock()
	}
	mergeAntifraudEvent(transaction, event, occurredAt, packetIdentifier, latency, retry, q850)
	snapshot := cloneAntifraudTransaction(transaction)
	shard.Unlock()
	if err := c.insertAntifraudTransaction(ctx, snapshot); err != nil {
		return err
	}
	return nil
}

func (c *Client) ProcessSyslogShadowDerived(ctx context.Context, event SyslogEvent) error {
	return c.ProcessSyslogShadowDerivedBatch(ctx, []SyslogEvent{event})
}

func (c *Client) ProcessSyslogShadowDerivedBatch(
	ctx context.Context, events []SyslogEvent,
) error {
	type fragment struct {
		event               SyslogEvent
		occurredAt          time.Time
		transactionID       uuid.UUID
		packetTransactionID uuid.UUID
		revision            uint64
	}
	fragments := make([]fragment, 0, len(events))
	for _, event := range events {
		if event.Category != "radius" {
			continue
		}
		occurredAt := event.ReceivedAt
		if event.EventTime != nil {
			occurredAt = *event.EventTime
		}
		revision := event.TimezoneRevision
		if revision == 0 {
			revision = 1
		}
		transactionID := antifraudTransactionID(event, occurredAt)
		fragments = append(fragments, fragment{
			event: event, occurredAt: occurredAt, transactionID: transactionID,
			packetTransactionID: antifraudPacketTransactionID(event, occurredAt, transactionID),
			revision:            revision,
		})
	}
	if len(fragments) == 0 {
		return nil
	}
	radiusBatch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.radius_fragments
		(device_id,timezone_revision,event_id,transaction_id,packet_transaction_id,
		 occurred_at,call_context,acct_session_id,packet_identifier,request_type,
		 packet_code,result,is_antifraud,attributes,inserted_at)`)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, item := range fragments {
		requestType := strings.ToLower(item.event.Attributes["xpgk_request_type"])
		packetCode := strings.ToLower(item.event.Attributes["packet_code"])
		result := item.event.Attributes["result"]
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
			requestType == "check_call" || item.event.Attributes["is_antifraud"] == "true"
		if err := radiusBatch.Append(
			item.event.DeviceID, item.revision, item.event.EventID, item.transactionID,
			item.packetTransactionID, item.occurredAt, item.event.Attributes["call_context"],
			item.event.Attributes["acct_session_id"],
			parseUint8Attribute(item.event.Attributes["packet_identifier"]), requestType,
			packetCode, result, boolToUInt8(isAntifraud), item.event.Attributes, now,
		); err != nil {
			return err
		}
	}
	if err := radiusBatch.Send(); err != nil {
		return err
	}

	type revisionGroup struct {
		deviceID uuid.UUID
		revision uint64
	}
	grouped := make(map[revisionGroup][]fragment)
	for _, item := range fragments {
		key := revisionGroup{item.event.DeviceID, item.revision}
		grouped[key] = append(grouped[key], item)
	}
	lifecycleBatch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.antifraud_lifecycles
		(device_id,timezone_revision,transaction_id,occurrence,updated_at,first_event_at,
		 last_event_at,call_context,acct_session_id,acct_session_id_normalized,request_type,
		 request_code,response_code,decision,decision_reason,server_address,retries,latency_ms,
		 calling_station_id,called_station_id,src_number_in,dst_number_in,src_number_out,
		 dst_number_out,in_trunkgroup_label,out_trunkgroup_label,accounting_status,q850_cause,
		 is_antifraud,completeness,defect,attributes,raw_event_ids)`)
	if err != nil {
		return err
	}
	for key, group := range grouped {
		ids := make([]uuid.UUID, 0, len(group))
		seen := make(map[uuid.UUID]bool)
		for _, item := range group {
			if !seen[item.transactionID] {
				seen[item.transactionID] = true
				ids = append(ids, item.transactionID)
			}
		}
		current, err := c.loadShadowAntifraudTransactions(
			ctx, key.deviceID, key.revision, ids,
		)
		if err != nil {
			return err
		}
		sort.Slice(group, func(i, j int) bool {
			if !group[i].occurredAt.Equal(group[j].occurredAt) {
				return group[i].occurredAt.Before(group[j].occurredAt)
			}
			return group[i].event.EventID.String() < group[j].event.EventID.String()
		})
		rawSessionPresent := make(map[uuid.UUID]bool)
		for _, item := range group {
			if strings.Contains(strings.ToLower(string(item.event.Payload)), "acct-session-id") {
				rawSessionPresent[item.transactionID] = true
			}
			transaction := current[item.transactionID]
			if transaction == nil {
				transaction = &AntifraudTransaction{
					TransactionID: item.transactionID, DeviceID: key.deviceID,
					FirstEventAt: item.occurredAt, Attributes: make(map[string]string),
					ParserVersion: SyslogParserVersion, TimezoneRevision: key.revision,
				}
				current[item.transactionID] = transaction
			}
			mergeAntifraudEvent(
				transaction, item.event, item.occurredAt,
				parseUint8Attribute(item.event.Attributes["packet_identifier"]),
				parseUint32Attribute(item.event.Attributes["latency_ms"]),
				valueOrZero(parseUint16Attribute(item.event.Attributes["retry"])),
				parseUint16Attribute(item.event.Attributes["q850_cause"]),
			)
		}
		for _, transaction := range current {
			if !seen[transaction.TransactionID] {
				continue
			}
			defect := ""
			if transaction.AcctSessionID == "" && rawSessionPresent[transaction.TransactionID] {
				defect = "acct_session_id_present_in_raw_but_missing_in_lifecycle"
			}
			if err := appendShadowLifecycle(lifecycleBatch, transaction, defect); err != nil {
				return err
			}
		}
	}
	return lifecycleBatch.Send()
}

func (c *Client) loadShadowAntifraudTransactions(
	ctx context.Context, deviceID uuid.UUID, revision uint64, ids []uuid.UUID,
) (map[uuid.UUID]*AntifraudTransaction, error) {
	result := make(map[uuid.UUID]*AntifraudTransaction)
	if len(ids) == 0 {
		return result, nil
	}
	rows, err := c.Conn.Query(ctx, `SELECT
		transaction_id,argMax(updated_at,updated_at),argMax(first_event_at,updated_at),
		argMax(last_event_at,updated_at),argMax(call_context,updated_at),
		argMax(acct_session_id,updated_at),argMax(acct_session_id_normalized,updated_at),
		argMax(request_type,updated_at),argMax(request_code,updated_at),
		argMax(response_code,updated_at),argMax(decision,updated_at),
		argMax(decision_reason,updated_at),argMax(server_address,updated_at),
		argMax(retries,updated_at),argMax(latency_ms,updated_at),
		argMax(calling_station_id,updated_at),argMax(called_station_id,updated_at),
		argMax(src_number_in,updated_at),argMax(dst_number_in,updated_at),
		argMax(src_number_out,updated_at),argMax(dst_number_out,updated_at),
		argMax(in_trunkgroup_label,updated_at),argMax(out_trunkgroup_label,updated_at),
		argMax(accounting_status,updated_at),argMax(q850_cause,updated_at),
		argMax(is_antifraud,updated_at),argMax(completeness,updated_at),
		argMax(attributes,updated_at),argMax(raw_event_ids,updated_at)
		FROM collector.antifraud_lifecycles
		WHERE device_id=? AND timezone_revision=? AND transaction_id IN ?
		GROUP BY transaction_id`, deviceID, revision, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		item := &AntifraudTransaction{
			DeviceID: deviceID, TimezoneRevision: revision, ParserVersion: SyslogParserVersion,
		}
		if err := rows.Scan(
			&item.TransactionID, &item.UpdatedAt, &item.FirstEventAt, &item.LastEventAt,
			&item.CallContext, &item.AcctSessionID, &item.AcctSessionIDNormalized,
			&item.RequestType, &item.RequestCode, &item.ResponseCode, &item.Decision,
			&item.DecisionReason, &item.ServerAddress, &item.Retries, &item.LatencyMS,
			&item.CallingStationID, &item.CalledStationID, &item.SrcNumberIn,
			&item.DstNumberIn, &item.SrcNumberOut, &item.DstNumberOut,
			&item.InTrunkgroupLabel, &item.OutTrunkgroupLabel, &item.AccountingStatus,
			&item.Q850Cause, &item.IsAntifraud, &item.Completeness, &item.Attributes,
			&item.RawEventIDs,
		); err != nil {
			return nil, err
		}
		result[item.TransactionID] = item
	}
	return result, rows.Err()
}

type lifecycleBatchAppender interface {
	Append(...any) error
}

func appendShadowLifecycle(
	batch lifecycleBatchAppender, item *AntifraudTransaction, defect string,
) error {
	return batch.Append(
		item.DeviceID, item.TimezoneRevision, item.TransactionID, uint32(0), item.UpdatedAt,
		item.FirstEventAt, item.LastEventAt, item.CallContext, item.AcctSessionID,
		item.AcctSessionIDNormalized, item.RequestType, item.RequestCode, item.ResponseCode,
		item.Decision, item.DecisionReason, item.ServerAddress, item.Retries, item.LatencyMS,
		item.CallingStationID, item.CalledStationID, item.SrcNumberIn, item.DstNumberIn,
		item.SrcNumberOut, item.DstNumberOut, item.InTrunkgroupLabel, item.OutTrunkgroupLabel,
		item.AccountingStatus, item.Q850Cause, item.IsAntifraud, item.Completeness, defect,
		item.Attributes, item.RawEventIDs)
}

func valueOrZero(value *uint16) uint16 {
	if value == nil {
		return 0
	}
	return *value
}

func (c *Client) pruneAntifraudCacheLocked(current uuid.UUID) {
	if len(c.antifraudActive) <= 10_000 {
		return
	}
	cutoff := time.Now().UTC().Add(-6 * time.Hour)
	for transactionID, transaction := range c.antifraudActive {
		if transactionID != current && transaction.LastEventAt.Before(cutoff) {
			delete(c.antifraudActive, transactionID)
		}
		if len(c.antifraudActive) <= 9_000 {
			return
		}
	}
	for transactionID := range c.antifraudActive {
		if transactionID != current {
			delete(c.antifraudActive, transactionID)
		}
		if len(c.antifraudActive) <= 9_000 {
			return
		}
	}
}

func cloneAntifraudTransaction(source *AntifraudTransaction) *AntifraudTransaction {
	clone := *source
	clone.Attributes = make(map[string]string, len(source.Attributes))
	for key, value := range source.Attributes {
		clone.Attributes[key] = value
	}
	clone.RawEventIDs = append([]uuid.UUID(nil), source.RawEventIDs...)
	return &clone
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
		FROM collector.antifraud_transactions FINAL
		WHERE transaction_id=? AND parser_version=? LIMIT 1`,
		transactionID, SyslogParserVersion)
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

func (c *Client) correlateExactProtocolEvent(ctx context.Context, event SyslogEvent) error {
	occurredAt := event.ReceivedAt
	if event.EventTime != nil {
		occurredAt = *event.EventTime
	}
	if callID := event.Attributes["sip_call_id"]; callID != "" {
		if err := c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
			(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
			SELECT device_id,record_id,?,'exact_sip_call_id',toFloat32(1.0),
				map('sip_call_id',?),'smg-3.410-v6',now64(3)
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
				map('global_callref',?),'smg-3.410-v6',now64(3)
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
				map('sip_call_id',?),'smg-3.410-v6',now64(3)
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
				map('global_callref',?),'smg-3.410-v6',now64(3)
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
				map('rejecting_radius_server',?),'smg-3.410-v6',now64(3)
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
	if revision, err := c.ActiveDeviceRevision(ctx, deviceID); err != nil {
		return AntifraudPage{}, err
	} else if revision != 0 {
		return c.listCurrentAntifraudPage(
			ctx, deviceID, revision, search, limit, cursor,
		)
	}
	query := `SELECT t.transaction_id,t.first_event_at,t.last_event_at,t.call_context,
		t.acct_session_id,t.request_type,t.request_code,t.response_code,t.decision,
		t.decision_reason,t.server_address,t.retries,t.latency_ms,t.calling_station_id,
		t.called_station_id,t.src_number_in,t.dst_number_in,t.src_number_out,t.dst_number_out,
		t.in_trunkgroup_label,t.out_trunkgroup_label,t.accounting_status,t.q850_cause,
		t.completeness,t.attributes,ifNull(c.record_ids,[]),ifNull(c.leg_count,0),
		c.setup_time,ifNull(c.method,''),ifNull(c.confidence,0),
		ifNull(c.time_delta_ms,0),ifNull(c.ambiguity_reason,''),ifNull(c.cdr_session_id,'')
		FROM collector.antifraud_transactions AS t FINAL
		LEFT JOIN (
			SELECT l.device_id AS device_id,l.transaction_id AS transaction_id,
				groupArrayIf(l.cdr_record_id,l.ambiguity=0) AS record_ids,
				countIf(l.ambiguity=0) AS leg_count,
				minIf(coalesce(ct.setup_time,d.setup_time),l.ambiguity=0) AS setup_time,
				argMaxIf(d.radius_session_id,l.linked_at,l.ambiguity=0) AS cdr_session_id,
				argMaxIf(l.method,l.linked_at,l.ambiguity=0) AS method,
				maxIf(l.confidence,l.ambiguity=0) AS confidence,
				argMaxIf(l.time_delta_ms,l.linked_at,l.ambiguity=0) AS time_delta_ms,
				argMaxIf(l.candidate_reason,l.linked_at,l.ambiguity=1) AS ambiguity_reason
			FROM collector.antifraud_call_links AS l FINAL
			LEFT JOIN collector.cdr_records AS d FINAL
				ON d.device_id=l.device_id AND d.record_id=l.cdr_record_id
			LEFT JOIN collector.cdr_time_interpretations AS ct FINAL
				ON ct.device_id=d.device_id AND ct.record_id=d.record_id
			WHERE l.parser_version IN ('smg-3.410-v5','smg-3.410-v6')
			GROUP BY l.device_id,l.transaction_id
		) c ON c.device_id=t.device_id AND c.transaction_id=t.transaction_id
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
			&item.LegCount, &item.CDRSetupTime, &item.CorrelationMethod,
			&item.CorrelationConfidence, &item.CorrelationTimeDeltaMS,
			&item.AmbiguityReason, &item.CDRSessionID,
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
	if revision, err := c.ActiveDeviceRevision(ctx, deviceID); err != nil {
		return nil, err
	} else if revision != 0 {
		return c.currentAntifraudTimeline(
			ctx, deviceID, revision, transactionID, "antifraud_transaction",
		)
	}
	rows, err := c.Conn.Query(ctx, `SELECT e.event_id,e.received_at,i.event_time,i.category,
		i.component,i.message,e.payload,i.parse_status,i.attributes,i.source_timezone,
		'antifraud_transaction',toFloat32(1.0)
		FROM collector.antifraud_transactions AS t FINAL
		ARRAY JOIN t.raw_event_ids AS linked_event_id
		INNER JOIN collector.raw_syslog e
			ON e.device_id=t.device_id AND e.event_id=linked_event_id
		INNER JOIN collector.syslog_interpretations AS i FINAL
			ON i.device_id=e.device_id AND i.event_id=e.event_id
		WHERE t.device_id=? AND t.transaction_id=? AND t.parser_version=?
			AND i.parser_version=?
		ORDER BY e.received_at,e.event_id`, deviceID, transactionID,
		SyslogParserVersion, SyslogParserVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TimelineRow, 0)
	for rows.Next() {
		var item TimelineRow
		if err := rows.Scan(
			&item.EventID, &item.ReceivedAt, &item.EventTime, &item.Category,
			&item.Component, &item.Message, &item.RawPayload, &item.Status,
			&item.Attributes, &item.SourceTimezone, &item.Method, &item.Confidence,
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
		any(r.source_ip),any(r.source_port),any(r.payload),any(r.source_timezone)
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
			&item.SourcePort, &payload, &item.SourceTimezone,
		); err != nil {
			return nil, err
		}
		item.Payload = []byte(payload)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (c *Client) MarkSyslogReprocessedBatch(
	ctx context.Context, events []SyslogEvent, parserVersion string,
) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.syslog_reprocess_ledger
		(event_id,device_id,parser_version,processed_at)`)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, event := range events {
		if err := batch.Append(event.EventID, event.DeviceID, parserVersion, now); err != nil {
			return err
		}
	}
	return batch.Send()
}

func antifraudTransactionID(event SyslogEvent, occurredAt time.Time) uuid.UUID {
	key := ""
	if contextValue := event.Attributes["call_context"]; contextValue != "" {
		key = fmt.Sprintf("context:%s:%s", contextValue,
			event.ReceivedAt.UTC().Truncate(30*time.Minute).Format(time.RFC3339))
	} else if requestID := event.Attributes["packet_identifier"]; requestID != "" {
		key = fmt.Sprintf("request:%s:%s:%s", event.Attributes["server_address"], requestID,
			event.ReceivedAt.UTC().Truncate(10*time.Minute).Format(time.RFC3339))
	} else if session := normalizeCorrelationValue(event.Attributes["acct_session_id"]); session != "" {
		key = "session:" + session
	} else {
		key = "event:" + event.EventID.String()
	}
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte(event.DeviceID.String()+"|"+key))
}

func antifraudPacketTransactionID(
	event SyslogEvent, occurredAt time.Time, lifecycleID uuid.UUID,
) uuid.UUID {
	identifier := event.Attributes["packet_identifier"]
	if identifier == "" {
		return lifecycleID
	}
	key := fmt.Sprintf("%s|%s|%s|%s", event.DeviceID, event.Attributes["call_context"],
		identifier, event.ReceivedAt.UTC().Truncate(10*time.Minute))
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(key))
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

func parseRadiusEventTimestamp(value, timezone string) *time.Time {
	if value == "" {
		return nil
	}
	if epoch, err := strconv.ParseInt(value, 10, 64); err == nil {
		result := time.Unix(epoch, 0).UTC()
		return &result
	}
	location := time.UTC
	if timezone != "" {
		if parsedLocation, err := time.LoadLocation(timezone); err == nil {
			location = parsedLocation
		}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.ParseInLocation(layout, value, location); err == nil {
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
