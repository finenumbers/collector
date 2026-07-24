package analytics

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

type correlationTransaction struct {
	ID           uuid.UUID
	DeviceID     uuid.UUID
	FirstEventAt time.Time
	LastEventAt  time.Time
	Session      string
	CallContext  string
	Calling      string
	Called       string
	SrcIn        string
	DstIn        string
	SrcOut       string
	DstOut       string
	InRoute      string
	OutRoute     string
	Attributes   map[string]string
	RawEventIDs  []uuid.UUID
}

type correlationCDR struct {
	ID             uuid.UUID
	SetupTime      time.Time
	Session        string
	IncomingCgPN   string
	OutgoingCgPN   string
	IncomingCdPN   string
	OutgoingCdPN   string
	IncomingRoute  string
	OutgoingRoute  string
	IncomingCallID string
	OutgoingCallID string
	GlobalCallref  string
}

type correlationEdge struct {
	transaction correlationTransaction
	cdr         correlationCDR
	method      string
	confidence  float32
	timeDeltaMS int64
	evidence    map[string]string
	ambiguous   bool
	reason      string
}

func (c *Client) ReconcileDevice(
	ctx context.Context, deviceID uuid.UUID, since time.Time,
) error {
	transactions, err := c.loadCorrelationTransactions(ctx, deviceID, since)
	if err != nil || len(transactions) == 0 {
		return err
	}
	minTime, maxTime := transactions[0].FirstEventAt, transactions[0].FirstEventAt
	for _, item := range transactions[1:] {
		if item.FirstEventAt.Before(minTime) {
			minTime = item.FirstEventAt
		}
		if item.FirstEventAt.After(maxTime) {
			maxTime = item.FirstEventAt
		}
	}
	cdrs, err := c.loadCorrelationCDRs(
		ctx, deviceID, minTime.Add(-10*time.Minute), maxTime.Add(10*time.Minute),
	)
	if err != nil {
		return err
	}
	sessionIndex := make(map[string][]correlationCDR)
	for _, record := range cdrs {
		if record.Session != "" {
			sessionIndex[record.Session] = append(sessionIndex[record.Session], record)
		}
	}
	links := make([]correlationEdge, 0)
	unmatched := make([]correlationTransaction, 0)
	usedCDRs := make(map[uuid.UUID]bool)
	exactEdges := make([]correlationEdge, 0)
	hasExact := make(map[uuid.UUID]bool)
	for _, transaction := range transactions {
		exact := sessionIndex[transaction.Session]
		if transaction.Session == "" || len(exact) == 0 {
			continue
		}
		hasExact[transaction.ID] = true
		for _, record := range exact {
			delta := record.SetupTime.Sub(transaction.FirstEventAt).Milliseconds()
			exactEdges = append(exactEdges, correlationEdge{
				transaction: transaction, cdr: record, method: "exact_acct_session",
				confidence: 1, timeDeltaMS: delta,
				evidence: map[string]string{"acct_session_id": transaction.Session},
			})
		}
	}
	sort.Slice(exactEdges, func(i, j int) bool {
		left, right := abs64(exactEdges[i].timeDeltaMS), abs64(exactEdges[j].timeDeltaMS)
		if left != right {
			return left < right
		}
		if exactEdges[i].transaction.ID != exactEdges[j].transaction.ID {
			return exactEdges[i].transaction.ID.String() < exactEdges[j].transaction.ID.String()
		}
		return exactEdges[i].cdr.ID.String() < exactEdges[j].cdr.ID.String()
	})
	assignedTransactions := make(map[uuid.UUID]bool)
	for _, edge := range exactEdges {
		if assignedTransactions[edge.transaction.ID] || usedCDRs[edge.cdr.ID] {
			continue
		}
		links = append(links, edge)
		assignedTransactions[edge.transaction.ID] = true
		usedCDRs[edge.cdr.ID] = true
	}
	ambiguous := make([]correlationEdge, 0)
	for _, transaction := range transactions {
		if assignedTransactions[transaction.ID] {
			continue
		}
		if hasExact[transaction.ID] {
			for _, edge := range exactEdges {
				if edge.transaction.ID == transaction.ID {
					edge.ambiguous = true
					edge.reason = "Acct-Session-Id conflicts with an already assigned lifecycle or CDR"
					ambiguous = append(ambiguous, edge)
					break
				}
			}
			continue
		}
		unmatched = append(unmatched, transaction)
	}
	candidatesByTransaction := make(map[uuid.UUID][]correlationEdge)
	for _, transaction := range unmatched {
		protocolMatched := false
		for _, record := range cdrs {
			if usedCDRs[record.ID] {
				continue
			}
			if edge, ok := exactProtocolCorrelationEdge(transaction, record); ok {
				links = append(links, edge)
				usedCDRs[record.ID] = true
				protocolMatched = true
				break
			}
		}
		if protocolMatched {
			continue
		}
		for _, record := range cdrs {
			if usedCDRs[record.ID] {
				continue
			}
			if edge, ok := compositeCorrelationEdge(transaction, record); ok {
				candidatesByTransaction[transaction.ID] = append(
					candidatesByTransaction[transaction.ID], edge,
				)
			}
		}
	}
	accepted := make([]correlationEdge, 0)
	for transactionID, edges := range candidatesByTransaction {
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].confidence != edges[j].confidence {
				return edges[i].confidence > edges[j].confidence
			}
			left, right := abs64(edges[i].timeDeltaMS), abs64(edges[j].timeDeltaMS)
			if left != right {
				return left < right
			}
			return edges[i].cdr.ID.String() < edges[j].cdr.ID.String()
		})
		best := edges[0]
		if len(edges) > 1 && best.confidence-edges[1].confidence < 0.05 &&
			abs64(abs64(best.timeDeltaMS)-abs64(edges[1].timeDeltaMS)) < 1000 {
			best.ambiguous = true
			best.reason = "multiple CDR candidates have equivalent evidence"
			ambiguous = append(ambiguous, best)
			continue
		}
		_ = transactionID
		accepted = append(accepted, best)
	}
	sort.Slice(accepted, func(i, j int) bool {
		if accepted[i].confidence != accepted[j].confidence {
			return accepted[i].confidence > accepted[j].confidence
		}
		left, right := abs64(accepted[i].timeDeltaMS), abs64(accepted[j].timeDeltaMS)
		if left != right {
			return left < right
		}
		return accepted[i].transaction.ID.String() < accepted[j].transaction.ID.String()
	})
	assigned := make(map[uuid.UUID]bool)
	for _, edge := range accepted {
		if assigned[edge.cdr.ID] {
			edge.ambiguous = true
			edge.reason = "CDR is the best candidate for another AntiFraud lifecycle"
			ambiguous = append(ambiguous, edge)
			continue
		}
		assigned[edge.cdr.ID] = true
		links = append(links, edge)
	}
	if err := c.persistAntifraudCallLinks(ctx, links, ambiguous); err != nil {
		return err
	}
	return c.recordCorrelationCoverage(
		ctx, deviceID, uint64(len(transactions)), links, ambiguous,
	)
}

func (c *Client) loadCorrelationTransactions(
	ctx context.Context, deviceID uuid.UUID, since time.Time,
) ([]correlationTransaction, error) {
	query := `SELECT transaction_id,first_event_at,last_event_at,acct_session_id_normalized,call_context,
		calling_station_id,called_station_id,src_number_in,dst_number_in,src_number_out,
		dst_number_out,in_trunkgroup_label,out_trunkgroup_label,attributes,raw_event_ids
		FROM collector.antifraud_transactions FINAL
		WHERE device_id=? AND parser_version=? AND is_antifraud=1`
	args := []any{deviceID, SyslogParserVersion}
	if !since.IsZero() {
		query += ` AND last_event_at>=?`
		args = append(args, since)
	}
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]correlationTransaction, 0)
	for rows.Next() {
		var item correlationTransaction
		if err := rows.Scan(
			&item.ID, &item.FirstEventAt, &item.LastEventAt, &item.Session, &item.CallContext,
			&item.Calling, &item.Called, &item.SrcIn, &item.DstIn, &item.SrcOut,
			&item.DstOut, &item.InRoute, &item.OutRoute, &item.Attributes,
			&item.RawEventIDs,
		); err != nil {
			return nil, err
		}
		item.DeviceID = deviceID
		result = append(result, item)
	}
	return result, rows.Err()
}

func (c *Client) loadCorrelationCDRs(
	ctx context.Context, deviceID uuid.UUID, from, to time.Time,
) ([]correlationCDR, error) {
	rows, err := c.Conn.Query(ctx, `SELECT c.record_id,
		coalesce(t.setup_time,c.setup_time,c.ingested_at),c.radius_session_id_normalized,
		c.incoming_cgpn,c.outgoing_cgpn,c.incoming_cdpn,c.outgoing_cdpn,
		c.incoming_description,c.outgoing_description,c.incoming_sip_call_id,
		c.outgoing_sip_call_id,c.global_callref
		FROM collector.cdr_records AS c FINAL
		LEFT JOIN collector.cdr_time_interpretations AS t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		WHERE c.device_id=? AND coalesce(t.setup_time,c.setup_time,c.ingested_at) BETWEEN ? AND ?`,
		deviceID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]correlationCDR, 0)
	for rows.Next() {
		var item correlationCDR
		if err := rows.Scan(
			&item.ID, &item.SetupTime, &item.Session, &item.IncomingCgPN,
			&item.OutgoingCgPN, &item.IncomingCdPN, &item.OutgoingCdPN,
			&item.IncomingRoute, &item.OutgoingRoute, &item.IncomingCallID,
			&item.OutgoingCallID, &item.GlobalCallref,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func exactProtocolCorrelationEdge(
	transaction correlationTransaction, record correlationCDR,
) (correlationEdge, bool) {
	callIDs := []string{
		transaction.Attributes["incoming_sip_call_id"],
		transaction.Attributes["outgoing_sip_call_id"],
		transaction.Attributes["h323_call_id"],
	}
	for _, callID := range callIDs {
		if callID != "" && (callID == record.IncomingCallID || callID == record.OutgoingCallID) {
			return correlationEdge{
				transaction: transaction, cdr: record, method: "exact_sip_call_id",
				confidence:  1,
				timeDeltaMS: record.SetupTime.Sub(transaction.FirstEventAt).Milliseconds(),
				evidence:    map[string]string{"sip_call_id": callID},
			}, true
		}
	}
	globalCallref := transaction.Attributes["global_callref"]
	if globalCallref != "" && globalCallref == record.GlobalCallref {
		return correlationEdge{
			transaction: transaction, cdr: record, method: "exact_global_callref",
			confidence:  1,
			timeDeltaMS: record.SetupTime.Sub(transaction.FirstEventAt).Milliseconds(),
			evidence:    map[string]string{"global_callref": globalCallref},
		}, true
	}
	return correlationEdge{}, false
}

func compositeCorrelationEdge(
	transaction correlationTransaction, record correlationCDR,
) (correlationEdge, bool) {
	delta := record.SetupTime.Sub(transaction.FirstEventAt)
	if delta < -5*time.Minute || delta > 5*time.Minute {
		return correlationEdge{}, false
	}
	antiA := normalizedPhoneSet(
		transaction.Calling, transaction.SrcIn, transaction.SrcOut,
	)
	antiB := normalizedPhoneSet(
		transaction.Called, transaction.DstIn, transaction.DstOut,
	)
	cdrA := normalizedPhoneSet(record.IncomingCgPN, record.OutgoingCgPN)
	cdrB := normalizedPhoneSet(record.IncomingCdPN, record.OutgoingCdPN)
	aMatch := intersects(antiA, cdrA)
	bMatch := intersects(antiB, cdrB)
	inRoute := normalizedLabel(transaction.InRoute) != "" &&
		normalizedLabel(transaction.InRoute) == normalizedLabel(record.IncomingRoute)
	outRoute := normalizedLabel(transaction.OutRoute) != "" &&
		normalizedLabel(transaction.OutRoute) == normalizedLabel(record.OutgoingRoute)
	if !aMatch && !bMatch {
		return correlationEdge{}, false
	}
	score := float32(0)
	matched := make([]string, 0, 5)
	if aMatch {
		score += 0.3
		matched = append(matched, "number_a")
	}
	if bMatch {
		score += 0.3
		matched = append(matched, "number_b")
	}
	if inRoute {
		score += 0.15
		matched = append(matched, "incoming_route")
	}
	if outRoute {
		score += 0.15
		matched = append(matched, "outgoing_route")
	}
	absoluteDelta := abs64(delta.Milliseconds())
	switch {
	case absoluteDelta <= 2000:
		score += 0.1
	case absoluteDelta <= 10000:
		score += 0.08
	case absoluteDelta <= 60000:
		score += 0.05
	}
	if score < 0.75 {
		return correlationEdge{}, false
	}
	return correlationEdge{
		transaction: transaction, cdr: record, method: "composite_unique",
		confidence: score, timeDeltaMS: delta.Milliseconds(),
		evidence: map[string]string{
			"matched_fields": strings.Join(matched, ","),
			"anti_calling":   transaction.Calling, "anti_called": transaction.Called,
			"cdr_incoming_cgpn": record.IncomingCgPN,
			"cdr_incoming_cdpn": record.IncomingCdPN,
		},
	}, true
}

func (c *Client) persistAntifraudCallLinks(
	ctx context.Context, links, ambiguous []correlationEdge,
) error {
	all := append(append([]correlationEdge{}, links...), ambiguous...)
	if len(all) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.antifraud_call_links
		(device_id,transaction_id,cdr_record_id,linked_at,method,confidence,ambiguity,
		 candidate_reason,time_delta_ms,evidence,parser_version)`)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, edge := range all {
		if err := batch.Append(
			edge.transaction.DeviceID, edge.transaction.ID, edge.cdr.ID, now, edge.method,
			edge.confidence, boolToUInt8(edge.ambiguous), edge.reason,
			edge.timeDeltaMS, edge.evidence, SyslogParserVersion,
		); err != nil {
			return err
		}
	}
	if err := batch.Send(); err != nil {
		return err
	}
	for _, edge := range links {
		if len(edge.transaction.RawEventIDs) == 0 {
			continue
		}
		if err := c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
			(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
			SELECT ?,?,arrayJoin(?),?,?,?,'smg-3.410-v6',now64(3)`,
			edge.transaction.DeviceID, edge.cdr.ID, edge.transaction.RawEventIDs,
			edge.method, edge.confidence, edge.evidence); err != nil {
			return err
		}
		if callContext := edge.transaction.CallContext; callContext != "" {
			if err := c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
				(device_id,cdr_record_id,event_id,method,confidence,evidence,parser_version,linked_at)
				SELECT i.device_id,?,i.event_id,'call_context_transaction',?,?,
					'smg-3.410-v6',now64(3)
				FROM collector.syslog_interpretations AS i FINAL
				WHERE i.device_id=? AND i.parser_version=?
					AND i.attributes['call_context']=?`,
				edge.cdr.ID, edge.confidence,
				map[string]string{"call_context": callContext},
				edge.transaction.DeviceID, SyslogParserVersion, callContext); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Client) recordCorrelationCoverage(
	ctx context.Context,
	deviceID uuid.UUID,
	total uint64,
	links, ambiguous []correlationEdge,
) error {
	var exact, composite uint64
	linkedTransactions := make(map[uuid.UUID]bool)
	for _, edge := range links {
		linkedTransactions[edge.transaction.ID] = true
		if edge.method == "exact_acct_session" {
			exact++
		} else {
			composite++
		}
	}
	orphan := total - uint64(len(linkedTransactions)) - uint64(len(ambiguous))
	return c.Conn.Exec(ctx, `INSERT INTO collector.correlation_runs
		(device_id,ran_at,parser_version,antifraud_total,exact_linked,composite_linked,
		 ambiguous,orphan) VALUES(?,now64(3),?,?,?,?,?,?)`,
		deviceID, SyslogParserVersion, total, exact, composite, len(ambiguous), orphan)
}

func normalizedPhoneSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, value := range values {
		var digits strings.Builder
		for _, char := range value {
			if unicode.IsDigit(char) {
				digits.WriteRune(char)
			}
		}
		normalized := digits.String()
		if len(normalized) == 10 {
			normalized = "7" + normalized
		} else if len(normalized) == 11 && strings.HasPrefix(normalized, "8") {
			normalized = "7" + normalized[1:]
		}
		if normalized != "" {
			result[normalized] = struct{}{}
		}
	}
	return result
}

func intersects(left, right map[string]struct{}) bool {
	for value := range left {
		if _, ok := right[value]; ok {
			return true
		}
	}
	return false
}

func normalizedLabel(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func abs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}
