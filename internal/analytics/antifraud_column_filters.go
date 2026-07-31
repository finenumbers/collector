package analytics

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"collector/internal/workload"

	"github.com/google/uuid"
)

const antifraudColumnFilterMaxLen = 256

// AntifraudColumnFilters are AND exact-match filters on AntiFraud list dimensions.
type AntifraudColumnFilters map[string]string

var antifraudFilterableColumns = map[string]struct{}{
	"calling":        {},
	"called":         {},
	"phases":         {},
	"chain":          {},
	"radius_outcome": {},
	"coverage":       {},
}

// SQL expressions reused by list filters and DISTINCT suggests (must stay aligned
// with orderedFamilies / chainCompletenessFromSummary / radiusOutcomeFromSummary /
// deriveAFCoverageState).
const (
	afPhasesExpr = `arrayStringConcat(arrayFilter(x -> x!='',[
		if(has(arrayMap(f->lower(f),ifNull(packet_summary.families,[])),'indication'),'indication',''),
		if(has(arrayMap(f->lower(f),ifNull(packet_summary.families,[])),'verification'),'verification',''),
		if(has(arrayMap(f->lower(f),ifNull(packet_summary.families,[])),'accounting'),'accounting','')
	]),' → ')`

	afPhasesLenExpr = `length(arrayFilter(x -> x!='',[
		if(has(arrayMap(f->lower(f),ifNull(packet_summary.families,[])),'indication'),'indication',''),
		if(has(arrayMap(f->lower(f),ifNull(packet_summary.families,[])),'verification'),'verification',''),
		if(has(arrayMap(f->lower(f),ifNull(packet_summary.families,[])),'accounting'),'accounting','')
	]))`

	afChainExpr = `multiIf(
		` + afPhasesLenExpr + `=3 AND ifNull(packet_summary.unpaired,0)=0 AND ifNull(packet_summary.fallback,0)=0,'complete',
		` + afPhasesLenExpr + `=0 OR (` + afPhasesLenExpr + `=1 AND ifNull(packet_summary.unpaired,0)>0),'minimal',
		'partial')`

	afRadiusOutcomeExpr = `multiIf(
		ifNull(packet_summary.rejects,0)>0,'reject',
		ifNull(packet_summary.accepts,0)>0,'accept',
		'no_response')`
)

// afCoverageExprSQL prefers assignment match/ambiguous, then persisted
// call.coverage_state from reconciliation, then age fallback using the same
// runtime coverage windows as the reconcile worker (Настройки → Параметры).
func afCoverageExprSQL(thresholds CoverageThresholds) string {
	thresholds = thresholds.normalized()
	grace := int64(thresholds.ExpectedGrace / time.Second)
	late := int64(thresholds.LateThreshold / time.Second)
	missing := int64(thresholds.MissingTerminal / time.Second)
	return fmt.Sprintf(`multiIf(
		length(ifNull(assignment.cdr_ids,[]))>0,'matched',
		ifNull(assignment.ambiguous,0)=1,'ambiguous',
		call.coverage_state IN ('awaiting_cdr','expected','late','missing','matched','ambiguous'),call.coverage_state,
		dateDiff('second',call.first_seen_at,now())<%d,'awaiting_cdr',
		dateDiff('second',call.first_seen_at,now())<%d,'expected',
		dateDiff('second',call.first_seen_at,now())<%d,'late',
		'missing')`, grace, late, missing)
}

func antifraudFilterExpr(column string, thresholds CoverageThresholds) (string, bool) {
	switch column {
	case "calling":
		return "call.calling", true
	case "called":
		return "call.called", true
	case "phases":
		return afPhasesExpr, true
	case "chain":
		return afChainExpr, true
	case "radius_outcome":
		return afRadiusOutcomeExpr, true
	case "coverage":
		return afCoverageExprSQL(thresholds), true
	default:
		return "", false
	}
}

// NormalizeAntifraudColumnFilters keeps only allowlisted non-empty keys.
func NormalizeAntifraudColumnFilters(raw map[string]string) (AntifraudColumnFilters, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(AntifraudColumnFilters, len(raw))
	for key, value := range raw {
		col := strings.TrimSpace(key)
		if _, ok := antifraudFilterableColumns[col]; !ok {
			return nil, fmt.Errorf("unsupported column filter %q", key)
		}
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if len(trimmed) > antifraudColumnFilterMaxLen {
			return nil, fmt.Errorf("column filter %s must be at most %d characters", col, antifraudColumnFilterMaxLen)
		}
		out[col] = trimmed
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func AntifraudColumnFilterAllowed(column string) bool {
	_, ok := antifraudFilterableColumns[strings.TrimSpace(column)]
	return ok
}

func appendAntifraudColumnFilters(
	query string, args []any, filters AntifraudColumnFilters, thresholds CoverageThresholds,
) (string, []any) {
	if len(filters) == 0 {
		return query, args
	}
	keys := make([]string, 0, len(filters))
	for key := range filters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		expr, ok := antifraudFilterExpr(key, thresholds)
		if !ok {
			continue
		}
		query += ` AND (` + expr + `)=?`
		args = append(args, filters[key])
	}
	return query, args
}

const antifraudListJoinsSQL = `
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

// ListAntifraudColumnValues returns distinct filter values with counts for a day.
func (c *Client) ListAntifraudColumnValues(
	ctx context.Context, deviceID uuid.UUID, column, prefix string, limit uint64,
	timeRange TimeRange, filters AntifraudColumnFilters,
) ([]SatelColumnValue, error) {
	column = strings.TrimSpace(column)
	thresholds := c.coverageWindows()
	expr, ok := antifraudFilterExpr(column, thresholds)
	if !ok {
		return nil, fmt.Errorf("unsupported suggest column %q", column)
	}
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return nil, err
	}
	defer release()
	limit = clampSatelColumnSuggestLimit(limit)
	prefix = strings.TrimSpace(prefix)
	peer := AntifraudColumnFilters{}
	for key, value := range filters {
		if key == column {
			continue
		}
		peer[key] = value
	}
	query := `SELECT (` + expr + `) AS value,count() AS cnt` + antifraudListJoinsSQL + `
		AND call.first_seen_at>=? AND call.first_seen_at<?`
	args := []any{deviceID, deviceID, deviceID, timeRange.From, timeRange.To}
	query, args = appendAntifraudColumnFilters(query, args, peer, thresholds)
	if column == "calling" || column == "called" || column == "phases" {
		query += ` AND (` + expr + `)!=''`
	}
	if prefix != "" {
		query += ` AND positionCaseInsensitiveUTF8(toString(` + expr + `),?)>0`
		args = append(args, prefix)
	}
	query += ` GROUP BY value ORDER BY cnt DESC,value ASC LIMIT ?`
	args = append(args, limit)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]SatelColumnValue, 0, limit)
	for rows.Next() {
		var item SatelColumnValue
		if err := rows.Scan(&item.Value, &item.Count); err != nil {
			return nil, err
		}
		if item.Value != "" {
			values = append(values, item)
		}
	}
	return values, rows.Err()
}
