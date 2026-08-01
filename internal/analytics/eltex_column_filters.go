package analytics

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"collector/internal/workload"

	"github.com/google/uuid"
)

const eltexColumnFilterMaxLen = 256

// EltexColumnFilters are AND exact-match filters on allowlisted Eltex CDR columns.
type EltexColumnFilters map[string]string

var eltexFilterableColumns = map[string]struct{}{
	"outgoing_cgpn":               {},
	"outgoing_cdpn":               {},
	"outgoing_redirecting_number": {},
	"incoming_description":        {},
	"outgoing_description":        {},
	"release_info":                {},
}

// NormalizeEltexColumnFilters keeps only allowlisted non-empty keys.
func NormalizeEltexColumnFilters(raw map[string]string) (EltexColumnFilters, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(EltexColumnFilters, len(raw))
	for key, value := range raw {
		col := strings.TrimSpace(key)
		if _, ok := eltexFilterableColumns[col]; !ok {
			return nil, fmt.Errorf("unsupported column filter %q", key)
		}
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if len(trimmed) > eltexColumnFilterMaxLen {
			return nil, fmt.Errorf("column filter %s must be at most %d characters", col, eltexColumnFilterMaxLen)
		}
		out[col] = trimmed
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func EltexColumnFilterAllowed(column string) bool {
	_, ok := eltexFilterableColumns[strings.TrimSpace(column)]
	return ok
}

func appendEltexColumnFilters(query string, args []any, filters EltexColumnFilters) (string, []any) {
	if len(filters) == 0 {
		return query, args
	}
	keys := make([]string, 0, len(filters))
	for key := range filters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		query += ` AND c.` + key + `=?`
		args = append(args, filters[key])
	}
	return query, args
}

const eltexColumnValuesBaseQuery = `SELECT c.%s AS value,count() AS cnt
		FROM collector.cdr_records AS c FINAL
		LEFT JOIN collector.cdr_time_interpretations AS t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		WHERE c.device_id=?
			AND c.%s!=''
			AND coalesce(t.setup_time,c.setup_time,c.ingested_at)>=?
			AND coalesce(t.setup_time,c.setup_time,c.ingested_at)<?`

// ListEltexColumnValues returns distinct non-empty values with counts for an
// allowlisted Eltex CDR column within timeRange.
func (c *Client) ListEltexColumnValues(
	ctx context.Context, deviceID uuid.UUID, column, prefix string, limit uint64,
	timeRange TimeRange, filters EltexColumnFilters,
) ([]SatelColumnValue, error) {
	column = strings.TrimSpace(column)
	if !EltexColumnFilterAllowed(column) {
		return nil, fmt.Errorf("unsupported suggest column %q", column)
	}
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return nil, err
	}
	defer release()
	limit = clampSatelColumnSuggestLimit(limit)
	prefix = strings.TrimSpace(prefix)
	peer := EltexColumnFilters{}
	for key, value := range filters {
		if key == column {
			continue
		}
		peer[key] = value
	}
	query := fmt.Sprintf(eltexColumnValuesBaseQuery, column, column)
	args := []any{deviceID, timeRange.From, timeRange.To}
	query, args = appendEltexColumnFilters(query, args, peer)
	if prefix != "" {
		query += ` AND positionCaseInsensitive(c.` + column + `,?)>0`
		args = append(args, prefix)
	}
	query += ` GROUP BY value ORDER BY cnt DESC,value ASC LIMIT ?`
	args = append(args, limit)
	rows, err := c.query(ctx, query, args...)
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
