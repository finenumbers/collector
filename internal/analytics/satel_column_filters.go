package analytics

import (
	"fmt"
	"sort"
	"strings"
)

// SatelColumnFilters are AND exact-match filters on allowlisted Satel CDR columns.
type SatelColumnFilters map[string]string

// SatelColumnValue is a distinct column value with its day-scoped row count.
type SatelColumnValue struct {
	Value string `json:"value"`
	Count uint64 `json:"count"`
}

var satelFilterableColumns = map[string]struct{}{
	"bill_ani":        {},
	"bill_dnis":       {},
	"out_orig_dnis":   {},
	"src_name":        {},
	"dst_name":        {},
	"dp_name":         {},
	"disconnect_text": {},
}

// NormalizeSatelColumnFilters keeps only allowlisted non-empty keys.
func NormalizeSatelColumnFilters(raw map[string]string) (SatelColumnFilters, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(SatelColumnFilters, len(raw))
	for key, value := range raw {
		col := strings.TrimSpace(key)
		if _, ok := satelFilterableColumns[col]; !ok {
			return nil, fmt.Errorf("unsupported column filter %q", key)
		}
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if len(trimmed) > 64 {
			return nil, fmt.Errorf("column filter %s must be at most 64 characters", col)
		}
		out[col] = trimmed
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func SatelColumnFilterAllowed(column string) bool {
	_, ok := satelFilterableColumns[strings.TrimSpace(column)]
	return ok
}

func appendSatelColumnFilters(query string, args []any, filters SatelColumnFilters) (string, []any) {
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

func clampSatelColumnSuggestLimit(limit uint64) uint64 {
	if limit == 0 || limit > 100 {
		return 50
	}
	return limit
}
