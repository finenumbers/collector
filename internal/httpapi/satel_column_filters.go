package httpapi

import (
	"net/http"
	"strings"

	"collector/internal/analytics"
)

func parseSatelColumnFilters(request *http.Request) (analytics.SatelColumnFilters, error) {
	raw := map[string]string{}
	for key, values := range request.URL.Query() {
		if !strings.HasPrefix(key, "f.") || len(values) == 0 {
			continue
		}
		raw[strings.TrimPrefix(key, "f.")] = values[0]
	}
	return analytics.NormalizeSatelColumnFilters(raw)
}

func parseSatelColumnFiltersMap(raw map[string]string) (analytics.SatelColumnFilters, error) {
	return analytics.NormalizeSatelColumnFilters(raw)
}
