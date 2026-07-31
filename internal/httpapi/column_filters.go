package httpapi

import (
	"net/http"
	"strings"

	"collector/internal/analytics"
)

func rawColumnFilters(request *http.Request) map[string]string {
	raw := map[string]string{}
	for key, values := range request.URL.Query() {
		if !strings.HasPrefix(key, "f.") || len(values) == 0 {
			continue
		}
		raw[strings.TrimPrefix(key, "f.")] = values[0]
	}
	return raw
}

func parseSatelColumnFilters(request *http.Request) (analytics.SatelColumnFilters, error) {
	return analytics.NormalizeSatelColumnFilters(rawColumnFilters(request))
}

func parseSatelColumnFiltersMap(raw map[string]string) (analytics.SatelColumnFilters, error) {
	return analytics.NormalizeSatelColumnFilters(raw)
}

func parseEltexColumnFilters(request *http.Request) (analytics.EltexColumnFilters, error) {
	return analytics.NormalizeEltexColumnFilters(rawColumnFilters(request))
}

func parseEltexColumnFiltersMap(raw map[string]string) (analytics.EltexColumnFilters, error) {
	return analytics.NormalizeEltexColumnFilters(raw)
}

func parseAntifraudColumnFilters(request *http.Request) (analytics.AntifraudColumnFilters, error) {
	return analytics.NormalizeAntifraudColumnFilters(rawColumnFilters(request))
}

func parseAntifraudColumnFiltersMap(raw map[string]string) (analytics.AntifraudColumnFilters, error) {
	return analytics.NormalizeAntifraudColumnFilters(raw)
}
