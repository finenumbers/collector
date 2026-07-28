package httpapi

import (
	"net/http"
	"strconv"
)

func (s *Server) listAuditLogs(writer http.ResponseWriter, request *http.Request) {
	limit := 200
	if raw := request.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(writer, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = parsed
	}
	items, err := s.Store.ListAuditLogs(request.Context(), request.URL.Query().Get("q"), limit)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to list audit logs")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}
