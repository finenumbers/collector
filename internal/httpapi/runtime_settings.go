package httpapi

import (
	"encoding/json"
	"net/http"

	"collector/internal/runtimesettings"
	"collector/internal/store"

	"github.com/google/uuid"
)

func (s *Server) runtimeDocument() runtimesettings.Document {
	if s.Runtime != nil {
		return s.Runtime.Snapshot()
	}
	return runtimesettings.Defaults()
}

func (s *Server) getRuntimeSettings(writer http.ResponseWriter, request *http.Request) {
	row, err := s.Store.LoadRuntimeSettings(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to load runtime settings")
		return
	}
	settings := row.Settings
	if !row.Seeded && s.Runtime != nil {
		settings = s.Runtime.Snapshot()
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"settings":  settings.PublicView(),
		"updatedAt": row.UpdatedAt,
		"updatedBy": row.UpdatedBy,
	})
}

func (s *Server) patchRuntimeSettings(writer http.ResponseWriter, request *http.Request) {
	if s.Runtime == nil {
		writeError(writer, http.StatusServiceUnavailable, "runtime settings unavailable")
		return
	}
	var body json.RawMessage
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid settings payload")
		return
	}
	current := s.Runtime.Snapshot()
	if row, err := s.Store.LoadRuntimeSettings(request.Context()); err == nil && row.Seeded {
		current = row.Settings
	}
	merged, err := runtimesettings.MergePatch(current, body)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if err := merged.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	var actor *uuid.UUID
	if session, ok := request.Context().Value(sessionKey).(store.Session); ok {
		id := session.User.ID
		actor = &id
	}
	saved, err := s.Store.SaveRuntimeSettings(request.Context(), merged, actor)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	s.Runtime.Replace(saved.Settings)
	if s.OnRuntimeSettingsChanged != nil {
		s.OnRuntimeSettingsChanged(saved.Settings)
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"settings":  saved.Settings.PublicView(),
		"updatedAt": saved.UpdatedAt,
		"updatedBy": saved.UpdatedBy,
	})
}

func (s *Server) downloadContainerLimitsEnv(writer http.ResponseWriter, request *http.Request) {
	doc := s.runtimeDocument()
	if row, err := s.Store.LoadRuntimeSettings(request.Context()); err == nil && row.Seeded {
		doc = row.Settings
	}
	fragment := doc.Containers.ComposeEnvFragment()
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Content-Disposition", `attachment; filename="container-limits.env"`)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte(fragment))
}
