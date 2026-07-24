package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"collector/internal/analytics"
	"collector/internal/config"
	ftpclient "collector/internal/ftp"
	"collector/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/xuri/excelize/v2"
)

const sessionCookie = "collector_session"

type Server struct {
	Config    config.Config
	Store     *store.Store
	Analytics *analytics.Client
	FTP       *ftpclient.Provisioner
	StaticDir string
}

type contextKey string

const sessionKey contextKey = "session"

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.RequestID, middleware.RealIP, middleware.Recoverer, s.securityHeaders)
	router.Get("/health/live", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	router.Get("/health/ready", s.ready)
	router.Route("/api", func(api chi.Router) {
		api.Get("/bootstrap/status", s.bootstrapStatus)
		api.Post("/bootstrap", s.bootstrap)
		api.Post("/auth/login", s.login)
		api.Group(func(private chi.Router) {
			private.Use(s.authenticate)
			private.Get("/auth/me", s.me)
			private.Post("/auth/logout", s.logout)
			private.Get("/devices", s.listDevices)
			private.With(s.requireAdmin).Post("/devices", s.createDevice)
			private.With(s.requireAdmin).Delete("/devices/{deviceID}", s.deleteDevice)
			private.Get("/devices/{deviceID}/events", s.listEvents)
			private.Get("/devices/{deviceID}/calls", s.listCalls)
			private.Get("/devices/{deviceID}/stats", s.deviceStats)
			private.Get("/devices/{deviceID}/calls/{recordID}/timeline", s.callTimeline)
			private.Get("/devices/{deviceID}/export.xlsx", s.exportXLSX)
		})
	})
	router.Handle("/*", s.staticHandler())
	return router
}

func (s *Server) ready(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.DB.Ping(ctx); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "postgres unavailable")
		return
	}
	if err := s.Analytics.Conn.Ping(ctx); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "clickhouse unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) bootstrapStatus(writer http.ResponseWriter, request *http.Request) {
	bootstrapped, err := s.Store.IsBootstrapped(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to read bootstrap state")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]bool{"bootstrapped": bootstrapped})
}

func (s *Server) bootstrap(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	user, err := s.Store.CreateInitialAdmin(request.Context(), input.Username, input.Password)
	if err != nil {
		writeError(writer, http.StatusConflict, err.Error())
		return
	}
	s.issueSession(writer, request, user)
}

func (s *Server) login(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	user, err := s.Store.Authenticate(request.Context(), input.Username, input.Password)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.issueSession(writer, request, user)
}

func (s *Server) issueSession(writer http.ResponseWriter, request *http.Request, user store.User) {
	token, csrf, err := s.Store.CreateSession(request.Context(), user, s.Config.SessionTTL,
		request.UserAgent(), request.RemoteAddr)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to create session")
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.Config.SecureCookies,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.Config.SessionTTL.Seconds()),
	})
	writeJSON(writer, http.StatusOK, map[string]any{"user": user, "csrfToken": csrf})
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(sessionCookie)
		if err != nil || cookie.Value == "" {
			writeError(writer, http.StatusUnauthorized, "authentication required")
			return
		}
		requireCSRF := request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodOptions
		session, err := s.Store.Session(request.Context(), cookie.Value, request.Header.Get("X-CSRF-Token"), requireCSRF)
		if err != nil {
			writeError(writer, http.StatusUnauthorized, "session expired")
			return
		}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), sessionKey, session)))
	})
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session := currentSession(request)
		if session.User.Role != "admin" {
			writeError(writer, http.StatusForbidden, "administrator role required")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) me(writer http.ResponseWriter, request *http.Request) {
	session := currentSession(request)
	writeJSON(writer, http.StatusOK, map[string]any{"user": session.User, "csrfToken": session.CSRF})
}

func (s *Server) logout(writer http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie(sessionCookie); err == nil {
		_ = s.Store.DeleteSession(request.Context(), cookie.Value)
	}
	http.SetCookie(writer, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) listDevices(writer http.ResponseWriter, request *http.Request) {
	devices, err := s.Store.ListDevices(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to list devices")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": devices})
}

func (s *Server) createDevice(writer http.ResponseWriter, request *http.Request) {
	var input store.NewDevice
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	session := currentSession(request)
	device, err := s.Store.CreateDevice(request.Context(), input, session.User, request.RemoteAddr)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if s.FTP != nil {
		if err := s.FTP.CreateUser(request.Context(), device.FTPUsername, device.GeneratedPassword, device.FTPHome); err != nil {
			slog.Error("FTP account provisioning failed", "device", device.ID, "error", err)
			_ = s.Store.DeleteDevice(request.Context(), device.ID, session.User, request.RemoteAddr)
			writeError(writer, http.StatusBadGateway, "unable to provision isolated FTP account")
			return
		}
	}
	writeJSON(writer, http.StatusCreated, device)
}

func (s *Server) deleteDevice(writer http.ResponseWriter, request *http.Request) {
	id, err := uuid.Parse(chi.URLParam(request, "deviceID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid device id")
		return
	}
	session := currentSession(request)
	devices, err := s.Store.ListDevices(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to find device")
		return
	}
	var username string
	for _, device := range devices {
		if device.ID == id {
			username = device.FTPUsername
			break
		}
	}
	if username == "" {
		writeError(writer, http.StatusNotFound, "device not found")
		return
	}
	if s.FTP != nil {
		if err := s.FTP.DeleteUser(request.Context(), username); err != nil {
			writeError(writer, http.StatusBadGateway, "unable to remove FTP account")
			return
		}
	}
	if err := s.Store.DeleteDevice(request.Context(), id, session.User, request.RemoteAddr); err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to delete device")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) listEvents(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	limit, _ := strconv.ParseUint(request.URL.Query().Get("limit"), 10, 64)
	rows, err := s.Analytics.ListEvents(request.Context(), deviceID,
		request.URL.Query().Get("category"), request.URL.Query().Get("q"), limit)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query events")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": rows})
}

func (s *Server) listCalls(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	limit, _ := strconv.ParseUint(request.URL.Query().Get("limit"), 10, 64)
	rows, err := s.Analytics.ListCalls(request.Context(), deviceID, request.URL.Query().Get("q"), limit)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query calls")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": rows})
}

func (s *Server) deviceStats(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	stats, err := s.Analytics.Stats(request.Context(), deviceID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query device statistics")
		return
	}
	writeJSON(writer, http.StatusOK, stats)
}

func (s *Server) callTimeline(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	recordID, err := uuid.Parse(chi.URLParam(request, "recordID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid record id")
		return
	}
	rows, err := s.Analytics.CallTimeline(request.Context(), deviceID, recordID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query call timeline")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": rows})
}

func (s *Server) exportXLSX(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	dataset := request.URL.Query().Get("dataset")
	search := request.URL.Query().Get("q")
	workbook := excelize.NewFile()
	defer workbook.Close()
	sheet := "Data"
	workbook.SetSheetName("Sheet1", sheet)
	stream, err := workbook.NewStreamWriter(sheet)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to create export")
		return
	}
	if dataset == "calls" {
		rows, queryErr := s.Analytics.ListCalls(request.Context(), deviceID, search, 50000)
		if queryErr != nil {
			writeError(writer, http.StatusInternalServerError, "unable to export calls")
			return
		}
		headers := []any{"Установка", "Входящий маршрут", "Исходящий маршрут", "Номер A вход", "Номер A выход",
			"Номер B вход", "Номер B выход", "Длительность, мс", "Q.850", "Результат", "Acct-Session-Id", "UniqueTag"}
		_ = stream.SetRow("A1", headers)
		for index, row := range rows {
			values := []any{row.SetupTime, row.IncomingDescription, row.OutgoingDescription, row.IncomingCgPN,
				row.OutgoingCgPN, row.IncomingCdPN, row.OutgoingCdPN, row.DurationMS, row.ReleaseCause,
				row.ReleaseInfo, row.RadiusSessionID, row.UniqueTag}
			cell, _ := excelize.CoordinatesToCellName(1, index+2)
			_ = stream.SetRow(cell, values)
		}
	} else {
		category := request.URL.Query().Get("category")
		rows, queryErr := s.Analytics.ListEvents(request.Context(), deviceID, category, search, 50000)
		if queryErr != nil {
			writeError(writer, http.StatusInternalServerError, "unable to export events")
			return
		}
		_ = stream.SetRow("A1", []any{"Получено", "Раздел", "Компонент", "Сообщение", "Статус", "Атрибуты"})
		for index, row := range rows {
			attributes, _ := json.Marshal(row.Attributes)
			cell, _ := excelize.CoordinatesToCellName(1, index+2)
			_ = stream.SetRow(cell, []any{row.ReceivedAt, row.Category, row.Component, row.Message, row.Status, string(attributes)})
		}
	}
	if err := stream.Flush(); err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to finalize export")
		return
	}
	writer.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="smg-%s-%s.xlsx"`, deviceID.String()[:8], time.Now().UTC().Format("20060102-150405")))
	if err := workbook.Write(writer); err != nil {
		slog.Error("XLSX response failed", "error", err)
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "same-origin")
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) staticHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := filepath.Join(s.StaticDir, filepath.Clean(request.URL.Path))
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			http.ServeFile(writer, request, path)
			return
		}
		index := filepath.Join(s.StaticDir, "index.html")
		if _, err := os.Stat(index); err != nil {
			writeError(writer, http.StatusNotFound, "web application is not built")
			return
		}
		http.ServeFile(writer, request, index)
	})
}

func parseDeviceID(writer http.ResponseWriter, request *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(request, "deviceID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid device id")
		return uuid.Nil, false
	}
	return id, true
}

func currentSession(request *http.Request) store.Session {
	session, _ := request.Context().Value(sessionKey).(store.Session)
	return session
}

func decodeJSON(request *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

func remoteIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil {
		return host
	}
	return strings.Trim(request.RemoteAddr, "[]")
}
