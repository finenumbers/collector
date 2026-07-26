package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"collector/internal/analytics"
	"collector/internal/archive"
	"collector/internal/config"
	"collector/internal/equipment"
	"collector/internal/exportworker"
	ftpclient "collector/internal/ftp"
	"collector/internal/ingest"
	"collector/internal/spool"
	"collector/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const sessionCookie = "collector_session"

type Server struct {
	Config             config.Config
	Store              *store.Store
	Analytics          *analytics.Client
	FTP                *ftpclient.Provisioner
	Archive            *archive.Archive
	StaticDir          string
	Version            string
	Metrics            *ingest.Metrics
	Spool              *spool.Queue
	NATS               *nats.Conn
	IngressStatusPath  string
	ExportHealth       *exportworker.Health
	ReconcileRetention func(context.Context) error
}

type contextKey string

const sessionKey contextKey = "session"

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.RequestID, middleware.RealIP, middleware.Recoverer, s.securityHeaders)
	router.Get("/health/live", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok", "version": s.Version})
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
			private.Get("/system/info", s.systemInfo)
			private.Get("/dashboard", s.dashboard)
			private.Get("/equipment-templates", s.listEquipmentTemplates)
			private.With(s.requireAdmin).Get("/system/users", s.listUsers)
			private.With(s.requireAdmin).Post("/system/users", s.createUser)
			private.With(s.requireAdmin).Patch("/system/users/{userID}", s.updateUser)
			private.With(s.requireAdmin).Delete("/system/users/{userID}", s.deleteUser)
			private.With(s.requireAdmin).Get("/system/retention", s.listRetention)
			private.With(s.requireAdmin).Patch("/system/retention", s.updateRetention)
			private.Get("/devices", s.listDevices)
			private.With(s.requireAdmin).Post("/devices", s.createDevice)
			private.With(s.requireAdmin).Patch("/devices/{deviceID}", s.updateDevice)
			private.With(s.requireAdmin).Delete("/devices/{deviceID}", s.deleteDevice)
			private.Get("/devices/{deviceID}/events", s.listEvents)
			private.Get("/devices/{deviceID}/syslog-constructs", s.listSyslogConstructs)
			private.Get("/devices/{deviceID}/syslog-constructs/{constructID}", s.getSyslogConstruct)
			private.Get("/devices/{deviceID}/calls", s.listCalls)
			private.Get("/devices/{deviceID}/antifraud", s.listAntifraud)
			private.Get("/devices/{deviceID}/stats", s.deviceStats)
			private.Get("/devices/{deviceID}/ingest-files", s.listIngestFiles)
			private.Get("/devices/{deviceID}/ingest-files/{fileID}/download", s.downloadIngestFile)
			private.With(s.requireAdmin).Get("/devices/{deviceID}/syslog-diagnostics", s.syslogDiagnostics)
			private.Get("/devices/{deviceID}/calls/{recordID}/timeline", s.callTimeline)
			private.Get("/devices/{deviceID}/antifraud/{transactionID}/timeline", s.antifraudTimeline)
			private.Post("/devices/{deviceID}/export-jobs", s.createExportJob)
			private.Get("/devices/{deviceID}/export-jobs", s.listExportJobs)
			private.Get("/devices/{deviceID}/export-jobs/{jobID}", s.getExportJob)
			private.Post("/devices/{deviceID}/export-jobs/{jobID}/cancel", s.cancelExportJob)
			private.Get("/devices/{deviceID}/export-jobs/{jobID}/download", s.downloadExportJob)
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
	http.SetCookie(writer, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: s.Config.SecureCookies, SameSite: http.SameSiteStrictMode,
	})
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) listDevices(writer http.ResponseWriter, request *http.Request) {
	category := request.URL.Query().Get("category")
	if category != "" && category != equipment.CategoryEquipment &&
		category != equipment.CategorySoftswitch {
		writeError(writer, http.StatusBadRequest, "category must be equipment or softswitch")
		return
	}
	devices, err := s.Store.ListDevicesByCategory(request.Context(), category)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to list devices")
		return
	}
	type deviceWithReplay struct {
		store.Device
		Replay store.IngestReplayProgress `json:"replay"`
	}
	items := make([]deviceWithReplay, 0, len(devices))
	for _, device := range devices {
		replay, replayErr := s.Store.DeviceIngestReplayProgress(request.Context(), device.ID)
		if replayErr != nil {
			writeError(writer, http.StatusInternalServerError, "unable to load device replay progress")
			return
		}
		items = append(items, deviceWithReplay{Device: device, Replay: replay})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) listEquipmentTemplates(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"items": equipment.List()})
}

func (s *Server) systemInfo(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	services := map[string]bool{"api": true}
	services["postgres"] = s.Store.DB.Ping(ctx) == nil
	services["clickhouse"] = s.Analytics.Conn.Ping(ctx) == nil
	services["nats"] = s.NATS != nil && s.NATS.IsConnected()
	services["export_worker"] = s.ExportHealth == nil || s.ExportHealth.Available(10*time.Second)
	if s.Archive != nil {
		exists, err := s.Archive.Client.BucketExists(ctx, s.Archive.Bucket)
		services["minio"] = err == nil && exists
	} else {
		services["minio"] = false
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"version":  s.Version,
		"status":   "ready",
		"user":     currentSession(request).User,
		"services": services,
	})
}

func (s *Server) dashboard(writer http.ResponseWriter, request *http.Request) {
	windowText := request.URL.Query().Get("window")
	window, err := analytics.ValidateDashboardWindow(windowText)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if windowText == "" {
		windowText = "24h"
	}
	devices, err := s.Store.ListDevices(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to list devices")
		return
	}
	fleet := s.Analytics.Dashboard(request.Context(), window)
	rows := make([]map[string]any, 0, len(devices))
	totals := map[string]any{
		"calls": uint64(0), "failed": uint64(0), "averageTalkMs": float64(0),
		"alarms": uint64(0), "unknown": uint64(0), "antifraud": uint64(0),
		"rejects": uint64(0), "incomplete": uint64(0), "activeDevices": 0,
	}
	var calls, failed, alarms, unknown, antifraud, rejects, incomplete uint64
	var weightedTalk float64
	activeDevices := 0
	type categoryAccumulator struct {
		totalSources, activeSources      int
		calls, failed, alarms, unknown   uint64
		antifraud, rejects, files, bytes uint64
		weightedTalk                     float64
	}
	categoryTotals := map[string]*categoryAccumulator{
		equipment.CategoryEquipment:  {},
		equipment.CategorySoftswitch: {},
	}
	for _, configured := range devices {
		var metrics *analytics.DashboardDevice
		var fileMetrics *store.IngestFileMetrics
		if configured.Capabilities.TypedCDR || configured.Capabilities.Syslog {
			metrics = fleet.Devices[configured.ID]
			if metrics == nil {
				metrics = &analytics.DashboardDevice{DeviceID: configured.ID}
			}
		}
		if configured.SourceCategory == equipment.CategorySoftswitch {
			ledger, ledgerErr := s.Store.DeviceIngestFileMetrics(request.Context(), configured.ID)
			if ledgerErr != nil {
				fleet.Diagnostics = append(fleet.Diagnostics, "ingest ledger: "+ledgerErr.Error())
			} else {
				fileMetrics = &ledger
			}
		}
		if configured.Enabled && configured.PurgeState == "active" {
			activeDevices++
		}
		category := categoryTotals[configured.SourceCategory]
		if category == nil {
			category = &categoryAccumulator{}
			categoryTotals[configured.SourceCategory] = category
		}
		category.totalSources++
		if configured.Enabled && configured.PurgeState == "active" {
			category.activeSources++
		}
		if metrics != nil {
			calls += metrics.Calls
			failed += metrics.FailedCalls
			alarms += metrics.Alarms
			unknown += metrics.Unknown
			antifraud += metrics.Antifraud
			rejects += metrics.AntifraudRejected
			incomplete += metrics.AntifraudIncomplete
			weightedTalk += metrics.AverageTalkMS * float64(metrics.Calls)
			category.calls += metrics.Calls
			category.failed += metrics.FailedCalls
			category.alarms += metrics.Alarms
			category.unknown += metrics.Unknown
			category.antifraud += metrics.Antifraud
			category.rejects += metrics.AntifraudRejected
			category.weightedTalk += metrics.AverageTalkMS * float64(metrics.Calls)
		}
		if fileMetrics != nil {
			category.files += fileMetrics.Files
			category.bytes += fileMetrics.Bytes
		}
		rows = append(rows, dashboardDeviceRow(configured, metrics, fileMetrics))
	}
	averageTalk := float64(0)
	if calls > 0 {
		averageTalk = weightedTalk / float64(calls)
	}
	totals["calls"], totals["failed"], totals["averageTalkMs"] = calls, failed, averageTalk
	totals["alarms"], totals["unknown"], totals["antifraud"] = alarms, unknown, antifraud
	totals["rejects"], totals["incomplete"], totals["activeDevices"] = rejects, incomplete, activeDevices
	categoryResponse := make(map[string]any, len(categoryTotals))
	for name, category := range categoryTotals {
		average := float64(0)
		if category.calls > 0 {
			average = category.weightedTalk / float64(category.calls)
		}
		categoryResponse[name] = map[string]any{
			"totalSources": category.totalSources, "activeSources": category.activeSources,
			"calls": category.calls, "failed": category.failed, "averageTalkMs": average,
			"alarms": category.alarms, "unknown": category.unknown,
			"antifraud": category.antifraud, "rejects": category.rejects,
			"files": category.files, "bytes": category.bytes,
		}
	}

	services := map[string]bool{"api": true}
	serviceCtx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	services["postgres"] = s.Store.DB.Ping(serviceCtx) == nil
	services["clickhouse"] = s.Analytics.Conn.Ping(serviceCtx) == nil
	services["nats"] = s.NATS != nil && s.NATS.IsConnected()
	services["export_worker"] = s.ExportHealth == nil || s.ExportHealth.Available(10*time.Second)
	var spoolDepth uint64
	if s.Spool != nil {
		if depth, depthErr := s.Spool.Depth(); depthErr == nil {
			spoolDepth = depth
		} else {
			fleet.Diagnostics = append(fleet.Diagnostics, "spool: "+depthErr.Error())
		}
	}
	var natsMessages uint64
	if s.NATS != nil {
		if js, jsErr := s.NATS.JetStream(); jsErr == nil {
			if info, infoErr := js.StreamInfo("SYSLOG"); infoErr == nil {
				natsMessages = info.State.Msgs
			} else {
				fleet.Diagnostics = append(fleet.Diagnostics, "nats: "+infoErr.Error())
			}
		}
	}
	var runtime any
	if s.Metrics != nil {
		runtime = s.Metrics.Snapshot()
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"window": windowText, "totals": totals, "categoryTotals": categoryResponse, "devices": rows,
		"system": map[string]any{
			"version": s.Version, "services": services, "runtime": runtime,
			"spoolDepth": spoolDepth, "natsStreamMessages": natsMessages,
		},
		"diagnostics": fleet.Diagnostics,
	})
}

func dashboardDeviceRow(
	configured store.Device,
	metrics *analytics.DashboardDevice,
	fileMetrics *store.IngestFileMetrics,
) map[string]any {
	var latestSyslogAt, latestCDRAt any
	if metrics != nil {
		latestSyslogAt, latestCDRAt = metrics.LatestSyslogAt, metrics.LatestCDRAt
	} else if fileMetrics != nil {
		latestCDRAt = fileMetrics.LatestAt
	}
	revision := any(nil)
	if metrics != nil {
		revision = map[string]any{
			"configured": configured.TimezoneRevision,
			"active":     metrics.ActiveRevision, "building": metrics.BuildingRevision,
			"status": metrics.RevisionStatus, "reason": metrics.RevisionReason,
			"aligned": uint64(configured.ActiveTimezoneRevision) == metrics.ActiveRevision,
		}
	}
	activeTimezone := configured.ActiveTimezone
	if metrics != nil && metrics.ActiveTimezone != "" {
		activeTimezone = metrics.ActiveTimezone
	}
	return map[string]any{
		"id": configured.ID, "name": configured.Name, "model": configured.Model,
		"firmware": configured.Firmware, "timezone": configured.Timezone,
		"activeTimezone": activeTimezone,
		"sourceCategory": configured.SourceCategory, "templateKey": configured.TemplateKey,
		"capabilities": configured.Capabilities,
		"enabled":      configured.Enabled, "metrics": metrics, "fileMetrics": fileMetrics,
		"freshness": map[string]any{
			"latestSyslogAt": latestSyslogAt, "latestCdrAt": latestCDRAt,
		},
		"revision": revision,
	}
}

func (s *Server) listRetention(writer http.ResponseWriter, request *http.Request) {
	policies, err := s.Store.ListRetentionPolicies(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to list retention policies")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": policies})
}

func (s *Server) updateRetention(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		PolicyClass string `json:"policyClass"`
		Days        int    `json:"days"`
		Cancel      bool   `json:"cancel"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	session := currentSession(request)
	_, err := s.Store.UpdateRetentionPolicy(request.Context(), input.PolicyClass,
		input.Days, input.Cancel, session.User, request.RemoteAddr)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "retention policy not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if s.ReconcileRetention == nil {
		writeError(writer, http.StatusInternalServerError, "retention reconciler is unavailable")
		return
	}
	reconcileErr := s.ReconcileRetention(request.Context())
	policies, refreshErr := s.Store.ListRetentionPolicies(request.Context())
	var refreshed *store.RetentionPolicy
	for index := range policies {
		if policies[index].PolicyClass == input.PolicyClass {
			refreshed = &policies[index]
			break
		}
	}
	if reconcileErr != nil {
		if refreshErr == nil && refreshed != nil {
			writeJSON(writer, http.StatusBadGateway, map[string]any{
				"error":  "unable to apply retention policy",
				"policy": refreshed,
			})
			return
		}
		writeError(writer, http.StatusBadGateway, "unable to apply retention policy")
		return
	}
	if refreshErr != nil {
		writeError(writer, http.StatusInternalServerError, "unable to refresh retention policy")
		return
	}
	if refreshed != nil {
		writeJSON(writer, http.StatusOK, refreshed)
		return
	}
	writeError(writer, http.StatusNotFound, "retention policy not found")
}

func (s *Server) listUsers(writer http.ResponseWriter, request *http.Request) {
	users, err := s.Store.ListUsers(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to list users")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": users})
}

func (s *Server) createUser(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	session := currentSession(request)
	user, err := s.Store.CreateUser(
		request.Context(), input.Username, input.Password, input.Role,
		session.User, request.RemoteAddr,
	)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusCreated, user)
}

func (s *Server) updateUser(writer http.ResponseWriter, request *http.Request) {
	id, err := uuid.Parse(chi.URLParam(request, "userID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid user id")
		return
	}
	var input store.UserUpdate
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	session := currentSession(request)
	user, err := s.Store.UpdateUser(
		request.Context(), id, input, session.User, request.RemoteAddr,
	)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, user)
}

func (s *Server) deleteUser(writer http.ResponseWriter, request *http.Request) {
	id, err := uuid.Parse(chi.URLParam(request, "userID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid user id")
		return
	}
	session := currentSession(request)
	err = s.Store.DeleteUser(request.Context(), id, session.User, request.RemoteAddr)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writer.WriteHeader(http.StatusNoContent)
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
	if device.Capabilities.Syslog {
		if err := ingest.UnblockIngressSource(
			request.Context(), s.Config.IngressControlPath, device.SyslogSourceIP,
		); err != nil {
			_ = s.Store.DeleteDevice(request.Context(), device.ID, session.User, request.RemoteAddr)
			writeError(writer, http.StatusBadGateway, "unable to enable source-preserving Syslog ingress")
			return
		}
	}
	if s.FTP != nil {
		if err := s.FTP.CreateUser(request.Context(), device.FTPUsername, device.GeneratedPassword, device.FTPHome); err != nil {
			slog.Error("FTP account provisioning failed", "device", device.ID, "error", err)
			_ = s.Store.DeleteDevice(request.Context(), device.ID, session.User, request.RemoteAddr)
			writeError(writer, http.StatusBadGateway, "unable to provision isolated FTP account")
			return
		}
	}
	if (device.Capabilities.Syslog ||
		(device.Capabilities.TypedCDR && device.TemplateKey != equipment.TemplateSatelRTUCDRV1)) &&
		s.Analytics != nil {
		if err := s.Analytics.ScheduleDeviceRebuild(
			request.Context(), device.ID, uint64(device.TimezoneRevision), device.Timezone,
			analytics.RevisionReasonInitialBuild,
		); err != nil {
			slog.Error("unable to initialize device derived revision",
				"device", device.ID, "error", err)
			writeError(writer, http.StatusInternalServerError,
				"device created, but derived revision initialization failed")
			return
		}
	}
	writeJSON(writer, http.StatusCreated, device)
}

func (s *Server) updateDevice(writer http.ResponseWriter, request *http.Request) {
	id, err := uuid.Parse(chi.URLParam(request, "deviceID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid device id")
		return
	}
	previous, err := s.Store.Device(request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to load device")
		return
	}
	var input store.DeviceUpdate
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	session := currentSession(request)
	device, err := s.Store.UpdateDevice(
		request.Context(), id, input, session.User, request.RemoteAddr,
	)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if previous.Capabilities.Syslog &&
		(!device.Capabilities.Syslog || previous.SyslogSourceIP != device.SyslogSourceIP) {
		if _, err := ingest.PurgeIngressSource(
			request.Context(), s.Config.IngressControlPath, previous.SyslogSourceIP,
		); err != nil {
			writeError(writer, http.StatusBadGateway, "device saved; old Syslog source could not be fenced")
			return
		}
	}
	if device.Capabilities.Syslog {
		if err := ingest.UnblockIngressSource(
			request.Context(), s.Config.IngressControlPath, device.SyslogSourceIP,
		); err != nil {
			writeError(writer, http.StatusBadGateway, "device saved; Syslog source could not be enabled")
			return
		}
	}
	if device.TemplateKey == equipment.TemplateSatelRTUCDRV1 &&
		previous.Timezone != device.Timezone {
		if err := s.Analytics.ReinterpretSatelRTUTimes(
			request.Context(), device.ID, uint64(device.TimezoneRevision), device.Timezone,
		); err != nil {
			writeError(writer, http.StatusInternalServerError,
				"device saved; Satel RTU timezone reparse failed")
			return
		}
	} else if device.TimezoneRevision != device.ActiveTimezoneRevision {
		if device.Capabilities.Syslog || device.Capabilities.TypedCDR {
			if err := s.Analytics.ScheduleDeviceRebuild(
				request.Context(), device.ID, uint64(device.TimezoneRevision), device.Timezone,
				analytics.RevisionReasonTimezoneChange,
			); err != nil {
				slog.Error("unable to schedule device timezone revision",
					"device", device.ID, "revision", device.TimezoneRevision, "error", err)
				writeError(writer, http.StatusInternalServerError,
					"device saved; timezone rebuild could not be scheduled")
				return
			}
		}
	}
	writeJSON(writer, http.StatusOK, device)
}

func (s *Server) deleteDevice(writer http.ResponseWriter, request *http.Request) {
	id, err := uuid.Parse(chi.URLParam(request, "deviceID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid device id")
		return
	}
	// Client disconnect must not cancel an already started erase; only the
	// server-side deadline bounds the synchronous purge.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if controller := http.NewResponseController(writer); controller != nil {
		_ = controller.SetWriteDeadline(time.Now().Add(16 * time.Minute))
	}
	release := s.Store.LockDevicePurge(id)
	defer release()
	device, err := s.Store.BeginDevicePurge(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to fence device ingest")
		return
	}
	fail := func(phase string, purgeErr error) {
		_ = s.Store.FailDevicePurge(context.Background(), id, phase, purgeErr)
		slog.Error("device purge failed", "device", id, "phase", phase, "error", purgeErr)
		writeError(writer, http.StatusInternalServerError, phase+": "+purgeErr.Error())
	}
	if device.Capabilities.Syslog {
		if _, err := ingest.PurgeIngressSource(ctx, s.Config.IngressControlPath, device.SyslogSourceIP); err != nil {
			fail("ingress", fmt.Errorf("unable to purge ingress queue: %w", err))
			return
		}
	}
	if s.FTP != nil {
		if err := s.FTP.DeleteUser(ctx, device.FTPUsername); err != nil {
			fail("ftp", fmt.Errorf("unable to remove FTP account: %w", err))
			return
		}
	}
	if device.Capabilities.Syslog && s.Spool != nil {
		if _, err := s.Spool.DeleteMatching(func(payload []byte) bool {
			var raw ingest.RawSyslog
			return json.Unmarshal(payload, &raw) == nil && raw.DeviceID == id
		}); err != nil {
			fail("spool", fmt.Errorf("unable to purge Syslog spool: %w", err))
			return
		}
	}
	if device.Capabilities.Syslog {
		if err := ingest.PurgeDeviceNATS(ctx, s.NATS, id); err != nil {
			fail("nats", fmt.Errorf("unable to purge NATS messages: %w", err))
			return
		}
		select {
		case <-ctx.Done():
			fail("drain", ctx.Err())
			return
		case <-time.After(2 * time.Second):
		}
	}
	hasAnalytics := device.Capabilities.Syslog || device.Capabilities.TypedCDR
	if hasAnalytics {
		if err := s.Analytics.PurgeDeviceData(ctx, id); err != nil {
			fail("clickhouse", err)
			return
		}
	}
	if s.Archive != nil {
		if err := s.Archive.DeletePrefix(ctx, "cdr/"+id.String()+"/"); err != nil {
			fail("minio", fmt.Errorf("unable to purge CDR archive: %w", err))
			return
		}
		if err := s.Archive.DeletePrefix(ctx, "exports/"+id.String()+"/"); err != nil {
			fail("minio", fmt.Errorf("unable to purge export artifacts: %w", err))
			return
		}
	}
	if err := os.RemoveAll(filepath.Join("/data/cdr", id.String())); err != nil {
		fail("cdr-volume", fmt.Errorf("unable to purge CDR files: %w", err))
		return
	}
	// A second synchronous sweep closes races with correlation/rebuild work that
	// started before the deleting fence was visible.
	if hasAnalytics {
		if err := s.Analytics.PurgeDeviceData(ctx, id); err != nil {
			fail("clickhouse-resweep", err)
			return
		}
	}
	if err := s.Store.FinalizeDevicePurge(ctx, id); err != nil {
		fail("postgres", fmt.Errorf("unable to purge PostgreSQL device data: %w", err))
		return
	}
	if s.Archive != nil {
		if err := s.Archive.DeletePrefix(ctx, "exports/"+id.String()+"/"); err != nil {
			// PostgreSQL is already finalized, so the lifecycle rule is the
			// fallback for a transient MinIO failure during the race-closing sweep.
			slog.Error("unable to resweep export artifacts after device purge",
				"device", id, "error", err)
		}
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) listIngestFiles(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	_, err := s.Store.Device(request.Context(), deviceID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to load device")
		return
	}
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	items, err := s.Store.ListRecentIngestFiles(request.Context(), deviceID, limit)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to list ingest files")
		return
	}
	if items == nil {
		items = []store.IngestFileSummary{}
	}
	replay, err := s.Store.DeviceIngestReplayProgress(request.Context(), deviceID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to load ingest replay progress")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"items":  items,
		"replay": replay,
	})
}

func (s *Server) downloadIngestFile(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	fileID, err := uuid.Parse(chi.URLParam(request, "fileID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid ingest file id")
		return
	}
	item, err := s.Store.IngestFile(request.Context(), deviceID, fileID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "ingest file not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to load ingest file")
		return
	}
	if s.Archive == nil {
		writeError(writer, http.StatusServiceUnavailable, "archive unavailable")
		return
	}
	object, err := s.Archive.OpenObject(request.Context(), item.ObjectKey)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "unable to open archived file")
		return
	}
	defer object.Reader.Close()
	session := currentSession(request)
	if err := s.Store.AuditIngestFileDownload(
		request.Context(), fileID, session.User, request.RemoteAddr,
	); err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to audit file download")
		return
	}
	filename := sanitizeDownloadName(item.OriginalName)
	writer.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{
		"filename": filename,
	}))
	contentType := object.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Length", strconv.FormatInt(object.Size, 10))
	writer.WriteHeader(http.StatusOK)
	if _, err := io.Copy(writer, object.Reader); err != nil {
		slog.Warn("archived file response interrupted", "file", fileID, "error", err)
	}
}

func sanitizeDownloadName(value string) string {
	value = filepath.Base(strings.ReplaceAll(value, "\\", "/"))
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	if value == "" || value == "." {
		return "cdr-file"
	}
	return value
}

func deviceDateRange(
	writer http.ResponseWriter, request *http.Request, device store.Device,
) (*analytics.TimeRange, bool) {
	value := request.URL.Query().Get("date")
	if value == "" {
		return nil, true
	}
	timezone := device.ActiveTimezone
	if timezone == "" {
		timezone = device.Timezone
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "invalid device timezone")
		return nil, false
	}
	from, err := time.ParseInLocation("2006-01-02", value, location)
	if err != nil || from.Format("2006-01-02") != value {
		writeError(writer, http.StatusBadRequest, "date must use YYYY-MM-DD")
		return nil, false
	}
	return &analytics.TimeRange{From: from.UTC(), To: from.AddDate(0, 0, 1).UTC()}, true
}

func (s *Server) listEvents(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	device, ok := s.deviceWithCapability(writer, request, deviceID, func(device store.Device) bool {
		return device.Capabilities.Syslog
	}, "Syslog events")
	if !ok {
		return
	}
	timeRange, ok := deviceDateRange(writer, request, device)
	if !ok {
		return
	}
	limit := parsePageLimit(request)
	var cursor *analytics.EventCursor
	before := request.URL.Query().Get("before")
	beforeID := request.URL.Query().Get("before_id")
	if before != "" || beforeID != "" {
		receivedAt, timeErr := time.Parse(time.RFC3339Nano, before)
		eventID, idErr := uuid.Parse(beforeID)
		if timeErr != nil || idErr != nil {
			writeError(writer, http.StatusBadRequest, "invalid event cursor")
			return
		}
		cursor = &analytics.EventCursor{ReceivedAt: receivedAt, EventID: eventID}
	}
	page, err := s.Analytics.ListEventsPageRange(request.Context(), deviceID,
		request.URL.Query().Get("category"), request.URL.Query().Get("q"), limit, cursor, timeRange)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query events")
		return
	}
	var nextCursor any
	if page.HasMore && len(page.Items) > 0 {
		last := page.Items[len(page.Items)-1]
		nextCursor = map[string]any{"before": last.ReceivedAt, "beforeId": last.EventID}
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"items": page.Items, "hasMore": page.HasMore, "nextCursor": nextCursor,
	})
}

func (s *Server) listSyslogConstructs(writer http.ResponseWriter, request *http.Request) {
	if !s.Config.SyslogConstructsEnabled {
		writeJSON(writer, http.StatusNotFound, map[string]string{
			"error": "feature_disabled", "message": "Syslog constructs are disabled",
		})
		return
	}
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	if !s.requireDeviceCapability(writer, request, deviceID, func(device store.Device) bool {
		return device.Capabilities.Syslog
	}, "Syslog constructs") {
		return
	}
	limit := parsePageLimit(request)
	var cursor *analytics.SyslogConstructCursor
	before := request.URL.Query().Get("before")
	beforeID := request.URL.Query().Get("before_id")
	if before != "" || beforeID != "" {
		startedAt, timeErr := time.Parse(time.RFC3339Nano, before)
		constructID, idErr := uuid.Parse(beforeID)
		if timeErr != nil || idErr != nil {
			writeError(writer, http.StatusBadRequest, "invalid Syslog construct cursor")
			return
		}
		cursor = &analytics.SyslogConstructCursor{
			StartedAt: startedAt, ConstructID: constructID,
		}
	}
	page, err := s.Analytics.ListSyslogConstructsFilteredPage(
		request.Context(), deviceID, analytics.SyslogConstructFilters{
			Category:     request.URL.Query().Get("category"),
			Search:       request.URL.Query().Get("q"),
			Kind:         request.URL.Query().Get("kind"),
			Direction:    strings.ToUpper(request.URL.Query().Get("direction")),
			MessageName:  request.URL.Query().Get("message_name"),
			CallContext:  request.URL.Query().Get("call_context"),
			ProblemsOnly: request.URL.Query().Get("problems") == "true",
		}, limit, cursor,
	)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query Syslog constructs")
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

func (s *Server) getSyslogConstruct(writer http.ResponseWriter, request *http.Request) {
	if !s.Config.SyslogConstructsEnabled {
		writeJSON(writer, http.StatusNotFound, map[string]string{
			"error": "feature_disabled", "message": "Syslog constructs are disabled",
		})
		return
	}
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	if !s.requireDeviceCapability(writer, request, deviceID, func(device store.Device) bool {
		return device.Capabilities.Syslog
	}, "Syslog constructs") {
		return
	}
	constructID, err := uuid.Parse(chi.URLParam(request, "constructID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid Syslog construct id")
		return
	}
	detail, err := s.Analytics.GetSyslogConstruct(
		request.Context(), deviceID, constructID,
	)
	if errors.Is(err, analytics.ErrSyslogConstructNotFound) {
		writeError(writer, http.StatusNotFound, "Syslog construct not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query Syslog construct")
		return
	}
	writeJSON(writer, http.StatusOK, detail)
}

func (s *Server) listCalls(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	device, ok := s.deviceWithCapability(writer, request, deviceID, func(device store.Device) bool {
		return device.Capabilities.TypedCDR
	}, "typed CDR calls")
	if !ok {
		return
	}
	timeRange, ok := deviceDateRange(writer, request, device)
	if !ok {
		return
	}
	limit := parsePageLimit(request)
	var cursor *analytics.CallCursor
	before := request.URL.Query().Get("before")
	beforeID := request.URL.Query().Get("before_id")
	if before != "" || beforeID != "" {
		sortTime, timeErr := time.Parse(time.RFC3339Nano, before)
		recordID, idErr := uuid.Parse(beforeID)
		if timeErr != nil || idErr != nil {
			writeError(writer, http.StatusBadRequest, "invalid call cursor")
			return
		}
		cursor = &analytics.CallCursor{SortTime: sortTime, RecordID: recordID}
	}
	if device.TemplateKey == equipment.TemplateSatelRTUCDRV1 {
		var page analytics.SatelRTUCallPage
		var err error
		if timeRange != nil {
			page, err = s.Analytics.ListSatelRTUCallsPageRange(
				request.Context(), deviceID, request.URL.Query().Get("q"), limit, cursor, timeRange,
			)
		} else {
			page, err = s.Analytics.ListSatelRTUCallsPage(
				request.Context(), deviceID, request.URL.Query().Get("q"), limit, cursor,
			)
		}
		if err != nil {
			writeError(writer, http.StatusInternalServerError, "unable to query Satel RTU calls")
			return
		}
		var nextCursor any
		if page.HasMore && len(page.Items) > 0 {
			last := page.Items[len(page.Items)-1]
			nextCursor = map[string]any{"before": last.SortTime, "beforeId": last.RecordID}
		}
		writeJSON(writer, http.StatusOK, map[string]any{
			"items": page.Items, "hasMore": page.HasMore, "nextCursor": nextCursor,
			"templateKey": device.TemplateKey,
		})
		return
	}
	page, err := s.Analytics.ListCallsPageRange(
		request.Context(), deviceID, request.URL.Query().Get("q"), limit, cursor, timeRange,
	)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query calls")
		return
	}
	var nextCursor any
	if page.HasMore && len(page.Items) > 0 {
		last := page.Items[len(page.Items)-1]
		nextCursor = map[string]any{"before": last.SortTime, "beforeId": last.RecordID}
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"items": page.Items, "hasMore": page.HasMore, "nextCursor": nextCursor,
		"templateKey": device.TemplateKey,
	})
}

func (s *Server) listAntifraud(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	device, ok := s.deviceWithCapability(writer, request, deviceID, func(device store.Device) bool {
		return device.Capabilities.Antifraud && device.Capabilities.Radius
	}, "AntiFraud/RADIUS")
	if !ok {
		return
	}
	timeRange, ok := deviceDateRange(writer, request, device)
	if !ok {
		return
	}
	limit := parsePageLimit(request)
	var cursor *analytics.AntifraudCursor
	before := request.URL.Query().Get("before")
	beforeID := request.URL.Query().Get("before_id")
	if before != "" || beforeID != "" {
		lastEventAt, timeErr := time.Parse(time.RFC3339Nano, before)
		transactionID, idErr := uuid.Parse(beforeID)
		if timeErr != nil || idErr != nil {
			writeError(writer, http.StatusBadRequest, "invalid AntiFraud cursor")
			return
		}
		cursor = &analytics.AntifraudCursor{
			LastEventAt: lastEventAt, TransactionID: transactionID,
		}
	}
	page, err := s.Analytics.ListAntifraudPageRange(
		request.Context(), deviceID, request.URL.Query().Get("q"), limit, cursor, timeRange,
	)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query AntiFraud lifecycle")
		return
	}
	var nextCursor any
	if page.HasMore && len(page.Items) > 0 {
		last := page.Items[len(page.Items)-1]
		nextCursor = map[string]any{
			"before": last.LastEventAt, "beforeId": last.TransactionID,
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"items": page.Items, "hasMore": page.HasMore, "nextCursor": nextCursor,
	})
}

func (s *Server) deviceStats(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	device, ok := s.deviceWithCapability(writer, request, deviceID, func(device store.Device) bool {
		return device.Capabilities.Syslog || device.Capabilities.TypedCDR
	}, "analytics statistics")
	if !ok {
		return
	}
	timeRange, ok := deviceDateRange(writer, request, device)
	if !ok {
		return
	}
	var stats analytics.DeviceStats
	var err error
	if timeRange == nil && device.TemplateKey == equipment.TemplateSatelRTUCDRV1 {
		stats, err = s.Analytics.SatelRTUStats(request.Context(), deviceID)
	} else if device.TemplateKey == equipment.TemplateSatelRTUCDRV1 {
		stats, err = s.Analytics.SatelRTUStatsRange(request.Context(), deviceID, *timeRange)
	} else if timeRange != nil {
		stats, err = s.Analytics.StatsRange(request.Context(), deviceID, *timeRange)
	} else {
		stats, err = s.Analytics.Stats(request.Context(), deviceID)
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query device statistics")
		return
	}
	writeJSON(writer, http.StatusOK, stats)
}

func (s *Server) syslogDiagnostics(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	if !s.requireDeviceCapability(writer, request, deviceID, func(device store.Device) bool {
		return device.Capabilities.Syslog
	}, "Syslog diagnostics") {
		return
	}
	diagnostics, err := s.Analytics.SyslogDiagnostics(request.Context(), deviceID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query Syslog diagnostics")
		return
	}
	device, err := s.Store.Device(request.Context(), deviceID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query device revision")
		return
	}
	var spoolDepth, quarantineDepth uint64
	if s.Spool != nil {
		if spoolDepth, err = s.Spool.Depth(); err != nil {
			writeError(writer, http.StatusInternalServerError, "unable to query Syslog spool")
			return
		}
		if quarantineDepth, err = s.Spool.QuarantineDepth(); err != nil {
			writeError(writer, http.StatusInternalServerError, "unable to query Syslog quarantine")
			return
		}
	}
	var natsStreamMessages, natsConsumerPending uint64
	if s.NATS != nil {
		if js, natsErr := s.NATS.JetStream(); natsErr == nil {
			if info, infoErr := js.StreamInfo("SYSLOG"); infoErr == nil {
				natsStreamMessages = info.State.Msgs
			}
			if consumer, consumerErr := js.ConsumerInfo("SYSLOG", "syslog-parser"); consumerErr == nil {
				natsConsumerPending = consumer.NumPending + uint64(consumer.NumAckPending)
			}
		}
	}
	ingressStatus, ingressStatusErr := ingest.ReadIngressStatus(s.IngressStatusPath)
	ingressAvailable := ingressStatusErr == nil &&
		time.Since(ingressStatus.UpdatedAt) < 5*time.Second
	replay := map[string]any{"status": "not_started"}
	replayJobs, replayErr := s.Store.ListSyslogParserRebuildJobs(
		request.Context(), analytics.SyslogParserVersion,
	)
	if replayErr != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query Syslog replay progress")
		return
	}
	for _, job := range replayJobs {
		if job.DeviceID != deviceID {
			continue
		}
		progress := float64(0)
		if job.TotalEvents > 0 {
			progress = float64(job.ProcessedEvents) / float64(job.TotalEvents)
			if progress > 1 {
				progress = 1
			}
		}
		replay = map[string]any{
			"status": job.Status, "processedEvents": job.ProcessedEvents,
			"totalEvents": job.TotalEvents, "processedBatches": job.ProcessedBatches,
			"progress": progress, "attempts": job.Attempts, "error": job.Error,
			"heartbeatAt": job.HeartbeatAt, "updatedAt": job.UpdatedAt,
		}
		if job.StartedAt != nil && job.ProcessedEvents > 0 &&
			job.ProcessedEvents < job.TotalEvents {
			elapsed := time.Since(*job.StartedAt).Seconds()
			if elapsed > 0 {
				rate := float64(job.ProcessedEvents) / elapsed
				replay["eventsPerSecond"] = rate
				replay["etaSeconds"] = float64(job.TotalEvents-job.ProcessedEvents) / rate
			}
		}
		break
	}
	response := map[string]any{
		"version": s.Version, "parserVersion": analytics.SyslogParserVersion,
		"runtime": s.Metrics.Snapshot(), "spoolDepth": spoolDepth,
		"quarantineDepth": quarantineDepth, "natsStreamMessages": natsStreamMessages,
		"natsConsumerPending": natsConsumerPending, "breakdown": diagnostics.Breakdown,
		"appliedMigrations": diagnostics.AppliedMigrations,
		"rawEvents24h":      diagnostics.RawEvents24h, "classified24h": diagnostics.Classified24h,
		"reprocessedCurrent":   diagnostics.ReprocessedCurrent,
		"reprocessRemaining":   diagnostics.ReprocessRemaining,
		"antifraudComplete":    diagnostics.AntifraudComplete,
		"antifraudIncomplete":  diagnostics.AntifraudIncomplete,
		"antifraudOrphan":      diagnostics.AntifraudOrphan,
		"correlationExact":     diagnostics.CorrelationExact,
		"correlationComposite": diagnostics.CorrelationComposite,
		"correlationAmbiguous": diagnostics.CorrelationAmbiguous,
		"ingress":              ingressStatus, "ingressAvailable": ingressAvailable,
		"historicalReplay": replay,
	}
	addRevisionDiagnostics(response, diagnostics)
	response["ingestRevision"] = device.ActiveTimezoneRevision
	response["revisionAligned"] = uint64(device.ActiveTimezoneRevision) == diagnostics.ActiveRevision
	ingestFiles, ingestErr := s.Store.ListRecentIngestFiles(request.Context(), deviceID, 20)
	if ingestErr != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query CDR ingest ledger")
		return
	}
	if ingestFiles == nil {
		ingestFiles = []store.IngestFileSummary{}
	}
	response["cdrIngestFiles"] = ingestFiles
	writeJSON(writer, http.StatusOK, response)
}

func addRevisionDiagnostics(response map[string]any, diagnostics analytics.SyslogDiagnostics) {
	response["activeRevision"] = diagnostics.ActiveRevision
	response["activeRevisionTimezone"] = diagnostics.ActiveTimezone
	response["buildingRevision"] = diagnostics.BuildingRevision
	response["revisionTimezone"] = diagnostics.RevisionTimezone
	response["revisionStatus"] = diagnostics.RevisionStatus
	response["revisionReason"] = diagnostics.RevisionReason
	response["replayProcessed"] = diagnostics.ReplayProcessed
	response["replayTotal"] = diagnostics.ReplayTotal
	response["cdrReplayProcessed"] = diagnostics.CDRReplayProcessed
	response["cdrReplayTotal"] = diagnostics.CDRReplayTotal
	response["missingCdrInterpretations"] = diagnostics.MissingCDRTimes
	response["radiusRawFragments"] = diagnostics.RadiusRawFragments
	response["lifecycleDerived"] = diagnostics.LifecycleDerived
	response["correlationTotal"] = diagnostics.CorrelationTotal
	response["correlationOrphan"] = diagnostics.CorrelationOrphan
	response["latestRawAt"] = diagnostics.LatestRawAt
	response["latestFactAt"] = diagnostics.LatestFactAt
	response["latestLifecycleAt"] = diagnostics.LatestLifecycleAt
	response["latestAssignmentAt"] = diagnostics.LatestAssignmentAt
	response["pendingDirtyBuckets"] = diagnostics.PendingDirtyBuckets
	response["oldestDirtyAt"] = diagnostics.OldestDirtyAt
}

func (s *Server) callTimeline(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	device, ok := s.deviceWithCapability(writer, request, deviceID, func(device store.Device) bool {
		return device.Capabilities.TypedCDR
	}, "typed CDR calls")
	if !ok {
		return
	}
	recordID, err := uuid.Parse(chi.URLParam(request, "recordID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid record id")
		return
	}
	if device.TemplateKey == equipment.TemplateSatelRTUCDRV1 {
		writeJSON(writer, http.StatusOK, map[string]any{"items": []analytics.TimelineRow{}})
		return
	}
	rows, err := s.Analytics.CallTimeline(request.Context(), deviceID, recordID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query call timeline")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": rows})
}

func (s *Server) antifraudTimeline(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	if !s.requireDeviceCapability(writer, request, deviceID, func(device store.Device) bool {
		return device.Capabilities.Antifraud && device.Capabilities.Radius
	}, "AntiFraud/RADIUS") {
		return
	}
	transactionID, err := uuid.Parse(chi.URLParam(request, "transactionID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid AntiFraud transaction id")
		return
	}
	rows, err := s.Analytics.AntifraudTimeline(request.Context(), deviceID, transactionID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to query AntiFraud timeline")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": rows})
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
		root, err := os.OpenRoot(s.StaticDir)
		if err != nil {
			writeError(writer, http.StatusNotFound, "web application is not built")
			return
		}
		defer root.Close()
		relative := strings.TrimPrefix(path.Clean("/"+request.URL.Path), "/")
		if relative != "" && relative != "." {
			if file, openErr := root.Open(relative); openErr == nil {
				info, statErr := file.Stat()
				if statErr == nil && !info.IsDir() {
					defer file.Close()
					http.ServeContent(
						writer, request, filepath.Base(relative), info.ModTime(), file,
					)
					return
				}
				_ = file.Close()
			}
		}
		index, err := root.Open("index.html")
		if err != nil {
			writeError(writer, http.StatusNotFound, "web application is not built")
			return
		}
		defer index.Close()
		info, err := index.Stat()
		if err != nil || info.IsDir() {
			writeError(writer, http.StatusNotFound, "web application is not built")
			return
		}
		http.ServeContent(writer, request, "index.html", info.ModTime(), index)
	})
}

func parsePageLimit(request *http.Request) uint64 {
	const (
		defaultPageSize = uint64(200)
		maxPageSize     = uint64(1000)
	)
	limit, err := strconv.ParseUint(request.URL.Query().Get("limit"), 10, 64)
	if err != nil || limit == 0 {
		return defaultPageSize
	}
	return min(limit, maxPageSize)
}

func parseDeviceID(writer http.ResponseWriter, request *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(request, "deviceID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid device id")
		return uuid.Nil, false
	}
	return id, true
}

func (s *Server) requireDeviceCapability(
	writer http.ResponseWriter,
	request *http.Request,
	deviceID uuid.UUID,
	supported func(store.Device) bool,
	feature string,
) bool {
	_, ok := s.deviceWithCapability(writer, request, deviceID, supported, feature)
	return ok
}

func (s *Server) deviceWithCapability(
	writer http.ResponseWriter,
	request *http.Request,
	deviceID uuid.UUID,
	supported func(store.Device) bool,
	feature string,
) (store.Device, bool) {
	device, err := s.Store.Device(request.Context(), deviceID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "device not found")
		return store.Device{}, false
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to load device")
		return store.Device{}, false
	}
	if !supported(device) {
		writeError(writer, http.StatusConflict, feature+" is not supported by this source template")
		return store.Device{}, false
	}
	return device, true
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

func formatTimeInLocation(value *time.Time, location *time.Location) string {
	if value == nil {
		return ""
	}
	return value.In(location).Format("2006-01-02 15:04:05.000")
}
