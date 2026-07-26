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
	"collector/internal/archive"
	"collector/internal/config"
	ftpclient "collector/internal/ftp"
	"collector/internal/ingest"
	"collector/internal/spool"
	"collector/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/xuri/excelize/v2"
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
			private.With(s.requireAdmin).Get("/devices/{deviceID}/syslog-diagnostics", s.syslogDiagnostics)
			private.Get("/devices/{deviceID}/calls/{recordID}/timeline", s.callTimeline)
			private.Get("/devices/{deviceID}/antifraud/{transactionID}/timeline", s.antifraudTimeline)
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

func (s *Server) systemInfo(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	services := map[string]bool{"api": true}
	services["postgres"] = s.Store.DB.Ping(ctx) == nil
	services["clickhouse"] = s.Analytics.Conn.Ping(ctx) == nil
	services["nats"] = s.NATS != nil && s.NATS.IsConnected()
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
	for _, configured := range devices {
		metrics := fleet.Devices[configured.ID]
		if metrics == nil {
			metrics = &analytics.DashboardDevice{DeviceID: configured.ID}
		}
		if configured.Enabled && configured.PurgeState == "active" {
			activeDevices++
		}
		calls += metrics.Calls
		failed += metrics.FailedCalls
		alarms += metrics.Alarms
		unknown += metrics.Unknown
		antifraud += metrics.Antifraud
		rejects += metrics.AntifraudRejected
		incomplete += metrics.AntifraudIncomplete
		weightedTalk += metrics.AverageTalkMS * float64(metrics.Calls)
		rows = append(rows, map[string]any{
			"id": configured.ID, "name": configured.Name, "model": configured.Model,
			"firmware": configured.Firmware, "timezone": configured.Timezone,
			"enabled": configured.Enabled, "metrics": metrics,
			"freshness": map[string]any{
				"latestSyslogAt": metrics.LatestSyslogAt, "latestCdrAt": metrics.LatestCDRAt,
			},
			"revision": map[string]any{
				"configured": configured.TimezoneRevision,
				"active":     metrics.ActiveRevision, "building": metrics.BuildingRevision,
				"status":  metrics.RevisionStatus,
				"aligned": uint64(configured.ActiveTimezoneRevision) == metrics.ActiveRevision,
			},
		})
	}
	averageTalk := float64(0)
	if calls > 0 {
		averageTalk = weightedTalk / float64(calls)
	}
	totals["calls"], totals["failed"], totals["averageTalkMs"] = calls, failed, averageTalk
	totals["alarms"], totals["unknown"], totals["antifraud"] = alarms, unknown, antifraud
	totals["rejects"], totals["incomplete"], totals["activeDevices"] = rejects, incomplete, activeDevices

	services := map[string]bool{"api": true}
	serviceCtx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	services["postgres"] = s.Store.DB.Ping(serviceCtx) == nil
	services["clickhouse"] = s.Analytics.Conn.Ping(serviceCtx) == nil
	services["nats"] = s.NATS != nil && s.NATS.IsConnected()
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
		"window": windowText, "totals": totals, "devices": rows,
		"system": map[string]any{
			"version": s.Version, "services": services, "runtime": runtime,
			"spoolDepth": spoolDepth, "natsStreamMessages": natsMessages,
		},
		"diagnostics": fleet.Diagnostics,
	})
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
	if err := ingest.UnblockIngressSource(
		request.Context(), s.Config.IngressControlPath, device.SyslogSourceIP,
	); err != nil {
		_ = s.Store.DeleteDevice(request.Context(), device.ID, session.User, request.RemoteAddr)
		writeError(writer, http.StatusBadGateway, "unable to enable source-preserving Syslog ingress")
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
	if err := s.Analytics.ScheduleDeviceRebuild(
		request.Context(), device.ID, uint64(device.TimezoneRevision), device.Timezone,
	); err != nil {
		slog.Error("unable to initialize device derived revision",
			"device", device.ID, "error", err)
		writeError(writer, http.StatusInternalServerError,
			"device created, but derived revision initialization failed")
		return
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
	if previous.SyslogSourceIP != device.SyslogSourceIP {
		if _, err := ingest.PurgeIngressSource(
			request.Context(), s.Config.IngressControlPath, previous.SyslogSourceIP,
		); err != nil {
			writeError(writer, http.StatusBadGateway, "device saved; old Syslog source could not be fenced")
			return
		}
	}
	if err := ingest.UnblockIngressSource(
		request.Context(), s.Config.IngressControlPath, device.SyslogSourceIP,
	); err != nil {
		writeError(writer, http.StatusBadGateway, "device saved; Syslog source could not be enabled")
		return
	}
	if device.TimezoneRevision != device.ActiveTimezoneRevision {
		if err := s.Analytics.ScheduleDeviceRebuild(
			request.Context(), device.ID, uint64(device.TimezoneRevision), device.Timezone,
		); err != nil {
			slog.Error("unable to schedule device timezone revision",
				"device", device.ID, "revision", device.TimezoneRevision, "error", err)
			writeError(writer, http.StatusInternalServerError,
				"device saved; timezone rebuild could not be scheduled")
			return
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
	if _, err := ingest.PurgeIngressSource(ctx, s.Config.IngressControlPath, device.SyslogSourceIP); err != nil {
		fail("ingress", fmt.Errorf("unable to purge ingress queue: %w", err))
		return
	}
	if s.FTP != nil {
		if err := s.FTP.DeleteUser(ctx, device.FTPUsername); err != nil {
			fail("ftp", fmt.Errorf("unable to remove FTP account: %w", err))
			return
		}
	}
	if s.Spool != nil {
		if _, err := s.Spool.DeleteMatching(func(payload []byte) bool {
			var raw ingest.RawSyslog
			return json.Unmarshal(payload, &raw) == nil && raw.DeviceID == id
		}); err != nil {
			fail("spool", fmt.Errorf("unable to purge Syslog spool: %w", err))
			return
		}
	}
	if err := ingest.PurgeDeviceNATS(ctx, s.NATS, id); err != nil {
		fail("nats", fmt.Errorf("unable to purge NATS messages: %w", err))
		return
	}
	// The worker fetch timeout is one second. Let already fetched messages observe
	// the durable deleting tombstone and terminate before analytics mutations.
	select {
	case <-ctx.Done():
		fail("drain", ctx.Err())
		return
	case <-time.After(2 * time.Second):
	}
	if err := s.Analytics.PurgeDeviceData(ctx, id); err != nil {
		fail("clickhouse", err)
		return
	}
	if s.Archive != nil {
		if err := s.Archive.DeletePrefix(ctx, "cdr/"+id.String()+"/"); err != nil {
			fail("minio", fmt.Errorf("unable to purge CDR archive: %w", err))
			return
		}
	}
	if err := os.RemoveAll(filepath.Join("/data/cdr", id.String())); err != nil {
		fail("cdr-volume", fmt.Errorf("unable to purge CDR files: %w", err))
		return
	}
	// A second synchronous sweep closes races with correlation/rebuild work that
	// started before the deleting fence was visible.
	if err := s.Analytics.PurgeDeviceData(ctx, id); err != nil {
		fail("clickhouse-resweep", err)
		return
	}
	if err := s.Store.FinalizeDevicePurge(ctx, id); err != nil {
		fail("postgres", fmt.Errorf("unable to purge PostgreSQL device data: %w", err))
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
	page, err := s.Analytics.ListEventsPage(request.Context(), deviceID,
		request.URL.Query().Get("category"), request.URL.Query().Get("q"), limit, cursor)
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
	limit, _ := strconv.ParseUint(request.URL.Query().Get("limit"), 10, 64)
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
	limit, _ := strconv.ParseUint(request.URL.Query().Get("limit"), 10, 64)
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
	page, err := s.Analytics.ListCallsPage(
		request.Context(), deviceID, request.URL.Query().Get("q"), limit, cursor,
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
	})
}

func (s *Server) listAntifraud(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	limit, _ := strconv.ParseUint(request.URL.Query().Get("limit"), 10, 64)
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
	page, err := s.Analytics.ListAntifraudPage(
		request.Context(), deviceID, request.URL.Query().Get("q"), limit, cursor,
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
	stats, err := s.Analytics.Stats(request.Context(), deviceID)
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
	response["buildingRevision"] = diagnostics.BuildingRevision
	response["revisionTimezone"] = diagnostics.RevisionTimezone
	response["revisionStatus"] = diagnostics.RevisionStatus
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

func (s *Server) antifraudTimeline(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
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

func (s *Server) exportXLSX(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	device, err := s.Store.Device(request.Context(), deviceID)
	if err != nil {
		writeError(writer, http.StatusNotFound, "device not found")
		return
	}
	location, err := time.LoadLocation(device.ActiveTimezone)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "invalid device timezone")
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
			values := []any{
				formatTimeInLocation(row.SetupTime, location),
				row.IncomingDescription, row.OutgoingDescription, row.IncomingCgPN,
				row.OutgoingCgPN, row.IncomingCdPN, row.OutgoingCdPN, row.DurationMS, row.ReleaseCause,
				row.ReleaseInfo, row.RadiusSessionID, row.UniqueTag}
			cell, _ := excelize.CoordinatesToCellName(1, index+2)
			_ = stream.SetRow(cell, values)
		}
	} else if dataset == "antifraud" {
		headers := []any{
			"Первое событие", "Последнее событие", "Call context", "Acct-Session-Id",
			"Операция", "Запрос", "Ответ", "Решение", "Причина", "RADIUS server",
			"Latency, мс", "Повторы", "Calling", "Called", "Номер A вход",
			"Номер B вход", "Номер A выход", "Номер B выход", "Входящий trunk",
			"Исходящий trunk", "Accounting", "Q.850", "Полнота", "CDR legs", "Атрибуты",
			"CDR setup", "CDR Acct-Session-Id", "Метод корреляции", "Confidence",
			"Delta, мс", "Неоднозначность",
		}
		_ = stream.SetRow("A1", headers)
		var cursor *analytics.AntifraudCursor
		rowNumber := 1
		for {
			page, queryErr := s.Analytics.ListAntifraudPage(
				request.Context(), deviceID, search, 10000, cursor,
			)
			if queryErr != nil {
				writeError(writer, http.StatusInternalServerError, "unable to export AntiFraud")
				return
			}
			for _, row := range page.Items {
				rowNumber++
				attributes, _ := json.Marshal(row.Attributes)
				cell, _ := excelize.CoordinatesToCellName(1, rowNumber)
				_ = stream.SetRow(cell, []any{
					formatTimeInLocation(&row.FirstEventAt, location),
					formatTimeInLocation(&row.LastEventAt, location),
					row.CallContext, row.AcctSessionID,
					row.RequestType, row.RequestCode, row.ResponseCode, row.Decision,
					row.DecisionReason, row.ServerAddress, row.LatencyMS, row.Retries,
					row.CallingStationID, row.CalledStationID, row.SrcNumberIn,
					row.DstNumberIn, row.SrcNumberOut, row.DstNumberOut,
					row.InTrunkgroupLabel, row.OutTrunkgroupLabel, row.AccountingStatus,
					row.Q850Cause, row.Completeness, row.LegCount, string(attributes),
					formatTimeInLocation(row.CDRSetupTime, location), row.CDRSessionID,
					row.CorrelationMethod, row.CorrelationConfidence,
					row.CorrelationTimeDeltaMS, row.AmbiguityReason,
				})
			}
			if !page.HasMore || len(page.Items) == 0 {
				break
			}
			last := page.Items[len(page.Items)-1]
			cursor = &analytics.AntifraudCursor{
				LastEventAt: last.LastEventAt, TransactionID: last.TransactionID,
			}
		}
	} else {
		category := request.URL.Query().Get("category")
		headers := []any{"Получено", "Раздел", "Компонент", "Сообщение", "Исходный Syslog", "Статус", "Атрибуты"}
		_ = stream.SetRow("A1", headers)
		var cursor *analytics.EventCursor
		rowInSheet := 1
		totalRows := 0
		sheetNumber := 1
		for {
			page, queryErr := s.Analytics.ListEventsPage(
				request.Context(), deviceID, category, search, 10000, cursor,
			)
			if queryErr != nil {
				writeError(writer, http.StatusInternalServerError, "unable to export events")
				return
			}
			for _, row := range page.Items {
				if rowInSheet >= 1000000 {
					if err := stream.Flush(); err != nil {
						writeError(writer, http.StatusInternalServerError, "unable to finalize export sheet")
						return
					}
					sheetNumber++
					sheet = fmt.Sprintf("Data %d", sheetNumber)
					if _, err := workbook.NewSheet(sheet); err != nil {
						writeError(writer, http.StatusInternalServerError, "unable to create export sheet")
						return
					}
					stream, err = workbook.NewStreamWriter(sheet)
					if err != nil {
						writeError(writer, http.StatusInternalServerError, "unable to create export stream")
						return
					}
					_ = stream.SetRow("A1", headers)
					rowInSheet = 1
				}
				rowInSheet++
				totalRows++
				attributes, _ := json.Marshal(row.Attributes)
				cell, _ := excelize.CoordinatesToCellName(1, rowInSheet)
				eventTime := row.EventTime
				if eventTime == nil {
					eventTime = &row.ReceivedAt
				}
				_ = stream.SetRow(cell, []any{
					formatTimeInLocation(eventTime, location), row.Category, row.Component, row.Message,
					row.RawPayload, row.Status, string(attributes)})
			}
			if !page.HasMore || len(page.Items) == 0 {
				break
			}
			last := page.Items[len(page.Items)-1]
			cursor = &analytics.EventCursor{ReceivedAt: last.ReceivedAt, EventID: last.EventID}
		}
		writer.Header().Set("X-Export-Rows", strconv.Itoa(totalRows))
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

func formatTimeInLocation(value *time.Time, location *time.Location) string {
	if value == nil {
		return ""
	}
	return value.In(location).Format("2006-01-02 15:04:05.000")
}
