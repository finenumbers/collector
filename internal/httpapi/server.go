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
	Config            config.Config
	Store             *store.Store
	Analytics         *analytics.Client
	FTP               *ftpclient.Provisioner
	StaticDir         string
	Version           string
	Metrics           *ingest.Metrics
	Spool             *spool.Queue
	NATS              *nats.Conn
	IngressStatusPath string
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
			private.Get("/devices", s.listDevices)
			private.With(s.requireAdmin).Post("/devices", s.createDevice)
			private.With(s.requireAdmin).Patch("/devices/{deviceID}", s.updateDevice)
			private.With(s.requireAdmin).Delete("/devices/{deviceID}", s.deleteDevice)
			private.Get("/devices/{deviceID}/events", s.listEvents)
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
	if err := s.Analytics.ScheduleDeviceRebuild(
		request.Context(), device.ID, uint64(device.TimezoneRevision), device.Timezone,
		device.CDRSourceTimezone,
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
	if device.TimezoneRevision != device.ActiveTimezoneRevision {
		if err := s.Analytics.ScheduleDeviceRebuild(
			request.Context(), device.ID, uint64(device.TimezoneRevision), device.Timezone,
			device.CDRSourceTimezone,
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
		headers := []any{"Установка UTC", "Входящий маршрут", "Исходящий маршрут", "Номер A вход", "Номер A выход",
			"Номер B вход", "Номер B выход", "Длительность, мс", "Q.850", "Результат", "Acct-Session-Id", "UniqueTag"}
		_ = stream.SetRow("A1", headers)
		for index, row := range rows {
			values := []any{
				formatTimeInLocation(row.SetupTime, time.UTC),
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
