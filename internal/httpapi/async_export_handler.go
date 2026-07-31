package httpapi

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"collector/internal/equipment"
	"collector/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type createExportInput struct {
	Dataset       string            `json:"dataset"`
	Category      string            `json:"category"`
	Search        string            `json:"q"`
	Filters       map[string]string `json:"filters"`
	From          string            `json:"from"`
	To            string            `json:"to"`
	Format        string            `json:"format"`
	AllTime       bool              `json:"allTime"`
}

type exportJobResponse struct {
	ID            uuid.UUID  `json:"id"`
	Status        string     `json:"status"`
	Format        string     `json:"format"`
	Filename      string     `json:"filename,omitempty"`
	RowsWritten   int64      `json:"rowsWritten"`
	EstimatedRows *int64     `json:"estimatedRows,omitempty"`
	BytesWritten  int64      `json:"bytesWritten"`
	Error         string     `json:"error,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	StartedAt     *time.Time `json:"startedAt,omitempty"`
	FinishedAt    *time.Time `json:"finishedAt,omitempty"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

func presentExportJob(job store.ExportJob) exportJobResponse {
	format := job.OutputFormat
	if format == "" {
		format = job.Format
	}
	return exportJobResponse{
		ID: job.ID, Status: job.Status, Format: format, Filename: job.Filename,
		RowsWritten: job.RowsProcessed, EstimatedRows: job.RowsEstimated,
		BytesWritten: job.BytesSpooled, Error: job.Error, CreatedAt: job.CreatedAt,
		StartedAt: job.StartedAt, FinishedAt: job.FinishedAt, ExpiresAt: job.ExpiresAt,
	}
}

func parseExportDate(value string, location *time.Location, endExclusive bool) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := time.ParseInLocation("2006-01-02", value, location)
	if err != nil {
		return nil, fmt.Errorf("date must use YYYY-MM-DD")
	}
	if endExclusive {
		parsed = parsed.AddDate(0, 0, 1)
	}
	return &parsed, nil
}

func (s *Server) createExportJob(writer http.ResponseWriter, request *http.Request) {
	session := currentSession(request)
	if !s.allowCostlyRequest(session.User.ID) {
		writeError(writer, http.StatusTooManyRequests, "export request rate limit exceeded")
		return
	}
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	var input createExportInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	values := make(url.Values)
	values.Set("dataset", input.Dataset)
	values.Set("category", input.Category)
	values.Set("q", input.Search)
	validated, err := parseExportRequest(values)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	columnFilters, err := parseSatelColumnFiltersMap(input.Filters)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if input.Format == "" {
		input.Format = "auto"
	}
	if input.Format != "auto" && input.Format != "xlsx" && input.Format != "csv_zip" {
		writeError(writer, http.StatusBadRequest, "format must be auto, xlsx, or csv_zip")
		return
	}
	if validated.Dataset == "antifraud" && input.Format != "csv_zip" {
		writeError(writer, http.StatusBadRequest, "AntiFraud export format must be csv_zip")
		return
	}
	if validated.Dataset == "antifraud" && !s.customProjectionEnabled() {
		writeError(writer, http.StatusServiceUnavailable, "Custom AntiFraud feature is unavailable")
		return
	}
	device, ok := s.deviceWithCapability(writer, request, deviceID,
		func(device store.Device) bool {
			switch validated.Dataset {
			case "calls":
				return device.Capabilities.TypedCDR
			case "antifraud":
				return device.Capabilities.Syslog && device.Capabilities.Antifraud &&
					device.Capabilities.Radius && device.AntifraudEnabled
			default:
				return device.Capabilities.Syslog
			}
		}, "requested export dataset")
	if !ok {
		return
	}
	if len(columnFilters) > 0 && device.TemplateKey != equipment.TemplateSatelRTUCDRV1 {
		writeError(writer, http.StatusBadRequest, "column filters are only available for Satel RTU")
		return
	}
	if validated.Dataset == "antifraud" {
		ready, readyErr := s.Store.CustomAntifraudReady(request.Context(), deviceID)
		if readyErr != nil || !ready {
			writeError(writer, http.StatusServiceUnavailable, "Custom AntiFraud projection is rebuilding")
			return
		}
	}
	location, err := time.LoadLocation(device.ActiveTimezone)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "invalid device timezone")
		return
	}
	rangeFrom, err := parseExportDate(input.From, location, false)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid from: "+err.Error())
		return
	}
	rangeTo, err := parseExportDate(input.To, location, true)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid to: "+err.Error())
		return
	}
	if rangeFrom != nil && rangeTo != nil && !rangeFrom.Before(*rangeTo) {
		writeError(writer, http.StatusBadRequest, "from must not be after to")
		return
	}
	if len(validated.Search) > 256 {
		writeError(writer, http.StatusBadRequest, "search must not exceed 256 characters")
		return
	}
	hasSearch := validated.Search != "" || len(columnFilters) > 0
	if hasSearch && (rangeFrom == nil || rangeTo == nil) {
		if !input.AllTime || session.User.Role != "admin" {
			writeError(writer, http.StatusBadRequest,
				"search requires from/to dates; administrators may request explicit allTime async exports")
			return
		}
	}
	if input.AllTime && (!hasSearch || session.User.Role != "admin") {
		writeError(writer, http.StatusBadRequest,
			"allTime is only valid for administrator search exports")
		return
	}
	if hasSearch && rangeFrom != nil && rangeTo != nil &&
		rangeTo.Sub(*rangeFrom) > 31*24*time.Hour {
		writeError(writer, http.StatusBadRequest, "search export date range must not exceed 31 days")
		return
	}
	if s.Analytics == nil {
		writeError(writer, http.StatusServiceUnavailable, "analytics unavailable")
		return
	}
	if !s.exportWorkerHealthy(request.Context()) {
		writeError(writer, http.StatusServiceUnavailable,
			"export worker is unavailable; retry in a few seconds")
		return
	}
	snapshot, err := s.Analytics.PinExportSnapshot(
		request.Context(), deviceID, uint64(device.ActiveTimezoneRevision),
		validated.Dataset, device.TemplateKey, device.ActiveTimezone,
		validated.Category, validated.Search, rangeFrom, rangeTo,
	)
	if err != nil {
		if writeAdmissionError(writer, err) {
			return
		}
		writeError(writer, http.StatusInternalServerError, "unable to pin export snapshot")
		return
	}
	job, err := s.Store.CreateExportJob(request.Context(), store.NewExportJob{
		DeviceID: deviceID, Dataset: validated.Dataset, Category: validated.Category,
		Search: validated.Search, ColumnFilters: columnFilters,
		RangeFrom: rangeFrom, RangeTo: rangeTo, Format: input.Format,
		RowsEstimated: snapshot.EstimatedRows, ActiveRevision: int64(snapshot.Revision),
		Timezone: device.ActiveTimezone, TemplateKey: device.TemplateKey,
		ParserVersion: snapshot.ParserVersion, RawHighWatermark: snapshot.HighWatermark,
		RawHighWatermarkID: snapshot.HighID,
	}, session.User, remoteIP(request))
	if errors.Is(err, store.ErrExportQueueFull) {
		writeError(writer, http.StatusTooManyRequests, err.Error())
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to queue export")
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"job": presentExportJob(job)})
}

func (s *Server) listExportJobs(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	if _, err := s.Store.Device(request.Context(), deviceID); err != nil {
		writeError(writer, http.StatusNotFound, "device not found")
		return
	}
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	var cursor *store.ExportJobCursor
	before := request.URL.Query().Get("before")
	beforeID := request.URL.Query().Get("before_id")
	if before != "" || beforeID != "" {
		createdAt, timeErr := time.Parse(time.RFC3339Nano, before)
		id, idErr := uuid.Parse(beforeID)
		if timeErr != nil || idErr != nil {
			writeError(writer, http.StatusBadRequest, "invalid export cursor")
			return
		}
		cursor = &store.ExportJobCursor{CreatedAt: createdAt, ID: id}
	}
	items, hasMore, err := s.Store.ListExportJobs(request.Context(), deviceID, limit, cursor)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to list exports")
		return
	}
	var next any
	if hasMore && len(items) != 0 {
		last := items[len(items)-1]
		next = map[string]any{"before": last.CreatedAt, "beforeId": last.ID}
	}
	presented := make([]exportJobResponse, 0, len(items))
	for _, item := range items {
		presented = append(presented, presentExportJob(item))
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"items": presented, "hasMore": hasMore, "nextCursor": next,
	})
}

func (s *Server) getExportJob(writer http.ResponseWriter, request *http.Request) {
	deviceID, job, ok := s.exportJobFromRequest(writer, request)
	if ok {
		changed, err := s.Store.FailStaleExportJob(
			request.Context(), deviceID, job.ID,
			store.QueuedExportTimeout, store.ExportHeartbeatTimeout,
		)
		if err != nil {
			writeError(writer, http.StatusInternalServerError, "unable to validate export worker")
			return
		}
		if !changed && job.Status == "queued" && s.ExportHealth != nil &&
			s.ExportHealth.LastError() != "" &&
			!s.ExportHealth.Available(store.ExportHeartbeatTimeout) {
			changed, err = s.Store.FailQueuedExportJob(
				request.Context(), deviceID, job.ID,
				"export worker is unavailable; retry the export",
			)
			if err != nil {
				writeError(writer, http.StatusInternalServerError, "unable to fail unavailable export")
				return
			}
		}
		if changed {
			job, err = s.Store.ExportJob(request.Context(), deviceID, job.ID)
			if err != nil {
				writeError(writer, http.StatusInternalServerError, "unable to reload export job")
				return
			}
		}
		writeJSON(writer, http.StatusOK, map[string]any{"job": presentExportJob(job)})
	}
}

func (s *Server) cancelExportJob(writer http.ResponseWriter, request *http.Request) {
	deviceID, job, ok := s.exportJobFromRequest(writer, request)
	if !ok {
		return
	}
	session := currentSession(request)
	if session.User.Role != "admin" && job.RequestedBy != session.User.ID {
		writeError(writer, http.StatusForbidden, "not allowed to cancel this export")
		return
	}
	job, err := s.Store.CancelExportJob(
		request.Context(), deviceID, job.ID, session.User, remoteIP(request),
	)
	if errors.Is(err, store.ErrExportConflict) {
		writeError(writer, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to cancel export")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"job": presentExportJob(job)})
}

func (s *Server) downloadExportJob(writer http.ResponseWriter, request *http.Request) {
	_, job, ok := s.exportJobFromRequest(writer, request)
	if !ok {
		return
	}
	if !exportDownloadAvailable(job, time.Now()) {
		writeError(writer, http.StatusConflict, "export is not available for download")
		return
	}
	if s.Archive == nil {
		writeError(writer, http.StatusServiceUnavailable, "archive unavailable")
		return
	}
	object, err := s.Archive.OpenObject(request.Context(), job.ObjectKey)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "unable to open export")
		return
	}
	defer object.Reader.Close()
	session := currentSession(request)
	if err = s.Store.AuditExportDownload(
		request.Context(), job.ID, session.User, remoteIP(request),
	); err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to audit export download")
		return
	}
	setExportDownloadHeaders(writer.Header(), job, object.Size)
	writer.WriteHeader(http.StatusOK)
	if _, err = io.Copy(writer, object.Reader); err != nil {
		slog.Warn("export response interrupted", "job", job.ID, "error", err)
	}
}

func exportDownloadAvailable(job store.ExportJob, now time.Time) bool {
	return job.Status == "completed" && (job.ExpiresAt == nil || job.ExpiresAt.After(now))
}

func setExportDownloadHeaders(header http.Header, job store.ExportJob, size int64) {
	filename := sanitizeDownloadName(job.Filename)
	header.Set("Content-Disposition", mime.FormatMediaType("attachment",
		map[string]string{"filename": filename}))
	header.Set("Content-Type", job.ContentType)
	if size >= 0 {
		header.Set("Content-Length", strconv.FormatInt(size, 10))
	}
	header.Set("ETag", fmt.Sprintf(`"%s"`, job.SHA256))
}

func (s *Server) exportJobFromRequest(
	writer http.ResponseWriter, request *http.Request,
) (uuid.UUID, store.ExportJob, bool) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return uuid.Nil, store.ExportJob{}, false
	}
	jobID, err := uuid.Parse(chi.URLParam(request, "jobID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid export job id")
		return uuid.Nil, store.ExportJob{}, false
	}
	job, err := s.Store.ExportJob(request.Context(), deviceID, jobID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "export job not found")
		return uuid.Nil, store.ExportJob{}, false
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to load export job")
		return uuid.Nil, store.ExportJob{}, false
	}
	return deviceID, job, true
}
