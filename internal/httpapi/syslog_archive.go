package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	syslogftp "collector/internal/ftpclient"
	"collector/internal/runtimesettings"
	"collector/internal/store"
	"collector/internal/syslogarchive"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) syslogArchiveWorkerHealthy(ctx context.Context) bool {
	if s.Store == nil {
		return false
	}
	state, err := s.Store.SyslogArchiveWorkerState(ctx, store.SyslogArchiveWorkerHeartbeatTimeout)
	return err == nil && state.Alive
}

func (s *Server) syslogArchiveStatus(writer http.ResponseWriter, request *http.Request) {
	status, err := s.buildSyslogArchiveStatus(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to load syslog archive status")
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

func (s *Server) buildSyslogArchiveStatus(ctx context.Context) (map[string]any, error) {
	doc := s.runtimeDocument()
	if s.Store != nil {
		if row, err := s.Store.LoadRuntimeSettings(ctx); err == nil && row.Seeded {
			doc = row.Settings
		}
	}
	runtimesettings.NormalizeSyslogArchive(&doc)
	cfg := doc.SyslogArchive
	ftpConfigured := strings.TrimSpace(cfg.FTPHost) != "" &&
		strings.TrimSpace(cfg.FTPUser) != "" &&
		strings.TrimSpace(cfg.FTPPassword) != ""

	worker := store.SyslogArchiveWorkerState{}
	if s.Store != nil {
		if state, err := s.Store.SyslogArchiveWorkerState(ctx, store.SyslogArchiveWorkerHeartbeatTimeout); err == nil {
			worker = state
		} else {
			return nil, err
		}
	}

	counts := store.SyslogArchiveJobCounts{}
	var spoolBytes int64
	var jobs []store.SyslogArchiveJob
	progress := map[uuid.UUID]store.SyslogArchiveDeviceProgress{}
	if s.Store != nil {
		var err error
		counts, err = s.Store.SyslogArchiveJobCounts(ctx)
		if err != nil {
			return nil, err
		}
		spoolBytes, err = s.Store.SyslogArchiveSpoolBytes(ctx)
		if err != nil {
			return nil, err
		}
		jobs, err = s.Store.ListRecentSyslogArchiveJobs(ctx, 100)
		if err != nil {
			return nil, err
		}
		items, err := s.Store.SyslogArchiveDeviceProgress(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			progress[item.DeviceID] = item
		}
	}

	closeDelay, err := time.ParseDuration(cfg.CloseDelay)
	if err != nil {
		closeDelay = time.Minute
	}
	now := time.Now()
	cutoff := syslogarchive.RawDeleteCutoff(now)
	var maxLag time.Duration
	deviceRows := []map[string]any{}
	if s.Store != nil {
		devices, listErr := s.Store.ListSyslogCapableDevices(ctx)
		if listErr != nil {
			return nil, listErr
		}
		for _, device := range devices {
			item := progress[device.ID]
			skip := ""
			sign := syslogarchive.SanitizeDeviceSign(device.DeviceSign)
			switch {
			case !device.SyslogArchiveEnabled:
				skip = "disabled"
			case strings.TrimSpace(device.SyslogArchiveRemoteDir) == "":
				skip = "emptyDir"
			case sign == "":
				skip = "emptySign"
			}
			row := map[string]any{
				"deviceId":       device.ID,
				"name":           device.Name,
				"sign":           device.DeviceSign,
				"archiveEnabled": device.SyslogArchiveEnabled,
				"remoteDir":      device.SyslogArchiveRemoteDir,
				"timezone":       device.ActiveTimezone,
				"lastUploadedAt": item.LastUploadedAt,
				"lastError":      item.LastError,
				"skipReason":     skip,
				"nameMismatch":   item.NameMismatch,
			}
			deviceRows = append(deviceRows, row)
			if skip != "" || !cfg.Enabled {
				continue
			}
			loc, locErr := time.LoadLocation(device.ActiveTimezone)
			if locErr != nil {
				loc = time.UTC
			}
			lag := liveArchiveLag(now, loc, closeDelay, cutoff, item.LastUploaded)
			if lag > maxLag {
				maxLag = lag
			}
		}
	}

	return map[string]any{
		"enabled":       cfg.Enabled,
		"ftpConfigured": ftpConfigured,
		"spoolBytes":    spoolBytes,
		"spoolBudget":   cfg.SpoolBudgetBytes,
		"lagSeconds":    int64(maxLag / time.Second),
		"worker":        worker,
		"counts":        counts,
		"devices":       deviceRows,
		"jobs":          jobs,
	}, nil
}

func liveArchiveLag(
	now time.Time, loc *time.Location, closeDelay time.Duration,
	cutoff time.Time, lastUploaded *time.Time,
) time.Duration {
	closed := syslogarchive.ClosedSlotStart(now, loc, closeDelay)
	oldest := closed
	for slot := closed; !slot.Before(cutoff); slot = slot.Add(-syslogarchive.SlotDuration) {
		from, _ := syslogarchive.SlotBoundsUTC(slot)
		if !from.After(cutoff) && !from.Equal(cutoff) {
			break
		}
		oldest = slot
	}
	if lastUploaded == nil || lastUploaded.Before(oldest) {
		return closed.Sub(oldest)
	}
	if !lastUploaded.Before(closed) {
		return 0
	}
	return closed.Sub(*lastUploaded)
}

func (s *Server) testSyslogArchiveFTP(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		FTPHost     string `json:"ftpHost"`
		FTPPort     int    `json:"ftpPort"`
		FTPUser     string `json:"ftpUser"`
		FTPPassword string `json:"ftpPassword"`
		FTPTLS      bool   `json:"ftpTls"`
		RemoteDir   string `json:"remoteDir"`
	}
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid ftp probe payload")
		return
	}
	doc := s.runtimeDocument()
	if s.Store != nil {
		if row, err := s.Store.LoadRuntimeSettings(request.Context()); err == nil && row.Seeded {
			doc = row.Settings
		}
	}
	host := strings.TrimSpace(body.FTPHost)
	user := strings.TrimSpace(body.FTPUser)
	password := body.FTPPassword
	if password == "" {
		password = doc.SyslogArchive.FTPPassword
	}
	port := body.FTPPort
	if port == 0 {
		port = doc.SyslogArchive.FTPPort
	}
	if host == "" || user == "" {
		writeError(writer, http.StatusBadRequest, "ftp host and user are required")
		return
	}
	if strings.TrimSpace(password) == "" {
		writeError(writer, http.StatusBadRequest, "ftp password is required")
		return
	}
	if err := syslogftp.ValidateRemoteDir(body.RemoteDir); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	defer cancel()
	client := syslogftp.New(syslogftp.Config{
		Host: host, Port: port, User: user, Password: password, TLS: body.FTPTLS,
	})
	report, err := client.ProbeDetailed(ctx, body.RemoteDir)
	if err != nil {
		writeJSON(writer, http.StatusBadGateway, map[string]any{
			"ok": false, "error": err.Error(), "steps": report.Steps,
		})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"ok": true, "steps": report.Steps})
}

func (s *Server) verifySyslogArchiveJob(writer http.ResponseWriter, request *http.Request) {
	jobID, err := uuid.Parse(chi.URLParam(request, "jobID"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid job id")
		return
	}
	job, err := s.Store.GetSyslogArchiveJob(request.Context(), jobID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "archive job not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to load archive job")
		return
	}
	if job.Status != store.SyslogArchiveStatusUploaded {
		writeError(writer, http.StatusBadRequest, "only uploaded jobs can be verified")
		return
	}
	doc := s.runtimeDocument()
	if row, loadErr := s.Store.LoadRuntimeSettings(request.Context()); loadErr == nil && row.Seeded {
		doc = row.Settings
	}
	client := syslogftp.New(syslogftp.Config{
		Host: doc.SyslogArchive.FTPHost, Port: doc.SyslogArchive.FTPPort,
		User: doc.SyslogArchive.FTPUser, Password: doc.SyslogArchive.FTPPassword,
		TLS: doc.SyslogArchive.FTPTLS,
	})
	if !client.Configured() || strings.TrimSpace(doc.SyslogArchive.FTPPassword) == "" {
		writeError(writer, http.StatusBadRequest, "ftp is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	defer cancel()
	ok, matchErr := client.RemoteMatches(ctx, job.RemoteDir, job.ArchiveName, job.Bytes)
	if matchErr != nil {
		writeError(writer, http.StatusBadGateway, matchErr.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"ok": ok, "archiveName": job.ArchiveName, "remoteDir": job.RemoteDir, "bytes": job.Bytes,
	})
}
