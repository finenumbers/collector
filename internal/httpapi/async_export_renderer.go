package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"collector/internal/analytics"
	"collector/internal/equipment"
	"collector/internal/exportworker"
	"collector/internal/store"
	"collector/internal/workload"

	"github.com/google/uuid"
)

type asyncExportContextKey struct{}

type asyncExportState struct {
	job      store.ExportJob
	progress exportworker.ProgressFunc
}

func asyncExportJob(ctx context.Context) (store.ExportJob, exportworker.ProgressFunc, bool) {
	state, ok := ctx.Value(asyncExportContextKey{}).(asyncExportState)
	return state.job, state.progress, ok
}

// AsyncExportRenderer adapts the existing export projections to the worker.
// The returned function is safe to pass directly as exportworker.Worker.Render.
func (s *Server) AsyncExportRenderer() exportworker.RenderFunc {
	return func(
		ctx context.Context, job store.ExportJob, output io.Writer,
		progress exportworker.ProgressFunc,
	) (exportworker.RenderResult, error) {
		if job.Dataset == "antifraud" {
			if !s.customProjectionEnabled() {
				return exportworker.RenderResult{}, errors.New("Custom AntiFraud feature is unavailable")
			}
			ready, readyErr := s.Store.CustomAntifraudReady(ctx, job.DeviceID)
			if readyErr != nil || !ready {
				return exportworker.RenderResult{}, errors.New("Custom AntiFraud projection is rebuilding")
			}
		}
		ctx, release, err := s.Analytics.AdmitWorkload(ctx, workload.Export)
		if err != nil {
			return exportworker.RenderResult{}, err
		}
		defer release()
		location, err := time.LoadLocation(job.Timezone)
		if err != nil {
			return exportworker.RenderResult{}, fmt.Errorf("load pinned timezone: %w", err)
		}
		if useCSVZip(job) {
			switch job.Dataset {
			case "syslog":
				return s.renderEventsCSVZip(ctx, job, location, output, progress)
			case "calls":
				if job.TemplateKey == equipment.TemplateSatelRTUCDRV1 {
					return s.renderSatelCallsCSVZip(ctx, job, location, output, progress)
				}
				return s.renderCallsCSVZip(ctx, job, location, output, progress)
			case "antifraud":
				return s.renderAntifraudCSVZip(ctx, job, location, output, progress)
			default:
				return exportworker.RenderResult{}, fmt.Errorf("unsupported dataset %q", job.Dataset)
			}
		}
		renderContext := context.WithValue(ctx, asyncExportContextKey{}, asyncExportState{
			job: job, progress: progress,
		})
		request := (&http.Request{}).WithContext(renderContext)
		var workbook *exportWorkbook
		switch job.Dataset {
		case "calls":
			if job.TemplateKey == equipment.TemplateSatelRTUCDRV1 {
				workbook, err = s.exportSatelCalls(request, job.DeviceID, job.Search, location)
			} else {
				workbook, err = s.exportEltexCalls(request, job.DeviceID, job.Search, location)
			}
		case "syslog":
			workbook, err = s.exportEvents(request, job.DeviceID, job.Category, job.Search, location)
		case "antifraud":
			err = fmt.Errorf("AntiFraud export is available as CSV.zip")
		default:
			err = fmt.Errorf("unsupported dataset %q", job.Dataset)
		}
		if err != nil {
			if workbook != nil {
				_ = workbook.Close()
			}
			return exportworker.RenderResult{}, err
		}
		defer workbook.Close()
		if err = progress(int64(workbook.totalRows)); err != nil {
			return exportworker.RenderResult{}, err
		}
		if err = workbook.Finish(output); err != nil {
			return exportworker.RenderResult{}, err
		}
		filename := exportFilename(job.DeviceID, job.Dataset, job.Category, job.CreatedAt)
		return exportworker.RenderResult{
			Rows: int64(workbook.totalRows), Format: "xlsx", Filename: filename,
			ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		}, nil
	}
}

func useCSVZip(job store.ExportJob) bool {
	if job.Format == "csv_zip" {
		return true
	}
	if job.Format == "xlsx" {
		return false
	}
	return (job.RangeFrom == nil && job.RangeTo == nil) ||
		(job.Dataset == "syslog" &&
			(job.RowsEstimated == nil || *job.RowsEstimated > analytics.ExportEstimateLimit))
}

func exportJobTimeRange(job store.ExportJob) *analytics.TimeRange {
	if job.RangeFrom == nil || job.RangeTo == nil {
		return nil
	}
	return &analytics.TimeRange{From: *job.RangeFrom, To: *job.RangeTo}
}

func (s *Server) renderEventsCSVZip(
	ctx context.Context, job store.ExportJob, location *time.Location, output io.Writer,
	progress exportworker.ProgressFunc,
) (exportworker.RenderResult, error) {
	archiveWriter := zip.NewWriter(output)
	csvName := exportFilename(job.DeviceID, job.Dataset, job.Category, job.CreatedAt)
	csvName = csvName[:len(csvName)-len(".xlsx")] + ".csv"
	entry, err := archiveWriter.Create(csvName)
	if err != nil {
		return exportworker.RenderResult{}, err
	}
	writer := csv.NewWriter(entry)
	if err = writer.Write([]string{
		"Event ID", "Device ID", "Received UTC", "Source IP", "Source port",
		"Transport", "Payload", "Payload SHA-256",
	}); err != nil {
		return exportworker.RenderResult{}, err
	}
	var cursor *analytics.SyslogMessageCursor
	if job.RawHighWatermark != nil {
		cursor = &analytics.SyslogMessageCursor{
			ReceivedAt: job.RawHighWatermark.Add(time.Microsecond),
			EventID:    maxUUID(),
		}
	}
	var total int64
	for {
		page, queryErr := s.Analytics.ListSyslogMessagesPage(
			ctx, job.DeviceID, job.Search, s.exportPageSize(), cursor, exportJobTimeRange(job),
		)
		if queryErr != nil {
			return exportworker.RenderResult{}, queryErr
		}
		for _, row := range page.Items {
			if exportRowAfterSnapshot(
				row.ReceivedAt, row.EventID, job.RawHighWatermark, job.RawHighWatermarkID,
			) {
				continue
			}
			if err = writeCSVValues(writer,
				row.EventID, row.DeviceID, row.ReceivedAt.UTC().Format(time.RFC3339Nano),
				row.SourceIP, row.SourcePort, row.Transport, row.Payload, row.PayloadSHA256,
			); err != nil {
				return exportworker.RenderResult{}, err
			}
			total++
		}
		writer.Flush()
		if err = writer.Error(); err != nil {
			return exportworker.RenderResult{}, err
		}
		if err = progress(total); err != nil {
			return exportworker.RenderResult{}, err
		}
		if !page.HasMore || len(page.Items) == 0 {
			break
		}
		last := page.Items[len(page.Items)-1]
		cursor = &analytics.SyslogMessageCursor{ReceivedAt: last.ReceivedAt, EventID: last.EventID}
	}
	if err = archiveWriter.Close(); err != nil {
		return exportworker.RenderResult{}, err
	}
	return exportworker.RenderResult{
		Rows: total, Format: "csv_zip", Filename: csvName + ".zip",
		ContentType: "application/zip",
	}, nil
}

func (s *Server) renderCallsCSVZip(
	ctx context.Context, job store.ExportJob, location *time.Location, output io.Writer,
	progress exportworker.ProgressFunc,
) (exportworker.RenderResult, error) {
	return renderCSVArchive(job, output, eltexCallExportHeaders(), func(writer *csv.Writer) (int64, error) {
		var cursor *analytics.CallCursor
		if job.RawHighWatermark != nil {
			cursor = &analytics.CallCursor{
				SortTime: job.RawHighWatermark.Add(time.Microsecond), RecordID: maxUUID(),
			}
		}
		var total int64
		for {
			page, err := s.Analytics.ListExportCallsPage(
				ctx, job.DeviceID, uint64(job.ActiveRevision), job.Search,
				s.exportPageSize(), cursor, exportJobTimeRange(job),
			)
			if err != nil {
				return total, err
			}
			for _, row := range page.Items {
				if job.RawHighWatermark != nil && exportRowAfterSnapshot(
					row.SortTime, row.RecordID, job.RawHighWatermark, job.RawHighWatermarkID,
				) {
					continue
				}
				if err = writeCSVValues(writer, eltexCallExportValues(row, location)...); err != nil {
					return total, err
				}
				total++
			}
			if err = progress(total); err != nil {
				return total, err
			}
			if !page.HasMore || len(page.Items) == 0 {
				return total, nil
			}
			last := page.Items[len(page.Items)-1]
			cursor = &analytics.CallCursor{SortTime: last.SortTime, RecordID: last.RecordID}
		}
	}, progress)
}

func (s *Server) renderAntifraudCSVZip(
	ctx context.Context, job store.ExportJob, location *time.Location, output io.Writer,
	progress exportworker.ProgressFunc,
) (exportworker.RenderResult, error) {
	return renderCSVArchive(job, output, []string{
		"Call ID", "Начало", "Завершение", "Acct-Session-Id", "H323 Conf ID",
		"Номер A", "Номер B", "Фазы", "Статус", "Lifecycle", "Покрытие CDR", "CDR IDs",
	}, func(writer *csv.Writer) (int64, error) {
		var cursor *analytics.AntifraudCallCursor
		if job.RawHighWatermark != nil {
			cursor = &analytics.AntifraudCallCursor{
				SortTime: job.RawHighWatermark.Add(time.Microsecond), CallID: maxUUID(),
			}
		}
		var total int64
		for {
			page, err := s.Analytics.ListAntifraudCallsPage(
				ctx, job.DeviceID, job.Search, s.exportPageSize(), cursor, exportJobTimeRange(job),
			)
			if err != nil {
				return total, err
			}
			for _, row := range page.Items {
				if job.RawHighWatermark != nil && exportRowAfterSnapshot(
					row.SortTime, row.CallID, job.RawHighWatermark, job.RawHighWatermarkID,
				) {
					continue
				}
				cdrIDs := make([]string, 0, len(row.Coverage.LinkedCDRIDs))
				for _, id := range row.Coverage.LinkedCDRIDs {
					cdrIDs = append(cdrIDs, id.String())
				}
				outcome := row.RadiusOutcome
				switch outcome {
				case "accept":
					outcome = "Accept"
				case "reject":
					outcome = "Reject"
				case "no_response":
					outcome = "Нет ответа"
				}
				if err = writeCSVValues(writer,
					row.CallID, formatTimeInLocation(&row.FirstSeenAt, location),
					formatTimeInLocation(&row.LastSeenAt, location), row.AcctSessionID,
					row.H323ConfID, row.Calling, row.Called, strings.Join(row.Phases, "|"),
					outcome, row.Status, row.Coverage.State, strings.Join(cdrIDs, "|"),
				); err != nil {
					return total, err
				}
				total++
			}
			if err = progress(total); err != nil {
				return total, err
			}
			if !page.HasMore || len(page.Items) == 0 {
				return total, nil
			}
			last := page.Items[len(page.Items)-1]
			cursor = &analytics.AntifraudCallCursor{SortTime: last.SortTime, CallID: last.CallID}
		}
	}, progress)
}

func (s *Server) renderSatelCallsCSVZip(
	ctx context.Context, job store.ExportJob, location *time.Location, output io.Writer,
	progress exportworker.ProgressFunc,
) (exportworker.RenderResult, error) {
	return renderCSVArchive(job, output, []string{
		"Установка", "Соединение", "Завершение", "Результат", "ANI вход", "DNIS вход",
		"ANI выход", "DNIS выход", "Src маршрут", "Dst маршрут", "DP маршрут",
		"Длительность, мс", "Протокол вход", "Протокол выход", "Разъединение", "Код", "Узел",
	}, func(writer *csv.Writer) (int64, error) {
		var cursor *analytics.CallCursor
		if job.RawHighWatermark != nil {
			cursor = &analytics.CallCursor{
				SortTime: job.RawHighWatermark.Add(time.Microsecond), RecordID: maxUUID(),
			}
		}
		var total int64
		for {
			page, err := s.Analytics.ListExportSatelRTUCallsPage(
				ctx, job.DeviceID, uint64(job.ActiveRevision), job.Search,
				s.exportPageSize(), cursor, exportJobTimeRange(job),
			)
			if err != nil {
				return total, err
			}
			for _, row := range page.Items {
				if job.RawHighWatermark != nil && exportRowAfterSnapshot(
					row.SortTime, row.RecordID, job.RawHighWatermark, job.RawHighWatermarkID,
				) {
					continue
				}
				if err = writeCSVValues(writer,
					formatTimeInLocation(row.SetupTime, location),
					formatTimeInLocation(row.ConnectTime, location),
					formatTimeInLocation(row.DisconnectTime, location), row.Outcome,
					row.InANI, row.InDNIS, row.OutANI, row.OutDNIS, row.SrcName,
					row.DstName, row.DPName, row.DurationMS, row.InLegProto,
					row.OutLegProto, row.DisconnectText, row.DisconnectCode, row.SignalNodeName,
				); err != nil {
					return total, err
				}
				total++
			}
			if err = progress(total); err != nil {
				return total, err
			}
			if !page.HasMore || len(page.Items) == 0 {
				return total, nil
			}
			last := page.Items[len(page.Items)-1]
			cursor = &analytics.CallCursor{SortTime: last.SortTime, RecordID: last.RecordID}
		}
	}, progress)
}

func renderCSVArchive(
	job store.ExportJob, output io.Writer, headers []string,
	writeRows func(*csv.Writer) (int64, error), _ exportworker.ProgressFunc,
) (exportworker.RenderResult, error) {
	archiveWriter := zip.NewWriter(output)
	base := exportFilename(job.DeviceID, job.Dataset, job.Category, job.CreatedAt)
	csvName := base[:len(base)-len(".xlsx")] + ".csv"
	entry, err := archiveWriter.Create(csvName)
	if err != nil {
		return exportworker.RenderResult{}, err
	}
	writer := csv.NewWriter(entry)
	if err = writer.Write(headers); err != nil {
		return exportworker.RenderResult{}, err
	}
	rows, err := writeRows(writer)
	writer.Flush()
	if err == nil {
		err = writer.Error()
	}
	if err == nil {
		err = archiveWriter.Close()
	}
	if err != nil {
		return exportworker.RenderResult{}, err
	}
	return exportworker.RenderResult{
		Rows: rows, Format: "csv_zip", Filename: csvName + ".zip",
		ContentType: "application/zip",
	}, nil
}

func writeCSVValues(writer *csv.Writer, values ...any) error {
	record := make([]string, len(values))
	for index, value := range values {
		record[index] = csvSafe(fmt.Sprint(exportScalar(value)))
	}
	return writer.Write(record)
}

func csvSafe(value string) string {
	if value != "" && strings.ContainsRune("=+-@", rune(value[0])) {
		return "'" + value
	}
	return value
}

func maxUUID() uuid.UUID {
	var id uuid.UUID
	for index := range id {
		id[index] = 0xff
	}
	return id
}

func exportRowAfterSnapshot(
	rowTime time.Time, rowID uuid.UUID, highTime *time.Time, highID *uuid.UUID,
) bool {
	if highTime == nil {
		return true
	}
	if rowTime.After(*highTime) {
		return true
	}
	return rowTime.Equal(*highTime) && highID != nil &&
		bytes.Compare(rowID[:], highID[:]) > 0
}

func estimatedRows(value *int64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(*value, 10)
}
