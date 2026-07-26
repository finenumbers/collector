package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
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
		location, err := time.LoadLocation(job.Timezone)
		if err != nil {
			return exportworker.RenderResult{}, fmt.Errorf("load pinned timezone: %w", err)
		}
		if useCSVZip(job) {
			switch job.Dataset {
			case "events":
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
		case "antifraud":
			workbook, err = s.exportAntifraud(request, job.DeviceID, job.Search, location)
		case "events":
			workbook, err = s.exportEvents(request, job.DeviceID, job.Category, job.Search, location)
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
		(job.Dataset == "events" &&
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
		"Время", "Раздел", "Компонент", "Сообщение", "Статус", "Атрибуты",
	}); err != nil {
		return exportworker.RenderResult{}, err
	}
	var cursor *analytics.EventCursor
	if job.RawHighWatermark != nil {
		cursor = &analytics.EventCursor{
			ReceivedAt: job.RawHighWatermark.Add(time.Microsecond),
			EventID:    maxUUID(),
		}
	}
	var total int64
	for {
		page, queryErr := s.Analytics.ListExportEventsPage(ctx, job.DeviceID,
			uint64(job.ActiveRevision), job.Category, job.Search, exportPageSize, cursor,
			exportJobTimeRange(job))
		if queryErr != nil {
			return exportworker.RenderResult{}, queryErr
		}
		for _, row := range page.Items {
			if exportRowAfterSnapshot(
				row.ReceivedAt, row.EventID, job.RawHighWatermark, job.RawHighWatermarkID,
			) {
				continue
			}
			eventTime := row.EventTime
			if eventTime == nil {
				eventTime = &row.ReceivedAt
			}
			attributes, marshalErr := json.Marshal(row.Attributes)
			if marshalErr != nil {
				return exportworker.RenderResult{}, marshalErr
			}
			if err = writeCSVValues(writer,
				formatTimeInLocation(eventTime, location), row.Category, row.Component,
				row.Message, row.Status, string(attributes),
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
		cursor = &analytics.EventCursor{ReceivedAt: last.ReceivedAt, EventID: last.EventID}
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
	return renderCSVArchive(job, output, []string{
		"Установка", "Входящий маршрут", "Исходящий маршрут", "Номер A вход",
		"Номер A выход", "Номер B вход", "Номер B выход", "Длительность, мс",
		"Q.850", "Результат", "Acct-Session-Id", "UniqueTag",
	}, func(writer *csv.Writer) (int64, error) {
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
				exportPageSize, cursor, exportJobTimeRange(job),
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
					row.IncomingDescription, row.OutgoingDescription, row.IncomingCgPN,
					row.OutgoingCgPN, row.IncomingCdPN, row.OutgoingCdPN, row.DurationMS,
					row.ReleaseCause, row.ReleaseInfo, row.RadiusSessionID, row.UniqueTag,
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
				exportPageSize, cursor, exportJobTimeRange(job),
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

func (s *Server) renderAntifraudCSVZip(
	ctx context.Context, job store.ExportJob, location *time.Location, output io.Writer,
	progress exportworker.ProgressFunc,
) (exportworker.RenderResult, error) {
	return renderCSVArchive(job, output, []string{
		"Последнее событие", "Операция", "Решение", "Номер A", "Номер B",
		"Входящий маршрут", "Исходящий маршрут", "RADIUS server", "Latency, мс",
		"Accounting", "Корреляция", "CDR legs", "Полнота", "Acct-Session-Id", "Call context",
	}, func(writer *csv.Writer) (int64, error) {
		var cursor *analytics.AntifraudCursor
		if job.RawHighWatermark != nil {
			cursor = &analytics.AntifraudCursor{
				LastEventAt: job.RawHighWatermark.Add(time.Microsecond), TransactionID: maxUUID(),
			}
		}
		var total int64
		for {
			page, err := s.Analytics.ListExportAntifraudPage(
				ctx, job.DeviceID, uint64(job.ActiveRevision), job.Search,
				exportPageSize, cursor, exportJobTimeRange(job),
			)
			if err != nil {
				return total, err
			}
			for _, row := range page.Items {
				if job.RawHighWatermark != nil && exportRowAfterSnapshot(
					row.LastEventAt, row.TransactionID,
					job.RawHighWatermark, job.RawHighWatermarkID,
				) {
					continue
				}
				if err = writeCSVValues(writer,
					formatTimeInLocation(&row.LastEventAt, location), row.RequestType,
					row.Decision, firstNonEmpty(row.SrcNumberIn, row.CallingStationID),
					firstNonEmpty(row.DstNumberIn, row.CalledStationID),
					row.InTrunkgroupLabel, row.OutTrunkgroupLabel, row.ServerAddress,
					row.LatencyMS, row.AccountingStatus, row.CorrelationState,
					row.LegCount, row.Completeness, row.AcctSessionID, row.CallContext,
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
			cursor = &analytics.AntifraudCursor{
				LastEventAt: last.LastEventAt, TransactionID: last.TransactionID,
			}
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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
