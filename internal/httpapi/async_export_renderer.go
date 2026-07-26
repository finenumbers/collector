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
			return s.renderEventsCSVZip(ctx, job, location, output, progress)
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
	if job.Dataset != "events" {
		return false
	}
	if job.Format == "csv_zip" {
		return true
	}
	if job.Format == "xlsx" {
		return false
	}
	return (job.RangeFrom == nil && job.RangeTo == nil) ||
		job.RowsEstimated == nil || *job.RowsEstimated > analytics.ExportEstimateLimit
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
		"Received", "Category", "Component", "Message", "Raw Syslog", "Status", "Attributes",
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
			uint64(job.ActiveRevision), job.Category, job.Search, exportPageSize, cursor)
		if queryErr != nil {
			return exportworker.RenderResult{}, queryErr
		}
		stop := false
		for _, row := range page.Items {
			if exportRowAfterSnapshot(
				row.ReceivedAt, row.EventID, job.RawHighWatermark, job.RawHighWatermarkID,
			) {
				continue
			}
			if job.RangeTo != nil && !row.ReceivedAt.Before(*job.RangeTo) {
				continue
			}
			if job.RangeFrom != nil && row.ReceivedAt.Before(*job.RangeFrom) {
				stop = true
				break
			}
			eventTime := row.EventTime
			if eventTime == nil {
				eventTime = &row.ReceivedAt
			}
			attributes, marshalErr := json.Marshal(row.Attributes)
			if marshalErr != nil {
				return exportworker.RenderResult{}, marshalErr
			}
			if err = writer.Write([]string{
				formatTimeInLocation(eventTime, location), row.Category, row.Component,
				row.Message, row.RawPayload, row.Status, string(attributes),
			}); err != nil {
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
		if stop || !page.HasMore || len(page.Items) == 0 {
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
