package httpapi

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xuri/excelize/v2"
)

const (
	defaultExportPageSize = uint64(1000)
	excelMaximumRows      = 1048576
	defaultExportName     = "export"
)

func (s *Server) exportPageSize() uint64 {
	size := s.Config.ExportPageSize
	if s.Runtime != nil {
		if runtimeSize := s.Runtime.Snapshot().Platform.ExportPageSize; runtimeSize > 0 {
			size = runtimeSize
		}
	}
	if size <= 0 {
		return defaultExportPageSize
	}
	return uint64(size)
}

type exportRequest struct {
	Dataset  string
	Category string
	Search   string
}

func parseExportRequest(values url.Values) (exportRequest, error) {
	result := exportRequest{
		Dataset:  values.Get("dataset"),
		Category: values.Get("category"),
		Search:   values.Get("q"),
	}
	switch result.Dataset {
	case "calls":
		if result.Category != "" {
			return exportRequest{}, fmt.Errorf("category is not supported")
		}
	case "syslog":
		if result.Category != "" {
			return exportRequest{}, fmt.Errorf("category is not supported for raw Syslog messages")
		}
	case "antifraud":
		if result.Category != "" {
			return exportRequest{}, fmt.Errorf("category is not supported")
		}
	default:
		return exportRequest{}, fmt.Errorf("invalid export dataset")
	}
	return result, nil
}

func exportScalar(value any) any {
	if value == nil {
		return ""
	}
	if id, ok := value.(uuid.UUID); ok {
		return id.String()
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Ptr {
		if reflected.IsNil() {
			return ""
		}
		return exportScalar(reflected.Elem().Interface())
	}
	return value
}

func exportFilename(deviceID uuid.UUID, dataset, category string, now time.Time) string {
	parts := []string{"collector", deviceID.String()[:8], safeFilenamePart(dataset)}
	if category != "" {
		parts = append(parts, safeFilenamePart(category))
	}
	parts = append(parts, now.UTC().Format("20060102-150405"))
	return strings.Join(parts, "-") + ".xlsx"
}

func safeFilenamePart(value string) string {
	var result strings.Builder
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' {
			result.WriteRune(character)
		} else {
			result.WriteByte('_')
		}
	}
	if result.Len() == 0 {
		return defaultExportName
	}
	return result.String()
}

func setExportResponseHeaders(
	writer http.ResponseWriter, deviceID uuid.UUID, request exportRequest, template string,
	rows int, now time.Time,
) {
	writer.Header().Set("Content-Type",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	writer.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{
		"filename": exportFilename(deviceID, request.Dataset, request.Category, now),
	}))
	writer.Header().Set("X-Export-Dataset", request.Dataset)
	writer.Header().Set("X-Export-Category", request.Category)
	writer.Header().Set("X-Export-Template", template)
	writer.Header().Set("X-Export-Rows", strconv.Itoa(rows))
}

type exportWorkbook struct {
	file      *excelize.File
	stream    *excelize.StreamWriter
	headers   []any
	maxRows   int
	sheet     int
	row       int
	totalRows int
}

func newExportWorkbook(headers []any, maxRows int) (*exportWorkbook, error) {
	if maxRows < 2 || maxRows > excelMaximumRows {
		return nil, fmt.Errorf("invalid sheet row limit %d", maxRows)
	}
	file := excelize.NewFile()
	result := &exportWorkbook{file: file, headers: headers, maxRows: maxRows}
	if err := result.startSheet(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return result, nil
}

func (workbook *exportWorkbook) startSheet() error {
	workbook.sheet++
	name := "Data"
	if workbook.sheet > 1 {
		name = fmt.Sprintf("Data %d", workbook.sheet)
		if _, err := workbook.file.NewSheet(name); err != nil {
			return fmt.Errorf("create sheet: %w", err)
		}
	} else if err := workbook.file.SetSheetName("Sheet1", name); err != nil {
		return fmt.Errorf("rename sheet: %w", err)
	}
	stream, err := workbook.file.NewStreamWriter(name)
	if err != nil {
		return fmt.Errorf("create stream: %w", err)
	}
	workbook.stream = stream
	workbook.row = 1
	return workbook.setRow(workbook.row, workbook.headers)
}

func (workbook *exportWorkbook) AddRow(ctx context.Context, values []any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if workbook.row >= workbook.maxRows {
		if err := workbook.stream.Flush(); err != nil {
			return fmt.Errorf("flush sheet: %w", err)
		}
		if err := workbook.startSheet(); err != nil {
			return err
		}
	}
	workbook.row++
	if err := workbook.setRow(workbook.row, values); err != nil {
		return err
	}
	workbook.totalRows++
	return nil
}

func (workbook *exportWorkbook) setRow(row int, values []any) error {
	cell, err := excelize.CoordinatesToCellName(1, row)
	if err != nil {
		return fmt.Errorf("row coordinates: %w", err)
	}
	scalars := make([]any, len(values))
	for index, value := range values {
		scalars[index] = exportScalar(value)
	}
	if err := workbook.stream.SetRow(cell, scalars); err != nil {
		return fmt.Errorf("set row: %w", err)
	}
	return nil
}

func (workbook *exportWorkbook) Finish(writer io.Writer) error {
	if err := workbook.stream.Flush(); err != nil {
		return fmt.Errorf("flush workbook: %w", err)
	}
	if err := workbook.file.Write(writer); err != nil {
		return fmt.Errorf("write workbook: %w", err)
	}
	return nil
}

func (workbook *exportWorkbook) Close() error {
	return workbook.file.Close()
}
