package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"collector/internal/analytics"
	"collector/internal/config"
	"collector/internal/store"

	"github.com/google/uuid"
	"github.com/xuri/excelize/v2"
)

func TestRawSyslogListRejectsLegacyCategory(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/?category=radius", nil)

	(&Server{}).listEvents(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "category is not supported") {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
}

func TestFindSyslogMessageRequiresQ(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/?date=2026-08-03", nil)

	(&Server{}).findSyslogMessage(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "q is required") {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
}

func TestCountSyslogFindRequiresQ(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/?date=2026-08-03", nil)

	(&Server{}).countSyslogFind(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "q is required") {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
}

func TestListEventsRejectsConflictingCursors(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet,
		"/?date=2026-08-03&from=2026-08-03T12:00:00Z&from_id="+uuid.NewString()+
			"&before=2026-08-03T11:00:00Z&before_id="+uuid.NewString(), nil)

	(&Server{}).listEvents(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "use only one of before, from, or after") {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
}

func TestDashboardWindowValidation(t *testing.T) {
	for _, value := range []string{"", "1h", "24h", "7d"} {
		if _, err := analytics.ValidateDashboardWindow(value); err != nil {
			t.Fatalf("valid window %q failed: %v", value, err)
		}
	}
	for _, value := range []string{"2h", "0h", "168h"} {
		if _, err := analytics.ValidateDashboardWindow(value); err == nil {
			t.Fatalf("invalid window %q was accepted", value)
		}
	}
}

func TestExportWorkerHealthyRequiresStoreWhenHealthNil(t *testing.T) {
	if (&Server{}).exportWorkerHealthy(context.Background()) {
		t.Fatal("nil ExportHealth and nil Store must not report healthy")
	}
}

func TestWriteAntifraudCallDetailErrorMapping(t *testing.T) {
	deviceID, callID := uuid.New(), uuid.New()

	notFound := httptest.NewRecorder()
	writeAntifraudCallDetailError(notFound, analytics.ErrAntifraudCallNotFound, deviceID, callID)
	if notFound.Code != http.StatusNotFound ||
		!strings.Contains(notFound.Body.String(), "AntiFraud call not found") {
		t.Fatalf("not-found mapping: status=%d body=%s", notFound.Code, notFound.Body.String())
	}

	internal := httptest.NewRecorder()
	writeAntifraudCallDetailError(internal, errors.New("clickhouse memory limit exceeded"), deviceID, callID)
	if internal.Code != http.StatusInternalServerError ||
		!strings.Contains(internal.Body.String(), "unable to load AntiFraud call card") {
		t.Fatalf("internal mapping: status=%d body=%s", internal.Code, internal.Body.String())
	}
	if !strings.Contains(internal.Body.String(), "clickhouse memory limit exceeded") {
		t.Fatalf("500 must include redacted detail: body=%s", internal.Body.String())
	}
	if strings.Contains(internal.Body.String(), "AntiFraud call not found") {
		t.Fatal("non-NoRows errors must not be masked as call not found")
	}

	timeout := httptest.NewRecorder()
	writeAntifraudCallDetailError(timeout, context.DeadlineExceeded, deviceID, callID)
	if timeout.Code != http.StatusGatewayTimeout {
		t.Fatalf("timeout mapping: status=%d body=%s", timeout.Code, timeout.Body.String())
	}

	canceled := httptest.NewRecorder()
	writeAntifraudCallDetailError(canceled, context.Canceled, deviceID, callID)
	if canceled.Code != http.StatusGatewayTimeout {
		t.Fatalf("canceled mapping: status=%d body=%s", canceled.Code, canceled.Body.String())
	}
}

func TestDashboardDeviceRowExposesConfiguredAndActiveTimezones(t *testing.T) {
	latest := time.Date(2026, 7, 26, 12, 30, 0, 0, time.UTC)
	device := store.Device{
		ID:                     uuid.New(),
		Name:                   "SMG",
		Timezone:               "Europe/Moscow",
		ActiveTimezone:         "Asia/Novosibirsk",
		TimezoneRevision:       3,
		ActiveTimezoneRevision: 2,
	}
	row := dashboardDeviceRow(device, &analytics.DashboardDevice{
		LatestSyslogAt: &latest,
		ActiveRevision: 2,
		ActiveTimezone: "UTC",
	}, nil)

	if row["timezone"] != "Europe/Moscow" {
		t.Fatalf("configured timezone = %v", row["timezone"])
	}
	if row["activeTimezone"] != "UTC" {
		t.Fatalf("active timezone = %v", row["activeTimezone"])
	}
	freshness := row["freshness"].(map[string]any)
	if freshness["latestSyslogAt"] != &latest {
		t.Fatalf("latest Syslog freshness = %v", freshness["latestSyslogAt"])
	}
}

func TestEquipmentTemplatesAPIUsesStableLabels(t *testing.T) {
	response := httptest.NewRecorder()
	(&Server{}).listEquipmentTemplates(response, httptest.NewRequest(http.MethodGet, "/", nil))
	body := response.Body.String()
	for _, value := range []string{
		`"key":"eltex-smg-1016m-3.410"`,
		`"displayName":"Eltex SMG-1016M (3.410)"`,
		`"key":"eltex-smg-1016m-3.23.2"`,
		`"displayName":"Eltex SMG-1016M (3.23.2)"`,
		`"key":"satel-rtu-cdr-v1"`,
		`"displayName":"Satel RTU"`,
	} {
		if !strings.Contains(body, value) {
			t.Fatalf("template response missing %s: %s", value, body)
		}
	}
}

func TestDeviceListRejectsInvalidCategoryBeforeDatabase(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/devices?category=invalid", nil)
	(&Server{}).listDevices(response, request)
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "equipment or softswitch") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSanitizeDownloadName(t *testing.T) {
	tests := map[string]string{
		`../../secret.csv`: "secret.csv",
		`..\..\secret.csv`: "secret.csv",
		"bad\r\nname.csv":  "badname.csv",
		"":                 "cdr-file",
	}
	for input, want := range tests {
		if got := sanitizeDownloadName(input); got != want {
			t.Fatalf("sanitizeDownloadName(%q)=%q want %q", input, got, want)
		}
	}
}

func TestParsePageLimitIsBounded(t *testing.T) {
	tests := map[string]uint64{
		"": 200, "invalid": 200, "0": 200, "25": 25, "1000": 1000, "1001": 1000,
		"18446744073709551615": 1000,
	}
	for value, want := range tests {
		request := httptest.NewRequest(http.MethodGet, "/?limit="+value, nil)
		if got := parsePageLimit(request); got != want {
			t.Fatalf("limit %q = %d, want %d", value, got, want)
		}
	}
}

func TestExportRequestValidation(t *testing.T) {
	valid := map[string]exportRequest{
		"?dataset=calls":        {Dataset: "calls"},
		"?dataset=syslog&q=raw": {Dataset: "syslog", Search: "raw"},
		"?dataset=antifraud":    {Dataset: "antifraud"},
	}
	for query, want := range valid {
		request := httptest.NewRequest(http.MethodGet, "/export.xlsx"+query, nil)
		got, err := parseExportRequest(request.URL.Query())
		if err != nil || got != want {
			t.Fatalf("%s: got %#v, %v; want %#v", query, got, err, want)
		}
	}
	for _, query := range []string{
		"", "?dataset=invalid", "?dataset=events", "?dataset=syslog_messages",
		"?dataset=syslog&category=all",
		"?dataset=events&category=calls", "?dataset=calls&category=all",
	} {
		request := httptest.NewRequest(http.MethodGet, "/export.xlsx"+query, nil)
		if _, err := parseExportRequest(request.URL.Query()); err == nil {
			t.Fatalf("%s was accepted", query)
		}
	}
}

func TestExportRejectsInvalidRequestBeforeDependencies(t *testing.T) {
	response := httptest.NewRecorder()
	(&Server{}).exportXLSX(
		response,
		httptest.NewRequest(http.MethodGet, "/export.xlsx?dataset=bogus", nil),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAsyncExportCreationDoesNotRegressViewerAccess(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost,
		"/api/devices/7845e6d4-b8f1-4d0f-a8d4-c527f6868d02/export-jobs",
		strings.NewReader(`{"dataset":"calls"}`))
	request = request.WithContext(context.WithValue(request.Context(), sessionKey, store.Session{
		User: store.User{ID: uuid.New(), Role: "viewer"},
	}))
	(&Server{}).createExportJob(response, request)
	if response.Code == http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestExportJobPresentationMatchesFrontendContract(t *testing.T) {
	estimate := int64(100)
	response := presentExportJob(store.ExportJob{
		ID: uuid.New(), Status: "running", Format: "auto", OutputFormat: "xlsx",
		RowsProcessed: 25, RowsEstimated: &estimate, BytesSpooled: 2048,
	})
	if response.Format != "xlsx" || response.RowsWritten != 25 ||
		response.EstimatedRows == nil || *response.EstimatedRows != 100 ||
		response.BytesWritten != 2048 {
		t.Fatalf("unexpected public export response: %#v", response)
	}
	writer := httptest.NewRecorder()
	writeJSON(writer, http.StatusOK, map[string]any{"job": response})
	if disposition := writer.Header().Get("Content-Disposition"); disposition != "" {
		t.Fatalf("status response unexpectedly triggers a download: %q", disposition)
	}
	if contentType := writer.Header().Get("Content-Type"); !strings.HasPrefix(
		contentType, "application/json",
	) {
		t.Fatalf("status response content type = %q", contentType)
	}
}

func TestExportDownloadRequiresExplicitAvailableArtifact(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	if exportDownloadAvailable(store.ExportJob{Status: "running"}, now) {
		t.Fatal("running export became downloadable")
	}
	if exportDownloadAvailable(store.ExportJob{Status: "completed", ExpiresAt: &past}, now) {
		t.Fatal("expired export became downloadable")
	}
	job := store.ExportJob{
		Status: "completed", ExpiresAt: &future, Filename: "../../alarms.csv.zip",
		ContentType: "application/zip", SHA256: "abc123",
	}
	if !exportDownloadAvailable(job, now) {
		t.Fatal("completed unexpired export is unavailable")
	}
	header := make(http.Header)
	setExportDownloadHeaders(header, job, 42)
	if got := header.Get("Content-Disposition"); !strings.Contains(got, "attachment") ||
		!strings.Contains(got, "alarms.csv.zip") {
		t.Fatalf("content disposition = %q", got)
	}
	if header.Get("Content-Type") != "application/zip" ||
		header.Get("Content-Length") != "42" || header.Get("ETag") != `"abc123"` {
		t.Fatalf("download headers = %#v", header)
	}
}

func TestParseExportDateUsesDeviceTimezoneAndExclusiveEnd(t *testing.T) {
	location, err := time.LoadLocation("Asia/Novosibirsk")
	if err != nil {
		t.Fatal(err)
	}
	from, err := parseExportDate("2026-07-01", location, false)
	if err != nil {
		t.Fatal(err)
	}
	to, err := parseExportDate("2026-07-01", location, true)
	if err != nil {
		t.Fatal(err)
	}
	if !to.Equal(from.AddDate(0, 0, 1)) || from.Location() != location || to.Location() != location {
		t.Fatalf("range = %v..%v in %v", from, to, location)
	}
}

func TestDeviceDateRangeUsesActiveTimezoneAndDST(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/syslog-messages?date=2026-03-29", nil)
	response := httptest.NewRecorder()
	timeRange, ok := deviceDateRange(response, request, store.Device{
		Timezone: "UTC", ActiveTimezone: "Europe/Berlin",
	})
	if !ok {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := timeRange.To.Sub(timeRange.From); got != 23*time.Hour {
		t.Fatalf("DST day duration = %v, want 23h", got)
	}
	if got := timeRange.From.Format(time.RFC3339); got != "2026-03-28T23:00:00Z" {
		t.Fatalf("from = %s", got)
	}
}

func TestDeviceDateRangeRejectsInvalidDate(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/syslog-messages?date=2026-02-30", nil)
	response := httptest.NewRecorder()
	if _, ok := deviceDateRange(response, request, store.Device{ActiveTimezone: "UTC"}); ok {
		t.Fatal("invalid date was accepted")
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestSyncAllSyslogRequiresAsyncExport(t *testing.T) {
	response := httptest.NewRecorder()
	(&Server{}).exportXLSX(response, httptest.NewRequest(
		http.MethodGet, "/export.xlsx?dataset=syslog", nil,
	))
	if response.Code != http.StatusRequestEntityTooLarge ||
		!strings.Contains(response.Body.String(), "export-jobs") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSnapshotTupleExcludesRowsAfterEnqueue(t *testing.T) {
	highTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	highID := uuid.MustParse("80000000-0000-0000-0000-000000000000")
	if exportRowAfterSnapshot(highTime, highID, &highTime, &highID) {
		t.Fatal("watermark row was excluded")
	}
	laterID := uuid.MustParse("90000000-0000-0000-0000-000000000000")
	if !exportRowAfterSnapshot(highTime, laterID, &highTime, &highID) {
		t.Fatal("row after watermark tuple was included")
	}
	if !exportRowAfterSnapshot(highTime.Add(time.Nanosecond), uuid.Nil, &highTime, &highID) {
		t.Fatal("row after watermark time was included")
	}
}

func TestAsyncExportContextPublishesProgress(t *testing.T) {
	var got int64
	state := asyncExportState{
		job: store.ExportJob{ID: uuid.New()},
		progress: func(rows int64) error {
			got = rows
			return nil
		},
	}
	ctx := context.WithValue(context.Background(), asyncExportContextKey{}, state)
	job, progress, ok := asyncExportJob(ctx)
	if !ok || job.ID != state.job.ID {
		t.Fatal("async export state was not recovered")
	}
	if err := progress(123); err != nil || got != 123 {
		t.Fatalf("progress = %d, err=%v", got, err)
	}
}

func TestAutoExportUsesCSVForUnknownSyslogEstimate(t *testing.T) {
	from := time.Now()
	to := from.Add(time.Hour)
	if !useCSVZip(store.ExportJob{
		Dataset: "syslog", Format: "auto", RangeFrom: &from, RangeTo: &to,
	}) {
		t.Fatal("unknown Syslog estimate did not select CSV.zip")
	}
	estimate := int64(100)
	if useCSVZip(store.ExportJob{
		Dataset: "syslog", Format: "auto", RangeFrom: &from, RangeTo: &to,
		RowsEstimated: &estimate,
	}) {
		t.Fatal("small bounded Syslog export did not select XLSX")
	}
	if useCSVZip(store.ExportJob{Dataset: "syslog", Format: "xlsx"}) {
		t.Fatal("explicit XLSX request was not honored")
	}
	if !useCSVZip(store.ExportJob{Dataset: "calls", Format: "csv_zip"}) {
		t.Fatal("explicit calls CSV.zip request was not honored")
	}
	if got := csvSafe("=WEBSERVICE(\"https://example.test\")"); got[0] != '\'' {
		t.Fatalf("CSV formula was not escaped: %q", got)
	}
}

func TestCSVArchiveStreamsSafeRows(t *testing.T) {
	var output bytes.Buffer
	job := store.ExportJob{
		DeviceID: uuid.New(), Dataset: "calls",
		CreatedAt: time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
	}
	result, err := renderCSVArchive(job, &output, []string{"A", "B"},
		func(writer *csv.Writer) (int64, error) {
			return 1, writeCSVValues(writer, "=danger", 42)
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "csv_zip" || result.Rows != 1 {
		t.Fatalf("result = %#v", result)
	}
	archive, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.File) != 1 {
		t.Fatalf("archive files=%d", len(archive.File))
	}
	entry, err := archive.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	rows, err := csv.NewReader(entry).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][0] != "'=danger" || rows[1][1] != "42" {
		t.Fatalf("CSV rows = %#v", rows)
	}
}

func BenchmarkCSVArchiveStreaming100k(b *testing.B) {
	job := store.ExportJob{
		DeviceID: uuid.New(), Dataset: "syslog",
		CreatedAt: time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
	}
	for range b.N {
		var output bytes.Buffer
		_, err := renderCSVArchive(job, &output, []string{"Time", "Message"},
			func(writer *csv.Writer) (int64, error) {
				for row := 0; row < 100_000; row++ {
					if err := writeCSVValues(writer, "2026-07-26T12:00:00+07:00", row); err != nil {
						return int64(row), err
					}
				}
				return 100_000, nil
			}, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestExportScalarDereferencesPointersAndFormatsUUID(t *testing.T) {
	number := uint64(42)
	timestamp := time.Date(2026, time.July, 26, 10, 0, 0, 0, time.UTC)
	id := uuid.MustParse("7845e6d4-b8f1-4d0f-a8d4-c527f6868d02")
	var missing *uint64
	if got := exportScalar(missing); got != "" {
		t.Fatalf("nil pointer exported as %#v", got)
	}
	if got := exportScalar(&number); got != number {
		t.Fatalf("numeric pointer exported as %#v", got)
	}
	if got := exportScalar(&timestamp); got != timestamp {
		t.Fatalf("time pointer exported as %#v", got)
	}
	if got := exportScalar(id); got != id.String() {
		t.Fatalf("UUID exported as %#v", got)
	}
}

func TestExportWorkbookWritesScalarsAndRotatesSheets(t *testing.T) {
	workbook, err := newExportWorkbook([]any{"ID", "Value"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer workbook.Close()
	number := uint64(7)
	var missing *uint64
	for _, row := range [][]any{
		{"00123", &number},
		{"=1+1", missing},
		{"third", uint16(9)},
	} {
		if err := workbook.AddRow(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := workbook.Finish(&output); err != nil {
		t.Fatal(err)
	}
	parsed, err := excelize.OpenReader(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Close()
	if sheets := parsed.GetSheetList(); len(sheets) != 2 {
		t.Fatalf("sheets=%v, want two sheets", sheets)
	}
	first, err := parsed.GetRows("Data")
	if err != nil {
		t.Fatal(err)
	}
	second, err := parsed.GetRows("Data 2")
	if err != nil {
		t.Fatal(err)
	}
	if first[1][0] != "00123" || first[1][1] != "7" || first[2][0] != "=1+1" {
		t.Fatalf("unexpected first sheet: %#v", first)
	}
	if formula, err := parsed.GetCellFormula("Data", "A3"); err != nil || formula != "" {
		t.Fatalf("identifier interpreted as formula: formula=%q err=%v", formula, err)
	}
	if len(second) != 2 || second[1][0] != "third" || workbook.totalRows != 3 {
		t.Fatalf("unexpected second sheet or count: rows=%#v count=%d", second, workbook.totalRows)
	}
}

func TestExportResponseMetadataAndFilename(t *testing.T) {
	response := httptest.NewRecorder()
	deviceID := uuid.MustParse("7845e6d4-b8f1-4d0f-a8d4-c527f6868d02")
	setExportResponseHeaders(response, deviceID, exportRequest{
		Dataset: "syslog",
	}, "eltex-smg-1016m-3.410", 123, time.Date(2026, 7, 26, 12, 34, 56, 0, time.UTC))
	if got := response.Header().Get("X-Export-Dataset"); got != "syslog" {
		t.Fatalf("dataset header=%q", got)
	}
	if got := response.Header().Get("X-Export-Category"); got != "" {
		t.Fatalf("category header=%q", got)
	}
	if got := response.Header().Get("X-Export-Template"); got != "eltex-smg-1016m-3.410" {
		t.Fatalf("template header=%q", got)
	}
	if got := response.Header().Get("X-Export-Rows"); got != "123" {
		t.Fatalf("rows header=%q", got)
	}
	disposition := response.Header().Get("Content-Disposition")
	for _, part := range []string{"syslog", "7845e6d4"} {
		if !strings.Contains(disposition, part) {
			t.Fatalf("Content-Disposition %q does not contain %q", disposition, part)
		}
	}
}

func TestStaticHandlerConfinesRequestsToStaticRoot(t *testing.T) {
	base := t.TempDir()
	staticDir := filepath.Join(base, "web")
	if err := os.Mkdir(staticDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("safe-index"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "secret.txt"), []byte("outside-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := &Server{StaticDir: staticDir}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.URL.Path = "/../secret.txt"
	response := httptest.NewRecorder()
	server.staticHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "safe-index" {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestLogoutClearsSecureSessionCookie(t *testing.T) {
	server := &Server{Config: config.Config{SecureCookies: true}}
	response := httptest.NewRecorder()
	server.logout(response, httptest.NewRequest(http.MethodPost, "/api/logout", nil))
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].MaxAge >= 0 {
		t.Fatalf("unexpected logout cookie: %#v", cookies)
	}
}

func TestDashboardAPIRejectsInvalidWindowBeforeQueries(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/dashboard?window=2h", nil)
	(&Server{}).dashboard(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", response.Code)
	}
	if !strings.Contains(response.Body.String(), "window must be one of") {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
}

func TestRetentionAPIValidatesInputBeforeDatabase(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "unknown class", body: `{"policyClass":"unknown","days":30}`,
			want: "invalid retention policy class"},
		{name: "too short", body: `{"policyClass":"syslog","days":6}`,
			want: "retention days must be between 7 and 1095"},
		{name: "too long", body: `{"policyClass":"cdr","days":1096}`,
			want: "retention days must be between 7 and 1095"},
	}
	server := &Server{Store: nil}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPatch, "/api/system/retention",
				strings.NewReader(test.body))
			request = request.WithContext(context.WithValue(request.Context(), sessionKey,
				store.Session{User: store.User{Role: "admin"}}))
			server.updateRetention(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("got status %d, want 400", response.Code)
			}
			if !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("unexpected response: %s", response.Body.String())
			}
		})
	}
}

func TestRetentionRoutesRemainAdminOnly(t *testing.T) {
	handler := (&Server{}).requireAdmin(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	for _, test := range []struct {
		role string
		want int
	}{
		{role: "viewer", want: http.StatusForbidden},
		{role: "analyst", want: http.StatusForbidden},
		{role: "admin", want: http.StatusNoContent},
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/system/retention", nil)
		request = request.WithContext(context.WithValue(request.Context(), sessionKey,
			store.Session{User: store.User{Role: test.role}}))
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("role %s got status %d, want %d", test.role, response.Code, test.want)
		}
	}
}

func TestRetentionAPISynchronouslyReconcilesAndRefreshes(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx := context.Background()
	control, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.DB.Close()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	var cdrColumnsExists bool
	if err := control.DB.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='devices' AND column_name='cdr_columns'
	)`).Scan(&cdrColumnsExists); err != nil {
		t.Fatal(err)
	}
	if cdrColumnsExists {
		t.Fatal("cdr_columns remains after PostgreSQL migrations")
	}
	actor := store.User{ID: uuid.New(), Username: "retention-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = control.DB.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor.ID)
	})
	t.Cleanup(func() {
		_, _ = control.DB.Exec(context.Background(), `UPDATE retention_policies SET
			active_days=1095,pending_days=NULL,effective_at=NULL,updated_by=NULL,last_error=NULL
			WHERE policy_class='syslog'`)
	})

	t.Run("success returns applied policy", func(t *testing.T) {
		if _, err := control.DB.Exec(ctx, `UPDATE retention_policies SET
			active_days=30,pending_days=NULL,effective_at=NULL,last_error=NULL
			WHERE policy_class='syslog'`); err != nil {
			t.Fatal(err)
		}
		called := false
		server := &Server{
			Store: control,
			ReconcileRetention: func(ctx context.Context) error {
				called = true
				policies, err := control.DueRetentionPolicies(ctx)
				if err != nil {
					return err
				}
				for _, policy := range policies {
					if policy.PolicyClass == "syslog" {
						return control.CompleteRetentionPolicy(
							ctx, policy.PolicyClass, *policy.PendingDays, policy.UpdatedAt,
						)
					}
				}
				return errors.New("updated policy was not due")
			},
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/system/retention",
			strings.NewReader(`{"policyClass":"syslog","days":14}`))
		request = request.WithContext(context.WithValue(request.Context(), sessionKey,
			store.Session{User: actor}))
		server.updateRetention(response, request)
		if !called || response.Code != http.StatusOK {
			t.Fatalf("called=%v status=%d body=%s", called, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"activeDays":14`) ||
			!strings.Contains(response.Body.String(), `"pendingDays":null`) {
			t.Fatalf("response was not refreshed: %s", response.Body.String())
		}
	})

	t.Run("failure remains pending", func(t *testing.T) {
		if _, err := control.DB.Exec(ctx, `UPDATE retention_policies SET
			active_days=30,pending_days=NULL,effective_at=NULL,last_error=NULL
			WHERE policy_class='syslog'`); err != nil {
			t.Fatal(err)
		}
		applyErr := errors.New("clickhouse unavailable")
		server := &Server{
			Store: control,
			ReconcileRetention: func(ctx context.Context) error {
				policies, err := control.DueRetentionPolicies(ctx)
				if err != nil {
					return err
				}
				for _, policy := range policies {
					if policy.PolicyClass == "syslog" {
						if err := control.FailRetentionPolicy(
							ctx, policy.PolicyClass, policy.UpdatedAt, applyErr,
						); err != nil {
							return err
						}
						return applyErr
					}
				}
				return errors.New("updated policy was not due")
			},
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/system/retention",
			strings.NewReader(`{"policyClass":"syslog","days":14}`))
		request = request.WithContext(context.WithValue(request.Context(), sessionKey,
			store.Session{User: actor}))
		server.updateRetention(response, request)
		if response.Code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"pendingDays":14`) ||
			!strings.Contains(response.Body.String(), `"lastError":"clickhouse unavailable"`) {
			t.Fatalf("failure response was not refreshed: %s", response.Body.String())
		}
		policies, err := control.ListRetentionPolicies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, policy := range policies {
			if policy.PolicyClass == "syslog" {
				if policy.PendingDays == nil || *policy.PendingDays != 14 ||
					policy.LastError == nil || *policy.LastError != applyErr.Error() {
					t.Fatalf("failed policy was not preserved: %+v", policy)
				}
				return
			}
		}
		t.Fatal("syslog policy not found")
	})

	t.Run("failed pending change can be cancelled", func(t *testing.T) {
		called := false
		server := &Server{
			Store: control,
			ReconcileRetention: func(context.Context) error {
				called = true
				return nil
			},
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/system/retention",
			strings.NewReader(`{"policyClass":"syslog","cancel":true}`))
		request = request.WithContext(context.WithValue(request.Context(), sessionKey,
			store.Session{User: actor}))
		server.updateRetention(response, request)
		if !called || response.Code != http.StatusOK {
			t.Fatalf("called=%v status=%d body=%s", called, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"pendingDays":null`) ||
			!strings.Contains(response.Body.String(), `"lastError":null`) {
			t.Fatalf("cancel response was not refreshed: %s", response.Body.String())
		}
	})
}
