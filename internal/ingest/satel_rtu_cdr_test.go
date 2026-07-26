package ingest

import (
	"bytes"
	"encoding/csv"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSatelRTUParserOutcomeAndTypedFields(t *testing.T) {
	content, err := os.ReadFile("testdata/satel_rtu_cdr.csv")
	if err != nil {
		t.Fatal(err)
	}
	parser := SatelRTUCDRParser{
		DeviceID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		FileID:   uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Location: time.FixedZone("synthetic", 3*60*60), TimezoneRevision: 7,
	}
	result, err := parser.Parse(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if result.Rows != 4 || len(result.Records) != 4 || len(result.Errors) != 0 {
		t.Fatalf("unexpected parse result: rows=%d valid=%d errors=%v",
			result.Rows, len(result.Records), result.Errors)
	}
	if len(result.Header) != 120 {
		t.Fatalf("fixture header has %d columns, want 120", len(result.Header))
	}
	answered := result.Records[0]
	if answered.Outcome != "answered" || answered.DurationMS == nil ||
		*answered.DurationMS != 10000 {
		t.Fatalf("answered record mapped incorrectly: %+v", answered)
	}
	if len(answered.RawFields) != 120 || answered.InLRN != "lrn-in" ||
		answered.RetrievedLRN != "lrn-retrieved" || answered.LNPServer !=
		"lnp.synthetic.invalid" || answered.RouteRetries == nil ||
		*answered.RouteRetries != 2 || answered.SourceUTCOffsetMinutes != 180 ||
		answered.TimezoneRevision != 7 {
		t.Fatalf("provenance/raw fields were not retained: %+v", answered)
	}
	sip487 := result.Records[1]
	if sip487.DisconnectSuccess != true || sip487.ConnectTime != nil ||
		sip487.Outcome != "failed" || sip487.DurationMS != nil {
		t.Fatalf("SIP 487 outcome used success flag instead of connect_time: %+v", sip487)
	}
	for _, record := range result.Records[1:] {
		if record.Outcome != "failed" {
			t.Fatalf("%s unexpectedly answered", record.CDRID)
		}
	}
}

func TestSatelRTUParserQuarantinesMalformedOptionalNumericData(t *testing.T) {
	content, err := os.ReadFile("testdata/satel_rtu_cdr.csv")
	if err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(bytes.NewReader(content))
	reader.Comma = ';'
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	column := -1
	for index, name := range records[0] {
		if name == "src_media_bytes_in" {
			column = index
			break
		}
	}
	if column < 0 {
		t.Fatal("src_media_bytes_in fixture column missing")
	}
	records[1][column] = "not-a-number"
	var malformed bytes.Buffer
	writer := csv.NewWriter(&malformed)
	writer.Comma = ';'
	if err := writer.WriteAll(records); err != nil {
		t.Fatal(err)
	}
	writer.Flush()
	result, err := (SatelRTUCDRParser{
		DeviceID: uuid.New(), FileID: uuid.New(), Location: time.UTC,
	}).Parse(&malformed)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rows != 4 || len(result.Records) != 3 || len(result.Errors) != 1 ||
		!strings.Contains(result.Errors[0].Error(), "src_media_bytes_in") {
		t.Fatalf("malformed numeric was not quarantined: %+v", result)
	}
}

func TestSatelRTURecordIDIsStableAcrossFiles(t *testing.T) {
	content, err := os.ReadFile("testdata/satel_rtu_cdr.csv")
	if err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.New()
	first, err := (SatelRTUCDRParser{
		DeviceID: deviceID, FileID: uuid.New(), Location: time.UTC,
	}).Parse(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	second, err := (SatelRTUCDRParser{
		DeviceID: deviceID, FileID: uuid.New(), Location: time.UTC,
	}).Parse(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if first.Records[0].RecordID != second.Records[0].RecordID {
		t.Fatalf("record id changed across files: %s != %s",
			first.Records[0].RecordID, second.Records[0].RecordID)
	}
}

func TestSatelRTUParserToleratesReorderedAndAdditionalColumns(t *testing.T) {
	content, err := os.ReadFile("testdata/satel_rtu_cdr.csv")
	if err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(bytes.NewReader(content))
	reader.Comma = ';'
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for index := range records {
		records[index][0], records[index][5] = records[index][5], records[index][0]
		records[index] = append(records[index], "extra-"+string(rune('a'+index)))
	}
	records[0][len(records[0])-1] = "new_header"
	var reordered bytes.Buffer
	writer := csv.NewWriter(&reordered)
	writer.Comma = ';'
	if err := writer.WriteAll(records); err != nil {
		t.Fatal(err)
	}
	writer.Flush()
	result, err := (SatelRTUCDRParser{
		DeviceID: uuid.New(), FileID: uuid.New(), Location: time.UTC,
	}).Parse(&reordered)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 4 || result.Records[0].CDRID != "synthetic-answered" ||
		result.Records[0].RawFields["new_header"] != "extra-b" {
		t.Fatalf("header-driven mapping failed: %+v", result)
	}
}

func TestSatelRTUParserValidatesRequiredHeaders(t *testing.T) {
	base := `"cdr_id";"cdr_id"` + "\n"
	if _, err := (SatelRTUCDRParser{}).Parse(strings.NewReader(base)); err == nil ||
		!strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate header error = %v", err)
	}
	if _, err := (SatelRTUCDRParser{}).Parse(strings.NewReader(`"cdr_id"` + "\n")); err == nil ||
		!strings.Contains(err.Error(), "required header") {
		t.Fatalf("missing header error = %v", err)
	}
}

func TestSatelRTUParserQuarantinesBadRowsButReturnsValidRows(t *testing.T) {
	content, err := os.ReadFile("testdata/satel_rtu_cdr.csv")
	if err != nil {
		t.Fatal(err)
	}
	value := strings.Replace(string(content), `"synthetic-487"`, `""`, 1)
	result, err := (SatelRTUCDRParser{
		DeviceID: uuid.New(), FileID: uuid.New(), Location: time.UTC,
	}).Parse(strings.NewReader(value))
	if err != nil {
		t.Fatal(err)
	}
	if result.Rows != 4 || len(result.Records) != 3 || len(result.Errors) != 1 {
		t.Fatalf("row quarantine semantics failed: rows=%d valid=%d errors=%v",
			result.Rows, len(result.Records), result.Errors)
	}
}
