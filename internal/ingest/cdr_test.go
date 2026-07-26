package ingest

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCDRParserFullEltexRow(t *testing.T) {
	const sample = `SMG1016M. CDR. File started at '20260723235757'
Device Sign;Setup time;Connect time;Disconnect time;Duration;Release cause;Call release info;Incoming IP-address;Incoming type;Incoming description;Outgoing IP-address;Outgoing type;Outgoing description;Incoming CgPN;Outgoing CgPN;Incoming CdPN;Outgoing CdPN;Redirecting mark;Pickup mark;Release side mark;Incoming SS7 CIC;Incoming SIP Call-ID;Outgoing SS7 CIC;Outgoing SIP Call-ID;Incoming SS7 category;Incoming Calling party category (RUS);Outgoing SS7 category;Outgoing Calling party category (RUS);Incoming E1 stream;Incoming E1 channel;Outgoing E1 stream;Outgoing E1 channel;Sequence number;Incoming redirecting number;Outgoing redirecting number;RADIUS Accounting-Session-Id;Global Callref;Incoming numplan;Outgoing numplan;UniqueTag identifier;Calling NAI;Called NAI;Incoming redirecting NAI;Outgoing redirecting NAI;Call transfer mark;Call record path;IVR call record path;Rejecting RADIUS server address;Calling NAI original;Called NAI original;
mts;2026-07-23 23:58:33.237;2026-07-23 23:58:37.191;2026-07-23 23:58:46.657;9.466;16;user answer;5.227.161.180;trunk-SIP;PSTN_Novosibirsk_MTS_Local;11.254.255.131;trunk-SIP;11369_Novosibirsk_MTS;73832888803;3832888803;73832188654;3832188654;normal;normal;originate;;6957b57c86f211f1a421005056a36854;;1784-851113-222573;10;1;225;2;;;;;20260628183403-155881;;;11000307 6a62aaa9 c9f5297a 4f6a3001;;0;0;110003076a62aaa9c9f5297a4f6a3001;2;2;2;2;;;;;3;3;
`
	location, err := time.LoadLocation("Asia/Novosibirsk")
	if err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.New()
	result, err := (CDRParser{DeviceID: deviceID, FileID: uuid.New(), Location: location}).Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected row errors: %v", result.Errors)
	}
	if len(result.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(result.Records))
	}
	record := result.Records[0]
	if record.SequenceNumber != "20260628183403-155881" || record.Sequence != 155881 {
		t.Fatalf("sequence parsed incorrectly: %#v", record)
	}
	if record.RadiusSessionIDNormalized != "110003076a62aaa9c9f5297a4f6a3001" {
		t.Fatalf("session id normalization failed: %q", record.RadiusSessionIDNormalized)
	}
	if record.DurationMS == nil || *record.DurationMS != 9466 {
		t.Fatalf("duration parsed incorrectly: %v", record.DurationMS)
	}
	if record.UniqueTag != "110003076a62aaa9c9f5297a4f6a3001" {
		t.Fatalf("unique tag parsed incorrectly: %q", record.UniqueTag)
	}
	if record.SourceTimezone != "Asia/Novosibirsk" || record.SourceUTCOffsetMinutes != 420 {
		t.Fatalf("source time audit parsed incorrectly: %q/%d",
			record.SourceTimezone, record.SourceUTCOffsetMinutes)
	}
	wantSetup := time.Date(2026, 7, 23, 16, 58, 33, 237_000_000, time.UTC)
	if record.SetupTime == nil || !record.SetupTime.Equal(wantSetup) {
		t.Fatalf("device CDR timestamp interpreted incorrectly: got %v want %v", record.SetupTime, wantSetup)
	}
	replayed, err := (CDRParser{
		DeviceID: deviceID, FileID: uuid.New(), Location: location,
	}).Parse(strings.NewReader(sample))
	if err != nil || len(replayed.Records) != 1 {
		t.Fatalf("replay parse failed: %v", err)
	}
	if replayed.Records[0].RecordID != record.RecordID {
		t.Fatal("same device/sequence must produce an idempotent record id")
	}
}

func TestCDRTimeUsesEachDeviceTimezone(t *testing.T) {
	novosibirsk, err := time.LoadLocation("Asia/Novosibirsk")
	if err != nil {
		t.Fatal(err)
	}
	moscow, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		t.Fatal(err)
	}
	const wallClock = "2026-07-24 12:00:00"
	novosibirskTime, err := parseCDRTime(wallClock, novosibirsk)
	if err != nil {
		t.Fatal(err)
	}
	moscowTime, err := parseCDRTime(wallClock, moscow)
	if err != nil {
		t.Fatal(err)
	}
	if novosibirskTime.Equal(*moscowTime) {
		t.Fatal("same wall clock from different SMG timezones became the same instant")
	}
	if novosibirskTime.In(novosibirsk).Format("2006-01-02 15:04:05") != wallClock ||
		moscowTime.In(moscow).Format("2006-01-02 15:04:05") != wallClock {
		t.Fatal("device wall clock was not preserved for display")
	}
}

func TestCDRRequiresProfileWithoutHeader(t *testing.T) {
	_, err := (CDRParser{}).Parse(strings.NewReader("mts;2026-07-23 23:58:33.237;16;"))
	if err == nil {
		t.Fatal("expected an error for a headerless CDR without a configured profile")
	}
}

func TestCDRProfile3410PadsShortRows(t *testing.T) {
	header := strings.Join(CDRProfileForFirmware("3.410"), ";") + ";"
	// 51 data fields after Eltex omits the final empty Redirection type column.
	dataFields := make([]string, 51)
	dataFields[0] = "mts"
	dataFields[1] = "2026-07-24 18:50:10.000"
	dataFields[2] = ""
	dataFields[3] = "2026-07-24 18:50:20.000"
	dataFields[4] = "10"
	dataFields[5] = "16"
	dataFields[32] = "20260724185002-1"
	sample := "SMG1016M. CDR. File started at '20260724185002'\n" +
		header + "\n" + strings.Join(dataFields, ";") + "\n"
	result, err := (CDRParser{
		DeviceID: uuid.New(), FileID: uuid.New(), Location: time.UTC,
		ExpectedHeader: CDRProfileForFirmware("3.410"),
	}).Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("short 3.410 row should be padded, got errors: %v", result.Errors)
	}
	if len(result.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(result.Records))
	}
	raw := result.Records[0].RawFields
	if raw["time_in_queue"] != "" || raw["redirection_type"] != "" {
		t.Fatalf("padded trailing fields: %#v", raw)
	}
	if _, ok := raw["time_in_queue"]; !ok {
		t.Fatal("time_in_queue missing from raw fields")
	}
	if _, ok := raw["redirection_type"]; !ok {
		t.Fatal("redirection_type missing from raw fields")
	}
}

func TestCDRProfilesMatchFirmwareSchemes(t *testing.T) {
	if len(CDRProfileForFirmware("3.410")) != 52 {
		t.Fatalf("3.410 profile want 52 columns, got %d", len(CDRProfileForFirmware("3.410")))
	}
	if len(CDRProfileForFirmware("3.23.2")) != 50 {
		t.Fatalf("3.23.2 profile want 50 columns, got %d", len(CDRProfileForFirmware("3.23.2")))
	}
}

func TestCDRRejectsAnotherDeviceSign(t *testing.T) {
	const sample = `Device Sign;Setup time;Connect time;Disconnect time;Sequence number
fixer;2026-07-24 12:00:00;;;20260724120000-1
`
	_, err := (CDRParser{
		DeviceID: uuid.New(), FileID: uuid.New(), Location: time.UTC,
		ExpectedDeviceSign: "mts",
	}).Parse(strings.NewReader(sample))
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("got %v, want device_sign mismatch", err)
	}
}

func TestCDRParserAcceptsRepeatedMatchingBlocks(t *testing.T) {
	const header = "Device Sign;Setup time;Connect time;Disconnect time;Sequence number"
	const sample = `SMG1016M. CDR. File started at '20260724120000'
Device Sign;Setup time;Connect time;Disconnect time;Sequence number
smg;2026-07-24 12:00:00;;;20260724120000-1
SMG1016M. CDR. File started at '20260724120100'
 device sign ; setup-time ; connect time ; disconnect_time ; sequence number
smg;2026-07-24 12:01:00;;;20260724120100-2
`
	result, err := (CDRParser{
		DeviceID:           uuid.New(),
		FileID:             uuid.New(),
		Location:           time.UTC,
		// Header-driven exports may contain a configured subset of the firmware
		// profile. Repeated blocks must match the file's active header.
		ExpectedHeader:     append(strings.Split(header, ";"), "Release cause"),
		ExpectedDeviceSign: "smg",
	}).Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected row errors: %v", result.Errors)
	}
	if result.Rows != 2 || len(result.Records) != 2 {
		t.Fatalf("rows=%d records=%d, want 2/2", result.Rows, len(result.Records))
	}
	for _, record := range result.Records {
		if record.RawFields["device_sign"] != "smg" {
			t.Fatalf("banner became device_sign: %#v", record.RawFields)
		}
	}
}

func TestCDRParserRejectsMismatchedRepeatedBlockHeader(t *testing.T) {
	const sample = `SMG1016M. CDR. File started at '20260724120000'
Device Sign;Setup time;Connect time;Disconnect time;Sequence number
smg;2026-07-24 12:00:00;;;20260724120000-1
SMG1016M. CDR. File started at '20260724120100'
Device Sign;Setup time;Connect time;Disconnect time;Release cause
smg;2026-07-24 12:01:00;;;16
`
	_, err := (CDRParser{
		DeviceID:           uuid.New(),
		FileID:             uuid.New(),
		Location:           time.UTC,
		ExpectedDeviceSign: "smg",
	}).Parse(strings.NewReader(sample))
	if err == nil || !strings.Contains(err.Error(), "repeated CDR block header") {
		t.Fatalf("got %v, want repeated header mismatch", err)
	}
}

func TestCDRSequenceNumberIsIsolatedByDevice(t *testing.T) {
	const sample = `Device Sign;Setup time;Connect time;Disconnect time;Sequence number
smg;2026-07-24 12:00:00;;;20260724120000-1
`
	parse := func(deviceID uuid.UUID) uuid.UUID {
		result, err := (CDRParser{
			DeviceID: deviceID, FileID: uuid.New(), Location: time.UTC,
			ExpectedDeviceSign: "smg",
		}).Parse(strings.NewReader(sample))
		if err != nil || len(result.Records) != 1 {
			t.Fatalf("parse for %s failed: %v", deviceID, err)
		}
		return result.Records[0].RecordID
	}
	if parse(uuid.New()) == parse(uuid.New()) {
		t.Fatal("same sequence number from different SMGs produced one record ID")
	}
}
