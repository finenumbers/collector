package analytics

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAntifraudLifecycleClickHouse(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}
	client, err := Open(
		address, "collector", os.Getenv("CLICKHOUSE_TEST_USER"),
		os.Getenv("CLICKHOUSE_TEST_PASSWORD"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := client.Migrate(ctx, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.New()
	now := time.Now().UTC().Add(-time.Minute)
	request := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now,
		SourceIP: net.ParseIP("10.0.0.10"), SourcePort: 10003,
		Payload: []byte("Access-Request"), HeaderFormat: "eltex-trace",
		ParseStatus: "parsed", Category: "radius", Component: "RADIUS",
		Message: "Access-Request",
		Attributes: map[string]string{
			"call_context": "C0TEST1", "packet_code": "access-request",
			"packet_direction": "request", "packet_identifier": "157",
			"acct_session_id": "session 42", "xpgk_request_type": "check_call",
			"is_antifraud": "true", "calling_station_id": "73832888803",
			"called_station_id": "74951234567",
		},
	}
	response := request
	response.EventID = uuid.New()
	response.ReceivedAt = now.Add(165 * time.Millisecond)
	response.Payload = []byte("Access-Reject")
	response.Message = "Access-Reject"
	response.Attributes = map[string]string{
		"call_context": "C0TEST1", "packet_code": "access-reject",
		"packet_direction": "response", "packet_identifier": "157",
		"result": "reject", "latency_ms": "165",
	}
	for _, event := range []SyslogEvent{request, response} {
		if err := client.InsertSyslog(ctx, event); err != nil {
			t.Fatal(err)
		}
		if err := client.ProcessSyslogDerived(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	recordID := uuid.New()
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: recordID, DeviceID: deviceID, FileID: uuid.New(), RowNumber: 1,
		IngestedAt: now, SequenceNumber: "20260724170000-1", BootEpoch: "20260724170000",
		Sequence: 1, SetupTime: &now, RadiusSessionID: "session 42",
		RadiusSessionIDNormalized: "session42", RawFields: map[string]string{},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := client.ReconcileDevice(ctx, deviceID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	candidateRecordID := uuid.New()
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: candidateRecordID, DeviceID: deviceID, FileID: uuid.New(), RowNumber: 2,
		IngestedAt: now, SequenceNumber: "20260724170000-2", BootEpoch: "20260724170000",
		Sequence: 2, SetupTime: &now, IncomingCgPN: "73832888803",
		RawFields: map[string]string{},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := client.ReconcileDevice(ctx, deviceID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	sipEvent := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now.Add(time.Second),
		SourceIP: net.ParseIP("10.0.0.10"), SourcePort: 10003,
		Payload: []byte("SIP connected"), HeaderFormat: "eltex-trace",
		ParseStatus: "parsed", Category: "sip", Component: "SIP",
		Message: "connected", Attributes: map[string]string{"call_context": "C0TEST1"},
	}
	if err := client.InsertSyslog(ctx, sipEvent); err != nil {
		t.Fatal(err)
	}
	if err := client.ProcessSyslogDerived(ctx, sipEvent); err != nil {
		t.Fatal(err)
	}
	page, err := client.ListAntifraudPage(ctx, deviceID, "", 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("got %d lifecycles, want 1", len(page.Items))
	}
	item := page.Items[0]
	if item.Decision != "reject" || item.Q850Cause == nil || *item.Q850Cause != 21 ||
		item.LegCount != 1 || item.Completeness != "complete" ||
		item.CorrelationMethod != "exact_acct_session" ||
		item.CorrelationConfidence != 1 || abs64(item.CorrelationTimeDeltaMS) >= 1000 {
		t.Fatalf("invalid lifecycle: %#v", item)
	}
	timeline, err := client.AntifraudTimeline(ctx, deviceID, item.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline) != 2 {
		t.Fatalf("got %d timeline events, want 2", len(timeline))
	}
	callTimeline, err := client.CallTimeline(ctx, deviceID, recordID)
	if err != nil {
		t.Fatal(err)
	}
	if len(callTimeline) < 2 {
		t.Fatalf("CDR did not receive complete AntiFraud evidence: %d", len(callTimeline))
	}
	eventsPage, err := client.ListEventsPage(ctx, deviceID, "all", "", 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(eventsPage.Items) != 3 {
		t.Fatalf("got %d interpreted Syslog events, want 3", len(eventsPage.Items))
	}
	var candidateLinks uint64
	if err := client.Conn.QueryRow(ctx, `SELECT count()
		FROM collector.call_event_links
		WHERE device_id=? AND cdr_record_id=?`, deviceID, candidateRecordID).
		Scan(&candidateLinks); err != nil {
		t.Fatal(err)
	}
	if candidateLinks != 0 {
		t.Fatalf("weak evidence must remain unlinked: links=%d", candidateLinks)
	}
	stats, err := client.Stats(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Antifraud24h != 1 || stats.AntifraudRejected24h != 1 ||
		stats.UnlinkedCalls24h != 1 {
		t.Fatalf("incorrect lifecycle coverage: %#v", stats)
	}
	diagnostics, err := client.SyslogDiagnostics(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics.RawEvents24h != 3 || diagnostics.Classified24h != 3 ||
		diagnostics.AntifraudComplete != 1 || diagnostics.CorrelationExact == 0 {
		t.Fatalf("incorrect parser/lifecycle diagnostics: %#v", diagnostics)
	}
}

func TestReconcilerEnforcesOneToOneOnSessionConflict(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}
	client, err := Open(
		address, "collector", os.Getenv("CLICKHOUSE_TEST_USER"),
		os.Getenv("CLICKHOUSE_TEST_PASSWORD"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := client.Migrate(ctx, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	for index, callContext := range []string{"C-CONFLICT-1", "C-CONFLICT-2"} {
		event := SyslogEvent{
			EventID: uuid.New(), DeviceID: deviceID,
			ReceivedAt: now.Add(time.Duration(index) * time.Second),
			SourceIP:   net.ParseIP("10.0.0.11"), SourcePort: 10003,
			Category: "radius", Component: "RADIUS", ParseStatus: "parsed",
			Attributes: map[string]string{
				"call_context": callContext, "acct_session_id": "shared-session",
				"packet_code": "Access-Request", "request_type": "check_call",
				"is_antifraud": "true",
			},
		}
		if err := client.ProcessSyslogDerived(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	setup := now
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: uuid.New(), DeviceID: deviceID, FileID: uuid.New(), RowNumber: 1,
		IngestedAt: now, SetupTime: &setup, RadiusSessionID: "shared-session",
		RadiusSessionIDNormalized: "shared-session", RawFields: map[string]string{},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := client.ReconcileDevice(ctx, deviceID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	var linked, ambiguous uint64
	if err := client.Conn.QueryRow(ctx, `SELECT countIf(ambiguity=0),countIf(ambiguity=1)
		FROM collector.antifraud_call_links FINAL
		WHERE device_id=? AND parser_version=?`, deviceID, SyslogParserVersion).
		Scan(&linked, &ambiguous); err != nil {
		t.Fatal(err)
	}
	if linked != 1 || ambiguous != 1 {
		t.Fatalf("linked=%d ambiguous=%d, want strict one-to-one 1/1", linked, ambiguous)
	}
	if err := client.InvalidateDeviceDerivedData(ctx, deviceID); err != nil {
		t.Fatalf("invalidate derived data after timezone edit: %v", err)
	}
}

func TestCDRTimezoneReinterpretationUsesRawWallClock(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}
	client, err := Open(
		address, "collector", os.Getenv("CLICKHOUSE_TEST_USER"),
		os.Getenv("CLICKHOUSE_TEST_PASSWORD"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := client.Migrate(ctx, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	deviceID, recordID := uuid.New(), uuid.New()
	wrongUTC := time.Date(2026, 7, 24, 18, 0, 0, 0, time.UTC)
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: recordID, DeviceID: deviceID, FileID: uuid.New(), RowNumber: 1,
		IngestedAt: wrongUTC, SetupTime: &wrongUTC, SourceTimezone: "UTC",
		RawFields: map[string]string{"setup_time": "2026-07-24 18:00:00.000"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := client.ReinterpretCDRTimes(ctx, deviceID, "Asia/Novosibirsk"); err != nil {
		t.Fatal(err)
	}
	var setup time.Time
	var timezone string
	var offset int16
	if err := client.Conn.QueryRow(ctx, `SELECT setup_time,source_timezone,
		source_utc_offset_minutes FROM collector.cdr_time_interpretations FINAL
		WHERE device_id=? AND record_id=?`, deviceID, recordID).
		Scan(&setup, &timezone, &offset); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 7, 24, 11, 0, 0, 0, time.UTC)
	if !setup.Equal(want) || timezone != "Asia/Novosibirsk" || offset != 420 {
		t.Fatalf("setup=%v timezone=%q offset=%d", setup, timezone, offset)
	}
	page, err := client.ListCallsPage(ctx, deviceID, "", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].SetupTime == nil ||
		!page.Items[0].SetupTime.Equal(want) {
		t.Fatalf("calls API did not use corrected time: %#v", page.Items)
	}
}

func TestShadowRevisionCorrelationAndStaleAssignmentReplacement(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}
	client, err := Open(
		address, "collector", os.Getenv("CLICKHOUSE_TEST_USER"),
		os.Getenv("CLICKHOUSE_TEST_PASSWORD"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := client.Migrate(ctx, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	job := DeviceRevisionJob{
		DeviceID: deviceID, Revision: 1, Timezone: "Asia/Novosibirsk",
		Status: "active", UpdatedAt: now,
	}
	if err := client.writeDeviceRevisionJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	request := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now,
		EventTime: &now, ParseStatus: "parsed", Category: "radius",
		Component: "RADIUS", SourceTimezone: "Asia/Novosibirsk",
		SourceUTCOffsetMinutes: 420, TimezoneRevision: 1,
		Attributes: map[string]string{
			"call_context": "C-SHADOW", "acct_session_id": "shadow-session",
			"packet_code": "access-request", "xpgk_request_type": "check_call",
			"is_antifraud": "true", "calling_station_id": "73832888803",
			"called_station_id": "74951234567",
		},
	}
	response := request
	response.EventID = uuid.New()
	response.ReceivedAt = now.Add(100 * time.Millisecond)
	response.EventTime = &response.ReceivedAt
	response.Attributes = map[string]string{
		"call_context": "C-SHADOW", "acct_session_id": "shadow-session",
		"packet_code": "access-accept", "xpgk_request_type": "check_call",
		"is_antifraud": "true", "result": "accept",
	}
	if err := client.InsertSyslogBatch(ctx, []SyslogEvent{request, response}); err != nil {
		t.Fatal(err)
	}
	if err := client.ProcessSyslogShadowDerivedBatch(ctx, []SyslogEvent{request, response}); err != nil {
		t.Fatal(err)
	}
	firstSetup := now.Add(30 * time.Second)
	firstRecordID := uuid.New()
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: firstRecordID, DeviceID: deviceID, FileID: uuid.New(), RowNumber: 1,
		IngestedAt: now, SetupTime: &firstSetup, RadiusSessionID: "shadow-session",
		RadiusSessionIDNormalized: "shadow-session",
		RawFields:                 map[string]string{"setup_time": "2026-07-24 19:00:30"},
		SourceTimezone:            "Asia/Novosibirsk", SourceUTCOffsetMinutes: 420,
		TimezoneRevision: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	bucket := DirtyCorrelationBucket{
		DeviceID: deviceID, Revision: 1, Bucket: now.Truncate(24 * time.Hour),
	}
	if err := client.ReconcileDirtyBucket(ctx, bucket); err != nil {
		t.Fatal(err)
	}
	page, err := client.ListAntifraudPage(ctx, deviceID, "", 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].CorrelationState != "exact" ||
		len(page.Items[0].LinkedRecordIDs) != 1 ||
		page.Items[0].LinkedRecordIDs[0] != firstRecordID ||
		!strings.Contains(page.Items[0].FirstEventLocal, "+07:00") {
		t.Fatalf("unexpected current AntiFraud page: %#v", page)
	}
	eventsPage, err := client.ListEventsPage(ctx, deviceID, "radius", "", 100, nil)
	if err != nil || len(eventsPage.Items) != 2 {
		t.Fatalf("current events page failed: items=%d err=%v", len(eventsPage.Items), err)
	}
	callsPage, err := client.ListCallsPage(ctx, deviceID, "", 100, nil)
	if err != nil || len(callsPage.Items) != 1 ||
		!strings.Contains(callsPage.Items[0].SetupTimeLocal, "+07:00") {
		t.Fatalf("current calls page failed: %#v err=%v", callsPage, err)
	}
	timeline, err := client.AntifraudTimeline(
		ctx, deviceID, page.Items[0].TransactionID,
	)
	if err != nil || len(timeline) != 2 {
		t.Fatalf("current lifecycle timeline failed: items=%d err=%v", len(timeline), err)
	}
	if _, err := client.Stats(ctx, deviceID); err != nil {
		t.Fatalf("current stats failed: %v", err)
	}
	secondRecordID := uuid.New()
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: secondRecordID, DeviceID: deviceID, FileID: uuid.New(), RowNumber: 2,
		IngestedAt: now.Add(time.Second), SetupTime: &now, RadiusSessionID: "shadow-session",
		RadiusSessionIDNormalized: "shadow-session",
		RawFields:                 map[string]string{"setup_time": "2026-07-24 19:00:00"},
		SourceTimezone:            "Asia/Novosibirsk", SourceUTCOffsetMinutes: 420,
		TimezoneRevision: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := client.ReconcileDirtyBucket(ctx, bucket); err != nil {
		t.Fatal(err)
	}
	var assigned uuid.UUID
	var assignmentCount uint64
	if err := client.Conn.QueryRow(ctx, `SELECT assumeNotNull(cdr_record_id),count()
		FROM collector.call_assignments FINAL
		WHERE device_id=? AND timezone_revision=?
		GROUP BY cdr_record_id`, deviceID, uint64(1)).
		Scan(&assigned, &assignmentCount); err != nil {
		t.Fatal(err)
	}
	if assigned != secondRecordID || assignmentCount != 1 {
		t.Fatalf("stale assignment survived: record=%s count=%d", assigned, assignmentCount)
	}
	diagnostics, err := client.SyslogDiagnostics(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics.CorrelationTotal != diagnostics.CorrelationExact+
		diagnostics.CorrelationComposite+diagnostics.CorrelationAmbiguous+
		diagnostics.CorrelationOrphan {
		t.Fatalf("coverage invariant failed: %#v", diagnostics)
	}
}

func TestChunkedRevisionReplayUsesDurableCursor(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}
	client, err := Open(
		address, "collector", os.Getenv("CLICKHOUSE_TEST_USER"),
		os.Getenv("CLICKHOUSE_TEST_PASSWORD"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := client.Migrate(ctx, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	for index := range 3 {
		event := SyslogEvent{
			EventID: uuid.New(), DeviceID: deviceID,
			ReceivedAt: now.Add(time.Duration(index) * time.Millisecond),
			SourceIP:   net.ParseIP("10.0.0.19"), SourcePort: 10003,
			Payload: []byte("WEBS: replay"), ParseStatus: "parsed",
			Category: "system_journal", SourceTimezone: "UTC", TimezoneRevision: 1,
		}
		if err := client.InsertSyslog(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: uuid.New(), DeviceID: deviceID, FileID: uuid.New(), RowNumber: 1,
		IngestedAt: now, SetupTime: &now,
		RawFields:      map[string]string{"setup_time": "2026-07-24 12:00:00"},
		SourceTimezone: "UTC", TimezoneRevision: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := client.ScheduleDeviceRebuild(ctx, deviceID, 2, "Asia/Novosibirsk"); err != nil {
		t.Fatal(err)
	}
	jobs, err := client.ListBuildingDeviceRevisions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var job DeviceRevisionJob
	for _, candidate := range jobs {
		if candidate.DeviceID == deviceID && candidate.Revision == 2 {
			job = candidate
		}
	}
	if job.DeviceID == uuid.Nil {
		t.Fatal("scheduled durable rebuild job was not found")
	}
	first, err := client.NextDeviceRevisionSyslogBatch(ctx, job, 2)
	if err != nil || len(first) == 0 || len(first) > 2 {
		t.Fatalf("first replay chunk: rows=%d err=%v", len(first), err)
	}
	if err := client.AdvanceDeviceRevisionSyslog(ctx, job, first); err != nil {
		t.Fatal(err)
	}
	jobs, err = client.ListBuildingDeviceRevisions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range jobs {
		if candidate.DeviceID == deviceID && candidate.Revision == 2 {
			job = candidate
		}
	}
	seen := make(map[uuid.UUID]bool)
	for _, row := range first {
		seen[row.EventID] = true
	}
	for len(seen) < 3 {
		next, nextErr := client.NextDeviceRevisionSyslogBatch(ctx, job, 2)
		if nextErr != nil || len(next) == 0 {
			t.Fatalf("durable cursor stopped early: seen=%d rows=%#v err=%v", len(seen), next, nextErr)
		}
		for _, row := range next {
			if seen[row.EventID] {
				t.Fatalf("durable cursor repeated event %s", row.EventID)
			}
			seen[row.EventID] = true
		}
		if err := client.AdvanceDeviceRevisionSyslog(ctx, job, next); err != nil {
			t.Fatal(err)
		}
		jobs, _ = client.ListBuildingDeviceRevisions(ctx)
		for _, candidate := range jobs {
			if candidate.DeviceID == deviceID && candidate.Revision == 2 {
				job = candidate
			}
		}
	}
	jobs, _ = client.ListBuildingDeviceRevisions(ctx)
	for _, candidate := range jobs {
		if candidate.DeviceID == deviceID && candidate.Revision == 2 {
			job = candidate
		}
	}
	job, done, err := client.RebuildCDRTimeChunk(ctx, job, 100)
	if err != nil || !done || job.CDRProcessed != 1 {
		t.Fatalf("CDR replay chunk failed: job=%#v done=%v err=%v", job, done, err)
	}
}
