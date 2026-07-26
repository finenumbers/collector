package analytics

import (
	"context"
	"net"
	"os"
	"strconv"
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
	if item.Decision != "verification_reject" || item.Q850Cause != nil ||
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
	selectedDay := &TimeRange{From: now.Add(-time.Hour), To: now.Add(time.Hour)}
	if dated, rangeErr := client.ListEventsPageRange(
		ctx, deviceID, "radius", "", 100, nil, selectedDay,
	); rangeErr != nil || len(dated.Items) != 2 {
		t.Fatalf("dated current events failed: items=%d err=%v", len(dated.Items), rangeErr)
	}
	if dated, rangeErr := client.ListCallsPageRange(
		ctx, deviceID, "", 100, nil, selectedDay,
	); rangeErr != nil || len(dated.Items) != 1 {
		t.Fatalf("dated current calls failed: items=%d err=%v", len(dated.Items), rangeErr)
	}
	if dated, rangeErr := client.ListAntifraudPageRange(
		ctx, deviceID, "", 100, nil, selectedDay,
	); rangeErr != nil || len(dated.Items) != 1 {
		t.Fatalf("dated current AntiFraud failed: items=%d err=%v", len(dated.Items), rangeErr)
	}
	if datedStats, rangeErr := client.StatsRange(ctx, deviceID, *selectedDay); rangeErr != nil ||
		datedStats.Calls24h != 1 || datedStats.Antifraud24h != 1 {
		t.Fatalf("dated current stats failed: %#v err=%v", datedStats, rangeErr)
	}
	outside := &TimeRange{From: now.AddDate(0, 0, 2), To: now.AddDate(0, 0, 3)}
	if dated, rangeErr := client.ListEventsPageRange(
		ctx, deviceID, "radius", "", 100, nil, outside,
	); rangeErr != nil || len(dated.Items) != 0 {
		t.Fatalf("outside current events failed: items=%d err=%v", len(dated.Items), rangeErr)
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
	if err := client.ScheduleDeviceRebuild(
		ctx, deviceID, 2, "Asia/Novosibirsk", RevisionReasonTimezoneChange,
	); err != nil {
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
	if job.Reason != RevisionReasonTimezoneChange {
		t.Fatalf("revision reason = %q", job.Reason)
	}
	first, err := client.NextDeviceRevisionSyslogBatch(ctx, job, 2)
	if err != nil || len(first) == 0 || len(first) > 2 {
		t.Fatalf("first replay chunk: rows=%d err=%v", len(first), err)
	}
	if err := client.AdvanceDeviceRevisionSyslog(ctx, job, first); err != nil {
		t.Fatal(err)
	}
	if err := client.ScheduleDeviceRebuild(
		ctx, deviceID, 2, "Asia/Novosibirsk", RevisionReasonTimezoneChange,
	); err != nil {
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
	if job.Processed != uint64(len(first)) {
		t.Fatalf("restart reset durable cursor: %#v", job)
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
	var rebuiltSetup time.Time
	var rebuiltSource string
	if err := client.Conn.QueryRow(ctx, `SELECT argMax(setup_time_utc,interpreted_at),
		argMax(source_timezone,interpreted_at)
		FROM collector.cdr_time_facts
		WHERE device_id=? AND timezone_revision=?`, deviceID, uint64(2)).
		Scan(&rebuiltSetup, &rebuiltSource); err != nil {
		t.Fatal(err)
	}
	wantSetup := time.Date(2026, 7, 24, 5, 0, 0, 0, time.UTC)
	if !rebuiltSetup.Equal(wantSetup) || rebuiltSource != "Asia/Novosibirsk" {
		t.Fatalf("CDR source time shifted during rebuild: %v/%s", rebuiltSetup, rebuiltSource)
	}
	job.Status = "cutover"
	sealed, changed, err := client.RefreshDeviceRevisionHighWatermarks(ctx, job)
	if err != nil || !changed || sealed.CutoverSealed != 1 {
		t.Fatalf("cutover watermark was not sealed: %#v changed=%v err=%v", sealed, changed, err)
	}
	late := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now.Add(time.Hour),
		SourceIP: net.ParseIP("10.0.0.19"), SourcePort: 10003,
		Payload: []byte("WEBS: after seal"), ParseStatus: "parsed",
		Category: "system_journal", SourceTimezone: "UTC", TimezoneRevision: 2,
	}
	if err := client.InsertSyslog(ctx, late); err != nil {
		t.Fatal(err)
	}
	unchanged, changed, err := client.RefreshDeviceRevisionHighWatermarks(ctx, sealed)
	if err != nil || changed || unchanged.HighWatermarkUS != sealed.HighWatermarkUS {
		t.Fatalf("sealed cutover chased live traffic: %#v changed=%v err=%v", unchanged, changed, err)
	}
	boundary := time.Date(2026, 7, 25, 0, 2, 0, 0, time.UTC)
	if err := client.EnqueueDirtySyslogBuckets(ctx, []SyslogEvent{{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: boundary,
		EventTime: &boundary, Category: "radius", TimezoneRevision: 2,
	}}); err != nil {
		t.Fatal(err)
	}
	var boundaryBuckets uint64
	if err := client.Conn.QueryRow(ctx, `SELECT countDistinct(bucket)
		FROM collector.correlation_dirty_buckets
		WHERE device_id=? AND timezone_revision=? AND bucket IN (?,?)`,
		deviceID, uint64(2), boundary.Add(-24*time.Hour), boundary).
		Scan(&boundaryBuckets); err != nil {
		t.Fatal(err)
	}
	if boundaryBuckets != 2 {
		t.Fatalf("midnight event did not dirty both UTC days: %d", boundaryBuckets)
	}
	ready, err := client.MarkDeviceRevisionReady(ctx, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ActivateDeviceRevision(ctx, ready); err != nil {
		t.Fatal(err)
	}
	if active, err := client.ActiveDeviceRevision(ctx, deviceID); err != nil || active != 2 {
		t.Fatalf("revision activation failed: active=%d err=%v", active, err)
	}
}

func TestActiveRevisionCoverageRepairCreatesTerminalAssignment(t *testing.T) {
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
	revision := uint64(14)
	occurredAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := client.Conn.Exec(ctx, `INSERT INTO collector.device_derived_revisions
		(device_id,revision,timezone,reason,status,updated_at)
		VALUES(?,?,'UTC','coverage_repair_test','active',now64(6))`,
		deviceID, revision); err != nil {
		t.Fatal(err)
	}
	event := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: occurredAt.Add(time.Minute),
		EventTime: &occurredAt, Category: "radius", TimezoneRevision: revision,
		SourceTimezone: "UTC", Attributes: map[string]string{
			"call_context": "REPAIR-14", "packet_code": "access-request",
			"xpgk_request_type": "check_call", "is_antifraud": "true",
			"acct_session_id": "repair session 14",
		},
	}
	if err := client.ProcessSyslogShadowDerived(ctx, event); err != nil {
		t.Fatal(err)
	}
	recordID := uuid.New()
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: recordID, DeviceID: deviceID, FileID: uuid.New(), RowNumber: 1,
		IngestedAt: occurredAt, SetupTime: &occurredAt, TimezoneRevision: revision,
		SourceTimezone: "UTC", RadiusSessionID: "repair session 14",
		RadiusSessionIDNormalized: "repairsession14", RawFields: map[string]string{},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := client.EnqueueActiveCorrelationRepairs(ctx, 20); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond)
	buckets, err := client.ListPendingCorrelationBuckets(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var repaired bool
	for _, bucket := range buckets {
		if bucket.DeviceID != deviceID || bucket.Revision != revision {
			continue
		}
		if err := client.ReconcileDirtyBucket(ctx, bucket); err != nil {
			t.Fatal(err)
		}
		repaired = true
	}
	if !repaired {
		t.Fatal("active revision repair did not enqueue a bucket")
	}
	var state string
	var assigned uuid.UUID
	if err := client.Conn.QueryRow(ctx, `SELECT argMax(state,updated_at),
		argMax(cdr_record_id,updated_at)
		FROM collector.call_assignments
		WHERE device_id=? AND timezone_revision=?`, deviceID, revision).
		Scan(&state, &assigned); err != nil {
		t.Fatal(err)
	}
	if state != "exact" || assigned != recordID {
		t.Fatalf("state=%s assigned=%s want=%s", state, assigned, recordID)
	}
}

func TestAntiFraudOperationProjectionClickHouse(t *testing.T) {
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
	revision := uint64(91)
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if err := client.Conn.Exec(ctx, `INSERT INTO collector.device_derived_revisions
		(device_id,revision,timezone,reason,status,updated_at)
		VALUES(?,?,'UTC','operation_projection_test','active',now64(6))`,
		deviceID, revision); err != nil {
		t.Fatal(err)
	}
	events := make([]SyslogEvent, 0, 6)
	requestEvents := make([]SyslogEvent, 0, 3)
	responseEvents := make([]SyslogEvent, 0, 3)
	for index, operationType := range []string{"number", "save_call", "check_call"} {
		requestAt := now.Add(time.Duration(index) * time.Second)
		requestID := uint8(70 + index)
		request := SyslogEvent{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: requestAt,
			EventTime: &requestAt, Category: "radius", TimezoneRevision: revision,
			SourceTimezone: "UTC", Payload: []byte(
				`Eltex-AVPair="xpgk-src-number-in=100" ` +
					`Eltex-AVPair="xpgk-src-number-in=200"`),
			Attributes: map[string]string{
				"call_context": "C-PROJECTION", "acct_session_id": "projection session",
				"packet_code": "access-request", "packet_direction": "request",
				"packet_identifier": strconv.Itoa(int(requestID)),
				"xpgk_request_type": operationType, "is_antifraud": "true",
			},
		}
		responseAt := requestAt.Add(100 * time.Millisecond)
		response := SyslogEvent{
			EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: responseAt,
			EventTime: &responseAt, Category: "radius", TimezoneRevision: revision,
			SourceTimezone: "UTC", Payload: []byte("Access-Accept"),
			Attributes: map[string]string{
				"call_context": "C-PROJECTION", "packet_code": "access-accept",
				"packet_direction":  "response",
				"packet_identifier": strconv.Itoa(int(requestID)),
			},
		}
		events = append(events, request, response)
		requestEvents = append(requestEvents, request)
		responseEvents = append(responseEvents, response)
	}
	if err := client.InsertSyslogBatch(ctx, events); err != nil {
		t.Fatal(err)
	}
	if err := client.ProcessSyslogShadowDerivedBatch(ctx, requestEvents); err != nil {
		t.Fatal(err)
	}
	if err := client.ProcessSyslogShadowDerivedBatch(ctx, responseEvents); err != nil {
		t.Fatal(err)
	}
	if err := client.ProcessSyslogShadowDerivedBatch(ctx, events); err != nil {
		t.Fatal(err)
	}
	var packets, operations, calls uint64
	if err := client.Conn.QueryRow(ctx, `SELECT
		(SELECT count() FROM collector.current_antifraud_packets
		 WHERE device_id=? AND timezone_revision=?),
		(SELECT count() FROM collector.current_antifraud_operations
		 WHERE device_id=? AND timezone_revision=?),
		(SELECT count() FROM collector.current_antifraud_calls
		 WHERE device_id=? AND timezone_revision=? AND parser_version=?)`,
		deviceID, revision, deviceID, revision,
		deviceID, revision, SyslogParserVersion).
		Scan(&packets, &operations, &calls); err != nil {
		t.Fatal(err)
	}
	if packets != 6 || operations != 3 || calls != 1 {
		t.Fatalf("packets=%d operations=%d calls=%d", packets, operations, calls)
	}
	var currentSession, currentIdentity string
	if err := client.Conn.QueryRow(ctx, `SELECT acct_session_id_normalized,identity_kind
		FROM collector.current_antifraud_calls
		WHERE device_id=? AND timezone_revision=? AND parser_version=?`,
		deviceID, revision, SyslogParserVersion).
		Scan(&currentSession, &currentIdentity); err != nil {
		t.Fatal(err)
	}
	if currentSession != "projectionsession" || currentIdentity != "acct_session_id" {
		t.Fatalf("weaker response overwrote call identity: %q/%q",
			currentSession, currentIdentity)
	}
	if preferred, preferenceErr := client.hasOperationProjection(
		ctx, deviceID, revision,
	); preferenceErr != nil {
		t.Fatal(preferenceErr)
	} else if preferred {
		t.Fatal("operation projection became visible before atomic replay cutover")
	}
	if err := client.ActivateParserProjection(
		ctx, deviceID, revision, SyslogParserVersion,
	); err != nil {
		t.Fatal(err)
	}
	if preferred, preferenceErr := client.hasOperationProjection(
		ctx, deviceID, revision,
	); preferenceErr != nil {
		t.Fatal(preferenceErr)
	} else if !preferred {
		t.Fatal("operation projection was not visible after atomic replay cutover")
	}
	page, err := client.ListAntifraudPage(ctx, deviceID, "", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 3 {
		t.Fatalf("operation read model was not preferred: %#v", page.Items)
	}
	operationTypes := make(map[string]bool)
	for _, item := range page.Items {
		operationTypes[item.RequestType] = true
		timeline, timelineErr := client.AntifraudTimeline(ctx, deviceID, item.TransactionID)
		if timelineErr != nil || len(timeline) != 2 {
			t.Fatalf("operation timeline rows=%d err=%v", len(timeline), timelineErr)
		}
	}
	for _, operationType := range []string{"number", "save_call", "check_call"} {
		if !operationTypes[operationType] {
			t.Fatalf("missing operation type %q in %#v", operationType, page.Items)
		}
	}
	var ordered []string
	if err := client.Conn.QueryRow(ctx, `SELECT attribute_values
		FROM collector.current_antifraud_packets
		WHERE device_id=? AND timezone_revision=? AND direction='request'
		ORDER BY occurred_at LIMIT 1`, deviceID, revision).Scan(&ordered); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ordered, ",") != "100,200" {
		t.Fatalf("ordered VSA values=%v", ordered)
	}
	firstRecordID := uuid.New()
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: firstRecordID, DeviceID: deviceID, FileID: uuid.New(), RowNumber: 1,
		IngestedAt: now, SetupTime: &now, TimezoneRevision: revision,
		SourceTimezone: "UTC", RadiusSessionID: "projection session",
		RadiusSessionIDNormalized: "projectionsession", RawFields: map[string]string{},
	}}); err != nil {
		t.Fatal(err)
	}
	bucket := DirtyCorrelationBucket{
		DeviceID: deviceID, Revision: revision, Bucket: now.Truncate(24 * time.Hour),
	}
	if err := client.ReconcileDirtyBucket(ctx, bucket); err != nil {
		t.Fatal(err)
	}
	var linked uint64
	if err := client.Conn.QueryRow(ctx, `SELECT countIf(state='linked') FROM
		(SELECT operation_id,argMax(state,updated_at) AS state
		 FROM collector.antifraud_operation_cdr_links
		 WHERE device_id=? AND timezone_revision=? GROUP BY operation_id)`,
		deviceID, revision).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != 3 {
		t.Fatalf("all operations must share one CDR, linked=%d", linked)
	}
	secondRecordID := uuid.New()
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: secondRecordID, DeviceID: deviceID, FileID: uuid.New(), RowNumber: 2,
		IngestedAt: now, SetupTime: &now, TimezoneRevision: revision,
		SourceTimezone: "UTC", RadiusSessionID: "projection session",
		RadiusSessionIDNormalized: "projectionsession", RawFields: map[string]string{},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := client.ReconcileDirtyBucket(ctx, bucket); err != nil {
		t.Fatal(err)
	}
	var ambiguous uint64
	if err := client.Conn.QueryRow(ctx, `SELECT countIf(
			state='ambiguous' AND reason='ambiguous_session_collision') FROM
		(SELECT operation_id,argMax(state,updated_at) AS state,
		 argMax(reason,updated_at) AS reason
		 FROM collector.antifraud_operation_cdr_links
		 WHERE device_id=? AND timezone_revision=? GROUP BY operation_id)`,
		deviceID, revision).Scan(&ambiguous); err != nil {
		t.Fatal(err)
	}
	if ambiguous != 3 {
		t.Fatalf("same-session collision was silently resolved: ambiguous=%d", ambiguous)
	}

	fallbackDeviceID := uuid.New()
	fallbackRevision := uint64(92)
	fallbackTransactionID := uuid.New()
	if err := client.Conn.Exec(ctx, `INSERT INTO collector.device_derived_revisions
		(device_id,revision,timezone,reason,status,updated_at)
		VALUES(?,?,'UTC','operation_fallback_test','active',now64(6))`,
		fallbackDeviceID, fallbackRevision); err != nil {
		t.Fatal(err)
	}
	if err := client.Conn.Exec(ctx, `INSERT INTO collector.antifraud_lifecycles
		(device_id,timezone_revision,transaction_id,updated_at,first_event_at,last_event_at,
		 request_type,is_antifraud,completeness)
		VALUES(?,?,?,now64(6),?,?, 'check_call',1,'incomplete')`,
		fallbackDeviceID, fallbackRevision, fallbackTransactionID, now, now); err != nil {
		t.Fatal(err)
	}
	fallbackPage, err := client.ListAntifraudPage(ctx, fallbackDeviceID, "", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fallbackPage.Items) != 1 ||
		fallbackPage.Items[0].TransactionID != fallbackTransactionID {
		t.Fatalf("legacy lifecycle fallback failed: %#v", fallbackPage.Items)
	}
}
