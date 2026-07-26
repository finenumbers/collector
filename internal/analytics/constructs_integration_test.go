package analytics

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSyslogConstructStorageAndActiveRevisionQueries(t *testing.T) {
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
	revision := uint64(1)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := client.Conn.Exec(ctx, `INSERT INTO collector.device_derived_revisions
		(device_id,revision,timezone,status,updated_at) VALUES(?,?,?,?,?)`,
		deviceID, revision, "UTC", "active", now); err != nil {
		t.Fatal(err)
	}

	olderEventID := uuid.New()
	newerEventID := uuid.New()
	events := []SyslogEvent{
		{
			EventID: olderEventID, DeviceID: deviceID, ReceivedAt: now.Add(-time.Minute),
			SourceIP: net.ParseIP("192.0.2.10"), SourcePort: 514,
			Payload: []byte("SIP INVITE raw"), HeaderFormat: "rfc3164",
			ParseStatus: "parsed", Category: "sip", Component: "SIP",
			Message: "INVITE", Attributes: map[string]string{"call_context": "C1"},
			SourceTimezone: "UTC", TimezoneRevision: revision,
		},
		{
			EventID: newerEventID, DeviceID: deviceID, ReceivedAt: now,
			SourceIP: net.ParseIP("192.0.2.10"), SourcePort: 514,
			Payload: []byte("alarm raw"), HeaderFormat: "rfc3164",
			ParseStatus: "parsed", Category: "alarms", Component: "Alarm",
			Message: "Link down", Attributes: map[string]string{},
			SourceTimezone: "UTC", TimezoneRevision: revision,
		},
	}
	if err := client.InsertSyslogBatch(ctx, events); err != nil {
		t.Fatal(err)
	}

	olderConstructID := uuid.New()
	newerConstructID := uuid.New()
	constructs := []SyslogConstruct{
		{
			DeviceID: deviceID, TimezoneRevision: revision,
			ConstructID: olderConstructID, UpdatedAt: now,
			StartedAt: now.Add(-time.Minute), EndedAt: now.Add(-time.Minute),
			ConstructType: "sip_exchange", Category: "sip", Direction: "RX",
			Title: "INVITE", Summary: "Initial request", MessageName: "INVITE",
			Completeness: "complete", GroupingMethod: "single_event",
			GroupingReason: "anchor", Confidence: 1, MemberCount: 1,
			SearchableText: "INVITE C1", Attributes: map[string]string{},
		},
		{
			DeviceID: deviceID, TimezoneRevision: revision,
			ConstructID: newerConstructID, UpdatedAt: now,
			StartedAt: now, EndedAt: now, ConstructType: "single_event",
			Category: "alarms", Title: "Link down", Summary: "Interface alarm",
			Completeness: "complete", GroupingMethod: "single_event",
			GroupingReason: "standalone", Confidence: 1, MemberCount: 1,
			SearchableText: "Link down Interface alarm", Attributes: map[string]string{},
		},
	}
	if err := client.InsertSyslogConstructsBatch(ctx, constructs); err != nil {
		t.Fatal(err)
	}
	updatedOlder := constructs[0]
	updatedOlder.UpdatedAt = now.Add(time.Second)
	updatedOlder.Summary = "Updated initial request"
	if err := client.InsertSyslogConstructsBatch(ctx, []SyslogConstruct{updatedOlder}); err != nil {
		t.Fatal(err)
	}
	members := []SyslogConstructMember{
		{
			DeviceID: deviceID, TimezoneRevision: revision,
			ConstructID: olderConstructID, EventID: olderEventID,
			Role: "anchor", LinkedAt: now,
		},
		{
			DeviceID: deviceID, TimezoneRevision: revision,
			ConstructID: newerConstructID, EventID: newerEventID,
			Role: "anchor", LinkedAt: now,
		},
	}
	if err := client.InsertSyslogConstructMembersBatch(ctx, members); err != nil {
		t.Fatal(err)
	}
	members[0].LinkedAt = now.Add(time.Second)
	if err := client.InsertSyslogConstructMembersBatch(ctx, members[:1]); err != nil {
		t.Fatal(err)
	}
	link := SyslogFragmentLink{
		DeviceID: deviceID, TimezoneRevision: revision,
		ChildEventID: newerEventID, ParentEventID: olderEventID,
		LinkMethod: "parent_event_id", FragmentKind: "body",
		Confidence: 1, LinkedAt: now,
	}
	if err := client.InsertSyslogFragmentLinksBatch(ctx, []SyslogFragmentLink{link}); err != nil {
		t.Fatal(err)
	}
	link.LinkedAt = now.Add(time.Second)
	if err := client.InsertSyslogFragmentLinksBatch(ctx, []SyslogFragmentLink{link}); err != nil {
		t.Fatal(err)
	}
	var linkCount uint64
	if err := client.Conn.QueryRow(ctx, `SELECT count()
		FROM collector.syslog_fragment_links FINAL
		WHERE device_id=? AND timezone_revision=? AND grouping_version=?`,
		deviceID, revision, SyslogGroupingVersion).Scan(&linkCount); err != nil {
		t.Fatal(err)
	}
	if linkCount != 1 {
		t.Fatalf("got %d fragment links after replacement, want 1", linkCount)
	}

	firstPage, err := client.ListSyslogConstructsPage(ctx, deviceID, "all", "", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Items) != 1 || firstPage.Items[0].ConstructID != newerConstructID ||
		!firstPage.HasMore || firstPage.NextCursor == nil {
		t.Fatalf("unexpected first page: %#v", firstPage)
	}
	secondPage, err := client.ListSyslogConstructsPage(
		ctx, deviceID, "all", "", 1, firstPage.NextCursor,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPage.Items) != 1 || secondPage.Items[0].ConstructID != olderConstructID {
		t.Fatalf("unexpected second page: %#v", secondPage)
	}
	searchPage, err := client.ListSyslogConstructsPage(ctx, deviceID, "sip", "invite", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(searchPage.Items) != 1 || searchPage.Items[0].ConstructID != olderConstructID {
		t.Fatalf("unexpected filtered page: %#v", searchPage)
	}
	filteredPage, err := client.ListSyslogConstructsFilteredPage(
		ctx, deviceID, SyslogConstructFilters{
			Kind: "sip_exchange", Direction: "RX", MessageName: "invite",
		}, 10, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(filteredPage.Items) != 1 || filteredPage.Items[0].ConstructID != olderConstructID {
		t.Fatalf("unexpected protocol filtered page: %#v", filteredPage)
	}

	detail, err := client.GetSyslogConstruct(ctx, deviceID, olderConstructID)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Members) != 1 || detail.Members[0].EventID != olderEventID ||
		detail.Members[0].RawPayload != "SIP INVITE raw" {
		t.Fatalf("unexpected detail: %#v", detail)
	}
}
