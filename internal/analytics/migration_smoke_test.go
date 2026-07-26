package analytics

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestClickHouseMigrationsSmoke(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}
	username := os.Getenv("CLICKHOUSE_TEST_USER")
	password := os.Getenv("CLICKHOUSE_TEST_PASSWORD")
	client, err := Open(address, "collector", username, password)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := client.Migrate(ctx, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	var applied uint64
	if err := client.Conn.QueryRow(ctx,
		"SELECT count() FROM collector.schema_migrations").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 21 {
		t.Fatalf("got %d applied migrations, want 21", applied)
	}
	for table, column := range map[string]string{
		"cdr_time_facts": "time_source", "call_assignments": "time_source",
	} {
		var columns uint64
		if err := client.Conn.QueryRow(ctx, `SELECT count() FROM system.columns
			WHERE database='collector' AND table=? AND name=?`, table, column).
			Scan(&columns); err != nil {
			t.Fatal(err)
		}
		if columns != 1 {
			t.Fatalf("%s.%s was not migrated", table, column)
		}
	}
	var hourlyEngine, viewEngine string
	if err := client.Conn.QueryRow(ctx, `SELECT engine FROM system.tables
		WHERE database='collector' AND name='syslog_hourly'`).Scan(&hourlyEngine); err != nil {
		t.Fatal(err)
	}
	if hourlyEngine != "SummingMergeTree" {
		t.Fatalf("syslog_hourly engine is %s, want SummingMergeTree", hourlyEngine)
	}
	if err := client.Conn.QueryRow(ctx, `SELECT engine FROM system.tables
		WHERE database='collector' AND name='syslog_hourly_mv'`).Scan(&viewEngine); err != nil {
		t.Fatal(err)
	}
	if viewEngine != "MaterializedView" {
		t.Fatalf("syslog_hourly_mv engine is %s, want MaterializedView", viewEngine)
	}
	var satelEngine string
	if err := client.Conn.QueryRow(ctx, `SELECT engine FROM system.tables
		WHERE database='collector' AND name='satel_rtu_cdr'`).Scan(&satelEngine); err != nil {
		t.Fatal(err)
	}
	if satelEngine != "ReplacingMergeTree" {
		t.Fatalf("satel_rtu_cdr engine is %s, want ReplacingMergeTree", satelEngine)
	}
}
