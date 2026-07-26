package analytics

import (
	"context"
	"fmt"
	"strconv"
)

type retentionTable struct {
	name     string
	timeExpr string
}

var retentionTables = map[string][]retentionTable{
	"syslog": {
		{name: "raw_syslog", timeExpr: "received_at"},
		{name: "syslog_interpretations", timeExpr: "interpreted_at"},
		{name: "syslog_facts", timeExpr: "received_at"},
		{name: "syslog_fragment_links", timeExpr: "linked_at"},
		{name: "syslog_constructs", timeExpr: "started_at"},
		{name: "syslog_construct_members", timeExpr: "linked_at"},
		{name: "syslog_hourly", timeExpr: "hour"},
	},
	"cdr": {
		{name: "cdr_records", timeExpr: "coalesce(setup_time, ingested_at)"},
		{name: "cdr_time_interpretations", timeExpr: "interpreted_at"},
		{name: "cdr_time_facts", timeExpr: "interpreted_at"},
	},
	"softswitch_cdr": {
		{name: "satel_rtu_cdr", timeExpr: "coalesce(setup_time, cdr_date, ingested_at)"},
		{name: "satel_rtu_cdr_time_facts", timeExpr: "interpreted_at"},
	},
	"derived": {
		{name: "radius_events", timeExpr: "occurred_at"},
		{name: "antifraud_transactions", timeExpr: "first_event_at"},
		{name: "call_event_links", timeExpr: "linked_at"},
		{name: "call_correlation_candidates", timeExpr: "created_at"},
		{name: "antifraud_call_links", timeExpr: "linked_at"},
		{name: "correlation_runs", timeExpr: "ran_at"},
		{name: "radius_fragments", timeExpr: "occurred_at"},
		{name: "antifraud_lifecycles", timeExpr: "first_event_at"},
		{name: "call_assignments", timeExpr: "updated_at"},
	},
}

func (c *Client) ApplyRetention(ctx context.Context, class string, days int) error {
	if days < 7 || days > 1095 {
		return fmt.Errorf("retention days must be between 7 and 1095")
	}
	tables, ok := retentionTables[class]
	if !ok {
		return fmt.Errorf("retention class %q has no ClickHouse mapping", class)
	}
	var mutations, merges uint64
	if err := c.Conn.QueryRow(ctx, `SELECT
		(SELECT count() FROM system.mutations WHERE database='collector' AND NOT is_done),
		(SELECT count() FROM system.merges WHERE database='collector')`).
		Scan(&mutations, &merges); err != nil {
		return fmt.Errorf("read ClickHouse merge pressure: %w", err)
	}
	if mutations > 16 || merges > 32 {
		return fmt.Errorf(
			"ClickHouse is busy (%d active mutations, %d merges); retention deferred",
			mutations, merges,
		)
	}
	safeDays := strconv.Itoa(days)
	for _, table := range tables {
		query := fmt.Sprintf(
			"ALTER TABLE collector.`%s` MODIFY TTL toDateTime(%s) + INTERVAL %s DAY DELETE",
			table.name, table.timeExpr, safeDays,
		)
		if err := c.Conn.Exec(ctx, query); err != nil {
			return fmt.Errorf("apply %s retention to %s: %w", class, table.name, err)
		}
	}
	return nil
}
