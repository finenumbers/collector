package analytics

import (
	"context"
	"fmt"
	"sort"
)

var legacySyslogTables = []string{
	"antifraud_call_links",
	"antifraud_calls",
	"antifraud_calls_current",
	"antifraud_current_calls",
	"antifraud_lifecycles",
	"antifraud_lifecycles_current",
	"antifraud_operation_cdr_links",
	"antifraud_operation_cdr_links_current",
	"antifraud_operations",
	"antifraud_operations_current",
	"antifraud_packets",
	"antifraud_packets_current",
	"antifraud_transactions",
	"call_antifraud_summary",
	"call_assignments",
	"call_assignments_current",
	"call_correlation_candidates",
	"call_event_links",
	"correlation_bucket_runs",
	"correlation_dirty_buckets",
	"correlation_runs",
	"current_antifraud_calls",
	"current_antifraud_operations",
	"current_antifraud_packets",
	"device_derived_revisions",
	"parser_projection_state",
	"radius_events",
	"radius_fragments",
	"radius_fragments_current",
	"raw_syslog",
	"syslog_current",
	"syslog_construct_members",
	"syslog_constructs",
	"syslog_facts",
	"syslog_fragment_links",
	"syslog_hourly",
	"syslog_hourly_mv",
	"syslog_interpretations",
	"syslog_reprocess_ledger",
}

type MigrationOptions struct {
	LegacyParserJobsChecked bool
	ActiveLegacyParserJobs  uint64
	StopBeforeCopy          bool
	StopBeforeCleanup       bool
	DeploymentLocker        interface {
		LockClickHouseMigrations(context.Context) (func(), error)
	}
	RequireDeploymentLock bool
}

type SyslogCopyDigest struct {
	Rows uint64 `json:"rows"`
	Sum  uint64 `json:"sum"`
	Xor  uint64 `json:"xor"`
}

type SyslogMigrationPreflight struct {
	Source                  SyslogCopyDigest `json:"source"`
	Destination             SyslogCopyDigest `json:"destination"`
	CopyVerified            bool             `json:"copyVerified"`
	LegacyTables            []string         `json:"legacyTables"`
	LegacyParserJobsChecked bool             `json:"legacyParserJobsChecked"`
	ActiveLegacyParserJobs  uint64           `json:"activeLegacyParserJobs"`
	AvailableDiskBytes      *uint64          `json:"availableDiskBytes,omitempty"`
	ReadyForCleanup         bool             `json:"readyForCleanup"`
}

const syslogCopyDigestQuery = `SELECT
	count(),
	sum(cityHash64(event_id,device_id,received_at,source_ip,source_port,transport,payload,payload_sha256)),
	groupBitXor(cityHash64(event_id,device_id,received_at,source_ip,source_port,transport,payload,payload_sha256))
	FROM collector.%s`

func (c *Client) PreflightLegacySyslogCleanup(
	ctx context.Context, options MigrationOptions,
) (SyslogMigrationPreflight, error) {
	result := SyslogMigrationPreflight{
		LegacyTables:            []string{},
		LegacyParserJobsChecked: options.LegacyParserJobsChecked,
		ActiveLegacyParserJobs:  options.ActiveLegacyParserJobs,
	}
	if err := c.Conn.QueryRow(ctx, fmt.Sprintf(syslogCopyDigestQuery, "raw_syslog")).
		Scan(&result.Source.Rows, &result.Source.Sum, &result.Source.Xor); err != nil {
		return result, fmt.Errorf("digest collector.raw_syslog: %w", err)
	}
	if err := c.Conn.QueryRow(ctx, fmt.Sprintf(syslogCopyDigestQuery, "syslog_messages")).
		Scan(&result.Destination.Rows, &result.Destination.Sum, &result.Destination.Xor); err != nil {
		return result, fmt.Errorf("digest collector.syslog_messages: %w", err)
	}
	result.CopyVerified = result.Source == result.Destination

	rows, err := c.Conn.Query(ctx, `SELECT name FROM system.tables
		WHERE database='collector' AND name IN ? ORDER BY name`, legacySyslogTables)
	if err != nil {
		return result, fmt.Errorf("inventory legacy ClickHouse tables: %w", err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return result, err
		}
		result.LegacyTables = append(result.LegacyTables, name)
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	sort.Strings(result.LegacyTables)

	var available uint64
	if err := c.Conn.QueryRow(ctx, `SELECT min(available_space) FROM system.disks`).Scan(&available); err == nil {
		result.AvailableDiskBytes = &available
	}
	result.ReadyForCleanup = result.CopyVerified &&
		result.LegacyParserJobsChecked && result.ActiveLegacyParserJobs == 0
	return result, nil
}

func (report SyslogMigrationPreflight) Validate() error {
	if !report.CopyVerified {
		return fmt.Errorf(
			"raw Syslog copy verification failed: source=%+v destination=%+v",
			report.Source, report.Destination,
		)
	}
	if !report.LegacyParserJobsChecked {
		return fmt.Errorf("legacy parser rebuild job state was not checked")
	}
	if report.ActiveLegacyParserJobs != 0 {
		return fmt.Errorf("%d legacy parser rebuild jobs are active", report.ActiveLegacyParserJobs)
	}
	return nil
}
