package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const postgresMigrationLockKey int64 = 0x436f6c6c6563746f

type postgresMigration struct {
	name     string
	content  []byte
	checksum string
}

func (s *Store) Migrate(ctx context.Context, directory string) error {
	migrations, err := readPostgresMigrations(directory)
	if err != nil {
		return err
	}

	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, postgresMigrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(
			unlockCtx, `SELECT pg_advisory_unlock($1)`, postgresMigrationLockKey,
		); err != nil {
			_ = conn.Conn().Close(unlockCtx)
		}
	}()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		filename text PRIMARY KEY,
		checksum text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := loadAppliedPostgresMigrations(ctx, conn)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		if err := baselineLegacyPostgresSchema(ctx, conn, migrations); err != nil {
			return err
		}
		applied, err = loadAppliedPostgresMigrations(ctx, conn)
		if err != nil {
			return err
		}
	}

	files := make(map[string]postgresMigration, len(migrations))
	for _, migration := range migrations {
		files[migration.name] = migration
		if checksum, ok := applied[migration.name]; ok && checksum != migration.checksum {
			return fmt.Errorf(
				"migration %s checksum mismatch: database has %s, file has %s",
				migration.name, checksum, migration.checksum,
			)
		}
	}
	for name := range applied {
		if _, ok := files[name]; !ok {
			return fmt.Errorf("applied migration %s is missing from %s", name, directory)
		}
	}

	for _, migration := range migrations {
		if _, ok := applied[migration.name]; ok {
			continue
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("%s: begin transaction: %w", migration.name, err)
		}
		if _, err = tx.Exec(ctx, string(migration.content)); err == nil {
			_, err = tx.Exec(ctx,
				`INSERT INTO schema_migrations(filename, checksum) VALUES($1, $2)`,
				migration.name, migration.checksum,
			)
		}
		if err == nil {
			err = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", migration.name, err)
		}
	}
	return nil
}

func readPostgresMigrations(directory string) ([]postgresMigration, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	migrations := make([]postgresMigration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(content)
		migrations = append(migrations, postgresMigration{
			name: entry.Name(), content: content, checksum: hex.EncodeToString(sum[:]),
		})
	}
	return migrations, nil
}

func loadAppliedPostgresMigrations(
	ctx context.Context, conn *pgxpool.Conn,
) (map[string]string, error) {
	rows, err := conn.Query(ctx, `SELECT filename, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	applied := make(map[string]string)
	for rows.Next() {
		var name, checksum string
		if err := rows.Scan(&name, &checksum); err != nil {
			return nil, fmt.Errorf("read schema_migrations: %w", err)
		}
		applied[name] = checksum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	return applied, nil
}

// baselineLegacyPostgresSchema adopts databases created by the pre-ledger runner.
// Migrations 001-014 are treated as one compatibility boundary because 003-005
// contain data updates that are unsafe to replay. Migrations 015 and 016 have
// independent, strong schema markers, so a legacy database missing either one
// receives the migration instead of silently skipping it.
func baselineLegacyPostgresSchema(
	ctx context.Context, conn *pgxpool.Conn, migrations []postgresMigration,
) error {
	var legacy bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('devices') IS NOT NULL`).Scan(&legacy); err != nil {
		return fmt.Errorf("detect legacy schema: %w", err)
	}
	if !legacy {
		return nil
	}

	if err := verifyLegacyThrough014(ctx, conn); err != nil {
		return fmt.Errorf("legacy PostgreSQL schema is not compatible through migration 014: %w", err)
	}
	level := 14
	if err := verifyLegacy015(ctx, conn); err == nil {
		level = 15
		if err := verifyLegacy016(ctx, conn); err == nil {
			level = 16
		}
	}

	required := make(map[int]bool, level)
	for number := 1; number <= level; number++ {
		required[number] = true
	}
	for _, migration := range migrations {
		number, ok := postgresMigrationNumber(migration.name)
		if !ok || number > level {
			continue
		}
		delete(required, number)
	}
	if len(required) != 0 {
		return fmt.Errorf("cannot baseline legacy schema: migration files 001-%03d are incomplete", level)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin legacy baseline: %w", err)
	}
	defer tx.Rollback(ctx)
	for _, migration := range migrations {
		number, ok := postgresMigrationNumber(migration.name)
		if !ok || number > level {
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations(filename, checksum) VALUES($1, $2)`,
			migration.name, migration.checksum,
		); err != nil {
			return fmt.Errorf("baseline %s: %w", migration.name, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit legacy baseline: %w", err)
	}
	return nil
}

func postgresMigrationNumber(name string) (int, bool) {
	if len(name) < 5 || name[3] != '_' {
		return 0, false
	}
	number, err := strconv.Atoi(name[:3])
	return number, err == nil && number > 0
}

func verifyLegacyThrough014(ctx context.Context, conn *pgxpool.Conn) error {
	requirements := map[string][]string{
		"users":              {"id", "username", "password_hash", "role", "active"},
		"sessions":           {"id_hash", "user_id", "csrf_hash", "expires_at"},
		"devices":            {"id", "timezone", "active_timezone", "timezone_revision", "active_timezone_revision", "cdr_source_timezone", "purge_state", "purge_error", "purge_updated_at", "source_category", "template_key", "detection_status", "detection_template", "detection_fingerprint", "detection_error", "detection_checked_at", "detection_last_file_at"},
		"ingest_files":       {"id", "device_id", "status", "parser_template", "parser_version", "replay_state", "replay_template", "replay_version", "replay_requested_at", "replay_started_at", "replay_completed_at", "replay_attempts", "replay_error"},
		"export_jobs":        {"id", "requested_by", "device_id", "dataset", "status"},
		"audit_log":          {"id", "action", "resource_type"},
		"retention_policies": {"policy_class", "active_days", "pending_days", "effective_at"},
	}
	if err := requireTablesAndColumns(ctx, conn, requirements); err != nil {
		return err
	}
	var obsoleteColumn, obsoleteIndex, softswitchPolicy, incompatible014 bool
	if err := conn.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='devices' AND column_name='cdr_columns'),
		to_regclass('devices_raw_detection_idx') IS NOT NULL,
		EXISTS (SELECT 1 FROM retention_policies WHERE policy_class='softswitch_cdr'),
		EXISTS (SELECT 1 FROM devices
			WHERE template_key='softswitch-cdr-raw-v1'
			   OR (template_key='satel-rtu-cdr-v1' AND (
					firmware IS DISTINCT FROM 'satel-rtu-cdr-v1'
					OR active_timezone IS DISTINCT FROM timezone
					OR active_timezone_revision IS DISTINCT FROM timezone_revision
					OR detection_status IS DISTINCT FROM 'activated'
					OR detection_template IS DISTINCT FROM 'satel-rtu-cdr-v1'
			   )))
	`).Scan(&obsoleteColumn, &obsoleteIndex, &softswitchPolicy, &incompatible014); err != nil {
		return err
	}
	if obsoleteColumn || obsoleteIndex || !softswitchPolicy || incompatible014 {
		return errors.New("migration 009, 013, or 014 marker is missing")
	}
	constraints := map[string][]string{
		"devices_purge_state_check":             {"purge_state", "deleting", "purge_failed"},
		"devices_source_category_check":         {"source_category", "equipment", "softswitch"},
		"devices_detection_status_check":        {"detection_status", "activated"},
		"ingest_files_status_check":             {"status", "archived"},
		"ingest_files_replay_state_check":       {"replay_state", "processing", "complete"},
		"retention_policies_policy_class_check": {"policy_class", "softswitch_cdr"},
	}
	return requireConstraints(ctx, conn, constraints)
}

func verifyLegacy015(ctx context.Context, conn *pgxpool.Conn) error {
	if err := requireTablesAndColumns(ctx, conn, map[string][]string{
		"syslog_parser_rebuild_jobs": {
			"device_id", "parser_version", "status", "cursor_received_us", "cursor_event_id",
			"watermark_received_us", "watermark_event_id", "total_events", "processed_events",
			"processed_batches", "attempts", "last_batch_events", "next_attempt_at",
		},
	}); err != nil {
		return err
	}
	if err := requireConstraints(ctx, conn, map[string][]string{
		"syslog_parser_rebuild_jobs_pkey":           {"device_id", "parser_version"},
		"syslog_parser_rebuild_jobs_device_id_fkey": {"device_id", "devices", "ON DELETE CASCADE"},
		"syslog_parser_rebuild_jobs_status_check":   {"status", "paused", "completed", "failed"},
	}); err != nil {
		return err
	}
	return requireIndexes(ctx, conn, "syslog_parser_rebuild_jobs_queue_idx")
}

func verifyLegacy016(ctx context.Context, conn *pgxpool.Conn) error {
	if err := requireTablesAndColumns(ctx, conn, map[string][]string{
		"export_jobs": {
			"category", "search", "range_from", "range_to", "format", "output_format",
			"filename", "content_type", "size_bytes", "sha256", "rows_estimated",
			"rows_processed", "bytes_spooled", "active_revision", "timezone",
			"template_key", "parser_version", "raw_high_watermark", "raw_high_watermark_id",
			"cancel_requested_at", "started_at", "heartbeat_at", "lease_expires_at",
			"worker_id", "updated_at",
		},
	}); err != nil {
		return err
	}
	var nullable string
	if err := conn.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='export_jobs' AND column_name='device_id'`).
		Scan(&nullable); err != nil {
		return err
	}
	if nullable != "NO" {
		return errors.New("export_jobs.device_id is nullable")
	}
	if err := requireConstraints(ctx, conn, map[string][]string{
		"export_jobs_device_id_fkey": {"device_id", "devices", "ON DELETE CASCADE"},
		"export_jobs_status_check":   {"status", "cancelled", "expired"},
		"export_jobs_format_check":   {"format", "xlsx", "csv_zip"},
	}); err != nil {
		return err
	}
	return requireIndexes(
		ctx, conn, "export_jobs_claim_idx", "export_jobs_device_page_idx", "export_jobs_expiry_idx",
	)
}

func requireTablesAndColumns(
	ctx context.Context, conn *pgxpool.Conn, requirements map[string][]string,
) error {
	for table, columns := range requirements {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("table %s is missing", table)
		}
		for _, column := range columns {
			if err := conn.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2
			)`, table, column).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return fmt.Errorf("column %s.%s is missing", table, column)
			}
		}
	}
	return nil
}

func requireConstraints(
	ctx context.Context, conn *pgxpool.Conn, requirements map[string][]string,
) error {
	for name, fragments := range requirements {
		var definition string
		err := conn.QueryRow(ctx, `SELECT pg_get_constraintdef(oid)
			FROM pg_constraint WHERE connamespace=current_schema()::regnamespace AND conname=$1`, name).
			Scan(&definition)
		if err != nil {
			return fmt.Errorf("constraint %s is missing: %w", name, err)
		}
		lower := strings.ToLower(definition)
		for _, fragment := range fragments {
			if !strings.Contains(lower, strings.ToLower(fragment)) {
				return fmt.Errorf("constraint %s lacks %q", name, fragment)
			}
		}
	}
	return nil
}

func requireIndexes(ctx context.Context, conn *pgxpool.Conn, names ...string) error {
	for _, name := range names {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("index %s is missing", name)
		}
	}
	return nil
}
