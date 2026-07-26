package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresMigrateRunsFilesOnce(t *testing.T) {
	store := isolatedMigrationStore(t)
	directory := writeTestMigrations(t, map[string]string{
		"001_once.sql": `CREATE TABLE migration_runs (value integer NOT NULL);
			INSERT INTO migration_runs VALUES (1);`,
	})

	if err := store.Migrate(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(context.Background(), directory); err != nil {
		t.Fatal(err)
	}

	var runs, ledgerRows int
	if err := store.DB.QueryRow(context.Background(), `SELECT count(*) FROM migration_runs`).
		Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := store.DB.QueryRow(context.Background(), `SELECT count(*) FROM schema_migrations`).
		Scan(&ledgerRows); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || ledgerRows != 1 {
		t.Fatalf("migration runs=%d ledger rows=%d, want 1 and 1", runs, ledgerRows)
	}
}

func TestPostgresMigrateSerializesConcurrentRuns(t *testing.T) {
	store := isolatedMigrationStore(t)
	directory := writeTestMigrations(t, map[string]string{
		"001_concurrent.sql": `CREATE TABLE concurrent_runs (value integer NOT NULL);
			SELECT pg_sleep(0.2);
			INSERT INTO concurrent_runs VALUES (1);`,
	})

	start := make(chan struct{})
	errs := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			errs <- store.Migrate(context.Background(), directory)
		}()
	}
	ready.Wait()
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	var runs int
	if err := store.DB.QueryRow(context.Background(), `SELECT count(*) FROM concurrent_runs`).
		Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("migration executed %d times, want 1", runs)
	}
}

func TestPostgresMigrateRejectsChecksumMismatch(t *testing.T) {
	store := isolatedMigrationStore(t)
	directory := writeTestMigrations(t, map[string]string{
		"001_checksum.sql": `CREATE TABLE checksum_probe (value integer);`,
	})
	if err := store.Migrate(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, "001_checksum.sql"),
		[]byte(`CREATE TABLE checksum_probe (value bigint);`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	err := store.Migrate(context.Background(), directory)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Migrate error=%v, want checksum mismatch", err)
	}
}

func TestPostgresMigrateRollsBackFailedFile(t *testing.T) {
	store := isolatedMigrationStore(t)
	directory := writeTestMigrations(t, map[string]string{
		"001_failure.sql": `CREATE TABLE rollback_probe (value integer);
			INSERT INTO rollback_probe VALUES (1);
			SELECT 1 / 0;`,
	})

	err := store.Migrate(context.Background(), directory)
	if err == nil {
		t.Fatal("Migrate succeeded, want failure")
	}
	var tableExists bool
	if err := store.DB.QueryRow(
		context.Background(), `SELECT to_regclass('rollback_probe') IS NOT NULL`,
	).Scan(&tableExists); err != nil {
		t.Fatal(err)
	}
	var ledgerRows int
	if err := store.DB.QueryRow(context.Background(), `SELECT count(*) FROM schema_migrations`).
		Scan(&ledgerRows); err != nil {
		t.Fatal(err)
	}
	if tableExists || ledgerRows != 0 {
		t.Fatalf("failed migration left table=%v ledger rows=%d", tableExists, ledgerRows)
	}
}

func TestPostgresMigrateBaselinesLegacySchemaWithoutRevisionBump(t *testing.T) {
	for _, legacyLevel := range []int{14, 16} {
		t.Run(fmt.Sprintf("through_%03d", legacyLevel), func(t *testing.T) {
			store := isolatedMigrationStore(t)
			ctx := context.Background()
			migrations, err := readPostgresMigrations("../../migrations/postgres")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.DB.Exec(ctx, string(migrations[0].content)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.DB.Exec(ctx, `INSERT INTO devices
				(name, syslog_source_ip, ftp_username, ftp_home)
				VALUES ('legacy', '192.0.2.10', 'legacy', '/legacy')`); err != nil {
				t.Fatal(err)
			}
			for index := 1; index < legacyLevel; index++ {
				if _, err := store.DB.Exec(ctx, string(migrations[index].content)); err != nil {
					t.Fatalf("%s: %v", migrations[index].name, err)
				}
			}

			var before int64
			if err := store.DB.QueryRow(ctx, `SELECT timezone_revision FROM devices WHERE name='legacy'`).
				Scan(&before); err != nil {
				t.Fatal(err)
			}
			if err := store.Migrate(ctx, "../../migrations/postgres"); err != nil {
				t.Fatal(err)
			}
			var after int64
			if err := store.DB.QueryRow(ctx, `SELECT timezone_revision FROM devices WHERE name='legacy'`).
				Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Fatalf("timezone_revision changed from %d to %d", before, after)
			}
			var ledgerRows int
			if err := store.DB.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).
				Scan(&ledgerRows); err != nil {
				t.Fatal(err)
			}
			if ledgerRows != len(migrations) {
				t.Fatalf("ledger rows=%d, want %d", ledgerRows, len(migrations))
			}
			var laterTables bool
			if err := store.DB.QueryRow(ctx, `SELECT
				to_regclass('syslog_parser_rebuild_jobs') IS NOT NULL
				AND EXISTS (
					SELECT 1 FROM information_schema.columns
					WHERE table_schema=current_schema()
					  AND table_name='export_jobs' AND column_name='worker_id'
				)`).
				Scan(&laterTables); err != nil {
				t.Fatal(err)
			}
			if !laterTables {
				t.Fatal("legacy baseline skipped migration 015 or 016")
			}
		})
	}
}

func isolatedMigrationStore(t *testing.T) *Store {
	t.Helper()
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "migration_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	store := &Store{DB: pool}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	return store
}

func writeTestMigrations(t *testing.T, files map[string]string) string {
	t.Helper()
	directory := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}
