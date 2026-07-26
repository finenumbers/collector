package store

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestRetentionScheduling(t *testing.T) {
	now := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	for _, days := range []int{7, 14, 60, 1095} {
		effective, err := retentionEffectiveAt(now, days)
		if err != nil || !effective.Equal(now) {
			t.Fatalf("days=%d was not immediate: %v, %v", days, effective, err)
		}
	}
	for _, days := range []int{6, 1096} {
		if _, err := retentionEffectiveAt(now, days); err == nil {
			t.Fatalf("invalid retention %d was accepted", days)
		}
	}
}

func TestValidRetentionClassIncludesSoftswitchCDR(t *testing.T) {
	for _, class := range []string{
		"syslog", "cdr", "softswitch_cdr", "derived", "raw_cdr_archive",
	} {
		if !validRetentionClass(class) {
			t.Errorf("retention class %q was rejected", class)
		}
	}
	if validRetentionClass("unknown") {
		t.Fatal("unknown retention class was accepted")
	}
}

func TestSoftswitchRetentionMigrationCopiesCDRAsImmediatelyDue(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx := context.Background()
	control, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.DB.Close()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../migrations/postgres/013_softswitch_retention.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := control.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE retention_policies SET active_days=73
		WHERE policy_class='cdr'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM retention_policies
		WHERE policy_class='softswitch_cdr'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	var active, pending int
	var effective time.Time
	if err := tx.QueryRow(ctx, `SELECT active_days,pending_days,effective_at
		FROM retention_policies WHERE policy_class='softswitch_cdr'`).
		Scan(&active, &pending, &effective); err != nil {
		t.Fatal(err)
	}
	if active != 73 || pending != 73 || effective.After(time.Now()) {
		t.Fatalf(
			"softswitch policy active=%d pending=%d effective=%s",
			active, pending, effective,
		)
	}
}
