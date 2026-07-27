package store

import (
	"context"
	"testing"
	"time"
)

func TestSessionRestoresCSRFAfterReload(t *testing.T) {
	store := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := store.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateInitialAdmin(ctx, "session-admin", "test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	token, csrf, err := store.CreateSession(ctx, user, time.Hour, "test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	// Page reload: cookie present, SPA CSRF memory empty.
	reloaded, err := store.Session(ctx, token, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.CSRF != "" {
		t.Fatalf("reload lookup must not invent CSRF, got %q", reloaded.CSRF)
	}

	rotated, err := store.RotateSessionCSRF(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == "" || rotated == csrf {
		t.Fatalf("expected fresh CSRF, got %q (old %q)", rotated, csrf)
	}

	if _, err := store.Session(ctx, token, csrf, true); err == nil {
		t.Fatal("old CSRF must fail after rotation")
	}
	active, err := store.Session(ctx, token, rotated, true)
	if err != nil {
		t.Fatal(err)
	}
	if active.CSRF != rotated {
		t.Fatalf("CSRF = %q, want %q", active.CSRF, rotated)
	}
}
