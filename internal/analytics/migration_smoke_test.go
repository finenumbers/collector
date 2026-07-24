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
	if applied != 6 {
		t.Fatalf("got %d applied migrations, want 6", applied)
	}
}
