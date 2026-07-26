package analytics

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateDashboardWindow(t *testing.T) {
	tests := map[string]time.Duration{
		"":    24 * time.Hour,
		"1h":  time.Hour,
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
	}
	for input, want := range tests {
		got, err := ValidateDashboardWindow(input)
		if err != nil {
			t.Fatalf("ValidateDashboardWindow(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ValidateDashboardWindow(%q) = %v, want %v", input, got, want)
		}
	}
	for _, input := range []string{"0h", "12h", "30d", "garbage"} {
		if _, err := ValidateDashboardWindow(input); err == nil {
			t.Fatalf("ValidateDashboardWindow(%q) accepted an unsupported window", input)
		}
	}
}

func TestDashboardLatestSyslogUsesRawReceiveFreshness(t *testing.T) {
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
	t.Cleanup(func() {
		_ = client.PurgeDeviceData(context.Background(), deviceID)
	})
	receivedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if err := client.Conn.Exec(ctx, `INSERT INTO collector.raw_syslog
		(event_id,device_id,received_at) VALUES(?,?,?)`,
		uuid.New(), deviceID, receivedAt); err != nil {
		t.Fatal(err)
	}

	result := client.Dashboard(ctx, time.Hour)
	got := result.Devices[deviceID]
	if got == nil || got.LatestSyslogAt == nil || !got.LatestSyslogAt.Equal(receivedAt) {
		t.Fatalf("latest raw Syslog = %#v, want %v", got, receivedAt)
	}
}
