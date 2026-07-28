package analytics

import (
	"os"
	"strings"
	"testing"
)

func TestDashboardAntifraudTipUsesDashboardWindow(t *testing.T) {
	body, err := os.ReadFile("dashboard.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	needle := `SELECT device_id,max(last_seen_at)
		FROM collector.custom_antifraud_calls_current
		WHERE last_seen_at>=now()-toIntervalSecond(?)
		GROUP BY device_id`
	if !strings.Contains(source, needle) {
		t.Fatal("antifraud tip query must be bounded by the dashboard window")
	}
}
