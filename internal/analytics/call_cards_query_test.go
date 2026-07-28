package analytics

import (
	"os"
	"strings"
	"testing"
)

func TestAntifraudCallListPushesDeviceIDIntoJoinSubqueries(t *testing.T) {
	body, err := os.ReadFile("call_cards.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, `FROM collector.cdr_antifraud_assignments_current
			WHERE device_id=? GROUP BY device_id,call_id`) {
		t.Fatal("assignment subquery must filter by device_id before GROUP BY")
	}
	if !strings.Contains(source, `WHERE links.deleted=0 AND links.device_id=?`) {
		t.Fatal("packet_summary subquery must filter by device_id before GROUP BY")
	}
	if !strings.Contains(source, `args := []any{deviceID, deviceID, deviceID}`) {
		t.Fatal("list query must bind device_id for both join subqueries and outer filter")
	}
}
