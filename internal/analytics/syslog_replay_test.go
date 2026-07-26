package analytics

import (
	"strings"
	"testing"
)

func TestDeviceSyslogReplayQueryIsLinearKeysetScan(t *testing.T) {
	query := strings.ToLower(deviceSyslogReplayQuery)
	for _, forbidden := range []string{" join ", "syslog_reprocess_ledger", " offset ", " final"} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("replay query contains %q:\n%s", forbidden, deviceSyslogReplayQuery)
		}
	}
	for _, required := range []string{
		"where device_id=?",
		"tuple(tounixtimestamp64micro(received_at),event_id)>tuple(?,?)",
		"tuple(tounixtimestamp64micro(received_at),event_id)<=tuple(?,?)",
		"order by received_at,event_id",
		"limit ?",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("replay query is missing %q:\n%s", required, deviceSyslogReplayQuery)
		}
	}
}
