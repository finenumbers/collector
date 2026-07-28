package ingest

import (
	"os"
	"strings"
	"testing"
)

func TestSyslogWorkerDedupesDeviceLookupsPerBatch(t *testing.T) {
	body, err := os.ReadFile("syslog_worker.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "deviceConfigErr := make(map[uuid.UUID]error)") {
		t.Fatal("DeviceTimeConfig lookups must be cached per batch")
	}
	if !strings.Contains(source, "policies := make(map[uuid.UUID]*policyLookup") {
		t.Fatal("CustomAntifraudPolicy lookups must be cached per batch")
	}
}
