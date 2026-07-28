package store

import (
	"os"
	"strings"
	"testing"
)

func TestDeviceIngestSummariesUsesShortTTLCache(t *testing.T) {
	body, err := os.ReadFile("postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "const ttl = 2 * time.Second") {
		t.Fatal("DeviceIngestSummaries must cache for 2s")
	}
	if !strings.Contains(source, "cloneDeviceIngestSummaries") {
		t.Fatal("cached ingest summaries must be cloned before return")
	}
}
