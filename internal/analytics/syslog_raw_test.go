package analytics

import (
	"os"
	"strings"
	"testing"
)

func TestSyslogSlotFingerprintScansCountAsUint64(t *testing.T) {
	body, err := os.ReadFile("syslog_raw.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if strings.Contains(source, "Scan(&fp.Count") {
		t.Fatal("ClickHouse count() is UInt64; scanning into int64 fails at runtime")
	}
	if !strings.Contains(source, "var count uint64") ||
		!strings.Contains(source, "Scan(&count, &maxAt, &maxID)") {
		t.Fatal("SyslogSlotFingerprint must scan count() into uint64")
	}
}
