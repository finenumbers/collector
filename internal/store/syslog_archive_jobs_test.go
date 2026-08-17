package store

import (
	"os"
	"strings"
	"testing"
)

func TestClaimSyslogArchiveJobRebuildsFailedWithoutLocalPath(t *testing.T) {
	body, err := os.ReadFile("syslog_archive_jobs.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "status='failed' AND local_path=''") {
		t.Fatal("failed jobs without a local ZIP must rebuild, not upload")
	}
	if !strings.Contains(source, "WHEN j.status='failed' AND j.local_path<>'' THEN 'uploading'") {
		t.Fatal("failed jobs with a local ZIP must retry upload")
	}
}
