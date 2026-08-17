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
	if !strings.Contains(source, "WHEN j.status IN ('failed','uploading') AND j.local_path<>'' THEN 'uploading'") {
		t.Fatal("failed/uploading jobs with a local ZIP must retry upload")
	}
	if !strings.Contains(source, "status='uploading' AND local_path=''") {
		t.Fatal("uploading jobs without a local ZIP must rebuild")
	}
	if !strings.Contains(source, "AND e.status NOT IN ('abandoned','skipped_stale')") {
		t.Fatal("device last_error must ignore abandoned/stale job reasons")
	}
}
