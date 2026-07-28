package exportworker

import (
	"os"
	"strings"
	"testing"
)

func TestExportUploadHashesInOnePass(t *testing.T) {
	body, err := os.ReadFile("worker.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "upload := io.TeeReader(file, hash)") {
		t.Fatal("export upload must hash via TeeReader in one pass")
	}
	if strings.Contains(source, "io.Copy(hash, file)") {
		t.Fatal("export must not pre-hash the spool file before upload")
	}
}
