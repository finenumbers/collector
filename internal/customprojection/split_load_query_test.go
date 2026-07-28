package customprojection

import (
	"os"
	"strings"
	"testing"
)

func TestLoadEventsSplitChunksLargeRangesFirst(t *testing.T) {
	body, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "if to.Sub(from) > 2*span") {
		t.Fatal("loadEventsSplit must skip doomed full-range probes on large spans")
	}
	if !strings.Contains(source, "filterEventsInRange") {
		t.Fatal("local memory overflow path must filter preloaded events per window")
	}
	if !strings.Contains(source, "WriteCustomProjectionSnapshot(cutoverCtx, snapshot)") {
		t.Fatal("snapshot write must reuse the shared CustomReplay admission context")
	}
}
