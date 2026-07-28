package customprojection

import (
	"os"
	"strings"
	"testing"
)

func TestFinishBucketReusesPreliminaryWhenSessionExpandEmpty(t *testing.T) {
	body, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "result := preliminary") {
		t.Fatal("bucket finish/window paths must reuse preliminary BuildAtCutoff result")
	}
	if strings.Count(source, "result = customradius.BuildAtCutoff(engineConfig, events,") < 2 {
		t.Fatal("rebuild after non-empty session merge must remain on window and hour paths")
	}
}
