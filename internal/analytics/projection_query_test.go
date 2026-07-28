package analytics

import (
	"os"
	"strings"
	"testing"
)

func TestLoadCustomRadiusEventsUsesMultiSearchFilter(t *testing.T) {
	body, err := os.ReadFile("custom_projection.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "multiSearchAnyCaseInsensitiveUTF8(payload, [") {
		t.Fatal("syslog AF filter must use multiSearchAnyCaseInsensitiveUTF8")
	}
	if strings.Count(source, "positionCaseInsensitiveUTF8(payload,'RADIUS')") != 0 {
		t.Fatal("legacy per-needle OR filter must be removed from LoadCustomRadiusEvents")
	}
}

func TestDiscoverSyslogBucketsUsesNonHeavyClass(t *testing.T) {
	body, err := os.ReadFile("custom_projection.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	discover := source[strings.Index(source, "func (c *Client) DiscoverSyslogBuckets"):]
	discover = discover[:strings.Index(discover, "\nfunc ")]
	if !strings.Contains(discover, "workload.CustomReconcile") {
		t.Fatal("discover must use non-heavy CustomReconcile admission")
	}
	if strings.Contains(discover, "workload.CustomReplay") {
		t.Fatal("discover must not take the heavy CustomReplay lane")
	}
}
