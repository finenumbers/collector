package analytics

import (
	"strings"
	"testing"
)

func TestClampSatelBillANISuggestLimit(t *testing.T) {
	if got := clampSatelBillANISuggestLimit(0); got != 50 {
		t.Fatalf("zero=%d want 50", got)
	}
	if got := clampSatelBillANISuggestLimit(200); got != 50 {
		t.Fatalf("over=%d want 50", got)
	}
	if got := clampSatelBillANISuggestLimit(12); got != 12 {
		t.Fatalf("ok=%d want 12", got)
	}
}

func TestSatelBillANIValuesQueryIsDayScopedDistinct(t *testing.T) {
	src := satelBillANIValuesBaseQuery
	for _, needle := range []string{
		"SELECT DISTINCT c.bill_ani",
		"c.bill_ani!=''",
		"coalesce(t.setup_time,t.cdr_date,c.ingested_at)>=?",
		"coalesce(t.setup_time,t.cdr_date,c.ingested_at)<?",
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("query missing %q in %q", needle, src)
		}
	}
}
