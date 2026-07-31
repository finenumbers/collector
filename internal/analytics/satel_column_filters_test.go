package analytics

import (
	"strings"
	"testing"
)

func TestNormalizeSatelColumnFilters(t *testing.T) {
	got, err := NormalizeSatelColumnFilters(map[string]string{
		"bill_ani": " 7900 ",
		"src_name": "",
		"dp_name":  "route-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["bill_ani"] != "7900" || got["dp_name"] != "route-a" {
		t.Fatalf("got %#v", got)
	}
	if _, err := NormalizeSatelColumnFilters(map[string]string{"evil": "x"}); err == nil {
		t.Fatal("expected unsupported column error")
	}
	long := strings.Repeat("1", 65)
	if _, err := NormalizeSatelColumnFilters(map[string]string{"bill_ani": long}); err == nil {
		t.Fatal("expected length error")
	}
}

func TestAppendSatelColumnFiltersExactMatch(t *testing.T) {
	query, args := appendSatelColumnFilters("WHERE 1=1", nil, SatelColumnFilters{
		"src_name": "a",
		"bill_ani": "b",
	})
	want := "WHERE 1=1 AND c.bill_ani=? AND c.src_name=?"
	if query != want {
		t.Fatalf("query=%q want %q", query, want)
	}
	if len(args) != 2 || args[0] != "b" || args[1] != "a" {
		t.Fatalf("args=%#v", args)
	}
}

func TestClampSatelColumnSuggestLimit(t *testing.T) {
	if got := clampSatelColumnSuggestLimit(0); got != 50 {
		t.Fatalf("zero=%d", got)
	}
	if got := clampSatelColumnSuggestLimit(200); got != 50 {
		t.Fatalf("over=%d", got)
	}
	if got := clampSatelColumnSuggestLimit(12); got != 12 {
		t.Fatalf("ok=%d", got)
	}
}

func TestSatelColumnValuesQueryTemplate(t *testing.T) {
	src := satelColumnValuesBaseQuery
	for _, needle := range []string{
		"SELECT c.%s AS value,count() AS cnt",
		"c.%s!=''",
		"coalesce(t.setup_time,t.cdr_date,c.ingested_at)>=?",
		"coalesce(t.setup_time,t.cdr_date,c.ingested_at)<?",
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("query missing %q in %q", needle, src)
		}
	}
}
