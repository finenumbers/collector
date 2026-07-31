package analytics

import (
	"strings"
	"testing"
)

func TestNormalizeEltexColumnFilters(t *testing.T) {
	if _, err := NormalizeEltexColumnFilters(map[string]string{"evil": "x"}); err == nil {
		t.Fatal("expected unsupported column error")
	}
	got, err := NormalizeEltexColumnFilters(map[string]string{
		"outgoing_cgpn":        " 7900 ",
		"incoming_description": "in",
		"release_info":         "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["outgoing_cgpn"] != "7900" {
		t.Fatalf("got %#v", got)
	}
	long := strings.Repeat("1", eltexColumnFilterMaxLen+1)
	if _, err := NormalizeEltexColumnFilters(map[string]string{"outgoing_cgpn": long}); err == nil {
		t.Fatal("expected length error")
	}
}

func TestAppendEltexColumnFilters(t *testing.T) {
	query, args := appendEltexColumnFilters("WHERE 1=1", nil, EltexColumnFilters{
		"release_info":  "a",
		"outgoing_cgpn": "b",
	})
	want := "WHERE 1=1 AND c.outgoing_cgpn=? AND c.release_info=?"
	if query != want {
		t.Fatalf("query=%q want %q", query, want)
	}
	if len(args) != 2 || args[0] != "b" || args[1] != "a" {
		t.Fatalf("args=%#v", args)
	}
}

func TestEltexColumnValuesQueryTemplate(t *testing.T) {
	for _, needle := range []string{
		"SELECT c.%s AS value,count() AS cnt",
		"collector.cdr_records",
		"coalesce(t.setup_time,c.setup_time,c.ingested_at)>=?",
	} {
		if !strings.Contains(eltexColumnValuesBaseQuery, needle) {
			t.Fatalf("missing %q", needle)
		}
	}
}
