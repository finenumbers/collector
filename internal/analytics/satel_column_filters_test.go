package analytics

import (
	"strings"
	"testing"
)

func TestNormalizeSatelColumnFilters(t *testing.T) {
	got, err := NormalizeSatelColumnFilters(map[string]string{
		"bill_ani":           " 7900 ",
		"src_name":           "",
		"dp_name":            "route-a",
		"bill_ani_operator":  "Rostelecom",
		"remote_src_asn_org": "AS Org",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got["bill_ani"] != "7900" || got["dp_name"] != "route-a" ||
		got["bill_ani_operator"] != "Rostelecom" || got["remote_src_asn_org"] != "AS Org" {
		t.Fatalf("got %#v", got)
	}
	if _, err := NormalizeSatelColumnFilters(map[string]string{"evil": "x"}); err == nil {
		t.Fatal("expected unsupported column error")
	}
	long := strings.Repeat("1", satelColumnFilterMaxLen+1)
	if _, err := NormalizeSatelColumnFilters(map[string]string{"bill_ani": long}); err == nil {
		t.Fatal("expected length error")
	}
	okLen := strings.Repeat("a", satelColumnFilterMaxLen)
	got, err = NormalizeSatelColumnFilters(map[string]string{"remote_src_asn_org": okLen})
	if err != nil || got["remote_src_asn_org"] != okLen {
		t.Fatalf("max len accepted: %#v err=%v", got, err)
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

func TestSatelFilterableColumnsCoverPresets(t *testing.T) {
	for _, col := range []string{
		"bill_ani", "bill_dnis", "out_orig_dnis", "src_name", "dst_name", "dp_name",
		"disconnect_text", "bill_ani_operator", "bill_dnis_operator",
		"bill_ani_region", "bill_dnis_region",
		"remote_src_geoip_iso", "remote_dst_geoip_iso",
		"remote_src_geoip_city", "remote_dst_geoip_city",
		"remote_src_asn_org", "remote_dst_asn_org",
	} {
		if !SatelColumnFilterAllowed(col) {
			t.Fatalf("missing allowlist entry %q", col)
		}
	}
}
