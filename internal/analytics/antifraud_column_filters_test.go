package analytics

import (
	"strings"
	"testing"
)

func TestNormalizeAntifraudColumnFilters(t *testing.T) {
	if _, err := NormalizeAntifraudColumnFilters(map[string]string{"evil": "x"}); err == nil {
		t.Fatal("expected unsupported")
	}
	got, err := NormalizeAntifraudColumnFilters(map[string]string{
		"calling":        "7900",
		"radius_outcome": "accept",
		"coverage":       "matched",
	})
	if err != nil || len(got) != 3 {
		t.Fatalf("got %#v err=%v", got, err)
	}
}

func TestAntifraudFilterExpressionsPresent(t *testing.T) {
	for _, col := range []string{"calling", "called", "phases", "chain", "radius_outcome", "coverage"} {
		expr, ok := antifraudFilterExpr(col)
		if !ok || expr == "" {
			t.Fatalf("missing expr for %s", col)
		}
	}
	for _, needle := range []string{
		"indication", "verification", "accounting",
		"'complete'", "'partial'", "'minimal'",
		"'reject'", "'accept'", "'no_response'",
		"'matched'", "'awaiting_cdr'", "'missing'",
		"call.coverage_state",
	} {
		blob := afPhasesExpr + afChainExpr + afRadiusOutcomeExpr + afCoverageExpr
		if !strings.Contains(blob, needle) {
			t.Fatalf("derived SQL missing %q", needle)
		}
	}
}

func TestAppendAntifraudColumnFilters(t *testing.T) {
	query, args := appendAntifraudColumnFilters("WHERE 1=1", nil, AntifraudColumnFilters{
		"calling": "a",
		"chain":   "complete",
	})
	if !strings.Contains(query, "call.calling") || !strings.Contains(query, "'complete'") {
		t.Fatalf("query=%q", query)
	}
	if len(args) != 2 {
		t.Fatalf("args=%#v", args)
	}
}
