package archive

import (
	"testing"

	"github.com/minio/minio-go/v7/pkg/lifecycle"
)

func TestCDRRetentionLifecyclePreservesUnrelatedRules(t *testing.T) {
	config := lifecycle.NewConfiguration()
	config.Rules = []lifecycle.Rule{
		{
			ID: "exports-retention", Status: "Enabled",
			RuleFilter: lifecycle.Filter{Prefix: "exports/"},
			Expiration: lifecycle.Expiration{Days: 14},
		},
		{
			ID: "collector-raw-cdr-retention", Status: "Enabled",
			RuleFilter: lifecycle.Filter{Prefix: "wrong/"},
			Expiration: lifecycle.Expiration{Days: 10},
		},
	}
	got := cdrRetentionLifecycle(config, 365)
	if len(got.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(got.Rules))
	}
	if got.Rules[0].ID != "exports-retention" ||
		got.Rules[0].RuleFilter.Prefix != "exports/" {
		t.Fatalf("unrelated lifecycle rule changed: %#v", got.Rules[0])
	}
	rule := got.Rules[1]
	if rule.ID != "collector-raw-cdr-retention" ||
		rule.RuleFilter.Prefix != "cdr/" || rule.Expiration.Days != 365 {
		t.Fatalf("raw CDR lifecycle rule is incorrect: %#v", rule)
	}
}

func TestExportRetentionLifecycleIsSevenDays(t *testing.T) {
	config := lifecycle.NewConfiguration()
	config.Rules = []lifecycle.Rule{{
		ID: "other", Status: "Enabled",
		RuleFilter: lifecycle.Filter{Prefix: "cdr/"},
		Expiration: lifecycle.Expiration{Days: 30},
	}, {
		ID: "collector-export-retention", Status: "Enabled",
		RuleFilter: lifecycle.Filter{Prefix: "wrong/"},
		Expiration: lifecycle.Expiration{Days: 99},
	}}
	got := exportRetentionLifecycle(config)
	if len(got.Rules) != 2 || got.Rules[0].ID != "other" {
		t.Fatalf("unrelated lifecycle rules changed: %#v", got.Rules)
	}
	rule := got.Rules[1]
	if rule.ID != "collector-export-retention" ||
		rule.RuleFilter.Prefix != "exports/" || rule.Expiration.Days != 7 {
		t.Fatalf("export lifecycle rule is incorrect: %#v", rule)
	}
}
