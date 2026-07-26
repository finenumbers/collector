package analytics

import (
	"context"
	"strings"
	"testing"
)

func TestRetentionRegistryIncludesSyslogHourly(t *testing.T) {
	found := false
	for _, table := range retentionTables["syslog"] {
		if table.name == "syslog_hourly" && table.timeExpr == "hour" {
			found = true
		}
	}
	if !found {
		t.Fatal("syslog_hourly is missing from the Syslog retention registry")
	}
}

func TestRetentionRegistrySeparatesEltexAndSatelCDR(t *testing.T) {
	eltexRecords, eltexInterpretations, eltexFacts := false, false, false
	for _, table := range retentionTables["cdr"] {
		eltexRecords = eltexRecords || table.name == "cdr_records"
		eltexInterpretations = eltexInterpretations || table.name == "cdr_time_interpretations"
		eltexFacts = eltexFacts || table.name == "cdr_time_facts"
		if table.name == "satel_rtu_cdr" || table.name == "satel_rtu_cdr_time_facts" {
			t.Fatalf("Satel table %s remains in cdr retention", table.name)
		}
	}
	if !eltexRecords || !eltexInterpretations || !eltexFacts {
		t.Fatalf(
			"Eltex retention incomplete: records=%v interpretations=%v facts=%v",
			eltexRecords, eltexInterpretations, eltexFacts,
		)
	}

	foundRecords, foundTimes := false, false
	for _, table := range retentionTables["softswitch_cdr"] {
		foundRecords = foundRecords || table.name == "satel_rtu_cdr"
		foundTimes = foundTimes || table.name == "satel_rtu_cdr_time_facts"
	}
	if !foundRecords || !foundTimes {
		t.Fatalf("Satel retention incomplete: records=%v times=%v", foundRecords, foundTimes)
	}
}

func TestApplyRetentionRejectsUnsafeInputBeforeDatabaseAccess(t *testing.T) {
	client := &Client{}
	for _, days := range []int{0, 6, 1096} {
		err := client.ApplyRetention(context.Background(), "syslog", days)
		if err == nil || !strings.Contains(err.Error(), "between 7 and 1095") {
			t.Fatalf("days=%d: got %v", days, err)
		}
	}
	if err := client.ApplyRetention(context.Background(), "not_allowlisted", 30); err == nil {
		t.Fatal("unknown policy class was accepted")
	}
}

func TestRetentionAllowlistExcludesLedgers(t *testing.T) {
	disallowed := map[string]bool{
		"schema_migrations":         true,
		"syslog_reprocess_ledger":   true,
		"device_derived_revisions":  true,
		"correlation_dirty_buckets": true,
	}
	for class, tables := range retentionTables {
		for _, table := range tables {
			if disallowed[table.name] {
				t.Fatalf("%s retention improperly includes ledger %s", class, table.name)
			}
		}
	}
}
