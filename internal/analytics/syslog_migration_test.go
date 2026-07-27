package analytics

import "testing"

func TestSyslogMigrationPreflightFailsClosed(t *testing.T) {
	valid := SyslogMigrationPreflight{
		Source:                  SyslogCopyDigest{Rows: 2, Sum: 3, Xor: 1},
		Destination:             SyslogCopyDigest{Rows: 2, Sum: 3, Xor: 1},
		CopyVerified:            true,
		LegacyParserJobsChecked: true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	mismatch := valid
	mismatch.CopyVerified = false
	mismatch.Destination.Rows = 1
	if err := mismatch.Validate(); err == nil {
		t.Fatal("copy mismatch was accepted")
	}
	active := valid
	active.ActiveLegacyParserJobs = 1
	if err := active.Validate(); err == nil {
		t.Fatal("active legacy rebuild job was accepted")
	}
	unchecked := valid
	unchecked.LegacyParserJobsChecked = false
	if err := unchecked.Validate(); err == nil {
		t.Fatal("unchecked legacy rebuild state was accepted")
	}
}
