package store

import "testing"

func TestIngestFileFullyIngested(t *testing.T) {
	cases := []struct {
		status    string
		rowsValid uint64
		want      bool
	}{
		{"processed", 0, true},
		{"processed", 10, true},
		{"archived", 0, true},
		{"quarantined", 5, true},
		{"quarantined", 0, false},
		{"failed", 0, false},
		{"failed", 3, false},
		{"received", 0, false},
		{"processing", 0, false},
	}
	for _, test := range cases {
		if got := IngestFileFullyIngested(test.status, test.rowsValid); got != test.want {
			t.Fatalf("IngestFileFullyIngested(%q,%d)=%v want %v",
				test.status, test.rowsValid, got, test.want)
		}
	}
}
