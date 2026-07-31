package store

import "testing"

func TestIngestFileRetryDisposition(t *testing.T) {
	if got := IngestFileRetryDisposition("quarantined", true); got.Retry || got.RemoveLocal {
		t.Fatalf("unchanged quarantine must remain in place without retry: %#v", got)
	}
	if got := IngestFileRetryDisposition("quarantined", false); !got.Retry {
		t.Fatalf("configuration change must reopen quarantine: %#v", got)
	}
	if got := IngestFileRetryDisposition("failed", true); !got.Retry {
		t.Fatalf("transient failure must remain retryable: %#v", got)
	}
	if got := IngestFileRetryDisposition("processed", false); got.Retry || !got.RemoveLocal {
		t.Fatalf("processed duplicate must be removed: %#v", got)
	}
}
