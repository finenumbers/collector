package analytics

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCompositeCorrelationNormalizesRussianNumbersAndUsesRoutes(t *testing.T) {
	at := time.Date(2026, 7, 24, 11, 0, 0, 0, time.UTC)
	transaction := correlationTransaction{
		ID: uuid.New(), FirstEventAt: at,
		Calling: "9131234567", Called: "83831234567",
		InRoute: "PSTN-IN", OutRoute: "SIP-OUT",
	}
	record := correlationCDR{
		ID: uuid.New(), SetupTime: at.Add(1500 * time.Millisecond),
		IncomingCgPN: "79131234567", IncomingCdPN: "83831234567",
		IncomingRoute: "PSTN-IN", OutgoingRoute: "SIP-OUT",
	}
	edge, ok := compositeCorrelationEdge(transaction, record)
	if !ok {
		t.Fatal("expected a composite correlation candidate")
	}
	if edge.method != "composite_unique" || edge.confidence != 1 {
		t.Fatalf("edge = %#v", edge)
	}
	if edge.timeDeltaMS != 1500 {
		t.Fatalf("delta = %d", edge.timeDeltaMS)
	}
}

func TestCompositeCorrelationRejectsWeakSingleNumberEvidence(t *testing.T) {
	at := time.Date(2026, 7, 24, 11, 0, 0, 0, time.UTC)
	_, ok := compositeCorrelationEdge(correlationTransaction{
		ID: uuid.New(), FirstEventAt: at, Calling: "79131234567",
	}, correlationCDR{
		ID: uuid.New(), SetupTime: at.Add(30 * time.Second),
		IncomingCgPN: "79131234567",
	})
	if ok {
		t.Fatal("single number without route evidence must remain unlinked")
	}
}

func TestAntifraudLifecycleIDUsesCanonicalOccurrenceWindow(t *testing.T) {
	event := SyslogEvent{
		EventID: uuid.New(), DeviceID: uuid.New(),
		Attributes: map[string]string{"call_context": "C42"},
	}
	first := antifraudTransactionID(event, time.Date(2026, 7, 24, 6, 1, 0, 0, time.UTC))
	second := antifraudTransactionID(event, time.Date(2026, 7, 24, 6, 29, 0, 0, time.UTC))
	nextWindow := antifraudTransactionID(event, time.Date(2026, 7, 24, 6, 31, 0, 0, time.UTC))
	if first != second || first == nextWindow {
		t.Fatalf("canonical windows not respected: %s %s %s", first, second, nextWindow)
	}
}

func TestCorrelationAllowsManyLifecyclesToOneCDR(t *testing.T) {
	at := time.Date(2026, 7, 24, 11, 0, 0, 0, time.UTC)
	recordID := uuid.New()
	transactions := []correlationTransaction{
		{ID: uuid.New(), FirstEventAt: at, Session: "shared"},
		{ID: uuid.New(), FirstEventAt: at.Add(time.Second), Session: "shared"},
	}
	assignments := correlateBucket(transactions, []correlationCDR{{
		ID: recordID, SetupTime: at, Session: "shared",
	}})
	for _, transaction := range transactions {
		if assignments[transaction.ID].cdr.ID != recordID {
			t.Fatalf("transaction %s was not linked to shared CDR", transaction.ID)
		}
	}
}

func TestCorrelationTerminalReasonCodes(t *testing.T) {
	transaction := correlationTransaction{
		ID: uuid.New(), FirstEventAt: time.Now().UTC(), Calling: "79990000000",
		Attributes: map[string]string{"correlation_time_source": "event_timestamp"},
	}
	withoutCDR := correlateBucket([]correlationTransaction{transaction}, nil)
	if withoutCDR[transaction.ID].reason != correlationReasonNoCDRInBucket {
		t.Fatalf("reason=%q", withoutCDR[transaction.ID].reason)
	}
	if withoutCDR[transaction.ID].evidence["time_source"] != "event_timestamp" {
		t.Fatalf("orphan provenance=%v", withoutCDR[transaction.ID].evidence)
	}
	noOverlap := correlateBucket([]correlationTransaction{transaction}, []correlationCDR{{
		ID: uuid.New(), SetupTime: transaction.FirstEventAt, IncomingCgPN: "78880000000",
	}})
	if noOverlap[transaction.ID].reason != correlationReasonNoIdentityOverlap {
		t.Fatalf("reason=%q", noOverlap[transaction.ID].reason)
	}
}

func BenchmarkCorrelateBucketReplayLoad(b *testing.B) {
	const size = 10_000
	at := time.Date(2026, 7, 24, 11, 0, 0, 0, time.UTC)
	transactions := make([]correlationTransaction, 0, size)
	cdrs := make([]correlationCDR, 0, size)
	for index := 0; index < size; index++ {
		session := uuid.NewString()
		transactions = append(transactions, correlationTransaction{
			ID: uuid.New(), FirstEventAt: at.Add(time.Duration(index) * time.Millisecond),
			Session: session,
		})
		cdrs = append(cdrs, correlationCDR{
			ID: uuid.New(), SetupTime: at.Add(time.Duration(index) * time.Millisecond),
			Session: session,
		})
	}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if assignments := correlateBucket(transactions, cdrs); len(assignments) != size {
			b.Fatalf("assignments=%d", len(assignments))
		}
	}
}
