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

func TestAntifraudLifecycleIDDoesNotDependOnInterpretedDate(t *testing.T) {
	event := SyslogEvent{
		EventID: uuid.New(), DeviceID: uuid.New(),
		Attributes: map[string]string{"call_context": "C42"},
	}
	first := antifraudTransactionID(event, time.Date(2026, 7, 23, 23, 59, 0, 0, time.UTC))
	second := antifraudTransactionID(event, time.Date(2026, 7, 24, 6, 59, 0, 0, time.UTC))
	if first != second {
		t.Fatalf("timezone correction changed lifecycle identity: %s != %s", first, second)
	}
}
