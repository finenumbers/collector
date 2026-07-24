package analytics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCorrelationIsOrderIndependentAndStrictOneToOne(t *testing.T) {
	at := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	transactions := []correlationTransaction{
		{ID: uuid.New(), FirstEventAt: at, Calling: "73832888803", Called: "74951234567", InRoute: "TG-A"},
		{ID: uuid.New(), FirstEventAt: at.Add(time.Second), Calling: "73832888803", Called: "74951234567", InRoute: "TG-A"},
	}
	cdrs := []correlationCDR{
		{ID: uuid.New(), SetupTime: at, IncomingCgPN: "+7 (383) 288-88-03", IncomingCdPN: "84951234567", IncomingRoute: "TG-A"},
		{ID: uuid.New(), SetupTime: at.Add(time.Second), IncomingCgPN: "83832888803", IncomingCdPN: "+74951234567", IncomingRoute: "TG-A"},
	}
	forward := correlateBucket(transactions, cdrs)
	reverse := correlateBucket(
		[]correlationTransaction{transactions[1], transactions[0]},
		[]correlationCDR{cdrs[1], cdrs[0]},
	)
	if len(forward) != 2 || len(reverse) != 2 {
		t.Fatalf("unexpected assignment counts: %d/%d", len(forward), len(reverse))
	}
	used := make(map[uuid.UUID]bool)
	for transactionID, edge := range forward {
		if edge.cdr.ID == uuid.Nil || edge.ambiguous {
			t.Fatalf("transaction %s was not deterministically linked: %#v", transactionID, edge)
		}
		if used[edge.cdr.ID] {
			t.Fatalf("CDR %s assigned more than once", edge.cdr.ID)
		}
		used[edge.cdr.ID] = true
		if reverse[transactionID].cdr.ID != edge.cdr.ID {
			t.Fatalf("input order changed assignment for %s", transactionID)
		}
	}
}

func TestFragmentSessionPropagationAndContextReuse(t *testing.T) {
	deviceID := uuid.New()
	received := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	first := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: received,
		Attributes: map[string]string{"call_context": "C-REUSED"},
	}
	second := first
	second.EventID = uuid.New()
	second.Attributes = map[string]string{
		"call_context": "C-REUSED", "acct_session_id": "SESSION-42",
	}
	transaction := &AntifraudTransaction{
		TransactionID: antifraudTransactionID(first, received),
		DeviceID:      deviceID, Attributes: make(map[string]string),
	}
	mergeAntifraudEvent(transaction, first, received, nil, nil, 0, nil)
	mergeAntifraudEvent(transaction, second, received.Add(time.Second), nil, nil, 0, nil)
	if transaction.AcctSessionID != "SESSION-42" ||
		transaction.AcctSessionIDNormalized != "session-42" {
		t.Fatalf("session was not propagated from later fragment: %#v", transaction)
	}
	reused := first
	reused.EventID = uuid.New()
	reused.ReceivedAt = received.Add(31 * time.Minute)
	if antifraudTransactionID(reused, reused.ReceivedAt) == transaction.TransactionID {
		t.Fatal("reused call context was merged across bounded occurrences")
	}
}

func TestIngestionHotPathsDoNotInvokeDeviceWideReconcile(t *testing.T) {
	paths := []string{
		filepath.Join("..", "ingest", "syslog.go"),
		filepath.Join("..", "ingest", "cdr.go"),
		filepath.Join("..", "ingest", "reprocess.go"),
		filepath.Join("..", "..", "cmd", "collector", "main.go"),
	}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), "ReconcileDevice(") {
			t.Fatalf("device-wide reconcile returned to hot path %s", path)
		}
	}
}

func TestCorrelationCorpusPerformance(t *testing.T) {
	const (
		transactionCount = 200
		cdrCount         = 4_000
	)
	at := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	transactions := make([]correlationTransaction, 0, transactionCount)
	cdrs := make([]correlationCDR, 0, cdrCount)
	for index := range cdrCount {
		session := ""
		if index < transactionCount {
			session = "session-" + uuid.NewSHA1(
				uuid.NameSpaceOID, []byte{byte(index), byte(index >> 8)},
			).String()
		}
		cdrs = append(cdrs, correlationCDR{
			ID:        uuid.NewSHA1(uuid.NameSpaceURL, []byte("cdr-"+time.Duration(index).String())),
			SetupTime: at.Add(time.Duration(index) * time.Second), Session: session,
			IncomingCgPN: "73832888803", IncomingCdPN: "74951234567",
		})
		if index < transactionCount {
			transactions = append(transactions, correlationTransaction{
				ID:           uuid.NewSHA1(uuid.NameSpaceURL, []byte("tx-"+time.Duration(index).String())),
				FirstEventAt: at.Add(time.Duration(index) * time.Second), Session: session,
				Calling: "73832888803", Called: "74951234567",
			})
		}
	}
	started := time.Now()
	assignments := correlateBucket(transactions, cdrs)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("bounded corpus correlation took %s", elapsed)
	}
	if len(assignments) != transactionCount {
		t.Fatalf("assigned %d/%d lifecycle rows", len(assignments), transactionCount)
	}
}
