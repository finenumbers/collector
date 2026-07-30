package analytics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"collector/internal/pstnlookup"
)

func TestEnrichSatelRecordsAppliesLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		phone := r.URL.Query().Get("phone")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"found": true,
			"phone": phone,
			"data": map[string]any{
				"operator": "Op-" + phone,
				"region":   "Reg-" + phone,
			},
		})
	}))
	defer server.Close()

	client := pstnlookup.New(server.URL, "token")
	client.HTTPClient = server.Client()
	records := []SatelRTURecord{
		{BillANI: "84996660000", BillDNIS: "4951234567"},
		{BillANI: "4996660000", BillDNIS: ""},
	}
	EnrichSatelRecords(context.Background(), client, records)
	if records[0].BillANIOperator != "Op-4996660000" ||
		records[0].BillANIRegion != "Reg-4996660000" ||
		records[0].BillDNISOperator != "Op-4951234567" ||
		records[0].BillDNISRegion != "Reg-4951234567" {
		t.Fatalf("unexpected enrichment %#v", records[0])
	}
	if records[1].BillANIOperator != "Op-4996660000" || records[1].BillDNISOperator != "" {
		t.Fatalf("unexpected second record %#v", records[1])
	}
}

func TestEnrichSatelRecordsNoopWithoutClient(t *testing.T) {
	records := []SatelRTURecord{{BillANI: "4996660000"}}
	EnrichSatelRecords(context.Background(), nil, records)
	EnrichSatelRecords(context.Background(), pstnlookup.New("", ""), records)
	if records[0].BillANIOperator != "" {
		t.Fatalf("expected empty enrichment, got %#v", records[0])
	}
}
