package analytics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"collector/internal/geoiplookup"
	"collector/internal/pstnlookup"
)

func TestEnrichSatelRecordsAppliesLookup(t *testing.T) {
	var pstnHits, geoipHits atomic.Int32
	pstnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pstnHits.Add(1)
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
	defer pstnServer.Close()
	geoipServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		geoipHits.Add(1)
		time.Sleep(20 * time.Millisecond)
		var body struct {
			IP string `json:"ip"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"city": map[string]any{
				"countryIsoCode": "RU",
				"cityName":       "City-" + body.IP,
			},
			"asn": map[string]any{
				"organization": "ASN-" + body.IP,
			},
		})
	}))
	defer geoipServer.Close()

	pstn := pstnlookup.New(pstnServer.URL, "token", true)
	pstn.HTTPClient = pstnServer.Client()
	geoip := geoiplookup.New(geoipServer.URL, "token", true)
	geoip.HTTPClient = geoipServer.Client()
	records := []SatelRTURecord{
		{
			BillANI: "84996660000", BillDNIS: "4951234567",
			RemoteSrcSigAddress: "1.2.3.4:5060", RemoteDstSigAddress: "5.6.7.8",
		},
		{BillANI: "4996660000", BillDNIS: ""},
	}
	start := time.Now()
	EnrichSatelRecords(context.Background(), pstn, geoip, records, 8)
	elapsed := time.Since(start)
	if records[0].BillANIOperator != "Op-4996660000" ||
		records[0].BillANIRegion != "Reg-4996660000" ||
		records[0].BillDNISOperator != "Op-4951234567" ||
		records[0].BillDNISRegion != "Reg-4951234567" {
		t.Fatalf("unexpected pstn enrichment %#v", records[0])
	}
	if records[0].RemoteSrcGeoipISO != "RU" ||
		records[0].RemoteSrcGeoipCity != "City-1.2.3.4" ||
		records[0].RemoteSrcASNOrg != "ASN-1.2.3.4" ||
		records[0].RemoteDstGeoipCity != "City-5.6.7.8" {
		t.Fatalf("unexpected geoip enrichment %#v", records[0])
	}
	if records[1].BillANIOperator != "Op-4996660000" || records[1].BillDNISOperator != "" {
		t.Fatalf("unexpected second record %#v", records[1])
	}
	if pstnHits.Load() == 0 || geoipHits.Load() == 0 {
		t.Fatalf("expected both APIs to be called")
	}
	// Parallel PSTN∥GeoIP should finish near max(pstn, geoip), not sum.
	if elapsed > 150*time.Millisecond {
		t.Fatalf("enrichment took %s; expected parallel PSTN∥GeoIP", elapsed)
	}
}

func TestEnrichSatelRecordsNoopWithoutClient(t *testing.T) {
	records := []SatelRTURecord{{BillANI: "4996660000", RemoteSrcSigAddress: "1.2.3.4"}}
	EnrichSatelRecords(context.Background(), nil, nil, records, 8)
	EnrichSatelRecords(
		context.Background(),
		pstnlookup.New("", "", false),
		geoiplookup.New("", "", false),
		records,
		8,
	)
	if records[0].BillANIOperator != "" || records[0].RemoteSrcGeoipISO != "" {
		t.Fatalf("expected empty enrichment, got %#v", records[0])
	}
}
