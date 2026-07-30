package analytics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
				"operator":     "Op-" + phone,
				"region":       "Reg-" + phone,
				"garTerritory": "Gar-" + phone,
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
		records[0].BillANIRegion != "Gar-4996660000" ||
		records[0].BillDNISOperator != "Op-4951234567" ||
		records[0].BillDNISRegion != "Gar-4951234567" {
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

func TestEnrichSatelRecordsSkipsNonEligiblePhones(t *testing.T) {
	var pstnHits atomic.Int32
	pstnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pstnHits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer pstnServer.Close()
	pstn := pstnlookup.New(pstnServer.URL, "token", true)
	pstn.HTTPClient = pstnServer.Client()
	records := []SatelRTURecord{
		{BillANI: "71234567890", BillDNIS: "15551234567"},
	}
	EnrichSatelRecords(context.Background(), pstn, nil, records, 4)
	if pstnHits.Load() != 0 {
		t.Fatalf("pstn hits=%d want 0 for non-eligible phones", pstnHits.Load())
	}
	if records[0].BillANIOperator != "" || records[0].BillANIRegion != "" {
		t.Fatalf("expected empty PSTN fields, got %#v", records[0])
	}
}

func TestEnrichSatelRecordsLeavesEmptyOnIncompleteLookup(t *testing.T) {
	pstnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"found": true,
			"data": map[string]any{
				"operator":     "Op",
				"garTerritory": "",
			},
		})
	}))
	defer pstnServer.Close()
	pstn := pstnlookup.New(pstnServer.URL, "token", true)
	pstn.HTTPClient = pstnServer.Client()
	records := []SatelRTURecord{{BillANI: "9031234567"}}
	EnrichSatelRecords(context.Background(), pstn, nil, records, 2)
	if records[0].BillANIOperator != "" || records[0].BillANIRegion != "" {
		t.Fatalf("incomplete lookup must leave fields empty, got %#v", records[0])
	}
}

func TestEnrichSatelRecordsForcePSTNOverwritesOldRegion(t *testing.T) {
	pstnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		phone := r.URL.Query().Get("phone")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"found": true,
			"data": map[string]any{
				"operator":     "NewOp-" + phone,
				"garTerritory": "NewGar-" + phone,
			},
		})
	}))
	defer pstnServer.Close()
	pstn := pstnlookup.New(pstnServer.URL, "token", true)
	pstn.HTTPClient = pstnServer.Client()
	records := []SatelRTURecord{{
		BillANI: "84996660000", BillANIOperator: "OldOp", BillANIRegion: "old-region-not-gar",
	}}
	EnrichSatelRecordsForcePSTN(context.Background(), pstn, nil, records, 2)
	if records[0].BillANIOperator != "NewOp-4996660000" ||
		records[0].BillANIRegion != "NewGar-4996660000" {
		t.Fatalf("force-pstn must overwrite old region: %#v", records[0])
	}
}

func TestEnrichSatelRecordsFillsHistoricalGapsWithoutWiping(t *testing.T) {
	var hits atomic.Int32
	pstnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		phone := r.URL.Query().Get("phone")
		if phone == "9031234567" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"found": true,
			"data": map[string]any{
				"operator":     "Op-" + phone,
				"garTerritory": "Gar-" + phone,
			},
		})
	}))
	defer pstnServer.Close()
	pstn := pstnlookup.New(pstnServer.URL, "token", true)
	pstn.HTTPClient = pstnServer.Client()
	records := []SatelRTURecord{{
		// Historical ANI gap (operator present, garTerritory missing).
		BillANI: "84996660000", BillANIOperator: "OldOp", BillANIRegion: "",
		// Eligible DNIS gap; API fails — must stay empty (no wipe of siblings).
		BillDNIS: "9031234567",
	}}
	EnrichSatelRecords(context.Background(), pstn, nil, records, 4)
	if records[0].BillANIOperator != "Op-4996660000" || records[0].BillANIRegion != "Gar-4996660000" {
		t.Fatalf("ANI gap not filled: %#v", records[0])
	}
	if records[0].BillDNISOperator != "" || records[0].BillDNISRegion != "" {
		t.Fatalf("failed DNIS lookup must not invent values: %#v", records[0])
	}
	if hits.Load() < 2 {
		t.Fatalf("expected lookups for both gap sides, hits=%d", hits.Load())
	}
	if !RecordNeedsPSTNEnrichment(records[0]) {
		t.Fatal("DNIS gap must still need enrichment after failed lookup")
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

func TestSatelPSTNEligibilitySQLHelpers(t *testing.T) {
	if got := satelPSTNEligibleSideExpr("bill_ani"); got == "" {
		t.Fatal("empty eligible expr")
	}
	if got := satelPSTNCallEnrichedExpr(); got == "" {
		t.Fatal("empty enriched expr")
	}
	if got := satelPSTNAllColumnsFilledExpr(); !strings.Contains(got, "bill_ani_operator") ||
		!strings.Contains(got, " AND ") {
		t.Fatalf("all-columns PSTN expr = %q", got)
	}
	if got := satelGeoipAllColumnsFilledExpr(); !strings.Contains(got, "remote_src_asn_org") ||
		strings.Contains(got, " OR ") {
		t.Fatalf("all-columns GeoIP expr = %q", got)
	}
	needs := satelNeedsEnrichmentPredicate()
	if needs == "" {
		t.Fatal("empty needs predicate")
	}
}
