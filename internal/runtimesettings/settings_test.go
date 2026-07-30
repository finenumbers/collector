package runtimesettings

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDefaultsValidate(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMergePatchKeepsPassword(t *testing.T) {
	base := Defaults()
	base.Voipmonitor.Password = "secret"
	base.Voipmonitor.Enabled = true
	base.Voipmonitor.APIURL = "https://vm.example"
	merged, err := MergePatch(base, json.RawMessage(`{"voipmonitor":{"enabled":true,"minScore":70}}`))
	if err != nil {
		t.Fatal(err)
	}
	if merged.Voipmonitor.Password != "secret" || merged.Voipmonitor.MinScore != 70 {
		t.Fatalf("merge failed: %+v", merged.Voipmonitor)
	}
}

func TestPublicViewRedactsPassword(t *testing.T) {
	doc := Defaults()
	doc.Voipmonitor.Password = "secret"
	view := doc.PublicView()
	if view.Voipmonitor.Password != "" || !view.Voipmonitor.PasswordSet {
		t.Fatalf("public view=%+v", view.Voipmonitor)
	}
}

func TestMergePatchKeepsEnrichmentTokens(t *testing.T) {
	base := Defaults()
	base.Enrichment.PSTN.Token = "pstn-secret"
	base.Enrichment.GeoIP.Token = "geoip-secret"
	merged, err := MergePatch(base, json.RawMessage(`{
		"enrichment":{"pstn":{"enabled":true,"apiUrl":"https://pstn.example/lookup"},
			"geoip":{"enabled":false,"apiUrl":"https://geoip.example/lookup"}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if merged.Enrichment.PSTN.Token != "pstn-secret" || merged.Enrichment.GeoIP.Token != "geoip-secret" {
		t.Fatalf("tokens lost: %+v", merged.Enrichment)
	}
	if merged.Enrichment.GeoIP.Enabled {
		t.Fatal("expected geoip disabled")
	}
}

func TestPublicViewRedactsEnrichmentTokens(t *testing.T) {
	doc := Defaults()
	doc.Enrichment.PSTN.Token = "pstn-secret"
	doc.Enrichment.GeoIP.Token = "geoip-secret"
	view := doc.PublicView()
	if view.Enrichment.PSTN.Token != "" || !view.Enrichment.PSTN.TokenSet {
		t.Fatalf("pstn public=%+v", view.Enrichment.PSTN)
	}
	if view.Enrichment.GeoIP.Token != "" || !view.Enrichment.GeoIP.TokenSet {
		t.Fatalf("geoip public=%+v", view.Enrichment.GeoIP)
	}
}

func TestContainersComposeEnvFragment(t *testing.T) {
	fragment := Defaults().Containers.ComposeEnvFragment()
	for _, key := range []string{
		"COLLECTOR_API_CPUS=", "COLLECTOR_API_MEMORY=",
		"COLLECTOR_EXPORT_CPUS=", "COLLECTOR_MAINTENANCE_MEMORY=",
		"COLLECTOR_CPUS=", "COLLECTOR_MEMORY=",
	} {
		if !strings.Contains(fragment, key) {
			t.Fatalf("missing %s in %q", key, fragment)
		}
	}
}
