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
