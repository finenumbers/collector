package equipment

import "testing"

func TestRegistryContainsStableTemplates(t *testing.T) {
	tests := []struct {
		key, category, label          string
		syslog, typed, raw, antifraud bool
	}{
		{TemplateEltex3410, CategoryEquipment, "Eltex SMG-1016M (3.410)", true, true, true, true},
		{TemplateEltex3232, CategoryEquipment, "Eltex SMG-1016M (3.23.2)", true, true, true, true},
		{TemplateSatelRTUCDRV1, CategorySoftswitch, "Satel RTU", false, true, true, false},
	}
	for _, test := range tests {
		template, err := Resolve(test.key)
		if err != nil {
			t.Fatal(err)
		}
		if template.Category != test.category || template.DisplayName != test.label {
			t.Fatalf("%s resolved to %#v", test.key, template)
		}
		got := template.Capabilities
		if got.Syslog != test.syslog || got.TypedCDR != test.typed ||
			got.RawCDR != test.raw || got.Antifraud != test.antifraud ||
			got.Radius != test.antifraud {
			t.Fatalf("%s capabilities = %#v", test.key, got)
		}
	}
}

func TestRegistryListIsCopyAndFiltersCategory(t *testing.T) {
	all := List()
	if len(all) != 3 {
		t.Fatalf("got %d templates", len(all))
	}
	all[0].DisplayName = "changed"
	resolved, _ := Resolve(all[0].Key)
	if resolved.DisplayName == "changed" {
		t.Fatal("List exposed mutable registry state")
	}
	if got := ListCategory(CategorySoftswitch); len(got) != 1 ||
		got[0].Key != TemplateSatelRTUCDRV1 {
		t.Fatalf("unexpected softswitch templates: %#v", got)
	}
	if _, err := Resolve("missing"); err != ErrUnknownTemplate {
		t.Fatalf("unexpected missing-template error: %v", err)
	}
}
