package store

import "testing"

func TestNormalizeFirmwareScheme(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"3.23.2", FirmwareScheme3232},
		{"3.410", FirmwareScheme3410},
		{"3.410.0.7443", FirmwareScheme3410},
		{"3.23.2.5834", FirmwareScheme3232},
		{"", FirmwareScheme3232},
		{"unknown", FirmwareScheme3232},
	}
	for _, test := range cases {
		if got := NormalizeFirmwareScheme(test.in); got != test.want {
			t.Fatalf("NormalizeFirmwareScheme(%q)=%q want %q", test.in, got, test.want)
		}
	}
}

func TestCanonicalFirmware(t *testing.T) {
	if value, err := CanonicalFirmware(""); err != nil || value != FirmwareScheme3232 {
		t.Fatalf("empty firmware: %q %v", value, err)
	}
	if value, err := CanonicalFirmware("3.410"); err != nil || value != FirmwareScheme3410 {
		t.Fatalf("3.410: %q %v", value, err)
	}
	if _, err := CanonicalFirmware("3.410.0.7443"); err == nil {
		t.Fatal("legacy full build must be rejected on save")
	}
}
