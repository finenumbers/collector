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
