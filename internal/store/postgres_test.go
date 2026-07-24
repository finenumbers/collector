package store

import "testing"

func TestNormalizeHostIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{name: "IPv4", input: "5.227.161.181", want: "5.227.161.181", ok: true},
		{name: "Postgres IPv4 text", input: "5.227.161.181/32", want: "5.227.161.181", ok: true},
		{name: "IPv6", input: "2001:db8::1", want: "2001:db8::1", ok: true},
		{name: "Postgres IPv6 text", input: "2001:db8::1/128", want: "2001:db8::1", ok: true},
		{name: "Subnet is not a device", input: "5.227.161.0/24", ok: false},
		{name: "Invalid", input: "not-an-ip", ok: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := normalizeHostIP(test.input)
			if got != test.want || ok != test.ok {
				t.Fatalf("normalizeHostIP(%q) = (%q, %v), want (%q, %v)",
					test.input, got, ok, test.want, test.ok)
			}
		})
	}
}
