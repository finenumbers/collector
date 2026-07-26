package store

import (
	"context"
	"strings"
	"testing"

	"collector/internal/equipment"
)

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

func TestCreateDeviceValidatesTemplateBeforeDatabase(t *testing.T) {
	tests := []struct {
		name  string
		input NewDevice
		want  string
	}{
		{
			name: "category mismatch",
			input: NewDevice{
				Name: "source", SourceCategory: equipment.CategoryEquipment,
				TemplateKey: equipment.TemplateSatelRTUCDRV1, Timezone: "UTC",
			},
			want: "does not match",
		},
		{
			name: "raw source rejects syslog",
			input: NewDevice{
				Name: "source", SourceCategory: equipment.CategorySoftswitch,
				TemplateKey: equipment.TemplateSatelRTUCDRV1, Timezone: "UTC",
				SyslogSourceIP: "192.0.2.1",
			},
			want: "does not support",
		},
		{
			name: "raw source requires timezone",
			input: NewDevice{
				Name: "source", SourceCategory: equipment.CategorySoftswitch,
				TemplateKey: equipment.TemplateSatelRTUCDRV1,
			},
			want: "timezone is required",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := (&Store{}).CreateDevice(context.Background(), test.input, User{}, "")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}
