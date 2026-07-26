package analytics

import (
	"testing"
	"time"
)

func TestValidateDashboardWindow(t *testing.T) {
	tests := map[string]time.Duration{
		"":    24 * time.Hour,
		"1h":  time.Hour,
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
	}
	for input, want := range tests {
		got, err := ValidateDashboardWindow(input)
		if err != nil {
			t.Fatalf("ValidateDashboardWindow(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ValidateDashboardWindow(%q) = %v, want %v", input, got, want)
		}
	}
	for _, input := range []string{"0h", "12h", "30d", "garbage"} {
		if _, err := ValidateDashboardWindow(input); err == nil {
			t.Fatalf("ValidateDashboardWindow(%q) accepted an unsupported window", input)
		}
	}
}
