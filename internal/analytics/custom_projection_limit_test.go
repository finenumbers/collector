package analytics

import "testing"

func TestClampCustomProjectionLoadLimit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int
		want int
	}{
		{0, 20_000},
		{-1, 20_000},
		{1, 1},
		{50_000, 50_000},
		{150_000, 150_000},
		{200_000, 200_000},
		{200_001, 20_000},
	}
	for _, tc := range cases {
		if got := clampCustomProjectionLoadLimit(tc.in); got != tc.want {
			t.Fatalf("clampCustomProjectionLoadLimit(%d)=%d want %d", tc.in, got, tc.want)
		}
	}
}
