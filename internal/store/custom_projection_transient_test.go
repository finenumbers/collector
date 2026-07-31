package store

import (
	"strings"
	"testing"
)

func TestIsTransientProjectionLastError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  string
		want bool
	}{
		{name: "empty", err: "", want: false},
		{name: "unrelated parse", err: "invalid radius packet layout", want: false},
		{name: "event overflow", err: "bucket exceeds 50000 events", want: true},
		{name: "memory bound", err: "projection memory bound exceeded", want: true},
		{name: "ch memory", err: "code: 241, message: Query memory limit exceeded", want: true},
		{name: "cancelled", err: "Query was cancelled", want: true},
		{name: "timeout", err: "timeout exceeded while reading", want: true},
		{name: "deadline", err: "context deadline exceeded", want: true},
		{
			name: "connection refused",
			err:  "dial tcp 172.22.0.6:9000: connect: connection refused",
			want: true,
		},
		{name: "connection reset", err: "read: connection reset by peer", want: true},
		{name: "broken pipe", err: "write: broken pipe", want: true},
		{name: "io timeout", err: "i/o timeout", want: true},
		{name: "no such host", err: "lookup clickhouse: no such host", want: true},
		{name: "unreachable", err: "network is unreachable", want: true},
		{name: "dial tcp only", err: "dial tcp 10.0.0.1:9000: i/o timeout", want: true},
		{name: "ch unavailable", err: "clickhouse unavailable: pool empty", want: true},
		{name: "code 210", err: "code: 210. DB::NetException", want: true},
		{name: "code 209", err: "code: 209. Timeout exceeded", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsTransientProjectionLastError(tc.err); got != tc.want {
				t.Fatalf("IsTransientProjectionLastError(%q)=%v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestTransientProjectionFailureSQLCoversNetworkFragments(t *testing.T) {
	t.Parallel()
	lower := strings.ToLower(transientProjectionFailureSQL)
	for _, fragment := range []string{
		"connection refused",
		"connection reset",
		"broken pipe",
		"i/o timeout",
		"no such host",
		"network is unreachable",
		"dial tcp",
		"clickhouse%unavailable",
		"code: 210",
		"code: 209",
	} {
		if !strings.Contains(lower, strings.ToLower(fragment)) {
			t.Fatalf("transientProjectionFailureSQL missing %q", fragment)
		}
	}
}
