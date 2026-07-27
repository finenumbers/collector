package config

import "testing"

func TestLegacySyslogWorkerFlagsAreIgnored(t *testing.T) {
	t.Setenv("COLLECTOR_ROLE", "ingress")
	t.Setenv("SYSLOG_CONSTRUCTS_ENABLED", "true")
	t.Setenv("SYSLOG_REPLAY_PAUSED", "true")
	t.Setenv("SYSLOG_REPLAY_BATCH_SIZE", "-1")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}
