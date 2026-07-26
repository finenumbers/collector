package config

import (
	"testing"
	"time"
)

func TestSyslogConstructsDisabledByDefault(t *testing.T) {
	t.Setenv("COLLECTOR_ROLE", "ingress")
	t.Setenv("SYSLOG_CONSTRUCTS_ENABLED", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SyslogConstructsEnabled {
		t.Fatal("Syslog constructs must default to disabled")
	}
}

func TestSyslogConstructsCanBeEnabled(t *testing.T) {
	t.Setenv("COLLECTOR_ROLE", "ingress")
	t.Setenv("SYSLOG_CONSTRUCTS_ENABLED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SyslogConstructsEnabled {
		t.Fatal("Syslog constructs flag was not enabled")
	}
}

func TestSyslogReplayDefaults(t *testing.T) {
	t.Setenv("COLLECTOR_ROLE", "ingress")
	t.Setenv("SYSLOG_REPLAY_PAUSED", "")
	t.Setenv("SYSLOG_REPLAY_BATCH_SIZE", "")
	t.Setenv("SYSLOG_REPLAY_SLEEP", "")
	t.Setenv("SYSLOG_REPLAY_MAX_THREADS", "")
	t.Setenv("SYSLOG_REPLAY_MAX_MEMORY_BYTES", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SyslogReplayPaused || cfg.SyslogReplayBatchSize != 500 ||
		cfg.SyslogReplaySleep != 250*time.Millisecond ||
		cfg.SyslogReplayMaxThreads != 2 || cfg.SyslogReplayMaxMemory != 512<<20 {
		t.Fatalf("unexpected Syslog replay defaults: %#v", cfg)
	}
}

func TestSyslogReplayConfiguration(t *testing.T) {
	t.Setenv("COLLECTOR_ROLE", "ingress")
	t.Setenv("SYSLOG_REPLAY_PAUSED", "true")
	t.Setenv("SYSLOG_REPLAY_BATCH_SIZE", "125")
	t.Setenv("SYSLOG_REPLAY_SLEEP", "2s")
	t.Setenv("SYSLOG_REPLAY_MAX_THREADS", "1")
	t.Setenv("SYSLOG_REPLAY_MAX_MEMORY_BYTES", "1048576")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SyslogReplayPaused || cfg.SyslogReplayBatchSize != 125 ||
		cfg.SyslogReplaySleep != 2*time.Second || cfg.SyslogReplayMaxThreads != 1 ||
		cfg.SyslogReplayMaxMemory != 1<<20 {
		t.Fatalf("unexpected Syslog replay configuration: %#v", cfg)
	}
}
