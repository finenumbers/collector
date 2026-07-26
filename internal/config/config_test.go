package config

import "testing"

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
