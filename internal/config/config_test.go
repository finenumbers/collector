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

func TestProductionRejectsDefaultPostgresPassword(t *testing.T) {
	t.Setenv("COLLECTOR_ROLE", "app")
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("SECURE_COOKIES", "true")
	t.Setenv("CLICKHOUSE_PASSWORD", "strong-clickhouse-secret")
	t.Setenv("MINIO_SECRET_KEY", "strong-minio-secret-key")
	t.Setenv("SFTPGO_ADMIN_PASSWORD", "strong-sftpgo-secret")
	t.Setenv("DATABASE_URL", "postgres://collector:collector@postgres:5432/collector?sslmode=disable")
	if _, err := Load(); err == nil {
		t.Fatal("default postgres password must be rejected in production")
	}
	t.Setenv("DATABASE_URL", "postgres://collector:strong-pg-secret@postgres:5432/collector?sslmode=disable")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}
