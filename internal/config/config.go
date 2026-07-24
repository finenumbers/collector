package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Role              string
	Environment       string
	HTTPAddr          string
	SyslogAddr        string
	IngressSpoolPath  string
	SyslogSpoolPath   string
	HandoffSocketPath string
	IngressStatusPath string
	IngressHealthAddr string
	PostgresURL       string
	ClickHouseAddr    string
	ClickHouseDB      string
	ClickHouseUser    string
	ClickHousePass    string
	NATSURL           string
	MinIOEndpoint     string
	MinIOAccessKey    string
	MinIOSecretKey    string
	MinIOUseTLS       bool
	RawBucket         string
	SFTPGoURL         string
	SFTPGoAdmin       string
	SFTPGoPassword    string
	SessionTTL        time.Duration
	SecureCookies     bool
	TrustedProxyCount int
}

func Load() (Config, error) {
	cfg := Config{
		Role:              env("COLLECTOR_ROLE", "app"),
		Environment:       env("ENVIRONMENT", "development"),
		HTTPAddr:          env("HTTP_ADDR", ":8080"),
		SyslogAddr:        env("SYSLOG_ADDR", ":1514"),
		IngressSpoolPath:  env("INGRESS_SPOOL_PATH", "/data/spool/ingress.db"),
		SyslogSpoolPath:   env("SYSLOG_SPOOL_PATH", "/data/spool/syslog.db"),
		HandoffSocketPath: env("HANDOFF_SOCKET_PATH", "/data/spool/handoff.sock"),
		IngressStatusPath: env("INGRESS_STATUS_PATH", "/data/spool/ingress-status.json"),
		IngressHealthAddr: env("INGRESS_HEALTH_ADDR", "127.0.0.1:18081"),
		PostgresURL:       env("DATABASE_URL", "postgres://collector:collector@postgres:5432/collector?sslmode=disable"),
		ClickHouseAddr:    env("CLICKHOUSE_ADDR", "clickhouse:9000"),
		ClickHouseDB:      env("CLICKHOUSE_DATABASE", "collector"),
		ClickHouseUser:    env("CLICKHOUSE_USER", "collector"),
		ClickHousePass:    env("CLICKHOUSE_PASSWORD", "collector"),
		NATSURL:           env("NATS_URL", "nats://nats:4222"),
		MinIOEndpoint:     env("MINIO_ENDPOINT", "minio:9000"),
		MinIOAccessKey:    env("MINIO_ACCESS_KEY", "collector"),
		MinIOSecretKey:    env("MINIO_SECRET_KEY", "collector-change-me"),
		RawBucket:         env("RAW_BUCKET", "collector-raw"),
		SFTPGoURL:         env("SFTPGO_URL", "http://sftpgo:8080"),
		SFTPGoAdmin:       env("SFTPGO_ADMIN", "collector"),
		SFTPGoPassword:    env("SFTPGO_ADMIN_PASSWORD", "collector-change-me"),
		SessionTTL:        12 * time.Hour,
		SecureCookies:     envBool("SECURE_COOKIES", false),
		TrustedProxyCount: envInt("TRUSTED_PROXY_COUNT", 1),
	}
	if cfg.Role != "app" && cfg.Role != "ingress" {
		return Config{}, fmt.Errorf("COLLECTOR_ROLE must be app or ingress")
	}
	if cfg.Role == "app" && cfg.PostgresURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.Environment == "production" && cfg.Role == "app" {
		if cfg.ClickHousePass == "collector" || cfg.MinIOSecretKey == "collector-change-me" ||
			cfg.SFTPGoPassword == "collector-change-me" || !cfg.SecureCookies {
			return Config{}, fmt.Errorf("production requires non-default service secrets and secure cookies")
		}
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
