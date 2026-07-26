package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Role                    string
	Environment             string
	HTTPAddr                string
	SyslogAddr              string
	IngressSpoolPath        string
	SyslogSpoolPath         string
	HandoffSocketPath       string
	IngressControlPath      string
	IngressStatusPath       string
	IngressHealthAddr       string
	PostgresURL             string
	ClickHouseAddr          string
	ClickHouseDB            string
	ClickHouseUser          string
	ClickHousePass          string
	NATSURL                 string
	MinIOEndpoint           string
	MinIOAccessKey          string
	MinIOSecretKey          string
	MinIOUseTLS             bool
	RawBucket               string
	SFTPGoURL               string
	SFTPGoAdmin             string
	SFTPGoPassword          string
	SessionTTL              time.Duration
	SecureCookies           bool
	TrustedProxyCount       int
	SyslogConstructsEnabled bool
	SyslogReplayPaused      bool
	SyslogReplayBatchSize   int
	SyslogReplaySleep       time.Duration
	SyslogReplayMaxThreads  int
	SyslogReplayMaxMemory   uint64
}

func Load() (Config, error) {
	cfg := Config{
		Role:                    env("COLLECTOR_ROLE", "app"),
		Environment:             env("ENVIRONMENT", "development"),
		HTTPAddr:                env("HTTP_ADDR", ":8080"),
		SyslogAddr:              env("SYSLOG_ADDR", ":1514"),
		IngressSpoolPath:        env("INGRESS_SPOOL_PATH", "/data/spool/ingress.db"),
		SyslogSpoolPath:         env("SYSLOG_SPOOL_PATH", "/data/spool/syslog.db"),
		HandoffSocketPath:       env("HANDOFF_SOCKET_PATH", "/data/spool/handoff.sock"),
		IngressControlPath:      env("INGRESS_CONTROL_PATH", "/data/spool/ingress-control.sock"),
		IngressStatusPath:       env("INGRESS_STATUS_PATH", "/data/spool/ingress-status.json"),
		IngressHealthAddr:       env("INGRESS_HEALTH_ADDR", "127.0.0.1:18081"),
		PostgresURL:             env("DATABASE_URL", "postgres://collector:collector@postgres:5432/collector?sslmode=disable"),
		ClickHouseAddr:          env("CLICKHOUSE_ADDR", "clickhouse:9000"),
		ClickHouseDB:            env("CLICKHOUSE_DATABASE", "collector"),
		ClickHouseUser:          env("CLICKHOUSE_USER", "collector"),
		ClickHousePass:          env("CLICKHOUSE_PASSWORD", "collector"),
		NATSURL:                 env("NATS_URL", "nats://nats:4222"),
		MinIOEndpoint:           env("MINIO_ENDPOINT", "minio:9000"),
		MinIOAccessKey:          env("MINIO_ACCESS_KEY", "collector"),
		MinIOSecretKey:          env("MINIO_SECRET_KEY", "collector-change-me"),
		MinIOUseTLS:             envBool("MINIO_USE_TLS", false),
		RawBucket:               env("RAW_BUCKET", "collector-raw"),
		SFTPGoURL:               env("SFTPGO_URL", "http://sftpgo:8080"),
		SFTPGoAdmin:             env("SFTPGO_ADMIN", "collector"),
		SFTPGoPassword:          env("SFTPGO_ADMIN_PASSWORD", "collector-change-me"),
		SessionTTL:              12 * time.Hour,
		SecureCookies:           envBool("SECURE_COOKIES", false),
		TrustedProxyCount:       envInt("TRUSTED_PROXY_COUNT", 1),
		SyslogConstructsEnabled: envBool("SYSLOG_CONSTRUCTS_ENABLED", false),
		SyslogReplayPaused:      envBool("SYSLOG_REPLAY_PAUSED", false),
		SyslogReplayBatchSize:   envInt("SYSLOG_REPLAY_BATCH_SIZE", 500),
		SyslogReplaySleep:       envDuration("SYSLOG_REPLAY_SLEEP", 250*time.Millisecond),
		SyslogReplayMaxThreads:  envInt("SYSLOG_REPLAY_MAX_THREADS", 2),
		SyslogReplayMaxMemory:   envUint64("SYSLOG_REPLAY_MAX_MEMORY_BYTES", 512<<20),
	}
	if cfg.Role != "app" && cfg.Role != "ingress" {
		return Config{}, fmt.Errorf("COLLECTOR_ROLE must be app or ingress")
	}
	if cfg.Role == "app" && cfg.PostgresURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.SyslogReplayBatchSize <= 0 || cfg.SyslogReplayMaxThreads <= 0 ||
		cfg.SyslogReplayMaxMemory == 0 || cfg.SyslogReplaySleep <= 0 {
		return Config{}, fmt.Errorf("Syslog replay limits must be positive")
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

func envUint64(key string, fallback uint64) uint64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
