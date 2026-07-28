package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Role                           string
	Environment                    string
	HTTPAddr                       string
	SyslogAddr                     string
	IngressSpoolPath               string
	SyslogSpoolPath                string
	HandoffSocketPath              string
	IngressControlPath             string
	IngressStatusPath              string
	IngressHealthAddr              string
	PostgresURL                    string
	ClickHouseAddr                 string
	ClickHouseDB                   string
	ClickHouseUser                 string
	ClickHousePass                 string
	NATSURL                        string
	MinIOEndpoint                  string
	MinIOAccessKey                 string
	MinIOSecretKey                 string
	MinIOUseTLS                    bool
	RawBucket                      string
	SFTPGoURL                      string
	SFTPGoAdmin                    string
	SFTPGoPassword                 string
	SessionTTL                     time.Duration
	SecureCookies                  bool
	TrustedProxyCount              int
	CustomProjectionEnabled        bool
	CustomProjectionBatchSize      int
	CustomProjectionMaxEvents      int
	CustomProjectionThreads        int
	CustomProjectionMaxMemoryBytes int64
	CustomProjectionSleep          time.Duration
	CustomProjectionLease          time.Duration
	CustomProjectionLookback       time.Duration
	CustomResponseTimeout          time.Duration
	CustomPairingHorizon           time.Duration
	CustomRetryHorizon             time.Duration
	CustomAssemblyIdle             time.Duration
	CoverageExpectedGrace          time.Duration
	CoverageLateThreshold          time.Duration
	CoverageMissingTerminal        time.Duration
	CoverageRetryHorizon           time.Duration
	CoverageWorkerSleep            time.Duration
	VoipmonitorEnabled             bool
	VoipmonitorAPIURL              string
	VoipmonitorUser                string
	VoipmonitorPassword            string
	VoipmonitorGUIURL              string
	VoipmonitorCardURLTemplate     string
	VoipmonitorTimeSkew            time.Duration
	VoipmonitorWorkerSleep         time.Duration
	VoipmonitorLease               time.Duration
	VoipmonitorMinScore            int
	VoipmonitorRateLimitPerSec     int
	ClickHouseAdmissionCapacity    int
	ExportPageSize                 int
}

func Load() (Config, error) {
	cfg := Config{
		Role:                           env("COLLECTOR_ROLE", "app"),
		Environment:                    env("ENVIRONMENT", "development"),
		HTTPAddr:                       env("HTTP_ADDR", ":8080"),
		SyslogAddr:                     env("SYSLOG_ADDR", ":1514"),
		IngressSpoolPath:               env("INGRESS_SPOOL_PATH", "/data/spool/ingress.db"),
		SyslogSpoolPath:                env("SYSLOG_SPOOL_PATH", "/data/spool/syslog.db"),
		HandoffSocketPath:              env("HANDOFF_SOCKET_PATH", "/data/spool/handoff.sock"),
		IngressControlPath:             env("INGRESS_CONTROL_PATH", "/data/spool/ingress-control.sock"),
		IngressStatusPath:              env("INGRESS_STATUS_PATH", "/data/spool/ingress-status.json"),
		IngressHealthAddr:              env("INGRESS_HEALTH_ADDR", "127.0.0.1:18081"),
		PostgresURL:                    env("DATABASE_URL", "postgres://collector:collector@postgres:5432/collector?sslmode=disable"),
		ClickHouseAddr:                 env("CLICKHOUSE_ADDR", "clickhouse:9000"),
		ClickHouseDB:                   env("CLICKHOUSE_DATABASE", "collector"),
		ClickHouseUser:                 env("CLICKHOUSE_USER", "collector"),
		ClickHousePass:                 env("CLICKHOUSE_PASSWORD", "collector"),
		NATSURL:                        env("NATS_URL", "nats://nats:4222"),
		MinIOEndpoint:                  env("MINIO_ENDPOINT", "minio:9000"),
		MinIOAccessKey:                 env("MINIO_ACCESS_KEY", "collector"),
		MinIOSecretKey:                 env("MINIO_SECRET_KEY", "collector-change-me"),
		MinIOUseTLS:                    envBool("MINIO_USE_TLS", false),
		RawBucket:                      env("RAW_BUCKET", "collector-raw"),
		SFTPGoURL:                      env("SFTPGO_URL", "http://sftpgo:8080"),
		SFTPGoAdmin:                    env("SFTPGO_ADMIN", "collector"),
		SFTPGoPassword:                 env("SFTPGO_ADMIN_PASSWORD", "collector-change-me"),
		SessionTTL:                     12 * time.Hour,
		SecureCookies:                  envBool("SECURE_COOKIES", false),
		TrustedProxyCount:              envInt("TRUSTED_PROXY_COUNT", 1),
		CustomProjectionEnabled:        envBool("CUSTOM_PROJECTION_ENABLED", false),
		CustomProjectionBatchSize:      envInt("CUSTOM_PROJECTION_BATCH_SIZE", 64),
		CustomProjectionMaxEvents:      envInt("CUSTOM_PROJECTION_MAX_EVENTS", 5_000),
		CustomProjectionThreads:        envInt("CUSTOM_PROJECTION_THREADS", 1),
		CustomProjectionMaxMemoryBytes: envInt64("CUSTOM_PROJECTION_MAX_MEMORY_BYTES", 64<<20),
		CustomProjectionSleep:          envDuration("CUSTOM_PROJECTION_SLEEP", 3*time.Second),
		CustomProjectionLease:          envDuration("CUSTOM_PROJECTION_LEASE", 2*time.Minute),
		CustomProjectionLookback:       envDuration("CUSTOM_PROJECTION_LOOKBACK", 24*time.Hour),
		CustomResponseTimeout:          envDuration("CUSTOM_RESPONSE_TIMEOUT", 5*time.Second),
		CustomPairingHorizon:           envDuration("CUSTOM_PAIRING_HORIZON", 5*time.Minute),
		CustomRetryHorizon:             envDuration("CUSTOM_RETRY_HORIZON", 7*24*time.Hour),
		CustomAssemblyIdle:             envDuration("CUSTOM_ASSEMBLY_IDLE", 2*time.Second),
		CoverageExpectedGrace:          envDuration("CDR_COVERAGE_EXPECTED_GRACE", 5*time.Minute),
		CoverageLateThreshold:          envDuration("CDR_COVERAGE_LATE_THRESHOLD", 5*time.Minute),
		CoverageMissingTerminal:        envDuration("CDR_COVERAGE_MISSING_TERMINAL", 30*time.Minute),
		CoverageRetryHorizon:           envDuration("CDR_COVERAGE_RETRY_HORIZON", 7*24*time.Hour),
		CoverageWorkerSleep:            envDuration("CDR_COVERAGE_WORKER_SLEEP", 5*time.Second),
		VoipmonitorEnabled:             envBool("VOIPMONITOR_ENABLED", false),
		VoipmonitorAPIURL:              env("VOIPMONITOR_API_URL", ""),
		VoipmonitorUser:                env("VOIPMONITOR_USER", ""),
		VoipmonitorPassword:            env("VOIPMONITOR_PASSWORD", ""),
		VoipmonitorGUIURL:              env("VOIPMONITOR_GUI_URL", ""),
		VoipmonitorCardURLTemplate: env("VOIPMONITOR_CARD_URL_TEMPLATE", ""),
		VoipmonitorTimeSkew:        envDuration("VOIPMONITOR_TIME_SKEW", 5*time.Second),
		VoipmonitorWorkerSleep:     envDuration("VOIPMONITOR_WORKER_SLEEP", 5*time.Second),
		VoipmonitorLease:           envDuration("VOIPMONITOR_LEASE", 2*time.Minute),
		VoipmonitorMinScore:        envInt("VOIPMONITOR_MIN_SCORE", 60),
		VoipmonitorRateLimitPerSec: envInt("VOIPMONITOR_RATE_LIMIT_PER_SEC", 5),
		ClickHouseAdmissionCapacity: envInt("CLICKHOUSE_ADMISSION_CAPACITY", 8),
		ExportPageSize:              envInt("EXPORT_PAGE_SIZE", 1000),
	}
	switch cfg.Role {
	case "app", "ingress", "api-ingest", "export", "maintenance":
	default:
		return Config{}, fmt.Errorf(
			"COLLECTOR_ROLE must be app, ingress, api-ingest, export, or maintenance",
		)
	}
	if cfg.Role != "ingress" && cfg.PostgresURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.ClickHouseAdmissionCapacity < 4 || cfg.ClickHouseAdmissionCapacity > 128 {
		return Config{}, fmt.Errorf("CLICKHOUSE_ADMISSION_CAPACITY must be between 4 and 128")
	}
	if cfg.ExportPageSize < 100 || cfg.ExportPageSize > 5000 {
		return Config{}, fmt.Errorf("EXPORT_PAGE_SIZE must be between 100 and 5000")
	}
	if cfg.Environment == "production" && cfg.Role != "ingress" {
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

func envInt64(key string, fallback int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
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
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
