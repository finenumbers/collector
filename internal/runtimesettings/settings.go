package runtimesettings

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Document is the admin-editable runtime configuration formerly kept only in .env.
type Document struct {
	Projection    ProjectionSettings     `json:"projection"`
	Coverage      CoverageSettings       `json:"coverage"`
	Voipmonitor   VoipmonitorSettings    `json:"voipmonitor"`
	Enrichment    EnrichmentSettings     `json:"enrichment"`
	Platform      PlatformSettings       `json:"platform"`
	Containers    ContainersSettings     `json:"containers"`
	SyslogArchive SyslogArchiveSettings  `json:"syslogArchive"`
}

type SyslogArchiveSettings struct {
	Enabled          bool   `json:"enabled"`
	FTPHost          string `json:"ftpHost"`
	FTPPort          int    `json:"ftpPort"`
	FTPUser          string `json:"ftpUser"`
	FTPPassword      string `json:"ftpPassword,omitempty"`
	PasswordSet      bool   `json:"passwordSet,omitempty"`
	FTPTLS           bool   `json:"ftpTls"`
	LocalSpoolDir    string `json:"localSpoolDir"`
	CloseDelay       string `json:"closeDelay"`
	LookbackHours    int    `json:"lookbackHours"`
	MaxArchiveBytes  int64  `json:"maxArchiveBytes"`
	SpoolBudgetBytes int64  `json:"spoolBudgetBytes"`
}

type EnrichmentSettings struct {
	PSTN    LookupAPISettings         `json:"pstn"`
	GeoIP   LookupAPISettings         `json:"geoip"`
	Workers int                       `json:"workers"`
	CatchUp EnrichmentCatchUpSettings `json:"catchUp"`
}

type LookupAPISettings struct {
	Enabled  bool   `json:"enabled"`
	APIURL   string `json:"apiUrl"`
	Token    string `json:"token,omitempty"`
	TokenSet bool   `json:"tokenSet,omitempty"`
}

type EnrichmentCatchUpSettings struct {
	Enabled  bool   `json:"enabled"`
	PageSize int    `json:"pageSize"`
	Sleep    string `json:"sleep"`
}

type ProjectionSettings struct {
	Enabled         bool   `json:"enabled"`
	Lookback        string `json:"lookback"`
	BatchSize       int    `json:"batchSize"`
	MaxEvents       int    `json:"maxEvents"`
	Threads         int    `json:"threads"`
	MaxMemoryBytes  int64  `json:"maxMemoryBytes"`
	Sleep           string `json:"sleep"`
	Lease           string `json:"lease"`
	ResponseTimeout string `json:"responseTimeout"`
	PairingHorizon  string `json:"pairingHorizon"`
	RetryHorizon    string `json:"retryHorizon"`
	AssemblyIdle    string `json:"assemblyIdle"`
}

type CoverageSettings struct {
	ExpectedGrace   string `json:"expectedGrace"`
	LateThreshold   string `json:"lateThreshold"`
	MissingTerminal string `json:"missingTerminal"`
	RetryHorizon    string `json:"retryHorizon"`
	WorkerSleep     string `json:"workerSleep"`
}

type VoipmonitorSettings struct {
	Enabled            bool   `json:"enabled"`
	APIURL             string `json:"apiUrl"`
	User               string `json:"user"`
	Password           string `json:"password,omitempty"`
	PasswordSet        bool   `json:"passwordSet,omitempty"`
	GUIURL             string `json:"guiUrl"`
	CardURLTemplate    string `json:"cardUrlTemplate"`
	CallIDWindow       string `json:"callIdWindow"`
	FallbackWindow     string `json:"fallbackWindow"`
	FallbackWindowMax  string `json:"fallbackWindowMax"`
	WorkerSleep        string `json:"workerSleep"`
	Lease              string `json:"lease"`
	MinScore           int    `json:"minScore"`
	DisambiguityMargin int    `json:"disambiguityMargin"`
	NumberSuffixLen    int    `json:"numberSuffixLen"`
	RateLimitPerSec    int    `json:"rateLimitPerSec"`
	UseShareURL        bool   `json:"useShareUrl"`
}

type PlatformSettings struct {
	ClickHouseAdmissionCapacity int `json:"clickhouseAdmissionCapacity"`
	ExportPageSize              int `json:"exportPageSize"`
}

// Defaults are production-sensible values for SMG fleets (including dense AF hours).
func Defaults() Document {
	return Document{
		Projection: ProjectionSettings{
			Enabled:         true,
			Lookback:        "24h",
			BatchSize:       128,
			MaxEvents:       50_000,
			Threads:         2,
			MaxMemoryBytes:  1024 << 20,
			Sleep:           "1s",
			Lease:           "2m",
			ResponseTimeout: "5s",
			PairingHorizon:  "5m",
			RetryHorizon:    "168h",
			AssemblyIdle:    "2s",
		},
		Coverage: CoverageSettings{
			ExpectedGrace:   "5m",
			LateThreshold:   "10m",
			MissingTerminal: "30m",
			RetryHorizon:    "168h",
			WorkerSleep:     "5s",
		},
		Voipmonitor: VoipmonitorSettings{
			Enabled:            false,
			CallIDWindow:       "30m",
			FallbackWindow:     "2m",
			FallbackWindowMax:  "10m",
			WorkerSleep:        "5s",
			Lease:              "2m",
			MinScore:           60,
			DisambiguityMargin: 8,
			NumberSuffixLen:    10,
			RateLimitPerSec:    5,
			UseShareURL:        false,
		},
		Enrichment: EnrichmentSettings{
			PSTN: LookupAPISettings{
				Enabled: true,
				APIURL:  "https://pstn.finenumbers.com/api/v1/lookup",
			},
			GeoIP: LookupAPISettings{
				Enabled: true,
				APIURL:  "https://geoip.finenumbers.com/api/v1/lookup",
			},
			Workers: 24,
			CatchUp: EnrichmentCatchUpSettings{
				Enabled:  true,
				PageSize: 1000,
				Sleep:    "2s",
			},
		},
		Platform: PlatformSettings{
			ClickHouseAdmissionCapacity: 8,
			ExportPageSize:              1000,
		},
		Containers: defaultContainers(),
		SyslogArchive: SyslogArchiveSettings{
			Enabled:          false,
			FTPPort:          21,
			LocalSpoolDir:    "/data/spool/syslog-archive",
			CloseDelay:       "2m",
			LookbackHours:    48,
			MaxArchiveBytes:  2 << 30,
			SpoolBudgetBytes: 50 << 30,
		},
	}
}

func (d Document) Clone() Document {
	raw, _ := json.Marshal(d)
	var out Document
	_ = json.Unmarshal(raw, &out)
	return out
}

func (d Document) PublicView() Document {
	view := d.Clone()
	view.Voipmonitor.PasswordSet = view.Voipmonitor.Password != ""
	view.Voipmonitor.Password = ""
	view.Enrichment.PSTN.TokenSet = view.Enrichment.PSTN.Token != ""
	view.Enrichment.PSTN.Token = ""
	view.Enrichment.GeoIP.TokenSet = view.Enrichment.GeoIP.Token != ""
	view.Enrichment.GeoIP.Token = ""
	view.SyslogArchive.PasswordSet = view.SyslogArchive.FTPPassword != ""
	view.SyslogArchive.FTPPassword = ""
	return view
}

func (d Document) Validate() error {
	if err := requireDuration("projection.lookback", d.Projection.Lookback, time.Hour, 30*24*time.Hour); err != nil {
		return err
	}
	if d.Projection.BatchSize < 8 || d.Projection.BatchSize > 10_000 {
		return fmt.Errorf("projection.batchSize must be between 8 and 10000")
	}
	if d.Projection.MaxEvents < 1000 || d.Projection.MaxEvents > 200_000 {
		return fmt.Errorf("projection.maxEvents must be between 1000 and 200000")
	}
	if d.Projection.Threads < 1 || d.Projection.Threads > 16 {
		return fmt.Errorf("projection.threads must be between 1 and 16")
	}
	if d.Projection.MaxMemoryBytes < 16<<20 || d.Projection.MaxMemoryBytes > 2<<30 {
		return fmt.Errorf("projection.maxMemoryBytes must be between 16MiB and 2GiB")
	}
	for _, item := range []struct {
		name string
		raw  string
		min  time.Duration
		max  time.Duration
	}{
		{"projection.sleep", d.Projection.Sleep, 200 * time.Millisecond, time.Minute},
		{"projection.lease", d.Projection.Lease, 30 * time.Second, 30 * time.Minute},
		{"projection.responseTimeout", d.Projection.ResponseTimeout, time.Second, 5 * time.Minute},
		{"projection.pairingHorizon", d.Projection.PairingHorizon, time.Minute, time.Hour},
		{"projection.retryHorizon", d.Projection.RetryHorizon, time.Hour, 30 * 24 * time.Hour},
		{"projection.assemblyIdle", d.Projection.AssemblyIdle, time.Second, time.Hour},
		{"coverage.expectedGrace", d.Coverage.ExpectedGrace, time.Minute, 24 * time.Hour},
		{"coverage.lateThreshold", d.Coverage.LateThreshold, time.Minute, 24 * time.Hour},
		{"coverage.missingTerminal", d.Coverage.MissingTerminal, time.Minute, 7 * 24 * time.Hour},
		{"coverage.retryHorizon", d.Coverage.RetryHorizon, time.Hour, 30 * 24 * time.Hour},
		{"coverage.workerSleep", d.Coverage.WorkerSleep, 200 * time.Millisecond, time.Minute},
		{"voipmonitor.callIdWindow", d.Voipmonitor.CallIDWindow, time.Minute, 6 * time.Hour},
		{"voipmonitor.fallbackWindow", d.Voipmonitor.FallbackWindow, time.Second, time.Hour},
		{"voipmonitor.fallbackWindowMax", d.Voipmonitor.FallbackWindowMax, time.Second, 6 * time.Hour},
		{"voipmonitor.workerSleep", d.Voipmonitor.WorkerSleep, 200 * time.Millisecond, time.Minute},
		{"voipmonitor.lease", d.Voipmonitor.Lease, 30 * time.Second, 30 * time.Minute},
	} {
		if err := requireDuration(item.name, item.raw, item.min, item.max); err != nil {
			return err
		}
	}
	fallback, _ := time.ParseDuration(d.Voipmonitor.FallbackWindow)
	fallbackMax, _ := time.ParseDuration(d.Voipmonitor.FallbackWindowMax)
	if fallbackMax < fallback {
		return fmt.Errorf("voipmonitor.fallbackWindowMax must be >= fallbackWindow")
	}
	if d.Voipmonitor.MinScore < 0 || d.Voipmonitor.MinScore > 100 {
		return fmt.Errorf("voipmonitor.minScore must be between 0 and 100")
	}
	if d.Voipmonitor.DisambiguityMargin < 0 || d.Voipmonitor.DisambiguityMargin > 50 {
		return fmt.Errorf("voipmonitor.disambiguityMargin must be between 0 and 50")
	}
	if d.Voipmonitor.NumberSuffixLen < 4 || d.Voipmonitor.NumberSuffixLen > 20 {
		return fmt.Errorf("voipmonitor.numberSuffixLen must be between 4 and 20")
	}
	if d.Voipmonitor.RateLimitPerSec < 1 || d.Voipmonitor.RateLimitPerSec > 100 {
		return fmt.Errorf("voipmonitor.rateLimitPerSec must be between 1 and 100")
	}
	if d.Voipmonitor.Enabled && d.Voipmonitor.APIURL == "" {
		return fmt.Errorf("voipmonitor.apiUrl is required when voipmonitor.enabled=true")
	}
	if d.Enrichment.PSTN.Enabled && strings.TrimSpace(d.Enrichment.PSTN.APIURL) == "" {
		return fmt.Errorf("enrichment.pstn.apiUrl is required when enrichment.pstn.enabled=true")
	}
	if d.Enrichment.GeoIP.Enabled && strings.TrimSpace(d.Enrichment.GeoIP.APIURL) == "" {
		return fmt.Errorf("enrichment.geoip.apiUrl is required when enrichment.geoip.enabled=true")
	}
	if d.Enrichment.Workers < 1 || d.Enrichment.Workers > 64 {
		return fmt.Errorf("enrichment.workers must be between 1 and 64")
	}
	if d.Enrichment.CatchUp.PageSize < 100 || d.Enrichment.CatchUp.PageSize > 5000 {
		return fmt.Errorf("enrichment.catchUp.pageSize must be between 100 and 5000")
	}
	if err := requireDuration("enrichment.catchUp.sleep", d.Enrichment.CatchUp.Sleep, time.Second, time.Hour); err != nil {
		return err
	}
	if d.Platform.ClickHouseAdmissionCapacity < 4 || d.Platform.ClickHouseAdmissionCapacity > 128 {
		return fmt.Errorf("platform.clickhouseAdmissionCapacity must be between 4 and 128")
	}
	if d.Platform.ExportPageSize < 100 || d.Platform.ExportPageSize > 5000 {
		return fmt.Errorf("platform.exportPageSize must be between 100 and 5000")
	}
	if err := d.Containers.Validate(); err != nil {
		return err
	}
	if err := requireDuration("syslogArchive.closeDelay", d.SyslogArchive.CloseDelay, time.Second, time.Hour); err != nil {
		return err
	}
	if d.SyslogArchive.FTPPort < 1 || d.SyslogArchive.FTPPort > 65535 {
		return fmt.Errorf("syslogArchive.ftpPort must be between 1 and 65535")
	}
	if d.SyslogArchive.LookbackHours < 1 || d.SyslogArchive.LookbackHours > 720 {
		return fmt.Errorf("syslogArchive.lookbackHours must be between 1 and 720")
	}
	if d.SyslogArchive.MaxArchiveBytes < 1<<20 || d.SyslogArchive.MaxArchiveBytes > 8<<30 {
		return fmt.Errorf("syslogArchive.maxArchiveBytes must be between 1MiB and 8GiB")
	}
	if d.SyslogArchive.SpoolBudgetBytes < 100<<20 || d.SyslogArchive.SpoolBudgetBytes > 500<<30 {
		return fmt.Errorf("syslogArchive.spoolBudgetBytes must be between 100MiB and 500GiB")
	}
	if strings.TrimSpace(d.SyslogArchive.LocalSpoolDir) == "" {
		return fmt.Errorf("syslogArchive.localSpoolDir is required")
	}
	if d.SyslogArchive.Enabled && strings.TrimSpace(d.SyslogArchive.FTPHost) == "" {
		return fmt.Errorf("syslogArchive.ftpHost is required when syslogArchive.enabled=true")
	}
	if d.SyslogArchive.Enabled && strings.TrimSpace(d.SyslogArchive.FTPUser) == "" {
		return fmt.Errorf("syslogArchive.ftpUser is required when syslogArchive.enabled=true")
	}
	return nil
}

func requireDuration(name, raw string, min, max time.Duration) error {
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("%s: invalid duration %q", name, raw)
	}
	if value < min || value > max {
		return fmt.Errorf("%s must be between %s and %s", name, min, max)
	}
	return nil
}

func MustDuration(raw string) time.Duration {
	value, err := time.ParseDuration(raw)
	if err != nil {
		panic(err)
	}
	return value
}

// MergePatch overlays non-zero / provided JSON fields from patch onto base.
// Password/tokens: empty string in patch keeps base secret; explicit clear unsupported.
func MergePatch(base Document, patch json.RawMessage) (Document, error) {
	out := base.Clone()
	if len(patch) == 0 || string(patch) == "null" {
		return out, nil
	}
	keptPassword := out.Voipmonitor.Password
	keptPSTN := out.Enrichment.PSTN.Token
	keptGeoIP := out.Enrichment.GeoIP.Token
	keptArchivePassword := out.SyslogArchive.FTPPassword
	if err := json.Unmarshal(patch, &out); err != nil {
		return Document{}, fmt.Errorf("invalid settings payload: %w", err)
	}
	var peek struct {
		Voipmonitor struct {
			Password *string `json:"password"`
		} `json:"voipmonitor"`
		Enrichment struct {
			PSTN  struct{ Token *string `json:"token"` } `json:"pstn"`
			GeoIP struct{ Token *string `json:"token"` } `json:"geoip"`
		} `json:"enrichment"`
		SyslogArchive struct {
			FTPPassword *string `json:"ftpPassword"`
		} `json:"syslogArchive"`
	}
	_ = json.Unmarshal(patch, &peek)
	if peek.Voipmonitor.Password == nil || *peek.Voipmonitor.Password == "" {
		out.Voipmonitor.Password = keptPassword
	}
	if peek.Enrichment.PSTN.Token == nil || *peek.Enrichment.PSTN.Token == "" {
		out.Enrichment.PSTN.Token = keptPSTN
	}
	if peek.Enrichment.GeoIP.Token == nil || *peek.Enrichment.GeoIP.Token == "" {
		out.Enrichment.GeoIP.Token = keptGeoIP
	}
	if peek.SyslogArchive.FTPPassword == nil || *peek.SyslogArchive.FTPPassword == "" {
		out.SyslogArchive.FTPPassword = keptArchivePassword
	}
	out.Voipmonitor.PasswordSet = false
	out.Enrichment.PSTN.TokenSet = false
	out.Enrichment.GeoIP.TokenSet = false
	out.SyslogArchive.PasswordSet = false
	// Fill zero enrichment fields from defaults when upgrading old documents.
	defaults := Defaults().Enrichment
	if out.Enrichment.PSTN.APIURL == "" {
		out.Enrichment.PSTN.APIURL = defaults.PSTN.APIURL
	}
	if out.Enrichment.GeoIP.APIURL == "" {
		out.Enrichment.GeoIP.APIURL = defaults.GeoIP.APIURL
	}
	if out.Enrichment.Workers == 0 {
		out.Enrichment.Workers = defaults.Workers
	}
	if out.Enrichment.CatchUp.PageSize == 0 {
		out.Enrichment.CatchUp.PageSize = defaults.CatchUp.PageSize
	}
	if out.Enrichment.CatchUp.Sleep == "" {
		out.Enrichment.CatchUp.Sleep = defaults.CatchUp.Sleep
	}
	NormalizeSyslogArchive(&out)
	return out, nil
}

// NormalizeSyslogArchive fills missing archive defaults for documents seeded
// before this section existed.
func NormalizeSyslogArchive(doc *Document) {
	if doc == nil {
		return
	}
	defaults := Defaults().SyslogArchive
	if doc.SyslogArchive.FTPPort == 0 {
		doc.SyslogArchive.FTPPort = defaults.FTPPort
	}
	if doc.SyslogArchive.LocalSpoolDir == "" {
		doc.SyslogArchive.LocalSpoolDir = defaults.LocalSpoolDir
	}
	if doc.SyslogArchive.CloseDelay == "" {
		doc.SyslogArchive.CloseDelay = defaults.CloseDelay
	}
	if doc.SyslogArchive.LookbackHours == 0 {
		doc.SyslogArchive.LookbackHours = defaults.LookbackHours
	}
	if doc.SyslogArchive.MaxArchiveBytes == 0 {
		doc.SyslogArchive.MaxArchiveBytes = defaults.MaxArchiveBytes
	}
	if doc.SyslogArchive.SpoolBudgetBytes == 0 {
		doc.SyslogArchive.SpoolBudgetBytes = defaults.SpoolBudgetBytes
	}
}

func FingerprintWorkers(d Document) string {
	return fmt.Sprintf("p=%t/%d;v=%t/%s/%d",
		d.Projection.Enabled, d.Projection.Threads,
		d.Voipmonitor.Enabled, d.Voipmonitor.APIURL, d.Voipmonitor.RateLimitPerSec,
	)
}
