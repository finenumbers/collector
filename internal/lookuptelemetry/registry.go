package lookuptelemetry

import (
	"sync"
	"sync/atomic"
	"time"
)

type Snapshot struct {
	Enabled       bool      `json:"enabled"`
	Configured    bool      `json:"configured"`
	Lookups       uint64    `json:"lookups"`
	CacheHits     uint64    `json:"cacheHits"`
	Errors        uint64    `json:"errors"`
	ErrorRate     float64   `json:"errorRate"`
	P95LatencyMs  int64     `json:"p95LatencyMs"`
	LastError     string    `json:"lastError,omitempty"`
	LastSuccessAt time.Time `json:"lastSuccessAt,omitempty"`
	Healthy       bool      `json:"healthy"`
}

type service struct {
	lookups   atomic.Uint64
	cacheHits atomic.Uint64
	errors    atomic.Uint64
	latencies [64]atomic.Int64
	latIdx    atomic.Uint64
	mu        sync.Mutex
	lastError string
	lastOK    time.Time
	enabled   atomic.Bool
	configured atomic.Bool
}

type Registry struct {
	pstn  service
	geoip service
}

var Default = &Registry{}

func (r *Registry) service(name string) *service {
	switch name {
	case "geoip":
		return &r.geoip
	default:
		return &r.pstn
	}
}

func (r *Registry) SetState(name string, enabled, configured bool) {
	svc := r.service(name)
	svc.enabled.Store(enabled)
	svc.configured.Store(configured)
}

func (r *Registry) RecordCacheHit(name string) {
	svc := r.service(name)
	svc.lookups.Add(1)
	svc.cacheHits.Add(1)
}

func (r *Registry) RecordSuccess(name string, latency time.Duration) {
	svc := r.service(name)
	svc.lookups.Add(1)
	idx := svc.latIdx.Add(1) % 64
	svc.latencies[idx].Store(latency.Milliseconds())
	svc.mu.Lock()
	svc.lastOK = time.Now().UTC()
	svc.lastError = ""
	svc.mu.Unlock()
}

func (r *Registry) RecordError(name string, latency time.Duration, err string) {
	svc := r.service(name)
	svc.lookups.Add(1)
	svc.errors.Add(1)
	idx := svc.latIdx.Add(1) % 64
	svc.latencies[idx].Store(latency.Milliseconds())
	svc.mu.Lock()
	svc.lastError = err
	svc.mu.Unlock()
}

func (r *Registry) Snapshot() map[string]Snapshot {
	return map[string]Snapshot{
		"pstn":  r.pstn.snapshot(),
		"geoip": r.geoip.snapshot(),
	}
}

func (s *service) snapshot() Snapshot {
	lookups := s.lookups.Load()
	errors := s.errors.Load()
	cacheHits := s.cacheHits.Load()
	var rate float64
	if lookups > 0 {
		rate = float64(errors) / float64(lookups)
	}
	s.mu.Lock()
	lastErr := s.lastError
	lastOK := s.lastOK
	s.mu.Unlock()
	enabled := s.enabled.Load()
	configured := s.configured.Load()
	healthy := !enabled || (configured && lastErr == "" && (lookups == 0 || rate < 0.25))
	if enabled && configured && !lastOK.IsZero() && time.Since(lastOK) < 15*time.Minute && lastErr == "" {
		healthy = true
	}
	if enabled && configured && lastErr != "" && time.Since(lastOK) > 15*time.Minute {
		healthy = false
	}
	return Snapshot{
		Enabled: enabled, Configured: configured,
		Lookups: lookups, CacheHits: cacheHits, Errors: errors, ErrorRate: rate,
		P95LatencyMs: s.p95(), LastError: lastErr, LastSuccessAt: lastOK, Healthy: healthy,
	}
}

func (s *service) p95() int64 {
	values := make([]int64, 0, 64)
	for i := range s.latencies {
		if v := s.latencies[i].Load(); v > 0 {
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		return 0
	}
	// simple selection: sort-ish via insertion for tiny N
	for i := 1; i < len(values); i++ {
		j := i
		for j > 0 && values[j-1] > values[j] {
			values[j-1], values[j] = values[j], values[j-1]
			j--
		}
	}
	return values[(len(values)*95)/100]
}
