package geoiplookup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"collector/internal/lookuptelemetry"
)

const DefaultURL = "https://geoip.finenumbers.com/api/v1/lookup"
const DefaultCacheTTL = 24 * time.Hour
const DefaultErrorCooldown = 45 * time.Second

type Result struct {
	CountryISO string
	City       string
	ASNOrg     string
}

type Client struct {
	BaseURL       string
	Token         string
	EnabledFlag   bool
	HTTPClient    *http.Client
	CacheTTL      time.Duration
	ErrorCooldown time.Duration
	Telemetry     *lookuptelemetry.Registry

	mu            sync.Mutex
	cache         map[string]cacheEntry
	lastFailureAt time.Time
}

type cacheEntry struct {
	result    Result
	expiresAt time.Time
	failed    bool
}

func New(baseURL, token string, enabled bool) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultURL
	}
	return &Client{
		BaseURL:       strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		Token:         strings.TrimSpace(token),
		EnabledFlag:   enabled,
		HTTPClient:    &http.Client{Timeout: 3 * time.Second},
		CacheTTL:      DefaultCacheTTL,
		ErrorCooldown: DefaultErrorCooldown,
		Telemetry:     lookuptelemetry.Default,
		cache:         make(map[string]cacheEntry),
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.EnabledFlag && c.Token != ""
}

// CoolingDown reports a recent upstream failure (5xx/transport) so catch-up can
// stop busy-looping the same GeoIP-gap page.
func (c *Client) CoolingDown() bool {
	if c == nil {
		return false
	}
	cooldown := c.ErrorCooldown
	if cooldown <= 0 {
		cooldown = DefaultErrorCooldown
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.lastFailureAt.IsZero() && time.Since(c.lastFailureAt) < cooldown
}

// StripHostPort removes :port from host:port or [ipv6]:port.
func StripHostPort(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	// bare IPv6 without brackets/port
	if strings.Count(raw, ":") >= 2 && !strings.Contains(raw, "]") {
		return raw
	}
	// host:port where SplitHostPort failed (missing brackets for ipv6)
	if i := strings.LastIndex(raw, ":"); i > 0 {
		port := raw[i+1:]
		if port != "" && isAllDigits(port) {
			return raw[:i]
		}
	}
	return raw
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func (c *Client) Lookup(ctx context.Context, rawAddr string) (Result, error) {
	if !c.Enabled() {
		return Result{}, nil
	}
	ip := StripHostPort(rawAddr)
	if ip == "" || net.ParseIP(ip) == nil {
		return Result{}, nil
	}
	if result, ok, failed := c.getCached(ip); ok {
		if failed {
			return Result{}, fmt.Errorf("geoip lookup cooling down for %s", ip)
		}
		if c.Telemetry != nil {
			c.Telemetry.RecordCacheHit("geoip")
		}
		return result, nil
	}
	start := time.Now()
	result, err := c.fetch(ctx, ip)
	latency := time.Since(start)
	if err != nil {
		c.rememberFailure(ip, err)
		if c.Telemetry != nil {
			c.Telemetry.RecordError("geoip", latency, err.Error())
		}
		return Result{}, err
	}
	c.putCached(ip, result)
	if c.Telemetry != nil {
		c.Telemetry.RecordSuccess("geoip", latency)
	}
	return result, nil
}

func (c *Client) LookupMany(ctx context.Context, addrs []string, workers int) map[string]Result {
	out := make(map[string]Result)
	if !c.Enabled() || len(addrs) == 0 {
		return out
	}
	if workers < 1 {
		workers = 8
	}
	unique := make([]string, 0, len(addrs))
	seen := make(map[string]struct{})
	for _, raw := range addrs {
		ip := StripHostPort(raw)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		if result, ok, failed := c.getCached(ip); ok {
			if failed {
				continue // omit: do not overwrite existing GeoIP fields with empty
			}
			out[ip] = result
			if c.Telemetry != nil {
				c.Telemetry.RecordCacheHit("geoip")
			}
			continue
		}
		unique = append(unique, ip)
	}
	if len(unique) == 0 {
		return out
	}
	type item struct {
		ip     string
		result Result
		ok     bool
	}
	jobs := make(chan string)
	results := make(chan item, len(unique))
	var wg sync.WaitGroup
	if workers > len(unique) {
		workers = len(unique)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				start := time.Now()
				result, err := c.fetch(ctx, ip)
				latency := time.Since(start)
				if err != nil {
					c.rememberFailure(ip, err)
					if c.Telemetry != nil {
						c.Telemetry.RecordError("geoip", latency, err.Error())
					}
					results <- item{ip: ip, ok: false}
					continue
				}
				c.putCached(ip, result)
				if c.Telemetry != nil {
					c.Telemetry.RecordSuccess("geoip", latency)
				}
				results <- item{ip: ip, result: result, ok: true}
			}
		}()
	}
	go func() {
		for _, ip := range unique {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case jobs <- ip:
			}
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	for item := range results {
		if item.ok {
			out[item.ip] = item.result
		}
	}
	return out
}

func (c *Client) getCached(ip string) (Result, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[ip]
	if !ok || time.Now().After(entry.expiresAt) {
		if ok {
			delete(c.cache, ip)
		}
		return Result{}, false, false
	}
	return entry.result, true, entry.failed
}

func (c *Client) putCached(ip string, result Result) {
	ttl := c.CacheTTL
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ip] = cacheEntry{result: result, expiresAt: time.Now().Add(ttl)}
}

func (c *Client) rememberFailure(ip string, err error) {
	if c == nil || err == nil {
		return
	}
	cooldown := c.ErrorCooldown
	if cooldown <= 0 {
		cooldown = DefaultErrorCooldown
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastFailureAt = time.Now()
	// Negative-cache 5xx/transport briefly so catch-up does not hammer the same IPs.
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "status 5") || strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "connection") || strings.Contains(msg, "502") ||
		strings.Contains(msg, "503") || strings.Contains(msg, "504") {
		c.cache[ip] = cacheEntry{failed: true, expiresAt: time.Now().Add(cooldown)}
	}
}

type apiResponse struct {
	City struct {
		CountryISOCode string `json:"countryIsoCode"`
		CityName       string `json:"cityName"`
	} `json:"city"`
	ASN struct {
		Organization string `json:"organization"`
	} `json:"asn"`
}

func (c *Client) fetch(ctx context.Context, ip string) (Result, error) {
	body, _ := json.Marshal(map[string]string{"ip": ip})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("geoip lookup status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var parsed apiResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Result{}, fmt.Errorf("geoip decode: %w", err)
	}
	return Result{
		CountryISO: strings.TrimSpace(parsed.City.CountryISOCode),
		City:       strings.TrimSpace(parsed.City.CityName),
		ASNOrg:     strings.TrimSpace(parsed.ASN.Organization),
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func ApplyToAddrs(src, dst string, byIP map[string]Result) (srcISO, srcCity, srcASN, dstISO, dstCity, dstASN string) {
	if result, ok := byIP[StripHostPort(src)]; ok {
		srcISO, srcCity, srcASN = result.CountryISO, result.City, result.ASNOrg
	}
	if result, ok := byIP[StripHostPort(dst)]; ok {
		dstISO, dstCity, dstASN = result.CountryISO, result.City, result.ASNOrg
	}
	return
}
