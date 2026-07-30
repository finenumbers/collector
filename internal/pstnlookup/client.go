package pstnlookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"collector/internal/lookuptelemetry"
)

const DefaultURL = "https://pstn.finenumbers.com/api/v1/lookup"
const DefaultCacheTTL = 24 * time.Hour

type Result struct {
	Operator string
	Region   string
}

type Client struct {
	BaseURL     string
	Token       string
	EnabledFlag bool
	HTTPClient  *http.Client
	CacheTTL    time.Duration
	Telemetry   *lookuptelemetry.Registry

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	result    Result
	expiresAt time.Time
}

func New(baseURL, token string, enabled bool) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultURL
	}
	return &Client{
		BaseURL:     strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		Token:       strings.TrimSpace(token),
		EnabledFlag: enabled,
		HTTPClient: &http.Client{
			Timeout: 3 * time.Second,
		},
		CacheTTL:  DefaultCacheTTL,
		Telemetry: lookuptelemetry.Default,
		cache:     make(map[string]cacheEntry),
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.EnabledFlag && c.Token != ""
}

// NormalizePhone keeps digits only and strips a leading Russian country/trunk
// digit when the number is 11 digits (7… / 8…).
func NormalizePhone(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	digits := b.String()
	if len(digits) == 11 && (digits[0] == '7' || digits[0] == '8') {
		return digits[1:]
	}
	return digits
}

func (c *Client) Lookup(ctx context.Context, rawPhone string) (Result, error) {
	if !c.Enabled() {
		return Result{}, nil
	}
	phone := NormalizePhone(rawPhone)
	if phone == "" {
		return Result{}, nil
	}
	if result, ok := c.getCached(phone); ok {
		if c.Telemetry != nil {
			c.Telemetry.RecordCacheHit("pstn")
		}
		return result, nil
	}
	start := time.Now()
	result, err := c.fetch(ctx, phone)
	latency := time.Since(start)
	if err != nil {
		if c.Telemetry != nil {
			c.Telemetry.RecordError("pstn", latency, err.Error())
		}
		return Result{}, err
	}
	c.putCached(phone, result)
	if c.Telemetry != nil {
		c.Telemetry.RecordSuccess("pstn", latency)
	}
	return result, nil
}

// LookupMany resolves unique phones with bounded parallelism.
func (c *Client) LookupMany(ctx context.Context, phones []string, workers int) map[string]Result {
	out := make(map[string]Result)
	if !c.Enabled() || len(phones) == 0 {
		return out
	}
	if workers < 1 {
		workers = 8
	}
	unique := make([]string, 0, len(phones))
	seen := make(map[string]struct{}, len(phones))
	for _, raw := range phones {
		phone := NormalizePhone(raw)
		if phone == "" {
			continue
		}
		if _, ok := seen[phone]; ok {
			continue
		}
		seen[phone] = struct{}{}
		if result, ok := c.getCached(phone); ok {
			out[phone] = result
			if c.Telemetry != nil {
				c.Telemetry.RecordCacheHit("pstn")
			}
			continue
		}
		unique = append(unique, phone)
	}
	if len(unique) == 0 {
		return out
	}
	type item struct {
		phone  string
		result Result
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
			for phone := range jobs {
				start := time.Now()
				result, err := c.fetch(ctx, phone)
				latency := time.Since(start)
				if err != nil {
					result = Result{}
					if c.Telemetry != nil {
						c.Telemetry.RecordError("pstn", latency, err.Error())
					}
				} else {
					c.putCached(phone, result)
					if c.Telemetry != nil {
						c.Telemetry.RecordSuccess("pstn", latency)
					}
				}
				results <- item{phone: phone, result: result}
			}
		}()
	}
	go func() {
		for _, phone := range unique {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case jobs <- phone:
			}
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	for item := range results {
		out[item.phone] = item.result
	}
	return out
}

func (c *Client) getCached(phone string) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[phone]
	if !ok || time.Now().After(entry.expiresAt) {
		if ok {
			delete(c.cache, phone)
		}
		return Result{}, false
	}
	return entry.result, true
}

func (c *Client) putCached(phone string, result Result) {
	ttl := c.CacheTTL
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[phone] = cacheEntry{result: result, expiresAt: time.Now().Add(ttl)}
}

type apiResponse struct {
	Found bool `json:"found"`
	Data  struct {
		Operator string `json:"operator"`
		Region   string `json:"region"`
	} `json:"data"`
}

func (c *Client) fetch(ctx context.Context, phone string) (Result, error) {
	endpoint, err := url.Parse(c.BaseURL)
	if err != nil {
		return Result{}, fmt.Errorf("pstn lookup url: %w", err)
	}
	query := endpoint.Query()
	query.Set("phone", phone)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("pstn lookup status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var parsed apiResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Result{}, fmt.Errorf("pstn lookup decode: %w", err)
	}
	if !parsed.Found {
		return Result{}, nil
	}
	return Result{
		Operator: strings.TrimSpace(parsed.Data.Operator),
		Region:   strings.TrimSpace(parsed.Data.Region),
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ApplyToPhones fills operator/region for ANI/DNIS using a precomputed map keyed
// by normalized phone.
func ApplyToPhones(ani, dnis string, byPhone map[string]Result) (aniOp, aniReg, dnisOp, dnisReg string) {
	if result, ok := byPhone[NormalizePhone(ani)]; ok {
		aniOp, aniReg = result.Operator, result.Region
	}
	if result, ok := byPhone[NormalizePhone(dnis)]; ok {
		dnisOp, dnisReg = result.Operator, result.Region
	}
	return aniOp, aniReg, dnisOp, dnisReg
}
