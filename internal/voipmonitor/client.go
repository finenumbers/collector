package voipmonitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	BaseURL         string
	User            string
	Password        string
	HTTPClient      *http.Client
	RateLimitPerSec int

	lastRequest time.Time
}

func (c *Client) throttle(ctx context.Context) error {
	if c == nil || c.RateLimitPerSec <= 0 {
		return nil
	}
	minGap := time.Second / time.Duration(c.RateLimitPerSec)
	if minGap <= 0 {
		return nil
	}
	if !c.lastRequest.IsZero() {
		wait := minGap - time.Since(c.lastRequest)
		if wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	c.lastRequest = time.Now()
	return nil
}

// ListVoipCallsRange fetches VoIPmonitor CDRs for [from,to] in 15-minute slices.
func (c *Client) ListVoipCallsRange(ctx context.Context, from, to time.Time) ([]VMCall, error) {
	from = from.UTC()
	to = to.UTC()
	if !to.After(from) {
		to = from.Add(time.Second)
	}
	const slice = 15 * time.Minute
	seen := map[string]struct{}{}
	var out []VMCall
	for cursor := from; cursor.Before(to); {
		next := cursor.Add(slice)
		if next.After(to) {
			next = to
		}
		hits, err := c.GetVoipCalls(ctx, map[string]any{
			"startTime":   cursor.Format("2006-01-02 15:04:05"),
			"startTimeTo": next.Format("2006-01-02 15:04:05"),
		})
		if err != nil {
			return nil, err
		}
		for _, hit := range hits {
			key := hit.CDRID
			if key == "" {
				key = hit.CallID + "|" + hit.CallDate.Format(time.RFC3339Nano)
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, hit)
		}
		if next.Equal(to) {
			break
		}
		cursor = next
	}
	return out, nil
}

func (c *Client) GetVoipCalls(ctx context.Context, params map[string]any) ([]VMCall, error) {
	payload, err := c.postTask(ctx, "getVoipCalls", params, 32<<20)
	if err != nil {
		return nil, err
	}
	return parseVoipCallsResponse(payload)
}

// GetShareURL asks VoIPmonitor for a shareable CDR link (getShareURL).
// Returns empty string without error when the feature is disabled / unavailable.
func (c *Client) GetShareURL(ctx context.Context, cdrID, callID string) (string, error) {
	params := map[string]any{"validDays": 30, "sip_history": true}
	switch {
	case strings.TrimSpace(cdrID) != "":
		params["cdrId"] = strings.TrimSpace(cdrID)
	case strings.TrimSpace(callID) != "":
		params["callId"] = strings.TrimSpace(callID)
	default:
		return "", fmt.Errorf("cdrId or callId required for getShareURL")
	}
	payload, err := c.postTask(ctx, "getShareURL", params, 1<<20)
	if err != nil {
		return "", err
	}
	return parseShareURLResponse(payload)
}

func (c *Client) postTask(ctx context.Context, task string, params map[string]any, maxBody int64) ([]byte, error) {
	if c == nil || strings.TrimSpace(c.BaseURL) == "" {
		return nil, fmt.Errorf("voipmonitor API URL is not configured")
	}
	if err := c.throttle(ctx); err != nil {
		return nil, err
	}
	endpoint, err := apiEndpoint(c.BaseURL)
	if err != nil {
		return nil, err
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("task", task)
	form.Set("user", c.User)
	form.Set("password", c.Password)
	form.Set("params", string(paramsJSON))

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if maxBody <= 0 {
		maxBody = 8 << 20
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("voipmonitor API HTTP %d: %s", resp.StatusCode, truncate(string(payload), 200))
	}
	return payload, nil
}

func parseShareURLResponse(payload []byte) (string, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", nil
	}
	var asString string
	if err := json.Unmarshal(trimmed, &asString); err == nil {
		return strings.TrimSpace(asString), nil
	}
	var envelope map[string]any
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		text := strings.TrimSpace(string(trimmed))
		if strings.HasPrefix(text, "http://") || strings.HasPrefix(text, "https://") {
			return text, nil
		}
		return "", fmt.Errorf("decode getShareURL response: %w", err)
	}
	if errMsg := apiErrorMessage(envelope); errMsg != "" {
		return "", fmt.Errorf("voipmonitor API: %s", errMsg)
	}
	for _, key := range []string{"url", "shareurl", "shareUrl", "link", "data", "result"} {
		if value := firstString(envelope, key); value != "" {
			if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
				return value, nil
			}
		}
	}
	return "", nil
}

func apiEndpoint(base string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(base), "/")
	if trimmed == "" {
		return "", fmt.Errorf("voipmonitor API URL is not configured")
	}
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasSuffix(lower, "/php/api.php"), strings.HasSuffix(lower, "/api.php"):
		return trimmed, nil
	case strings.HasSuffix(lower, "/php"):
		return trimmed + "/api.php", nil
	default:
		return trimmed + "/php/api.php", nil
	}
}

func parseVoipCallsResponse(payload []byte) ([]VMCall, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var asArray []map[string]any
	if err := json.Unmarshal(trimmed, &asArray); err == nil {
		return mapVMCalls(asArray), nil
	}
	var envelope map[string]any
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return nil, fmt.Errorf("decode voipmonitor response: %w", err)
	}
	if isEmptyVoipCallsEnvelope(envelope) {
		return nil, nil
	}
	if errMsg := apiErrorMessage(envelope); errMsg != "" {
		return nil, fmt.Errorf("voipmonitor API: %s", errMsg)
	}
	for _, key := range []string{"cdr", "results", "data", "rows"} {
		if raw, ok := envelope[key]; ok {
			encoded, _ := json.Marshal(raw)
			var nested []map[string]any
			if err := json.Unmarshal(encoded, &nested); err == nil {
				return mapVMCalls(nested), nil
			}
		}
	}
	return mapVMCalls([]map[string]any{envelope}), nil
}

func isEmptyVoipCallsEnvelope(envelope map[string]any) bool {
	msg := strings.ToLower(strings.TrimSpace(firstString(envelope, "error", "msg", "message")))
	if msg == "" {
		return false
	}
	switch {
	case strings.Contains(msg, "no match"):
		return true
	case strings.Contains(msg, "not found"):
		return true
	case strings.Contains(msg, "no cdr"):
		return true
	case strings.Contains(msg, "no calls"):
		return true
	default:
		return false
	}
}

func apiErrorMessage(envelope map[string]any) string {
	success, ok := envelope["success"]
	if !ok {
		return ""
	}
	failed := false
	switch typed := success.(type) {
	case bool:
		failed = !typed
	case string:
		failed = !(strings.EqualFold(typed, "true") || typed == "1")
	default:
		return ""
	}
	if !failed {
		return ""
	}
	if isEmptyVoipCallsEnvelope(envelope) {
		return ""
	}
	if msg := firstString(envelope, "error", "msg", "message"); msg != "" {
		return msg
	}
	return "request failed"
}

func mapVMCalls(rows []map[string]any) []VMCall {
	out := make([]VMCall, 0, len(rows))
	for _, row := range rows {
		call := VMCall{
			CDRID:           firstString(row, "cdrId", "cdr_id", "ID"),
			CallID:          firstString(row, "callId", "callid", "fcallid"),
			Caller:          firstString(row, "caller", "sipcaller"),
			Called:          firstString(row, "called", "sipcalled"),
			SIPCallerIP:     firstString(row, "sipcallerip", "callerip"),
			SIPCalledIP:     firstString(row, "sipcalledip", "calledip"),
			Duration:        firstInt64(row, "duration"),
			ConnectDuration: firstInt64(row, "connect_duration", "connectduration"),
			LastSIPResponse: firstInt64(row, "lastSIPresponseNum", "lastsipresponsenum"),
			SensorID:        firstInt64(row, "id_sensor", "sensor_id"),
		}
		call.CallDate = firstTime(row, "calldate", "callDate", "start")
		call.CallEnd = firstTime(row, "callend", "callEnd", "end")
		if call.CDRID == "" && call.CallID == "" {
			continue
		}
		out = append(out, call)
	}
	return out
}

func firstString(row map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := row[key]; ok && value != nil {
			switch typed := value.(type) {
			case string:
				if strings.TrimSpace(typed) != "" {
					return strings.TrimSpace(typed)
				}
			case float64:
				return strconv.FormatInt(int64(typed), 10)
			case json.Number:
				return typed.String()
			default:
				text := strings.TrimSpace(fmt.Sprint(typed))
				if text != "" && text != "<nil>" {
					return text
				}
			}
		}
	}
	return ""
}

func firstInt64(row map[string]any, keys ...string) int64 {
	for _, key := range keys {
		if value, ok := row[key]; ok && value != nil {
			switch typed := value.(type) {
			case float64:
				return int64(typed)
			case json.Number:
				parsed, _ := typed.Int64()
				return parsed
			case string:
				parsed, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
				return parsed
			}
		}
	}
	return 0
}

func firstTime(row map[string]any, keys ...string) time.Time {
	for _, key := range keys {
		text := firstString(row, key)
		if text == "" {
			continue
		}
		for _, layout := range []string{
			time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05",
		} {
			if parsed, err := time.ParseInLocation(layout, text, time.UTC); err == nil {
				return parsed.UTC()
			}
		}
	}
	return time.Time{}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func BuildCardURL(template, guiBase string, parts CardURLParts) string {
	base := strings.TrimRight(strings.TrimSpace(guiBase), "/")
	template = strings.Trim(strings.TrimSpace(template), `"'`)
	if base == "" {
		return ""
	}
	if template == "" {
		if filter := cardFilter(parts); filter != "" {
			return base + "/admin.php?cdr_filter=" + url.QueryEscape(filter)
		}
		return ""
	}
	// Official deep-link is fcallid. Do not rewrite Call-ID templates to undocumented fId.
	replaced := strings.NewReplacer(
		"{gui_base}", base,
		"{voipmonitor_cdr_id}", digitsOnly(parts.CDRID),
		"{voipmonitor_call_id}", escapeJSONString(parts.CallID),
	).Replace(template)
	return encodeCDRFilterQuery(replaced)
}

// RewriteLegacyCardURL replaces undocumented {fId:…} URLs with official fcallid links
// when a VoIPmonitor Call-ID is available. Used at attach-time for already-stored rows.
func RewriteLegacyCardURL(cardURL, guiBase, vmCallID string, callDate time.Time) string {
	if vmCallID == "" {
		return cardURL
	}
	legacy := cardURL == "" ||
		strings.Contains(cardURL, "fId:") ||
		strings.Contains(cardURL, "fId%3A") ||
		strings.Contains(cardURL, "fId%3a")
	if !legacy {
		return cardURL
	}
	if guiBase == "" {
		guiBase = guiBaseFromCardURL(cardURL)
	}
	if guiBase == "" {
		return cardURL
	}
	return BuildCardURL("", guiBase, CardURLParts{CallID: vmCallID, CallDate: callDate})
}

func guiBaseFromCardURL(cardURL string) string {
	parsed, err := url.Parse(cardURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// cardFilter builds the official VoIPmonitor browser CDR filter.
// Documented form: {fcallid:"…"}. Optional fdatefrom/fdateto narrow collisions.
// Undocumented {fId:N} must NOT be used — GUI ignores it and shows an unrelated list.
func cardFilter(parts CardURLParts) string {
	if parts.CallID == "" {
		return ""
	}
	quoted, err := json.Marshal(parts.CallID)
	if err != nil {
		return ""
	}
	filter := `{fcallid:` + string(quoted)
	if !parts.CallDate.IsZero() {
		from := parts.CallDate.UTC().Add(-24 * time.Hour).Format("2006-01-02T15:04:05")
		to := parts.CallDate.UTC().Add(24 * time.Hour).Format("2006-01-02T15:04:05")
		filter += `,"fdatefrom":"` + from + `","fdateto":"` + to + `"`
	}
	return filter + `}`
}

func digitsOnly(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func encodeCDRFilterQuery(raw string) string {
	const key = "cdr_filter="
	index := strings.Index(raw, key)
	if index < 0 {
		return raw
	}
	prefix := raw[:index+len(key)]
	value := strings.Trim(raw[index+len(key):], `"'`)
	if value == "" {
		return raw
	}
	// Avoid double-encoding already-escaped values.
	if strings.Contains(value, "%7B") || strings.Contains(value, "%7b") {
		return prefix + value
	}
	return prefix + url.QueryEscape(value)
}

func escapeJSONString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}
	return strings.Trim(string(encoded), `"`)
}
