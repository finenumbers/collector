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
	BaseURL    string
	User       string
	Password   string
	HTTPClient *http.Client
}

func (c *Client) GetVoipCalls(ctx context.Context, params map[string]any) ([]VMCall, error) {
	if c == nil || strings.TrimSpace(c.BaseURL) == "" {
		return nil, fmt.Errorf("voipmonitor API URL is not configured")
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
	form.Set("task", "getVoipCalls")
	form.Set("user", c.User)
	form.Set("password", c.Password)
	form.Set("params", string(paramsJSON))

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
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
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("voipmonitor API HTTP %d: %s", resp.StatusCode, truncate(string(payload), 200))
	}
	return parseVoipCallsResponse(payload)
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
	// Prefer stable numeric CDR id when the template still points at Call-ID only.
	if parts.CDRID != "" && strings.Contains(template, "{voipmonitor_call_id}") &&
		!strings.Contains(template, "{voipmonitor_cdr_id}") {
		if filter := cardFilter(CardURLParts{CDRID: parts.CDRID}); filter != "" {
			return base + "/admin.php?cdr_filter=" + url.QueryEscape(filter)
		}
	}
	replaced := strings.NewReplacer(
		"{gui_base}", base,
		"{voipmonitor_cdr_id}", digitsOnly(parts.CDRID),
		"{voipmonitor_call_id}", escapeJSONString(parts.CallID),
	).Replace(template)
	return encodeCDRFilterQuery(replaced)
}

func cardFilter(parts CardURLParts) string {
	if id := digitsOnly(parts.CDRID); id != "" {
		return "{fId:" + id + "}"
	}
	if parts.CallID == "" {
		return ""
	}
	quoted, err := json.Marshal(parts.CallID)
	if err != nil {
		return ""
	}
	return `{fcallid:` + string(quoted) + `}`
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
