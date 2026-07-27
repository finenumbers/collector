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

type getVoipCallsRequest struct {
	Task     string         `json:"task"`
	User     string         `json:"user"`
	Password string         `json:"password"`
	Params   map[string]any `json:"params"`
}

func (c *Client) GetVoipCalls(ctx context.Context, params map[string]any) ([]VMCall, error) {
	if c == nil || strings.TrimSpace(c.BaseURL) == "" {
		return nil, fmt.Errorf("voipmonitor API URL is not configured")
	}
	endpoint := strings.TrimRight(c.BaseURL, "/") + "/php/api.php"
	body, err := json.Marshal(getVoipCallsRequest{
		Task: "getVoipCalls", User: c.User, Password: c.Password, Params: params,
	})
	if err != nil {
		return nil, err
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
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
	base := strings.TrimRight(guiBase, "/")
	if template == "" {
		template = `{gui_base}/admin.php?cdr_filter={fcallid:"{voipmonitor_call_id}"}`
	}
	replacer := strings.NewReplacer(
		"{gui_base}", base,
		"{voipmonitor_cdr_id}", url.QueryEscape(parts.CDRID),
		"{voipmonitor_call_id}", escapeJSONString(parts.CallID),
	)
	return replacer.Replace(template)
}

func escapeJSONString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}
	return strings.Trim(string(encoded), `"`)
}
