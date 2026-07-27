package voipmonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
)

type Matcher struct {
	Client     *Client
	GUIBase    string
	CardTpl    string
	TimeSkew   time.Duration
	MinScore   int
	Now        func() time.Time
}

func (m *Matcher) Match(ctx context.Context, cdr CDRCandidate) (MatchResult, error) {
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	skew := m.TimeSkew
	if skew <= 0 {
		skew = 5 * time.Second
	}
	minScore := m.MinScore
	if minScore <= 0 {
		minScore = 60
	}
	evidence := map[string]any{
		"source_system": cdr.SourceSystem,
		"sip_call_ids":  cdr.SIPCallIDs,
		"setup_time":    cdr.SetupTime.UTC().Format(time.RFC3339Nano),
		"attempts":      []any{},
	}
	attempts := make([]any, 0, 8)

	// Exact / high-confidence Call-ID attempts.
	for index, callID := range cdr.SIPCallIDs {
		callID = strings.TrimSpace(callID)
		if callID == "" {
			continue
		}
		method := methodForCallIDAttempt(cdr.SourceSystem, index)
		params := map[string]any{
			"startTime":   cdr.SetupTime.Add(-skew).UTC().Format("2006-01-02 15:04:05"),
			"startTimeTo": cdr.SetupTime.Add(skew).UTC().Format("2006-01-02 15:04:05"),
			"callId":      callID,
		}
		hits, err := m.Client.GetVoipCalls(ctx, params)
		attempt := map[string]any{"method": method, "callId": callID, "hits": len(hits)}
		if err != nil {
			attempt["error"] = err.Error()
			attempts = append(attempts, attempt)
			evidence["attempts"] = attempts
			return unmatchedResult(evidence, now), err
		}
		attempts = append(attempts, attempt)
		if len(hits) == 1 {
			score := uint8(100)
			status := StatusMatchedExact
			if cdr.SourceSystem == SourceSatel && !numbersAgree(cdr, hits[0]) {
				status = StatusMatchedFallback
				score = 85
				method = method + "_unverified"
			}
			evidence["attempts"] = attempts
			return m.success(hits[0], status, method, score, evidence, now), nil
		}
		if len(hits) > 1 {
			evidence["attempts"] = attempts
			evidence["reason"] = "multiple_call_id_hits"
			return MatchResult{
				Status: StatusAmbiguous, Method: method, Score: 0,
				EvidenceJSON: mustJSON(evidence),
			}, nil
		}
	}

	// Fallback: time window + soft filters.
	params := map[string]any{
		"startTime":   cdr.SetupTime.Add(-skew).UTC().Format("2006-01-02 15:04:05"),
		"startTimeTo": cdr.SetupTime.Add(skew).UTC().Format("2006-01-02 15:04:05"),
	}
	if caller := digits(cdr.Caller); caller != "" {
		params["caller"] = caller
	}
	if called := digits(cdr.Called); called != "" {
		params["called"] = called
	}
	hits, err := m.Client.GetVoipCalls(ctx, params)
	attempt := map[string]any{"method": "fallback_time_numbers", "hits": len(hits)}
	if err != nil {
		attempt["error"] = err.Error()
		attempts = append(attempts, attempt)
		evidence["attempts"] = attempts
		return unmatchedResult(evidence, now), err
	}
	attempts = append(attempts, attempt)
	scored := scoreCandidates(cdr, hits)
	evidence["attempts"] = attempts
	evidence["scored"] = scored
	if len(scored) == 0 {
		return unmatchedResult(evidence, now), nil
	}
	best := scored[0]
	if len(scored) > 1 && scored[1].Score >= best.Score-5 {
		evidence["reason"] = "multiple_close_fallback_hits"
		return MatchResult{
			Status: StatusAmbiguous, Method: "fallback_time_numbers", Score: best.Score,
			EvidenceJSON: mustJSON(evidence),
		}, nil
	}
	if int(best.Score) < minScore {
		evidence["reason"] = "below_min_score"
		return unmatchedResult(evidence, now), nil
	}
	return m.success(best.Call, StatusMatchedFallback, "fallback_time_numbers", best.Score, evidence, now), nil
}

func (m *Matcher) success(
	call VMCall, status, method string, score uint8, evidence map[string]any, now time.Time,
) MatchResult {
	matchedAt := now
	url := BuildCardURL(m.CardTpl, m.GUIBase, CardURLParts{CDRID: call.CDRID, CallID: call.CallID})
	evidence["selected"] = map[string]any{
		"cdrId": call.CDRID, "callId": call.CallID, "score": score, "method": method,
	}
	return MatchResult{
		Status: status, Method: method, Score: score, VM: &call, CardURL: url,
		EvidenceJSON: mustJSON(evidence), MatchedAt: &matchedAt,
	}
}

type scoredCall struct {
	Call  VMCall
	Score uint8
}

func scoreCandidates(cdr CDRCandidate, hits []VMCall) []scoredCall {
	out := make([]scoredCall, 0, len(hits))
	for _, hit := range hits {
		var score int
		if !cdr.SetupTime.IsZero() && !hit.CallDate.IsZero() {
			delta := hit.CallDate.Sub(cdr.SetupTime).Abs()
			switch {
			case delta <= 2*time.Second:
				score += 35
			case delta <= 5*time.Second:
				score += 25
			case delta <= 15*time.Second:
				score += 10
			}
		}
		if digits(cdr.Caller) != "" && digits(cdr.Caller) == digits(hit.Caller) {
			score += 20
		}
		if digits(cdr.Called) != "" && digits(cdr.Called) == digits(hit.Called) {
			score += 20
		}
		if cdr.DurationSec != nil && *cdr.DurationSec > 0 {
			diff := abs64(*cdr.DurationSec - hit.Duration)
			switch {
			case diff <= 1:
				score += 15
			case diff <= 3:
				score += 10
			case diff <= 8:
				score += 5
			}
		}
		if cdr.ConnectDurationSec != nil && *cdr.ConnectDurationSec > 0 {
			diff := abs64(*cdr.ConnectDurationSec - hit.ConnectDuration)
			if diff <= 2 {
				score += 5
			}
		}
		if ipEqual(cdr.CallerIP, hit.SIPCallerIP) || ipEqual(cdr.CalledIP, hit.SIPCalledIP) {
			score += 5
		}
		if score <= 0 {
			continue
		}
		if score > 100 {
			score = 100
		}
		out = append(out, scoredCall{Call: hit, Score: uint8(score)})
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Score > out[i].Score {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func methodForCallIDAttempt(source string, index int) string {
	if source == SourceEltex {
		if index == 0 {
			return "sip_call_id_in"
		}
		return "sip_call_id_out"
	}
	switch index {
	case 0:
		return "rtu_call_id_out_proto"
	case 1:
		return "rtu_protocol_conf_id"
	case 2:
		return "rtu_call_id"
	case 3:
		return "rtu_conf_id"
	default:
		return fmt.Sprintf("rtu_call_id_%d", index)
	}
}

func numbersAgree(cdr CDRCandidate, hit VMCall) bool {
	callerOK := digits(cdr.Caller) == "" || digits(cdr.Caller) == digits(hit.Caller)
	calledOK := digits(cdr.Called) == "" || digits(cdr.Called) == digits(hit.Called)
	return callerOK && calledOK
}

func unmatchedResult(evidence map[string]any, now time.Time) MatchResult {
	_ = now
	return MatchResult{Status: StatusUnmatched, Method: "none", Score: 0, EvidenceJSON: mustJSON(evidence)}
}

func digits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func ipEqual(a, b string) bool {
	a = strings.TrimSpace(strings.ToLower(a))
	b = strings.TrimSpace(strings.ToLower(b))
	return a != "" && a == b
}

func abs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func mustJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
