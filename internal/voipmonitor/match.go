package voipmonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Matcher struct {
	Client             *Client
	GUIBase            string
	CardTpl            string
	CallIDWindow       time.Duration
	FallbackWindow     time.Duration
	FallbackWindowMax  time.Duration
	MinScore           int
	DisambiguityMargin int
	NumberSuffixLen    int
	UseShareURL        bool
	Now                func() time.Time
}

type callIndex struct {
	byCallID map[string][]VMCall
	byCDRID  map[string]VMCall
	all      []VMCall
}

func buildCallIndex(calls []VMCall) *callIndex {
	idx := &callIndex{
		byCallID: make(map[string][]VMCall, len(calls)),
		byCDRID:  make(map[string]VMCall, len(calls)),
		all:      make([]VMCall, 0, len(calls)),
	}
	for _, call := range calls {
		if call.CDRID != "" {
			if _, exists := idx.byCDRID[call.CDRID]; !exists {
				idx.byCDRID[call.CDRID] = call
				idx.all = append(idx.all, call)
			}
		} else {
			idx.all = append(idx.all, call)
		}
		for _, key := range CallIDVariants(call.CallID) {
			idx.byCallID[key] = appendUniqueCall(idx.byCallID[key], call)
		}
	}
	return idx
}

func (idx *callIndex) merge(calls []VMCall) {
	if idx == nil {
		return
	}
	for _, call := range calls {
		if call.CDRID != "" {
			if _, exists := idx.byCDRID[call.CDRID]; !exists {
				idx.byCDRID[call.CDRID] = call
				idx.all = append(idx.all, call)
			}
		} else {
			idx.all = append(idx.all, call)
		}
		for _, key := range CallIDVariants(call.CallID) {
			idx.byCallID[key] = appendUniqueCall(idx.byCallID[key], call)
		}
	}
}

func appendUniqueCall(list []VMCall, call VMCall) []VMCall {
	for _, existing := range list {
		if existing.CDRID != "" && existing.CDRID == call.CDRID {
			return list
		}
	}
	return append(list, call)
}

func (m *Matcher) opts() matchOpts {
	callIDWindow := m.CallIDWindow
	if callIDWindow <= 0 {
		callIDWindow = 30 * time.Minute
	}
	fallback := m.FallbackWindow
	if fallback <= 0 {
		fallback = 2 * time.Minute
	}
	fallbackMax := m.FallbackWindowMax
	if fallbackMax <= 0 {
		fallbackMax = 10 * time.Minute
	}
	if fallbackMax < fallback {
		fallbackMax = fallback
	}
	minScore := m.MinScore
	if minScore <= 0 {
		minScore = 60
	}
	margin := m.DisambiguityMargin
	if margin <= 0 {
		margin = 8
	}
	suffix := m.NumberSuffixLen
	if suffix <= 0 {
		suffix = 10
	}
	return matchOpts{
		callIDWindow: callIDWindow,
		fallback:     fallback,
		fallbackMax:  fallbackMax,
		minScore:     minScore,
		margin:       margin,
		suffixLen:    suffix,
	}
}

type matchOpts struct {
	callIDWindow time.Duration
	fallback     time.Duration
	fallbackMax  time.Duration
	minScore     int
	margin       int
	suffixLen    int
}

// MatchBucket uses a hybrid strategy:
//  1. one hour-range VM fetch (cheap, high coverage index);
//  2. in-memory exact Call-ID match;
//  3. targeted getVoipCalls(callId) only for Call-ID misses (truncation / skew);
//  4. gated number/IP fallback against the hour index (+ cdrId verify).
func (m *Matcher) MatchBucket(ctx context.Context, candidates []CDRCandidate) ([]MatchResult, error) {
	opts := m.opts()
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	from, to := bucketBounds(candidates)
	fetchFrom := from.Add(-opts.callIDWindow)
	fetchTo := to.Add(opts.callIDWindow)

	hourCalls, err := m.Client.ListVoipCallsRange(ctx, fetchFrom, fetchTo)
	if err != nil {
		results := make([]MatchResult, len(candidates))
		for i := range candidates {
			results[i] = missResult(MissAPIError, map[string]any{
				"stage": "hour_fetch", "error": err.Error(),
				"fetch_from": fetchFrom.Format(time.RFC3339),
				"fetch_to":   fetchTo.Format(time.RFC3339),
			})
		}
		return results, err
	}
	idx := buildCallIndex(hourCalls)
	fetchMeta := map[string]any{
		"hour_fetch_count": len(hourCalls),
		"fetch_from":       fetchFrom.Format(time.RFC3339),
		"fetch_to":         fetchTo.Format(time.RFC3339),
	}

	// Targeted Call-ID probes only for unique Call-IDs missing from the hour index.
	var missCandidates []CDRCandidate
	for _, cdr := range candidates {
		if _, ok := m.stageExact(cdr, idx, opts, nil); !ok {
			missCandidates = append(missCandidates, cdr)
		}
	}
	probeAttempts := make([]any, 0, 8)
	seenProbe := map[string]struct{}{}
	for _, cdr := range missCandidates {
		for _, raw := range cdr.SIPCallIDs {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if _, done := seenProbe[NormalizeCallID(raw)]; done {
				continue
			}
			hitAny := false
			for _, q := range CallIDQueryVariants(raw) {
				hits, probeErr := m.Client.GetVoipCalls(ctx, map[string]any{
					"startTime":   fetchFrom.Format("2006-01-02 15:04:05"),
					"startTimeTo": fetchTo.Format("2006-01-02 15:04:05"),
					"callId":      q,
				})
				attempt := map[string]any{"callId": q, "hits": len(hits)}
				if probeErr != nil {
					attempt["error"] = probeErr.Error()
					probeAttempts = append(probeAttempts, attempt)
					continue
				}
				probeAttempts = append(probeAttempts, attempt)
				if len(hits) > 0 {
					idx.merge(hits)
					hitAny = true
					break
				}
			}
			seenProbe[NormalizeCallID(raw)] = struct{}{}
			_ = hitAny
		}
	}
	fetchMeta["call_id_probes"] = len(probeAttempts)

	return m.assignBucket(ctx, candidates, idx, opts, now, fetchMeta, probeAttempts), nil
}

// Match keeps a single-CDR API for tests.
func (m *Matcher) Match(ctx context.Context, cdr CDRCandidate) (MatchResult, error) {
	results, err := m.MatchBucket(ctx, []CDRCandidate{cdr})
	if len(results) == 0 {
		return MatchResult{Status: StatusUnmatched, Method: "none", Score: 0}, err
	}
	return results[0], err
}

func bucketBounds(candidates []CDRCandidate) (time.Time, time.Time) {
	from := candidates[0].SetupTime.UTC()
	to := from
	for _, c := range candidates[1:] {
		t := c.SetupTime.UTC()
		if t.Before(from) {
			from = t
		}
		if t.After(to) {
			to = t
		}
	}
	return from, to.Add(time.Second)
}

type pendingMatch struct {
	candIdx  int
	call     VMCall
	score    uint8
	method   string
	status   string
	evidence map[string]any
	legs     []VMCall
}

func (m *Matcher) assignBucket(
	ctx context.Context,
	candidates []CDRCandidate, idx *callIndex, opts matchOpts, now time.Time,
	fetchMeta map[string]any, probeAttempts []any,
) []MatchResult {
	results := make([]MatchResult, len(candidates))
	used := map[string]int{}

	var exact []pendingMatch
	for i, cdr := range candidates {
		pm, ok := m.stageExact(cdr, idx, opts, probeAttempts)
		if !ok {
			continue
		}
		pm.candIdx = i
		if fetchMeta != nil {
			pm.evidence["hour_fetch"] = fetchMeta
		}
		exact = append(exact, pm)
	}
	sort.SliceStable(exact, func(i, j int) bool {
		if exact[i].score != exact[j].score {
			return exact[i].score > exact[j].score
		}
		return exact[i].candIdx < exact[j].candIdx
	})
	assigned := make([]bool, len(candidates))
	for _, pm := range exact {
		if assigned[pm.candIdx] {
			continue
		}
		legs := pm.legs
		if len(legs) == 0 {
			legs = []VMCall{pm.call}
		}
		picked := false
		for _, leg := range legs {
			if leg.CDRID != "" {
				if owner, taken := used[leg.CDRID]; taken && owner != pm.candIdx {
					continue
				}
				used[leg.CDRID] = pm.candIdx
			}
			ev := cloneEvidence(pm.evidence)
			ev["selected"] = map[string]any{
				"cdrId": leg.CDRID, "callId": leg.CallID, "score": pm.score,
			}
			results[pm.candIdx] = m.success(ctx, leg, pm.status, pm.method, pm.score, ev, now)
			assigned[pm.candIdx] = true
			picked = true
			break
		}
		if !picked {
			results[pm.candIdx] = missResult(MissAssignedElsewhere, cloneEvidence(pm.evidence))
			assigned[pm.candIdx] = true
		}
	}

	var fallback []pendingMatch
	for i, cdr := range candidates {
		if assigned[i] {
			continue
		}
		pm, miss, ok := m.stageFallback(ctx, cdr, idx, opts, used, fetchMeta)
		if !ok {
			results[i] = miss
			continue
		}
		pm.candIdx = i
		fallback = append(fallback, pm)
	}
	sort.SliceStable(fallback, func(i, j int) bool {
		if fallback[i].score != fallback[j].score {
			return fallback[i].score > fallback[j].score
		}
		return fallback[i].candIdx < fallback[j].candIdx
	})
	for _, pm := range fallback {
		if assigned[pm.candIdx] {
			continue
		}
		if pm.call.CDRID != "" {
			if owner, taken := used[pm.call.CDRID]; taken && owner != pm.candIdx {
				ev := pm.evidence
				ev["miss_reason"] = MissAssignedElsewhere
				ev["taken_by_candidate"] = owner
				results[pm.candIdx] = missResult(MissAssignedElsewhere, ev)
				continue
			}
			used[pm.call.CDRID] = pm.candIdx
		}
		results[pm.candIdx] = m.success(ctx, pm.call, pm.status, pm.method, pm.score, pm.evidence, now)
		assigned[pm.candIdx] = true
	}

	for i := range results {
		if results[i].Status == "" {
			results[i] = missResult(MissNoCandidatesInWindow, map[string]any{
				"stage":                      "unassigned",
				"source_call_ids_normalized": sourceCallIDNorms(candidates[i]),
				"hour_fetch":                 fetchMeta,
			})
		}
	}
	return results
}

func (m *Matcher) stageExact(
	cdr CDRCandidate, idx *callIndex, opts matchOpts, probeAttempts []any,
) (pendingMatch, bool) {
	norms := sourceCallIDNorms(cdr)
	evidence := map[string]any{
		"stage":                      "exact_call_id",
		"source_system":              cdr.SourceSystem,
		"source_call_ids_normalized": norms,
		"setup_time":                 cdr.SetupTime.UTC().Format(time.RFC3339Nano),
	}
	if len(probeAttempts) > 0 {
		evidence["call_id_probes"] = probeAttempts
	}
	if len(norms) == 0 && len(cdr.SIPCallIDs) == 0 {
		return pendingMatch{}, false
	}
	var hits []VMCall
	seenCDR := map[string]struct{}{}
	matchedNorm := ""
	for i, raw := range cdr.SIPCallIDs {
		for _, norm := range CallIDVariants(raw) {
			group := idx.byCallID[norm]
			if len(group) == 0 {
				continue
			}
			if matchedNorm == "" {
				matchedNorm = norm
				evidence["matched_call_id_norm"] = norm
				evidence["method_seed"] = methodForCallIDAttempt(cdr.SourceSystem, i)
			}
			for _, hit := range group {
				key := hit.CDRID
				if key == "" {
					key = hit.CallID + "|" + hit.CallDate.Format(time.RFC3339Nano)
				}
				if _, ok := seenCDR[key]; ok {
					continue
				}
				seenCDR[key] = struct{}{}
				hits = append(hits, hit)
			}
		}
	}
	if len(hits) == 0 {
		return pendingMatch{}, false
	}
	evidence["vm_legs_with_same_call_id"] = len(hits)
	ordered, score := orderLegs(cdr, hits, opts.suffixLen)
	winner := ordered[0]
	evidence["selected"] = map[string]any{
		"cdrId": winner.CDRID, "callId": winner.CallID, "score": score,
	}
	if len(ordered) > 1 {
		evidence["runner_up"] = map[string]any{
			"cdrId": ordered[1].CDRID, "callId": ordered[1].CallID,
		}
	}
	method, _ := evidence["method_seed"].(string)
	if method == "" {
		method = "sip_call_id"
	}
	if len(hits) > 1 {
		method = method + "_multi_leg"
		evidence["multi_leg_disambiguated"] = true
	}
	return pendingMatch{
		call: winner, score: score, method: method,
		status: StatusMatchedExact, evidence: evidence, legs: ordered,
	}, true
}

func (m *Matcher) stageFallback(
	ctx context.Context, cdr CDRCandidate, idx *callIndex, opts matchOpts, used map[string]int,
	fetchMeta map[string]any,
) (pendingMatch, MatchResult, bool) {
	norms := sourceCallIDNorms(cdr)
	evidence := map[string]any{
		"stage":                      "fallback",
		"source_system":              cdr.SourceSystem,
		"source_call_ids_normalized": norms,
		"call_id_hits":               0,
		"setup_time":                 cdr.SetupTime.UTC().Format(time.RFC3339Nano),
		"hour_fetch":                 fetchMeta,
	}
	if len(norms) > 0 {
		evidence["miss_reason_seed"] = MissCallIDNotInIndex
	} else {
		evidence["miss_reason_seed"] = MissEmptyCallIDWeakSignal
	}

	scored := scoreFallbackCandidates(cdr, idx.all, used, opts.fallback, opts.suffixLen)
	evidence["candidates_in_window"] = len(scored)
	if len(scored) == 0 {
		scored = scoreFallbackCandidates(cdr, idx.all, used, opts.fallbackMax, opts.suffixLen)
		evidence["expanded_window"] = true
		evidence["candidates_in_window"] = len(scored)
	}
	if len(scored) == 0 {
		reason := MissNoCandidatesInWindow
		if seed, _ := evidence["miss_reason_seed"].(string); seed != "" {
			reason = seed
		}
		return pendingMatch{}, missResult(reason, evidence), false
	}

	best := scored[0]
	var runner *scoredCall
	if len(scored) > 1 {
		runner = &scored[1]
	}
	gates := map[string]any{
		"min_score": opts.minScore, "margin": opts.margin,
		"best_score": best.Score, "number_ok": best.NumberOK, "ip_ok": best.IPOK,
	}
	evidence["gates"] = gates
	evidence["selected"] = map[string]any{
		"cdrId": best.Call.CDRID, "callId": best.Call.CallID, "score": best.Score,
	}
	if runner != nil {
		evidence["runner_up"] = map[string]any{
			"cdrId": runner.Call.CDRID, "callId": runner.Call.CallID, "score": runner.Score,
		}
	}

	if !best.NumberOK && !best.IPOK {
		return pendingMatch{}, missResult(MissEmptyCallIDWeakSignal, evidence), false
	}
	if !best.NumberOK && !best.AllowIPOnly {
		return pendingMatch{}, missResult(MissFallbackBelowThreshold, evidence), false
	}
	if int(best.Score) < opts.minScore {
		return pendingMatch{}, missResult(MissFallbackBelowThreshold, evidence), false
	}
	if runner != nil && int(best.Score)-int(runner.Score) < opts.margin {
		evidence["miss_reason"] = MissFallbackAmbiguous
		return pendingMatch{}, MatchResult{
			Status: StatusAmbiguous, Method: "fallback_numbers_ip_time", Score: best.Score,
			MissReason: MissFallbackAmbiguous, EvidenceJSON: mustJSON(evidence),
		}, false
	}

	if best.Call.CDRID != "" {
		center := best.Call.CallDate
		if center.IsZero() {
			center = cdr.SetupTime
		}
		verified, err := m.Client.GetVoipCalls(ctx, map[string]any{
			"cdrId":       best.Call.CDRID,
			"startTime":   center.UTC().Add(-time.Hour).Format("2006-01-02 15:04:05"),
			"startTimeTo": center.UTC().Add(time.Hour).Format("2006-01-02 15:04:05"),
		})
		if err != nil {
			evidence["verify_error"] = err.Error()
			return pendingMatch{}, missResult(MissAPIError, evidence), false
		}
		ok := false
		for _, v := range verified {
			if v.CDRID == best.Call.CDRID {
				ok = true
				best.Call = v
				break
			}
		}
		if !ok {
			// Hour-index already contained the row; accept without API corroboration
			// when verify returns empty (some GUI builds require different cdrId typing).
			evidence["verify_empty"] = true
		} else {
			evidence["verified_cdr_id"] = true
		}
	}

	return pendingMatch{
		call: best.Call, score: best.Score, method: "fallback_numbers_ip_time",
		status: StatusMatchedFallback, evidence: evidence,
	}, MatchResult{}, true
}

type scoredCall struct {
	Call        VMCall
	Score       uint8
	NumberOK    bool
	IPOK        bool
	AllowIPOnly bool
}

func scoreFallbackCandidates(
	cdr CDRCandidate, calls []VMCall, used map[string]int, window time.Duration, suffixLen int,
) []scoredCall {
	out := make([]scoredCall, 0, 16)
	for _, hit := range calls {
		if hit.CDRID != "" {
			if _, taken := used[hit.CDRID]; taken {
				continue
			}
		}
		if !cdr.SetupTime.IsZero() && !hit.CallDate.IsZero() {
			if hit.CallDate.Sub(cdr.SetupTime).Abs() > window {
				continue
			}
		}
		scored := scoreOne(cdr, hit, suffixLen, true)
		if scored.Score == 0 {
			continue
		}
		if !scored.NumberOK && !scored.IPOK {
			continue
		}
		if scored.NumberOK || scored.AllowIPOnly {
			out = append(out, scored)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Call.CDRID < out[j].Call.CDRID
	})
	return out
}

func orderLegs(cdr CDRCandidate, hits []VMCall, suffixLen int) ([]VMCall, uint8) {
	scored := make([]scoredCall, 0, len(hits))
	for _, hit := range hits {
		scored = append(scored, scoreOne(cdr, hit, suffixLen, false))
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].Score != scored[j].Score {
			return scored[i].Score > scored[j].Score
		}
		if scored[i].IPOK != scored[j].IPOK {
			return scored[i].IPOK
		}
		di := timeDelta(cdr, scored[i].Call)
		dj := timeDelta(cdr, scored[j].Call)
		if di != dj {
			return di < dj
		}
		return cdrIDLess(scored[i].Call.CDRID, scored[j].Call.CDRID)
	})
	out := make([]VMCall, len(scored))
	for i := range scored {
		out[i] = scored[i].Call
	}
	return out, 100
}

func cloneEvidence(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func timeDelta(cdr CDRCandidate, hit VMCall) time.Duration {
	if cdr.SetupTime.IsZero() || hit.CallDate.IsZero() {
		return time.Hour * 24
	}
	return hit.CallDate.Sub(cdr.SetupTime).Abs()
}

func cdrIDLess(a, b string) bool {
	ai, ea := strconv.ParseInt(digits(a), 10, 64)
	bi, eb := strconv.ParseInt(digits(b), 10, 64)
	if ea == nil && eb == nil && ai != bi {
		return ai > bi
	}
	return a > b
}

func scoreOne(cdr CDRCandidate, hit VMCall, suffixLen int, requireStrong bool) scoredCall {
	var score int
	callerNums := cdrCallerNumbers(cdr)
	calledNums := cdrCalledNumbers(cdr)
	callerHit := numberSuffixes(hit.Caller, suffixLen)
	calledHit := numberSuffixes(hit.Called, suffixLen)

	callerMatch, callerSide := bestNumberMatch(callerNums, callerHit, calledHit, suffixLen)
	calledMatch, calledSide := bestNumberMatch(calledNums, calledHit, callerHit, suffixLen)
	numberOK := false
	allowIPOnly := false
	switch {
	case callerMatch && calledMatch:
		numberOK = true
		score += 40
		if callerSide == "swap" || calledSide == "swap" {
			score += 5
		}
	case callerMatch || calledMatch:
		score += 18
		if requireStrong {
			numberOK = false
		} else {
			numberOK = true
		}
	}

	ipOK := ipEqual(cdr.CallerIP, hit.SIPCallerIP) ||
		ipEqual(cdr.CallerIP, hit.SIPCalledIP) ||
		ipEqual(cdr.CalledIP, hit.SIPCallerIP) ||
		ipEqual(cdr.CalledIP, hit.SIPCalledIP)
	if ipOK {
		score += 20
	}
	if requireStrong && (callerMatch || calledMatch) && ipOK {
		numberOK = true
		score += 10
	}
	if requireStrong && !callerMatch && !calledMatch && ipOK &&
		len(callerNums) == 0 && len(calledNums) == 0 {
		allowIPOnly = true
	}

	if !cdr.SetupTime.IsZero() && !hit.CallDate.IsZero() {
		delta := hit.CallDate.Sub(cdr.SetupTime).Abs()
		switch {
		case delta <= 2*time.Second:
			score += 25
		case delta <= 15*time.Second:
			score += 18
		case delta <= time.Minute:
			score += 12
		case delta <= 2*time.Minute:
			score += 8
		case delta <= 10*time.Minute:
			score += 4
		}
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
	if cdr.ConnectDurationSec != nil && *cdr.ConnectDurationSec > 0 && hit.ConnectDuration > 0 {
		diff := abs64(*cdr.ConnectDurationSec - hit.ConnectDuration)
		if diff <= 2 {
			score += 5
		}
	}
	if score > 100 {
		score = 100
	}
	return scoredCall{
		Call: hit, Score: uint8(score), NumberOK: numberOK, IPOK: ipOK, AllowIPOnly: allowIPOnly,
	}
}

func bestNumberMatch(sources []string, primary, alternate []string, suffixLen int) (bool, string) {
	for _, src := range sources {
		for _, s := range numberSuffixes(src, suffixLen) {
			for _, p := range primary {
				if s == p {
					return true, "direct"
				}
			}
			for _, a := range alternate {
				if s == a {
					return true, "swap"
				}
			}
		}
	}
	return false, ""
}

func (m *Matcher) success(
	ctx context.Context,
	call VMCall, status, method string, score uint8, evidence map[string]any, now time.Time,
) MatchResult {
	matchedAt := now
	url := BuildCardURL(m.CardTpl, m.GUIBase, CardURLParts{
		CDRID: call.CDRID, CallID: call.CallID, CallDate: call.CallDate,
	})
	if m.UseShareURL && m.Client != nil {
		if share, err := m.Client.GetShareURL(ctx, call.CDRID, call.CallID); err == nil && share != "" {
			url = share
			if evidence == nil {
				evidence = map[string]any{}
			}
			evidence["share_url"] = true
		}
	}
	if evidence == nil {
		evidence = map[string]any{}
	}
	evidence["selected"] = map[string]any{
		"cdrId": call.CDRID, "callId": call.CallID, "score": score, "method": method,
	}
	return MatchResult{
		Status: status, Method: method, Score: score, VM: &call, CardURL: url,
		EvidenceJSON: mustJSON(evidence), MatchedAt: &matchedAt,
	}
}

func missResult(reason string, evidence map[string]any) MatchResult {
	if evidence == nil {
		evidence = map[string]any{}
	}
	evidence["miss_reason"] = reason
	status := StatusUnmatched
	method := "none"
	if reason == MissFallbackAmbiguous {
		status = StatusAmbiguous
		method = "fallback_numbers_ip_time"
	}
	return MatchResult{
		Status: status, Method: method, Score: 0,
		MissReason: reason, EvidenceJSON: mustJSON(evidence),
	}
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
		return "rtu_src_out_leg_call_id"
	case 2:
		return "rtu_call_id_in"
	case 3:
		return "rtu_src_in_leg_call_id"
	case 4:
		return "rtu_src_in_leg_conf_id"
	case 5:
		return "rtu_conf_id"
	default:
		return fmt.Sprintf("rtu_call_id_%d", index)
	}
}

func mustJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

// AuditExactCallIDInvariant returns false when a matched_exact result does not
// share a Call-ID with the source candidate (raw or normalized).
func AuditExactCallIDInvariant(cdr CDRCandidate, result MatchResult) bool {
	if result.Status != StatusMatchedExact {
		return true
	}
	if result.VM == nil {
		return false
	}
	for _, raw := range cdr.SIPCallIDs {
		if callIDsEqual(raw, result.VM.CallID) {
			return true
		}
	}
	return false
}

// AuditLinkInvariants checks shared post-match rules for a device-hour batch.
func AuditLinkInvariants(candidates []CDRCandidate, results []MatchResult) []string {
	var issues []string
	if len(candidates) != len(results) {
		return []string{"candidate/result length mismatch"}
	}
	used := map[string]int{}
	for i, result := range results {
		if result.CardURL != "" &&
			result.Status != StatusMatchedExact && result.Status != StatusMatchedFallback {
			issues = append(issues, fmt.Sprintf("url_without_match_status[%d]=%s", i, result.Status))
		}
		if result.CardURL != "" &&
			(strings.Contains(result.CardURL, "fId:") ||
				strings.Contains(result.CardURL, "fId%3A") ||
				strings.Contains(result.CardURL, "fId%3a")) {
			issues = append(issues, fmt.Sprintf("legacy_fid_url[%d]", i))
		}
		if (result.Status == StatusUnmatched || result.Status == StatusAmbiguous) &&
			result.MissReason == "" {
			var ev map[string]any
			_ = json.Unmarshal([]byte(result.EvidenceJSON), &ev)
			if _, ok := ev["miss_reason"]; !ok {
				issues = append(issues, fmt.Sprintf("missing_miss_reason[%d]", i))
			}
		}
		if result.Status == StatusMatchedFallback {
			var ev map[string]any
			_ = json.Unmarshal([]byte(result.EvidenceJSON), &ev)
			if hits, ok := ev["call_id_hits"].(float64); ok && hits != 0 {
				issues = append(issues, fmt.Sprintf("fallback_with_call_id_hits[%d]", i))
			}
		}
		if !AuditExactCallIDInvariant(candidates[i], result) {
			issues = append(issues, fmt.Sprintf("exact_call_id_invariant[%d]", i))
		}
		if result.VM != nil && result.VM.CDRID != "" &&
			(result.Status == StatusMatchedExact || result.Status == StatusMatchedFallback) {
			if prev, ok := used[result.VM.CDRID]; ok {
				issues = append(issues, fmt.Sprintf("duplicate_vm_cdr_id[%d,%d]=%s", prev, i, result.VM.CDRID))
			} else {
				used[result.VM.CDRID] = i
			}
		}
	}
	return issues
}
