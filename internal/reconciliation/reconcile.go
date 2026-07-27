package reconciliation

import (
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const Version uint32 = 1

type State string

const (
	StateExpected      State = "expected"
	StateAwaitingCDR   State = "awaiting_cdr"
	StateMatched       State = "matched"
	StateLate          State = "late"
	StateMissing       State = "missing"
	StateNotApplicable State = "not_applicable"
)

type Config struct {
	ExpectedGrace   time.Duration
	LateThreshold   time.Duration
	MissingTerminal time.Duration
	RetryHorizon    time.Duration
}

func (c Config) normalized() Config {
	if c.ExpectedGrace <= 0 {
		c.ExpectedGrace = 5 * time.Minute
	}
	if c.LateThreshold <= 0 {
		c.LateThreshold = c.ExpectedGrace
	}
	if c.MissingTerminal <= 0 {
		c.MissingTerminal = 30 * time.Minute
	}
	if c.RetryHorizon <= 0 {
		c.RetryHorizon = 7 * 24 * time.Hour
	}
	return c
}

type CDR struct {
	ID              uuid.UUID
	DeviceID        uuid.UUID
	EventTime       time.Time
	IngestedAt      time.Time
	AcctSessionID   string
	H323FieldValues []string
	Calling         string
	Called          string
	Enabled         bool
	PolicyRevision  uint64
}

type Call struct {
	ID             uuid.UUID
	DeviceID       uuid.UUID
	EventTime      time.Time
	AcctSessionID  string
	H323ConfID     string
	Calling        string
	Called         string
	PolicyRevision uint64
}

type Assignment struct {
	CDRID           uuid.UUID
	CallID          uuid.UUID
	Method          string
	Reason          string
	Delta           time.Duration
	MatchedEvidence map[string]string
	Version         uint32
}

type Coverage struct {
	CDRID           uuid.UUID
	State           State
	ExpectedAt      time.Time
	GraceExpiresAt  time.Time
	MissingAt       time.Time
	RetryUntil      time.Time
	Assignment      *Assignment
	Ambiguous       bool
	AmbiguityReason string
	Reason          string
}

type CallCoverage struct {
	CallID uuid.UUID
	State  State
}

type Result struct {
	Coverage     []Coverage
	Calls        []CallCoverage
	Assignments  []Assignment
	NextDeadline *time.Time
}

func Reconcile(config Config, now time.Time, cdrs []CDR, calls []Call) Result {
	config = config.normalized()
	result := Result{}
	usedCalls := make(map[uuid.UUID]bool)
	usedCDRs := make(map[uuid.UUID]bool)
	sort.SliceStable(cdrs, func(i, j int) bool {
		if cdrs[i].EventTime.Equal(cdrs[j].EventTime) {
			return cdrs[i].ID.String() < cdrs[j].ID.String()
		}
		return cdrs[i].EventTime.Before(cdrs[j].EventTime)
	})
	for _, cdr := range cdrs {
		coverage := baseCoverage(config, cdr)
		if !cdr.Enabled {
			coverage.State, coverage.Reason = StateNotApplicable, "device_disabled"
			result.Coverage = append(result.Coverage, coverage)
			continue
		}
		candidates, method := candidatesFor(cdr, calls)
		if len(candidates) > 1 {
			coverage.Ambiguous = true
			coverage.AmbiguityReason = method + "_multiple_candidates"
			coverage.Reason = "ambiguous"
			coverage.State = ageState(config, now, cdr.EventTime)
			result.Coverage = append(result.Coverage, coverage)
			scheduleCoverageDeadline(&result, coverage, now)
			continue
		}
		if len(candidates) == 1 {
			call := candidates[0]
			if usedCalls[call.ID] {
				coverage.Ambiguous = true
				coverage.AmbiguityReason = "call_already_assigned"
				coverage.Reason = "one_to_one_collision"
				coverage.State = ageState(config, now, cdr.EventTime)
				result.Coverage = append(result.Coverage, coverage)
				scheduleCoverageDeadline(&result, coverage, now)
				continue
			}
			assignment := Assignment{
				CDRID: cdr.ID, CallID: call.ID, Method: method, Reason: "unique_" + method,
				Delta: call.EventTime.Sub(cdr.EventTime), Version: Version,
				MatchedEvidence: map[string]string{},
			}
			if method == "acct_session_id" {
				assignment.MatchedEvidence["acct_session_id"] = normalize(cdr.AcctSessionID)
			} else {
				assignment.MatchedEvidence["h323_conf_id"] = normalize(call.H323ConfID)
			}
			if cdr.Calling != "" && normalize(cdr.Calling) == normalize(call.Calling) {
				assignment.MatchedEvidence["calling"] = "supporting"
			}
			if cdr.Called != "" && normalize(cdr.Called) == normalize(call.Called) {
				assignment.MatchedEvidence["called"] = "supporting"
			}
			coverage.State = StateMatched
			if cdr.IngestedAt.Sub(call.EventTime) > config.LateThreshold {
				coverage.State = StateLate
			}
			coverage.Reason = assignment.Reason
			coverage.Assignment = &assignment
			result.Assignments = append(result.Assignments, assignment)
			usedCalls[call.ID], usedCDRs[cdr.ID] = true, true
		} else {
			coverage.State = ageState(config, now, cdr.EventTime)
			coverage.Reason = "no_identity_match"
		}
		result.Coverage = append(result.Coverage, coverage)
		scheduleCoverageDeadline(&result, coverage, now)
	}
	for _, call := range calls {
		state := StateAwaitingCDR
		if usedCalls[call.ID] {
			state = StateMatched
		}
		result.Calls = append(result.Calls, CallCoverage{CallID: call.ID, State: state})
	}
	_ = usedCDRs
	return result
}

func scheduleCoverageDeadline(result *Result, coverage Coverage, now time.Time) {
	if coverage.Assignment == nil && now.Before(coverage.MissingAt) &&
		(result.NextDeadline == nil || coverage.MissingAt.Before(*result.NextDeadline)) {
		deadline := coverage.MissingAt
		result.NextDeadline = &deadline
	}
}

func candidatesFor(cdr CDR, calls []Call) ([]Call, string) {
	session := normalize(cdr.AcctSessionID)
	if session != "" {
		var matches []Call
		for _, call := range calls {
			if call.DeviceID == cdr.DeviceID &&
				cdr.PolicyRevision != 0 && call.PolicyRevision == cdr.PolicyRevision &&
				normalize(call.AcctSessionID) == session {
				matches = append(matches, call)
			}
		}
		return matches, "acct_session_id"
	}
	values := make(map[string]struct{})
	for _, value := range cdr.H323FieldValues {
		if normalized := normalize(value); normalized != "" {
			values[normalized] = struct{}{}
		}
	}
	if len(values) == 0 {
		return nil, "none"
	}
	var matches []Call
	for _, call := range calls {
		_, present := values[normalize(call.H323ConfID)]
		if call.DeviceID == cdr.DeviceID &&
			cdr.PolicyRevision != 0 && call.PolicyRevision == cdr.PolicyRevision &&
			call.H323ConfID != "" && present {
			matches = append(matches, call)
		}
	}
	return matches, "h323_conf_id"
}

func baseCoverage(config Config, cdr CDR) Coverage {
	return Coverage{
		CDRID: cdr.ID, State: StateExpected, ExpectedAt: cdr.IngestedAt,
		GraceExpiresAt: cdr.EventTime.Add(config.ExpectedGrace),
		MissingAt:      cdr.EventTime.Add(config.MissingTerminal),
		RetryUntil:     cdr.EventTime.Add(config.RetryHorizon),
	}
}

func ageState(config Config, now, eventTime time.Time) State {
	if !now.Before(eventTime.Add(config.MissingTerminal)) {
		return StateMissing
	}
	return StateExpected
}

func normalize(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}
