package voipmonitor

import (
	"time"

	"github.com/google/uuid"
)

const (
	SourceEltex = "eltex_smg"
	SourceSatel = "satel_rtu"

	StatusMatchedExact    = "matched_exact"
	StatusMatchedFallback = "matched_fallback"
	StatusUnmatched       = "unmatched"
	StatusAmbiguous       = "ambiguous"

	MissCallIDNotInIndex       = "call_id_not_in_index"
	MissEmptyCallIDWeakSignal  = "empty_callid_and_weak_signal"
	MissFallbackBelowThreshold = "fallback_below_threshold"
	MissFallbackAmbiguous      = "fallback_ambiguous"
	MissAssignedElsewhere      = "assigned_elsewhere"
	MissNoCandidatesInWindow   = "no_candidates_in_window"
	MissAPIError               = "api_error"
)

type CDRCandidate struct {
	DeviceID             uuid.UUID
	SourceSystem         string
	SourceRecordID       uuid.UUID
	SourceCDRID          string
	SourceCallID         string
	SourceProtocolConfID string
	SourceCallIDOutProto string
	SetupTime            time.Time
	DurationSec          *int64
	ConnectDurationSec   *int64
	Caller               string
	Called               string
	CallerNumbers        []string
	CalledNumbers        []string
	CallerIP             string
	CalledIP             string
	ReleaseCause         *uint16
	SIPCallIDs           []string // priority order; also used for Call-ID index lookup
	EventMonth           time.Time
}

type VMCall struct {
	CDRID           string
	CallID          string
	CallDate        time.Time
	CallEnd         time.Time
	Duration        int64
	ConnectDuration int64
	Caller          string
	Called          string
	SIPCallerIP     string
	SIPCalledIP     string
	LastSIPResponse int64
	SensorID        int64
}

type MatchResult struct {
	Status       string
	Method       string
	Score        uint8
	VM           *VMCall
	CardURL      string
	EvidenceJSON string
	MatchedAt    *time.Time
	MissReason   string
}

// Link is the persisted VoIPmonitor correlation row written to ClickHouse.
type Link struct {
	DeviceID             uuid.UUID
	SourceSystem         string
	SourceRecordID       uuid.UUID
	SourceCDRID          string
	SourceCallID         string
	SourceProtocolConfID string
	SourceCallIDOutProto string
	PolicyRevision       uint64
	ProjectionSeq        uint64
	VoipmonitorCDRID     string
	VoipmonitorCallID    string
	VoipmonitorCardURL   string
	MatchMethod          string
	MatchScore           uint8
	MatchStatus          string
	MatchEvidenceJSON    string
	MatchedAt            *time.Time
	EventMonth           time.Time
}

type CardURLParts struct {
	GUIBase  string
	CDRID    string
	CallID   string
	CallDate time.Time // optional; narrows fcallid deep-link with fdatefrom/fdateto
}
