package voipmonitor

import (
	"time"

	"github.com/google/uuid"
)

const (
	SourceEltex = "eltex_smg"
	SourceSatel = "satel_rtu"

	StatusPending         = "pending"
	StatusMatchedExact    = "matched_exact"
	StatusMatchedFallback = "matched_fallback"
	StatusUnmatched       = "unmatched"
	StatusAmbiguous       = "ambiguous"
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
	CallerIP             string
	CalledIP             string
	ReleaseCause         *uint16
	SIPCallIDs           []string // Eltex preferred; Satel trial keys also listed here in priority order
	EventMonth           time.Time
}

type VMCall struct {
	CDRID            string
	CallID           string
	CallDate         time.Time
	CallEnd          time.Time
	Duration         int64
	ConnectDuration  int64
	Caller           string
	Called           string
	SIPCallerIP      string
	SIPCalledIP      string
	LastSIPResponse  int64
	SensorID         int64
}

type MatchResult struct {
	Status       string
	Method       string
	Score        uint8
	VM           *VMCall
	CardURL      string
	EvidenceJSON string
	MatchedAt    *time.Time
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
	GUIBase string
	CDRID   string
	CallID  string
}
