// Package customradius derives Custom AntiFraud RADIUS packets and calls from
// immutable raw syslog events. It deliberately has no persistence dependency.
package customradius

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type Family string

const (
	FamilyIndication   Family = "indication"
	FamilyVerification Family = "verification"
	FamilyAccounting   Family = "accounting"
	FamilyUnknown      Family = "unknown"
)

type Phase string

const (
	PhaseStart   Phase = "start"
	PhaseMid     Phase = "mid"
	PhaseEnd     Phase = "end"
	PhaseUnknown Phase = "unknown"
)

type Decision string

const (
	DecisionInfoOnly            Decision = "info_only"
	DecisionAllow               Decision = "allow"
	DecisionDeny                Decision = "deny"
	DecisionAcknowledgement     Decision = "acknowledgement"
	DecisionUnavailableFallback Decision = "unavailable_fallback"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
	DirectionUnknown  Direction = "unknown"
)

type PacketStatus string

const (
	PacketPending   PacketStatus = "pending"
	PacketPaired    PacketStatus = "paired"
	PacketOrphan    PacketStatus = "orphan"
	PacketAmbiguous PacketStatus = "ambiguous"
	PacketUnmatched PacketStatus = "unmatched"
)

type CallStatus string

const (
	CallBlocked       CallStatus = "blocked"
	CallUnavailable   CallStatus = "unavailable_fallback"
	CallIndeterminate CallStatus = "ambiguous_indeterminate"
	CallVerified      CallStatus = "verified"
	CallCompleted     CallStatus = "completed"
	CallOpen          CallStatus = "open"
	CallPending       CallStatus = "pending"
)

// RawEvent is the complete and only input model. Payload is consumed during
// parsing and is never retained in Packet, Call, Result, or their JSON forms.
type RawEvent struct {
	EventID    uuid.UUID `json:"eventId"`
	DeviceID   uuid.UUID `json:"deviceId"`
	ReceivedAt time.Time `json:"receivedAt"`
	SourceIP   string    `json:"sourceIp"`
	SourcePort uint16    `json:"sourcePort"`
	Transport  string    `json:"transport,omitempty"`
	Payload    []byte    `json:"payload"`
}

// EventProvenance identifies a raw event without retaining its payload.
type EventProvenance struct {
	EventID    uuid.UUID `json:"eventId"`
	DeviceID   uuid.UUID `json:"deviceId"`
	ReceivedAt time.Time `json:"receivedAt"`
	SourceIP   string    `json:"sourceIp"`
	SourcePort uint16    `json:"sourcePort"`
}

type Explanation struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

// Attribute preserves source order and display spelling. Secret values are
// removed at tokenization time; Value and RawValue are empty when Redacted.
type Attribute struct {
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName,omitempty"`
	Value       string    `json:"value,omitempty"`
	RawValue    string    `json:"rawValue,omitempty"`
	NumericID   *int      `json:"numericId,omitempty"`
	Redacted    bool      `json:"redacted,omitempty"`
	EventID     uuid.UUID `json:"eventId"`
}

type Participants struct {
	Calling string `json:"calling,omitempty"`
	Called  string `json:"called,omitempty"`
}

type CallKey struct {
	AcctSessionID        string `json:"acctSessionId,omitempty"`
	AcctSessionIDDisplay string `json:"acctSessionIdDisplay,omitempty"`
	H323ConfID           string `json:"h323ConfId,omitempty"`
	H323ConfIDDisplay    string `json:"h323ConfIdDisplay,omitempty"`
	// Context is the Eltex SMG call lane ([C…]) for assembly/pairing only.
	// Logical Call identity prefers h323-conf-id, else Acct-Session-Id.
	Context        string `json:"context,omitempty"`
	ContextDisplay string `json:"contextDisplay,omitempty"`
	Calling        string `json:"calling,omitempty"`
	Called         string `json:"called,omitempty"`
}

type Packet struct {
	ID                    uuid.UUID         `json:"id"`
	IsAntifraud           bool              `json:"is_antifraud"`
	Family                Family            `json:"family"`
	RadiusType            string            `json:"radius_type"`
	Direction             Direction         `json:"direction"`
	Identifier            *uint8            `json:"identifier,omitempty"`
	CallKey               CallKey           `json:"callKey"`
	Phase                 Phase             `json:"phase"`
	Decision              Decision          `json:"decision"`
	Confidence            Confidence        `json:"confidence"`
	Status                PacketStatus      `json:"status"`
	RequestID             *uuid.UUID        `json:"requestId,omitempty"`
	ResponseID            *uuid.UUID        `json:"responseId,omitempty"`
	AttemptIDs            []uuid.UUID       `json:"attemptIds,omitempty"`
	Attributes            []Attribute       `json:"attributes"`
	Provenance            []EventProvenance `json:"provenance"`
	Explanations          []Explanation     `json:"explanations"`
	Warnings              []Explanation     `json:"warnings,omitempty"`
	CallContext           string            `json:"callContext,omitempty"`
	Component             string            `json:"component,omitempty"`
	Server                string            `json:"server,omitempty"`
	ResponseLatencyMillis *int64            `json:"responseLatencyMillis,omitempty"`
	FirstSeenAt           time.Time         `json:"firstSeenAt"`
	LastSeenAt            time.Time         `json:"lastSeenAt"`
}

type PacketPhase struct {
	Phase      Phase      `json:"phase"`
	RequestID  *uuid.UUID `json:"requestId,omitempty"`
	ResponseID *uuid.UUID `json:"responseId,omitempty"`
}

type Accounting struct {
	StartTime            *time.Time `json:"startTime,omitempty"`
	StopTime             *time.Time `json:"stopTime,omitempty"`
	SetupTime            *time.Time `json:"setupTime,omitempty"`
	ConnectTime          *time.Time `json:"connectTime,omitempty"`
	DisconnectTime       *time.Time `json:"disconnectTime,omitempty"`
	EventTimestamp       *time.Time `json:"eventTimestamp,omitempty"`
	TerminateCause       string     `json:"terminateCause,omitempty"`
	DisconnectCauseQ850  *int64     `json:"disconnectCauseQ850,omitempty"`
	SessionDuration      *int64     `json:"sessionDurationSeconds,omitempty"`
	DelayTimeSec         *int64     `json:"delayTimeSec,omitempty"`
}

// Routing holds optional Custom Eltex AVP context for a logical call.
type Routing struct {
	OriginatingIP      string `json:"originatingIp,omitempty"`
	TerminationIP      string `json:"terminationIp,omitempty"`
	SrcNumberIn        string `json:"srcNumberIn,omitempty"`
	DstNumberIn        string `json:"dstNumberIn,omitempty"`
	SrcNumberOut       string `json:"srcNumberOut,omitempty"`
	DstNumberOut       string `json:"dstNumberOut,omitempty"`
	RedirectNumber     string `json:"redirectNumber,omitempty"`
	RemoteID           string `json:"remoteId,omitempty"`
	OutTrunkgroupLabel string `json:"outTrunkgroupLabel,omitempty"`
	InTrunkgroupLabel  string `json:"inTrunkgroupLabel,omitempty"`
	CallOrigin         string `json:"callOrigin,omitempty"`
	CallType           string `json:"callType,omitempty"`
	NASPort            string `json:"nasPort,omitempty"`
	NASPortType        string `json:"nasPortType,omitempty"`
	FramedIPAddress    string `json:"framedIpAddress,omitempty"`
}

type Call struct {
	ID                  uuid.UUID         `json:"id"`
	Key                 CallKey           `json:"key"`
	AcctSessionIDs      []string          `json:"acctSessionIds,omitempty"`
	Participants        Participants      `json:"participants"`
	Indicators          []string          `json:"indicators"`
	Phases              []PacketPhase     `json:"phases"`
	Attributes          []Attribute       `json:"attributes"`
	Accounting          Accounting        `json:"accounting"`
	Routing             Routing           `json:"routing,omitempty"`
	IndicationAcked     bool              `json:"indicationAcked"`
	VerificationResult  string            `json:"verificationResult,omitempty"`
	AccountingAcked     bool              `json:"accountingAcked"`
	FinalDecision       string            `json:"finalDecision,omitempty"`
	Packets             []Packet          `json:"packets"`
	Unmatched           []EventProvenance `json:"unmatched"`
	Orphans             []uuid.UUID       `json:"orphans"`
	Explanations        []Explanation     `json:"explanations"`
	Status              CallStatus        `json:"status"`
}

type UnmatchedFact struct {
	Provenance  EventProvenance `json:"provenance"`
	Reason      string          `json:"reason"`
	Attributes  []Attribute     `json:"attributes,omitempty"`
	Explanation Explanation     `json:"explanation"`
	CallContext string          `json:"callContext,omitempty"`
	Component   string          `json:"component,omitempty"`
}

type Result struct {
	Packets      []Packet        `json:"packets"`
	Calls        []Call          `json:"calls"`
	Unmatched    []UnmatchedFact `json:"unmatched"`
	NextDeadline *time.Time      `json:"nextDeadline,omitempty"`
}

// MarshalJSON exists to make the no-payload public contract explicit.
func (r Result) MarshalJSON() ([]byte, error) {
	type public Result
	return json.Marshal(public(r))
}

type Config struct {
	Enabled         bool
	ResponseTimeout time.Duration
	PairingHorizon  time.Duration
	RetryHorizon    time.Duration
	AssemblyIdle    time.Duration
	MaxMembers      int
	MaxBytes        int
}

func (c Config) normalized() Config {
	if c.ResponseTimeout <= 0 {
		c.ResponseTimeout = 5 * time.Second
	}
	if c.PairingHorizon <= 0 {
		c.PairingHorizon = 5 * time.Minute
	}
	if c.RetryHorizon <= 0 {
		c.RetryHorizon = c.ResponseTimeout
	}
	if c.AssemblyIdle <= 0 {
		c.AssemblyIdle = 2 * time.Second
	}
	if c.AssemblyIdle > 2*time.Second {
		c.AssemblyIdle = 2 * time.Second
	}
	if c.MaxMembers <= 0 || c.MaxMembers > 128 {
		c.MaxMembers = 128
	}
	if c.MaxBytes <= 0 || c.MaxBytes > 64<<10 {
		c.MaxBytes = 64 << 10
	}
	return c
}
