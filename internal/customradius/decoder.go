package customradius

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type EnvelopeKind string

const (
	EnvelopeHeader     EnvelopeKind = "header"
	EnvelopeAttributes EnvelopeKind = "attributes"
	EnvelopeStatus     EnvelopeKind = "status"
	EnvelopeOther      EnvelopeKind = "other"
)

// Envelope is a payload-free decoded event fact.
type Envelope struct {
	Kind                  EnvelopeKind    `json:"kind"`
	RadiusType            string          `json:"radiusType,omitempty"`
	Direction             Direction       `json:"direction,omitempty"`
	Identifier            *uint8          `json:"identifier,omitempty"`
	ExplicitAF            bool            `json:"explicitAntifraud,omitempty"`
	CallContext           string          `json:"callContext,omitempty"`
	Server                string          `json:"server,omitempty"`
	Attributes            []Attribute     `json:"attributes,omitempty"`
	Warnings              []Explanation   `json:"warnings,omitempty"`
	Provenance            EventProvenance `json:"provenance"`
	Component             string          `json:"component,omitempty"`
	ResponseLatencyMillis *int64          `json:"responseLatencyMillis,omitempty"`
}

var (
	standardHeader     = regexp.MustCompile(`(?i)\b(Access|Accounting)[- ](Request|Accept|Reject|Response|Reply)\b(?:\s*\[(\d+)\]|\s+(?:Request\s+)?ID\s*[:=]?\s*(\d+))?`)
	accsHeader         = regexp.MustCompile(`(?i)\bAccs-(Request|Reply)\b(?:\s*\[(\d+)\])?`)
	antifraudHeader    = regexp.MustCompile(`(?i)\bAntifraud-Auth-Request\b(?:\s*\[(\d+)\])?`)
	antifraudRequestID = regexp.MustCompile(`(?i)\bRequest\s+ID\s*\[(\d+)\]\s+(?:process\s+)?Antifraud-Auth-Request\b`)
	procReply          = regexp.MustCompile(`(?i)\bProc\s+Reply\.\s*Request\s+ID\s*\[(\d+)\]\s*Accs-Reply\s*\[(accept|reject)\]\.\s*Time\s*\[(\d+):(\d+)\]`)
	procReplyLoose     = regexp.MustCompile(`(?i)\bProc\s+Reply\.?\s+Request\s+ID\s*(?:\[(\d+)\]|[:=]?\s*(\d+)).*?\[?(accept|reject)\]?`)
	contextPattern     = regexp.MustCompile(`\[(C[A-Za-z0-9_.:-]+)\]`)
	serverPattern      = regexp.MustCompile(`(?i)\bserver\s+([A-Za-z0-9_.-]+(?::\d+)?)`)
	acceptedStatus     = regexp.MustCompile(`(?i)\b(?:server\s+)?accepted\b`)
	rejectedStatus     = regexp.MustCompile(`(?i)\b(?:server\s+)?rejected\b`)
	falseCDRReject     = regexp.MustCompile(`(?i)\bserver rejected:\s*:0\s*\(replied 0\)`)
)

// DecodeEnvelope recognizes Eltex RADIUS forms without retaining the payload.
func DecodeEnvelope(event RawEvent) Envelope {
	text := string(event.Payload)
	tokenized := Tokenize(event.Payload, event.EventID)
	envelope := Envelope{
		Kind: EnvelopeOther, Direction: DirectionUnknown,
		Attributes: tokenized.Attributes, Warnings: tokenized.Warnings,
		Provenance: provenance(event),
	}
	if context := contextPattern.FindStringSubmatch(text); len(context) > 1 {
		envelope.CallContext = strings.ToLower(context[1])
	}
	if strings.Contains(strings.ToLower(text), "radius") ||
		strings.Contains(strings.ToLower(text), "accs-") {
		envelope.Component = "radius"
	}
	if server := serverPattern.FindStringSubmatch(text); len(server) > 1 {
		envelope.Server = strings.ToLower(server[1])
	}

	if match := procReply.FindStringSubmatch(text); match != nil {
		envelope.Kind = EnvelopeStatus
		envelope.Direction = DirectionResponse
		envelope.Identifier = parsePacketID(match[1], &envelope.Warnings)
		if strings.EqualFold(match[2], "accept") {
			envelope.RadiusType = "access-accept"
		} else {
			envelope.RadiusType = "access-reject"
		}
		seconds, _ := strconv.ParseInt(match[3], 10, 64)
		fraction, _ := strconv.ParseInt(match[4], 10, 64)
		latency := seconds*1000 + fraction
		envelope.ResponseLatencyMillis = &latency
		return envelope
	}
	if match := procReplyLoose.FindStringSubmatch(text); match != nil {
		envelope.Kind = EnvelopeStatus
		envelope.Direction = DirectionResponse
		id := match[1]
		if id == "" {
			id = match[2]
		}
		envelope.Identifier = parsePacketID(id, &envelope.Warnings)
		if strings.EqualFold(match[3], "accept") {
			envelope.RadiusType = "access-accept"
		} else {
			envelope.RadiusType = "access-reject"
		}
		return envelope
	}
	if match := antifraudRequestID.FindStringSubmatch(text); match != nil {
		envelope.Kind = EnvelopeHeader
		envelope.RadiusType = "access-request"
		envelope.Direction = DirectionRequest
		envelope.ExplicitAF = true
		envelope.Identifier = parsePacketID(match[1], &envelope.Warnings)
		return envelope
	}
	if match := antifraudHeader.FindStringSubmatch(text); match != nil {
		envelope.Kind = EnvelopeHeader
		envelope.RadiusType = "access-request"
		envelope.Direction = DirectionRequest
		envelope.ExplicitAF = true
		envelope.Identifier = parsePacketID(match[1], &envelope.Warnings)
		return envelope
	}
	if match := standardHeader.FindStringSubmatch(text); match != nil {
		envelope.Kind = EnvelopeHeader
		family := strings.ToLower(match[1])
		action := strings.ToLower(match[2])
		envelope.RadiusType, envelope.Direction = standardRadiusType(family, action)
		id := match[3]
		if id == "" {
			id = match[4]
		}
		envelope.Identifier = parsePacketID(id, &envelope.Warnings)
		return envelope
	}
	if match := accsHeader.FindStringSubmatch(text); match != nil {
		envelope.Kind = EnvelopeHeader
		envelope.Identifier = parsePacketID(match[2], &envelope.Warnings)
		if strings.EqualFold(match[1], "request") {
			envelope.RadiusType, envelope.Direction = "access-request", DirectionRequest
		} else {
			envelope.RadiusType, envelope.Direction = "access-response", DirectionResponse
		}
		return envelope
	}
	if falseCDRReject.MatchString(text) {
		envelope.Kind = EnvelopeOther
		envelope.Attributes = nil
		envelope.Warnings = append(envelope.Warnings, Explanation{
			Code: "custom.guard.cdr_reject",
			Text: "A CDR dump server-rejected field was explicitly excluded from RADIUS.",
		})
		return envelope
	}
	if acceptedStatus.MatchString(text) {
		envelope.Kind, envelope.RadiusType, envelope.Direction = EnvelopeStatus, "access-accept", DirectionResponse
		return envelope
	}
	if rejectedStatus.MatchString(text) {
		envelope.Kind, envelope.RadiusType, envelope.Direction = EnvelopeStatus, "access-reject", DirectionResponse
		return envelope
	}
	if len(envelope.Attributes) > 0 {
		envelope.Kind = EnvelopeAttributes
	}
	return envelope
}

func standardRadiusType(family, action string) (string, Direction) {
	if family == "accounting" {
		if action == "request" {
			return "accounting-request", DirectionRequest
		}
		return "accounting-response", DirectionResponse
	}
	switch action {
	case "request":
		return "access-request", DirectionRequest
	case "accept":
		return "access-accept", DirectionResponse
	case "reject":
		return "access-reject", DirectionResponse
	default:
		return "access-response", DirectionResponse
	}
}

func parsePacketID(value string, warnings *[]Explanation) *uint8 {
	if value == "" {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 || parsed > 255 {
		*warnings = append(*warnings, Explanation{
			Code: "custom.packet.invalid_identifier",
			Text: "The packet identifier was outside the RADIUS range 0 through 255.",
		})
		return nil
	}
	result := uint8(parsed)
	return &result
}

func provenance(event RawEvent) EventProvenance {
	return EventProvenance{
		EventID: event.EventID, DeviceID: event.DeviceID, ReceivedAt: event.ReceivedAt,
		SourceIP: event.SourceIP, SourcePort: event.SourcePort,
	}
}

func eventIDString(id uuid.UUID) string {
	if id == uuid.Nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	return id.String()
}
