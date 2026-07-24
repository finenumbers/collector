package ingest

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"collector/internal/analytics"

	"github.com/google/uuid"
)

var sequencePattern = regexp.MustCompile(`^([0-9]{14})-([0-9]+)$`)

type CDRParser struct {
	DeviceID         uuid.UUID
	FileID           uuid.UUID
	Location         *time.Location
	TimezoneRevision uint64
	ExpectedHeader   []string
}

type CDRResult struct {
	Records []analytics.CDRRecord
	Errors  []error
	Header  []string
	Rows    uint64
}

func (p CDRParser) Parse(reader io.Reader) (CDRResult, error) {
	if p.Location == nil {
		p.Location = time.UTC
	}
	decoder := csv.NewReader(reader)
	decoder.Comma = ';'
	decoder.FieldsPerRecord = -1
	decoder.LazyQuotes = true
	decoder.TrimLeadingSpace = false

	first, err := decoder.Read()
	if err != nil {
		return CDRResult{}, err
	}
	first = trimTrailingEmpty(first)
	var header []string
	var pending []string
	if isBanner(first) {
		header, err = decoder.Read()
		if err != nil {
			return CDRResult{}, fmt.Errorf("CDR banner is not followed by a header or record: %w", err)
		}
		header = trimTrailingEmpty(header)
	} else {
		header = first
	}
	if !looksLikeHeader(header) {
		if len(p.ExpectedHeader) == 0 {
			return CDRResult{}, errors.New("CDR has no field-name row and no configured field profile")
		}
		header = p.ExpectedHeader
		pending = first
	}
	normalized := make([]string, len(header))
	for index, value := range header {
		normalized[index] = normalizeColumn(value)
	}
	result := CDRResult{Header: header, Records: make([]analytics.CDRRecord, 0, 1024)}
	for {
		var row []string
		var readErr error
		if pending != nil {
			row, pending = pending, nil
		} else {
			row, readErr = decoder.Read()
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		result.Rows++
		if readErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("row %d: %w", result.Rows, readErr))
			continue
		}
		row = trimTrailingEmpty(row)
		if len(row) != len(normalized) {
			result.Errors = append(result.Errors,
				fmt.Errorf("row %d: got %d fields, expected %d", result.Rows, len(row), len(normalized)))
			continue
		}
		fields := make(map[string]string, len(row))
		for index, value := range row {
			fields[normalized[index]] = strings.TrimSpace(value)
		}
		record, parseErr := p.mapRecord(result.Rows, fields)
		if parseErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("row %d: %w", result.Rows, parseErr))
			continue
		}
		result.Records = append(result.Records, record)
	}
	return result, nil
}

func (p CDRParser) mapRecord(row uint64, fields map[string]string) (analytics.CDRRecord, error) {
	setup, err := parseCDRTime(fields["setup_time"], p.Location)
	if err != nil {
		return analytics.CDRRecord{}, fmt.Errorf("setup time: %w", err)
	}
	connect, err := parseCDRTime(fields["connect_time"], p.Location)
	if err != nil {
		return analytics.CDRRecord{}, fmt.Errorf("connect time: %w", err)
	}
	disconnect, err := parseCDRTime(fields["disconnect_time"], p.Location)
	if err != nil {
		return analytics.CDRRecord{}, fmt.Errorf("disconnect time: %w", err)
	}
	sequenceNumber := fields["sequence_number"]
	var bootEpoch string
	var sequence uint64
	if match := sequencePattern.FindStringSubmatch(sequenceNumber); match != nil {
		bootEpoch = match[1]
		sequence, _ = strconv.ParseUint(match[2], 10, 64)
	}
	radiusSessionID := fields["radius_accounting_session_id"]
	recordIDKey := p.DeviceID.String() + "|" + sequenceNumber
	if sequenceNumber == "" {
		recordIDKey = p.DeviceID.String() + "|" + p.FileID.String() + "|" + strconv.FormatUint(row, 10)
	}
	offsetAt := time.Now().UTC()
	if setup != nil {
		offsetAt = *setup
	}
	_, offsetSeconds := offsetAt.In(p.Location).Zone()
	return analytics.CDRRecord{
		RecordID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(recordIDKey)),
		DeviceID: p.DeviceID, FileID: p.FileID, RowNumber: row,
		IngestedAt: time.Now().UTC(), SequenceNumber: sequenceNumber, BootEpoch: bootEpoch,
		Sequence: sequence, SetupTime: setup, ConnectTime: connect, DisconnectTime: disconnect,
		DurationMS: parseDuration(fields["duration"]), ReleaseCause: parseUint16(fields["release_cause"]),
		ReleaseInfo: fields["call_release_info"], ReleaseSide: fields["release_side_mark"],
		IncomingIP: parseIP(fields["incoming_ip_address"]), OutgoingIP: parseIP(fields["outgoing_ip_address"]),
		IncomingType: fields["incoming_type"], OutgoingType: fields["outgoing_type"],
		IncomingDescription: fields["incoming_description"], OutgoingDescription: fields["outgoing_description"],
		IncomingCgPN: fields["incoming_cgpn"], OutgoingCgPN: fields["outgoing_cgpn"],
		IncomingCdPN: fields["incoming_cdpn"], OutgoingCdPN: fields["outgoing_cdpn"],
		IncomingRedirectingNumber: fields["incoming_redirecting_number"],
		OutgoingRedirectingNumber: fields["outgoing_redirecting_number"],
		IncomingNumplan:           fields["incoming_numplan"], OutgoingNumplan: fields["outgoing_numplan"],
		CallingNAI: fields["calling_nai"], CalledNAI: fields["called_nai"],
		IncomingE1Stream: fields["incoming_e1_stream"], IncomingE1Channel: fields["incoming_e1_channel"],
		OutgoingE1Stream: fields["outgoing_e1_stream"], OutgoingE1Channel: fields["outgoing_e1_channel"],
		IncomingSIPCallID: fields["incoming_sip_call_id"], OutgoingSIPCallID: fields["outgoing_sip_call_id"],
		IncomingSS7CIC: parseUint32(fields["incoming_ss7_cic"]), OutgoingSS7CIC: parseUint32(fields["outgoing_ss7_cic"]),
		RadiusSessionID: radiusSessionID, RadiusSessionIDNormalized: normalizeSessionID(radiusSessionID),
		GlobalCallref: fields["global_callref"], UniqueTag: fields["uniquetag_identifier"],
		TransferMark: fields["call_transfer_mark"], RejectingRadiusServer: fields["rejecting_radius_server_address"],
		RawFields: fields, SourceTimezone: p.Location.String(),
		SourceUTCOffsetMinutes: int16(offsetSeconds / 60),
		TimezoneRevision:       p.TimezoneRevision,
	}, nil
}

func normalizeColumn(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(value, "\ufeff"))
	var builder strings.Builder
	underscore := false
	for _, char := range strings.ToLower(value) {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			builder.WriteRune(char)
			underscore = false
			continue
		}
		if !underscore {
			builder.WriteByte('_')
			underscore = true
		}
	}
	return strings.Trim(builder.String(), "_")
}

func isBanner(record []string) bool {
	return len(record) == 1 && strings.Contains(strings.ToLower(record[0]), "cdr") &&
		strings.Contains(strings.ToLower(record[0]), "file started")
}

func looksLikeHeader(record []string) bool {
	if len(record) < 5 {
		return false
	}
	first := normalizeColumn(record[0])
	for _, field := range record {
		normalized := normalizeColumn(field)
		if normalized == "setup_time" || normalized == "connect_time" || normalized == "device_sign" {
			return true
		}
	}
	return first == "device_sign"
}

func trimTrailingEmpty(values []string) []string {
	if len(values) > 0 && strings.TrimSpace(values[len(values)-1]) == "" {
		return values[:len(values)-1]
	}
	return values
}

func parseCDRTime(value string, location *time.Location) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999", "2006-01-02 15:04:05"} {
		parsed, err := time.ParseInLocation(layout, value, location)
		if err == nil {
			utc := parsed.UTC()
			return &utc, nil
		}
	}
	return nil, fmt.Errorf("unsupported timestamp %q", value)
}

func parseDuration(value string) *uint64 {
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || seconds < 0 {
		return nil
	}
	millis := uint64(seconds * 1000)
	return &millis
}

func parseUint16(value string) *uint16 {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return nil
	}
	result := uint16(parsed)
	return &result
}

func parseUint32(value string) *uint32 {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return nil
	}
	result := uint32(parsed)
	return &result
}

func parseIP(value string) *net.IP {
	parsed := net.ParseIP(value)
	if parsed == nil {
		return nil
	}
	return &parsed
}

func normalizeSessionID(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), ""))
}
