package ingest

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"collector/internal/analytics"
	"collector/internal/equipment"

	"github.com/google/uuid"
)

var satelRTURequiredHeaders = []string{
	"cdr_id", "cdr_date", "setup_time", "connect_time", "disconnect_time",
	"in_ani", "in_dnis", "out_ani", "out_dnis", "bill_ani", "bill_dnis",
	"src_name", "dst_name", "dp_name",
	"disconnect_code", "disconnect_code_string", "disconnect_code_success",
	"disconnect_initiator",
}

// satelRTUCanonicalHeaders is the immutable 120-column Satel RTU signature.
// Parsing deliberately remains forward-compatible, while automatic template
// selection requires this exact normalized set.
var satelRTUCanonicalHeaders = []string{
	"cdr_id", "cdr_date", "in_ani", "in_dnis", "out_ani", "out_dnis", "bill_ani", "bill_dnis",
	"sig_node_name", "src_gatekeeper_address", "remote_src_sig_address", "remote_dst_sig_address",
	"remote_src_media_address", "remote_dst_media_address", "local_src_sig_address",
	"local_dst_sig_address", "local_src_media_address", "local_dst_media_address", "in_leg_proto",
	"out_leg_proto", "conf_id", "in_leg_call_id", "out_leg_call_id", "src_user", "dst_user",
	"radius_user", "src_name", "dst_name", "dp_name", "elapsed_time", "setup_time", "connect_time",
	"disconnect_time", "in_leg_codecs", "out_leg_codecs", "src_faststart_present",
	"dst_faststart_present", "src_tunneling_present", "dst_tunneling_present", "proxy_mode",
	"lar_fault_reason", "route_retries", "scd", "pdd", "media_group", "src_media_bytes_in",
	"src_media_bytes_out", "dst_media_bytes_in", "dst_media_bytes_out", "src_media_packets",
	"dst_media_packets", "src_media_packets_late", "dst_media_packets_late", "src_media_packets_lost",
	"dst_media_packets_lost", "src_min_jitter_size", "src_max_jitter_size", "dst_min_jitter_size",
	"dst_max_jitter_size", "last_cdr", "in_cpc", "out_cpc", "in_zone", "out_zone",
	"disconnect_initiator", "in_ani_type_of_number", "in_dnis_type_of_number",
	"out_ani_type_of_number", "out_dnis_type_of_number", "src_in_leg_conf_id",
	"src_in_leg_call_id", "src_out_leg_call_id", "in_orig_dnis", "out_orig_dnis", "record_type",
	"extradata", "term_elapsed_time", "term_setup_time", "term_connect_time", "term_disconnect_time",
	"term_scd", "term_pdd", "external_router", "radius_group", "in_ani_screening",
	"in_ani_presentation", "out_ani_screening", "out_ani_presentation", "outgoing_pulses",
	"incoming_pulses", "in_lrn", "retrieved_lrn", "lrn", "ext_lrn", "out_lrn", "lnp_server",
	"in_leg_transport_proto", "out_leg_transport_proto", "sip_routing_group", "looping_cycles",
	"auth_dnis", "ext_ani", "ext_dnis", "ext_sig_address", "in_partner_id", "out_partner_id",
	"disconnect_code_string", "disconnect_code_success", "src_disconnect_codes_string",
	"dst_disconnect_codes_string", "in_orig_dnis_type_of_number", "out_orig_dnis_type_of_number",
	"in_encryption", "out_encryption", "ext_ani_type_of_number", "ext_dnis_type_of_number",
	"ext_orig_dnis_type_of_number", "src_disconnect_codes", "dst_disconnect_codes",
	"disconnect_code",
}

type SatelRTUDetection struct {
	Match       bool
	Fingerprint string
	Reason      string
	Columns     int
}

func SatelRTUHeaderFingerprint(reader io.Reader) SatelRTUDetection {
	decoder := csv.NewReader(reader)
	decoder.Comma = ';'
	decoder.FieldsPerRecord = -1
	header, err := decoder.Read()
	if err != nil {
		return SatelRTUDetection{Reason: fmt.Sprintf("header read failed: %v", err)}
	}
	result := SatelRTUDetection{Columns: len(header)}
	names := make([]string, 0, len(header))
	seen := make(map[string]struct{}, len(header))
	for index, value := range header {
		name := normalizeColumn(value)
		if name == "" {
			result.Reason = fmt.Sprintf("column %d is empty", index+1)
			return result
		}
		if _, duplicate := seen[name]; duplicate {
			result.Reason = fmt.Sprintf("column %q is duplicated", name)
			return result
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	sum := sha256.Sum256([]byte(strings.Join(names, "\n")))
	result.Fingerprint = hex.EncodeToString(sum[:])
	if len(names) != len(satelRTUCanonicalHeaders) {
		result.Reason = fmt.Sprintf("got %d columns, require exact Satel set of %d", len(names), len(satelRTUCanonicalHeaders))
		return result
	}
	expected := append([]string(nil), satelRTUCanonicalHeaders...)
	sort.Strings(expected)
	for index := range expected {
		if names[index] != expected[index] {
			result.Reason = fmt.Sprintf("header set differs at %q (expected %q)", names[index], expected[index])
			return result
		}
	}
	result.Match = true
	result.Reason = "exact normalized Satel RTU 120-column header"
	return result
}

type SatelRTUCDRParser struct {
	DeviceID         uuid.UUID
	FileID           uuid.UUID
	Location         *time.Location
	TimezoneRevision uint64
}

type SatelRTUCDRResult struct {
	Records []analytics.SatelRTURecord
	Errors  []error
	Header  []string
	Rows    uint64
}

func (p SatelRTUCDRParser) Parse(reader io.Reader) (SatelRTUCDRResult, error) {
	if p.Location == nil {
		p.Location = time.UTC
	}
	decoder := csv.NewReader(reader)
	decoder.Comma = ';'
	decoder.FieldsPerRecord = -1
	decoder.ReuseRecord = false

	header, err := decoder.Read()
	if err != nil {
		return SatelRTUCDRResult{}, err
	}
	normalized := make([]string, len(header))
	indexes := make(map[string]int, len(header))
	for index, value := range header {
		name := normalizeColumn(value)
		if name == "" {
			return SatelRTUCDRResult{}, fmt.Errorf("Satel RTU header column %d is empty", index+1)
		}
		if _, exists := indexes[name]; exists {
			return SatelRTUCDRResult{}, fmt.Errorf("Satel RTU header %q is duplicated", name)
		}
		normalized[index] = name
		indexes[name] = index
	}
	for _, required := range satelRTURequiredHeaders {
		if _, exists := indexes[required]; !exists {
			return SatelRTUCDRResult{}, fmt.Errorf("Satel RTU required header %q is missing", required)
		}
	}

	result := SatelRTUCDRResult{
		Header: header, Records: make([]analytics.SatelRTURecord, 0, 1024),
	}
	for {
		row, readErr := decoder.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		result.Rows++
		if readErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("row %d: %w", result.Rows, readErr))
			continue
		}
		if len(row) != len(normalized) {
			result.Errors = append(result.Errors, fmt.Errorf(
				"row %d: got %d fields, expected %d", result.Rows, len(row), len(normalized),
			))
			continue
		}
		fields := make(map[string]string, len(row))
		for index, value := range row {
			fields[normalized[index]] = strings.TrimSpace(value)
		}
		record, mapErr := p.mapRecord(result.Rows, fields)
		if mapErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("row %d: %w", result.Rows, mapErr))
			continue
		}
		result.Records = append(result.Records, record)
	}
	return result, nil
}

func (p SatelRTUCDRParser) mapRecord(
	row uint64, fields map[string]string,
) (analytics.SatelRTURecord, error) {
	cdrID := fields["cdr_id"]
	if cdrID == "" {
		return analytics.SatelRTURecord{}, errors.New("cdr_id is empty")
	}
	cdrDate, err := parseRequiredSatelTime("cdr_date", fields["cdr_date"], p.Location)
	if err != nil {
		return analytics.SatelRTURecord{}, err
	}
	setup, err := parseRequiredSatelTime("setup_time", fields["setup_time"], p.Location)
	if err != nil {
		return analytics.SatelRTURecord{}, err
	}
	connect, err := parseCDRTime(fields["connect_time"], p.Location)
	if err != nil {
		return analytics.SatelRTURecord{}, fmt.Errorf("connect_time: %w", err)
	}
	disconnect, err := parseRequiredSatelTime(
		"disconnect_time", fields["disconnect_time"], p.Location,
	)
	if err != nil {
		return analytics.SatelRTURecord{}, err
	}
	termSetup, err := parseCDRTime(fields["term_setup_time"], p.Location)
	if err != nil {
		return analytics.SatelRTURecord{}, fmt.Errorf("term_setup_time: %w", err)
	}
	termConnect, err := parseCDRTime(fields["term_connect_time"], p.Location)
	if err != nil {
		return analytics.SatelRTURecord{}, fmt.Errorf("term_connect_time: %w", err)
	}
	termDisconnect, err := parseCDRTime(fields["term_disconnect_time"], p.Location)
	if err != nil {
		return analytics.SatelRTURecord{}, fmt.Errorf("term_disconnect_time: %w", err)
	}
	outcome := "failed"
	var durationMS *uint64
	if connect != nil {
		if disconnect.Before(*connect) {
			return analytics.SatelRTURecord{}, errors.New("disconnect_time precedes connect_time")
		}
		outcome = "answered"
		value := uint64(disconnect.Sub(*connect) / time.Millisecond)
		durationMS = &value
	}
	disconnectCode, err := strconv.ParseUint(fields["disconnect_code"], 10, 64)
	if err != nil {
		return analytics.SatelRTURecord{}, fmt.Errorf(
			"disconnect_code %q is invalid", fields["disconnect_code"],
		)
	}
	uints, floats, err := parseSatelNumericFields(fields)
	if err != nil {
		return analytics.SatelRTURecord{}, err
	}
	offsetAt := setup
	_, offsetSeconds := offsetAt.In(p.Location).Zone()
	return analytics.SatelRTURecord{
		RecordID: uuid.NewSHA1(
			uuid.NameSpaceOID, []byte(p.DeviceID.String()+"|"+cdrID),
		),
		DeviceID: p.DeviceID, FileID: p.FileID, RowNumber: row,
		IngestedAt: time.Now().UTC(), ParserVersion: analytics.SatelRTUParserVersion,
		TemplateKey: equipment.TemplateSatelRTUCDRV1, CDRID: cdrID,
		CDRDate: cdrDate, SetupTime: setup, ConnectTime: connect,
		DisconnectTime: disconnect, DurationMS: durationMS,
		ElapsedTime: floats["elapsed_time"], Outcome: outcome,
		InANI: fields["in_ani"], InDNIS: fields["in_dnis"],
		OutANI: fields["out_ani"], OutDNIS: fields["out_dnis"],
		BillANI: fields["bill_ani"], BillDNIS: fields["bill_dnis"],
		SrcUser: fields["src_user"], DstUser: fields["dst_user"],
		RadiusUser: fields["radius_user"], SrcName: fields["src_name"],
		DstName: fields["dst_name"], DPName: fields["dp_name"],
		InCPC: fields["in_cpc"], OutCPC: fields["out_cpc"],
		InZone: fields["in_zone"], OutZone: fields["out_zone"],
		InOrigDNIS: fields["in_orig_dnis"], OutOrigDNIS: fields["out_orig_dnis"],
		InANITypeOfNumber:       fields["in_ani_type_of_number"],
		InDNISTypeOfNumber:      fields["in_dnis_type_of_number"],
		OutANITypeOfNumber:      fields["out_ani_type_of_number"],
		OutDNISTypeOfNumber:     fields["out_dnis_type_of_number"],
		InOrigDNISTypeOfNumber:  fields["in_orig_dnis_type_of_number"],
		OutOrigDNISTypeOfNumber: fields["out_orig_dnis_type_of_number"],
		ExtANITypeOfNumber:      fields["ext_ani_type_of_number"],
		ExtDNISTypeOfNumber:     fields["ext_dnis_type_of_number"],
		ExtOrigDNISTypeOfNumber: fields["ext_orig_dnis_type_of_number"],
		InANIScreening:          fields["in_ani_screening"],
		InANIPresentation:       fields["in_ani_presentation"],
		OutANIScreening:         fields["out_ani_screening"],
		OutANIPresentation:      fields["out_ani_presentation"],
		InLRN:                   fields["in_lrn"], RetrievedLRN: fields["retrieved_lrn"],
		LRN: fields["lrn"], ExtLRN: fields["ext_lrn"], OutLRN: fields["out_lrn"],
		LNPServer:             fields["lnp_server"],
		SignalNodeName:        fields["sig_node_name"],
		SrcGatekeeperAddress:  fields["src_gatekeeper_address"],
		RemoteSrcSigAddress:   fields["remote_src_sig_address"],
		RemoteDstSigAddress:   fields["remote_dst_sig_address"],
		RemoteSrcMediaAddress: fields["remote_src_media_address"],
		RemoteDstMediaAddress: fields["remote_dst_media_address"],
		LocalSrcSigAddress:    fields["local_src_sig_address"],
		LocalDstSigAddress:    fields["local_dst_sig_address"],
		LocalSrcMediaAddress:  fields["local_src_media_address"],
		LocalDstMediaAddress:  fields["local_dst_media_address"],
		InLegProto:            fields["in_leg_proto"], OutLegProto: fields["out_leg_proto"],
		InLegTransportProto:  fields["in_leg_transport_proto"],
		OutLegTransportProto: fields["out_leg_transport_proto"],
		ConfID:               fields["conf_id"], InLegCallID: fields["in_leg_call_id"],
		OutLegCallID:    fields["out_leg_call_id"],
		SrcInLegConfID:  fields["src_in_leg_conf_id"],
		SrcInLegCallID:  fields["src_in_leg_call_id"],
		SrcOutLegCallID: fields["src_out_leg_call_id"],
		InLegCodecs:     fields["in_leg_codecs"], OutLegCodecs: fields["out_leg_codecs"],
		DisconnectCode: disconnectCode, DisconnectText: fields["disconnect_code_string"],
		DisconnectSuccess:   parseSatelBool(fields["disconnect_code_success"]),
		DisconnectInitiator: fields["disconnect_initiator"],
		SrcDisconnectCodes:  fields["src_disconnect_codes"],
		DstDisconnectCodes:  fields["dst_disconnect_codes"],
		SrcDisconnectText:   fields["src_disconnect_codes_string"],
		DstDisconnectText:   fields["dst_disconnect_codes_string"],
		PDD:                 floats["pdd"], SCD: floats["scd"],
		TermElapsedTime: floats["term_elapsed_time"],
		TermSetupTime:   termSetup, TermConnectTime: termConnect,
		TermDisconnectTime: termDisconnect,
		TermPDD:            floats["term_pdd"], TermSCD: floats["term_scd"],
		SrcMediaBytesIn:     uints["src_media_bytes_in"],
		SrcMediaBytesOut:    uints["src_media_bytes_out"],
		DstMediaBytesIn:     uints["dst_media_bytes_in"],
		DstMediaBytesOut:    uints["dst_media_bytes_out"],
		SrcMediaPackets:     uints["src_media_packets"],
		DstMediaPackets:     uints["dst_media_packets"],
		SrcMediaPacketsLate: uints["src_media_packets_late"],
		DstMediaPacketsLate: uints["dst_media_packets_late"],
		SrcMediaPacketsLost: uints["src_media_packets_lost"],
		DstMediaPacketsLost: uints["dst_media_packets_lost"],
		SrcMinJitter:        floats["src_min_jitter_size"],
		SrcMaxJitter:        floats["src_max_jitter_size"],
		DstMinJitter:        floats["dst_min_jitter_size"],
		DstMaxJitter:        floats["dst_max_jitter_size"],
		RouteRetries:        uints["route_retries"],
		OutgoingPulses:      uints["outgoing_pulses"],
		IncomingPulses:      uints["incoming_pulses"],
		LoopingCycles:       uints["looping_cycles"],
		ProxyMode:           fields["proxy_mode"],
		LARFaultReason:      fields["lar_fault_reason"],
		MediaGroup:          fields["media_group"],
		ExternalRouter:      fields["external_router"],
		RadiusGroup:         fields["radius_group"],
		SIPRoutingGroup:     fields["sip_routing_group"],
		AuthDNIS:            fields["auth_dnis"],
		ExtANI:              fields["ext_ani"],
		ExtDNIS:             fields["ext_dnis"],
		ExtSigAddress:       fields["ext_sig_address"],
		InPartnerID:         fields["in_partner_id"],
		OutPartnerID:        fields["out_partner_id"],
		InEncryption:        fields["in_encryption"],
		OutEncryption:       fields["out_encryption"],
		RecordType:          fields["record_type"], LastCDR: parseSatelBool(fields["last_cdr"]),
		RawFields: fields, SourceTimezone: p.Location.String(),
		SourceUTCOffsetMinutes: int16(offsetSeconds / 60),
		TimezoneRevision:       uint64(max(1, int(p.TimezoneRevision))),
	}, nil
}

func parseRequiredSatelTime(
	name, value string, location *time.Location,
) (*time.Time, error) {
	parsed, err := parseCDRTime(value, location)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if parsed == nil {
		return nil, fmt.Errorf("%s is empty", name)
	}
	return parsed, nil
}

func parseSatelBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y":
		return true
	default:
		return false
	}
}

func parseSatelNumericFields(
	fields map[string]string,
) (map[string]*uint64, map[string]*float64, error) {
	uints := make(map[string]*uint64)
	for _, name := range []string{
		"src_media_bytes_in", "src_media_bytes_out", "dst_media_bytes_in",
		"dst_media_bytes_out", "src_media_packets", "dst_media_packets",
		"src_media_packets_late", "dst_media_packets_late", "src_media_packets_lost",
		"dst_media_packets_lost", "route_retries", "outgoing_pulses",
		"incoming_pulses", "looping_cycles",
	} {
		value := strings.TrimSpace(fields[name])
		if value == "" {
			uints[name] = nil
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("%s %q is invalid", name, value)
		}
		uints[name] = &parsed
	}
	floats := make(map[string]*float64)
	for _, name := range []string{
		"elapsed_time", "pdd", "scd", "term_elapsed_time", "term_pdd", "term_scd",
		"src_min_jitter_size", "src_max_jitter_size", "dst_min_jitter_size",
		"dst_max_jitter_size",
	} {
		value := strings.TrimSpace(fields[name])
		if value == "" {
			floats[name] = nil
			continue
		}
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || parsed < 0 || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return nil, nil, fmt.Errorf("%s %q is invalid", name, value)
		}
		floats[name] = &parsed
	}
	return uints, floats, nil
}
