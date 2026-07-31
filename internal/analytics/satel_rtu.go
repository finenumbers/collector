package analytics

import (
	"context"
	"fmt"
	"strings"
	"time"

	"collector/internal/equipment"
	"collector/internal/workload"

	"github.com/google/uuid"
)

const SatelRTUParserVersion = equipment.SatelRTUParserVersion

type SatelRTURecord struct {
	RecordID, DeviceID, FileID uuid.UUID
	RowNumber                  uint64
	IngestedAt                 time.Time
	ParserVersion, TemplateKey string
	CDRID                      string
	CDRDate                    *time.Time
	SetupTime                  *time.Time
	ConnectTime                *time.Time
	DisconnectTime             *time.Time
	DurationMS                 *uint64
	ElapsedTime                *float64
	Outcome                    string
	InANI, InDNIS              string
	OutANI, OutDNIS            string
	BillANI, BillDNIS          string
	BillANIOperator            string
	BillDNISOperator           string
	BillANIRegion              string
	BillDNISRegion             string
	SrcUser, DstUser           string
	RadiusUser                 string
	SrcName, DstName, DPName   string
	InCPC, OutCPC              string
	InZone, OutZone            string
	InOrigDNIS, OutOrigDNIS    string
	InANITypeOfNumber          string
	InDNISTypeOfNumber         string
	OutANITypeOfNumber         string
	OutDNISTypeOfNumber        string
	InOrigDNISTypeOfNumber     string
	OutOrigDNISTypeOfNumber    string
	ExtANITypeOfNumber         string
	ExtDNISTypeOfNumber        string
	ExtOrigDNISTypeOfNumber    string
	InANIScreening             string
	InANIPresentation          string
	OutANIScreening            string
	OutANIPresentation         string
	InLRN, RetrievedLRN        string
	LRN, ExtLRN, OutLRN        string
	LNPServer                  string
	SignalNodeName             string
	SrcGatekeeperAddress       string
	RemoteSrcSigAddress        string
	RemoteDstSigAddress        string
	RemoteSrcGeoipISO          string
	RemoteSrcGeoipCity         string
	RemoteSrcASNOrg            string
	RemoteDstGeoipISO          string
	RemoteDstGeoipCity         string
	RemoteDstASNOrg            string
	RemoteSrcMediaAddress      string
	RemoteDstMediaAddress      string
	LocalSrcSigAddress         string
	LocalDstSigAddress         string
	LocalSrcMediaAddress       string
	LocalDstMediaAddress       string
	InLegProto                 string
	OutLegProto                string
	InLegTransportProto        string
	OutLegTransportProto       string
	ConfID                     string
	InLegCallID                string
	OutLegCallID               string
	SrcInLegConfID             string
	SrcInLegCallID             string
	SrcOutLegCallID            string
	InLegCodecs                string
	OutLegCodecs               string
	DisconnectCode             uint64
	DisconnectText             string
	DisconnectSuccess          bool
	DisconnectInitiator        string
	SrcDisconnectCodes         string
	DstDisconnectCodes         string
	SrcDisconnectText          string
	DstDisconnectText          string
	PDD, SCD                   *float64
	TermElapsedTime            *float64
	TermSetupTime              *time.Time
	TermConnectTime            *time.Time
	TermDisconnectTime         *time.Time
	TermPDD, TermSCD           *float64
	SrcMediaBytesIn            *uint64
	SrcMediaBytesOut           *uint64
	DstMediaBytesIn            *uint64
	DstMediaBytesOut           *uint64
	SrcMediaPackets            *uint64
	DstMediaPackets            *uint64
	SrcMediaPacketsLate        *uint64
	DstMediaPacketsLate        *uint64
	SrcMediaPacketsLost        *uint64
	DstMediaPacketsLost        *uint64
	SrcMinJitter               *float64
	SrcMaxJitter               *float64
	DstMinJitter               *float64
	DstMaxJitter               *float64
	RouteRetries               *uint64
	OutgoingPulses             *uint64
	IncomingPulses             *uint64
	LoopingCycles              *uint64
	ProxyMode                  string
	LARFaultReason             string
	MediaGroup                 string
	ExternalRouter             string
	RadiusGroup                string
	SIPRoutingGroup            string
	AuthDNIS                   string
	ExtANI                     string
	ExtDNIS                    string
	ExtSigAddress              string
	InPartnerID                string
	OutPartnerID               string
	InEncryption               string
	OutEncryption              string
	RecordType                 string
	LastCDR                    bool
	RawFields                  map[string]string
	SourceTimezone             string
	SourceUTCOffsetMinutes     int16
	TimezoneRevision           uint64
}

type SatelRTUCallRow struct {
	RecordID                uuid.UUID         `json:"recordId"`
	CDRID                   string            `json:"cdrId"`
	CDRDate                 *time.Time        `json:"cdrDate"`
	SetupTime               *time.Time        `json:"setupTime"`
	ConnectTime             *time.Time        `json:"connectTime"`
	DisconnectTime          *time.Time        `json:"disconnectTime"`
	DurationMS              *uint64           `json:"durationMs"`
	ElapsedTime             *float64          `json:"elapsedTime"`
	Outcome                 string            `json:"outcome"`
	InANI                   string            `json:"inAni"`
	InDNIS                  string            `json:"inDnis"`
	OutANI                  string            `json:"outAni"`
	OutDNIS                 string            `json:"outDnis"`
	BillANI                 string            `json:"billAni"`
	BillDNIS                string            `json:"billDnis"`
	BillANIOperator         string            `json:"billAniOperator"`
	BillDNISOperator        string            `json:"billDnisOperator"`
	BillANIRegion           string            `json:"billAniRegion"`
	BillDNISRegion          string            `json:"billDnisRegion"`
	SrcUser                 string            `json:"srcUser"`
	DstUser                 string            `json:"dstUser"`
	RadiusUser              string            `json:"radiusUser"`
	SrcName                 string            `json:"srcName"`
	DstName                 string            `json:"dstName"`
	DPName                  string            `json:"dpName"`
	InCPC                   string            `json:"inCpc"`
	OutCPC                  string            `json:"outCpc"`
	InZone                  string            `json:"inZone"`
	OutZone                 string            `json:"outZone"`
	InOrigDNIS              string            `json:"inOrigDnis"`
	OutOrigDNIS             string            `json:"outOrigDnis"`
	InANITypeOfNumber       string            `json:"inAniTypeOfNumber"`
	InDNISTypeOfNumber      string            `json:"inDnisTypeOfNumber"`
	OutANITypeOfNumber      string            `json:"outAniTypeOfNumber"`
	OutDNISTypeOfNumber     string            `json:"outDnisTypeOfNumber"`
	InOrigDNISTypeOfNumber  string            `json:"inOrigDnisTypeOfNumber"`
	OutOrigDNISTypeOfNumber string            `json:"outOrigDnisTypeOfNumber"`
	ExtANITypeOfNumber      string            `json:"extAniTypeOfNumber"`
	ExtDNISTypeOfNumber     string            `json:"extDnisTypeOfNumber"`
	ExtOrigDNISTypeOfNumber string            `json:"extOrigDnisTypeOfNumber"`
	InANIScreening          string            `json:"inAniScreening"`
	InANIPresentation       string            `json:"inAniPresentation"`
	OutANIScreening         string            `json:"outAniScreening"`
	OutANIPresentation      string            `json:"outAniPresentation"`
	InLRN                   string            `json:"inLrn"`
	RetrievedLRN            string            `json:"retrievedLrn"`
	LRN                     string            `json:"lrn"`
	ExtLRN                  string            `json:"extLrn"`
	OutLRN                  string            `json:"outLrn"`
	LNPServer               string            `json:"lnpServer"`
	InLegProto              string            `json:"inLegProto"`
	OutLegProto             string            `json:"outLegProto"`
	InLegTransportProto     string            `json:"inLegTransportProto"`
	OutLegTransportProto    string            `json:"outLegTransportProto"`
	ConfID                  string            `json:"confId"`
	InLegCallID             string            `json:"inLegCallId"`
	OutLegCallID            string            `json:"outLegCallId"`
	SrcInLegConfID          string            `json:"srcInLegConfId"`
	SrcInLegCallID          string            `json:"srcInLegCallId"`
	SrcOutLegCallID         string            `json:"srcOutLegCallId"`
	SignalNodeName          string            `json:"signalNodeName"`
	SrcGatekeeperAddress    string            `json:"srcGatekeeperAddress"`
	RemoteSrcSigAddress     string            `json:"remoteSrcSigAddress"`
	RemoteDstSigAddress     string            `json:"remoteDstSigAddress"`
	RemoteSrcGeoipISO       string            `json:"remoteSrcGeoipIso"`
	RemoteSrcGeoipCity      string            `json:"remoteSrcGeoipCity"`
	RemoteSrcASNOrg         string            `json:"remoteSrcAsnOrg"`
	RemoteDstGeoipISO       string            `json:"remoteDstGeoipIso"`
	RemoteDstGeoipCity      string            `json:"remoteDstGeoipCity"`
	RemoteDstASNOrg         string            `json:"remoteDstAsnOrg"`
	RemoteSrcMediaAddress   string            `json:"remoteSrcMediaAddress"`
	RemoteDstMediaAddress   string            `json:"remoteDstMediaAddress"`
	LocalSrcSigAddress      string            `json:"localSrcSigAddress"`
	LocalDstSigAddress      string            `json:"localDstSigAddress"`
	LocalSrcMediaAddress    string            `json:"localSrcMediaAddress"`
	LocalDstMediaAddress    string            `json:"localDstMediaAddress"`
	InLegCodecs             string            `json:"inLegCodecs"`
	OutLegCodecs            string            `json:"outLegCodecs"`
	DisconnectCode          uint64            `json:"disconnectCode"`
	DisconnectText          string            `json:"disconnectText"`
	DisconnectSuccess       bool              `json:"disconnectSuccess"`
	DisconnectInitiator     string            `json:"disconnectInitiator"`
	SrcDisconnectCodes      string            `json:"srcDisconnectCodes"`
	DstDisconnectCodes      string            `json:"dstDisconnectCodes"`
	SrcDisconnectText       string            `json:"srcDisconnectText"`
	DstDisconnectText       string            `json:"dstDisconnectText"`
	PDD                     *float64          `json:"pdd"`
	SCD                     *float64          `json:"scd"`
	TermElapsedTime         *float64          `json:"termElapsedTime"`
	TermSetupTime           *time.Time        `json:"termSetupTime"`
	TermConnectTime         *time.Time        `json:"termConnectTime"`
	TermDisconnectTime      *time.Time        `json:"termDisconnectTime"`
	TermPDD                 *float64          `json:"termPdd"`
	TermSCD                 *float64          `json:"termScd"`
	SrcMediaBytesIn         *uint64           `json:"srcMediaBytesIn"`
	SrcMediaBytesOut        *uint64           `json:"srcMediaBytesOut"`
	DstMediaBytesIn         *uint64           `json:"dstMediaBytesIn"`
	DstMediaBytesOut        *uint64           `json:"dstMediaBytesOut"`
	SrcMediaPackets         *uint64           `json:"srcMediaPackets"`
	DstMediaPackets         *uint64           `json:"dstMediaPackets"`
	SrcMediaPacketsLate     *uint64           `json:"srcMediaPacketsLate"`
	DstMediaPacketsLate     *uint64           `json:"dstMediaPacketsLate"`
	SrcMediaPacketsLost     *uint64           `json:"srcMediaPacketsLost"`
	DstMediaPacketsLost     *uint64           `json:"dstMediaPacketsLost"`
	SrcMinJitter            *float64          `json:"srcMinJitter"`
	SrcMaxJitter            *float64          `json:"srcMaxJitter"`
	DstMinJitter            *float64          `json:"dstMinJitter"`
	DstMaxJitter            *float64          `json:"dstMaxJitter"`
	RouteRetries            *uint64           `json:"routeRetries"`
	OutgoingPulses          *uint64           `json:"outgoingPulses"`
	IncomingPulses          *uint64           `json:"incomingPulses"`
	LoopingCycles           *uint64           `json:"loopingCycles"`
	ProxyMode               string            `json:"proxyMode"`
	LARFaultReason          string            `json:"larFaultReason"`
	MediaGroup              string            `json:"mediaGroup"`
	ExternalRouter          string            `json:"externalRouter"`
	RadiusGroup             string            `json:"radiusGroup"`
	SIPRoutingGroup         string            `json:"sipRoutingGroup"`
	AuthDNIS                string            `json:"authDnis"`
	ExtANI                  string            `json:"extAni"`
	ExtDNIS                 string            `json:"extDnis"`
	ExtSigAddress           string            `json:"extSigAddress"`
	InPartnerID             string            `json:"inPartnerId"`
	OutPartnerID            string            `json:"outPartnerId"`
	InEncryption            string            `json:"inEncryption"`
	OutEncryption           string            `json:"outEncryption"`
	RecordType              string            `json:"recordType"`
	LastCDR                 bool              `json:"lastCdr"`
	RawFields               map[string]string `json:"rawFields"`
	ParserVersion           string            `json:"parserVersion"`
	SourceTimezone          string            `json:"sourceTimezone"`
	SourceUTCOffsetMinutes  int16             `json:"sourceUtcOffsetMinutes"`
	SetupTimeLocal           string            `json:"setupTimeLocal"`
	VoipmonitorCDRID         string            `json:"voipmonitorCdrId,omitempty"`
	VoipmonitorCallID        string            `json:"voipmonitorCallId,omitempty"`
	VoipmonitorCardURL       string            `json:"voipmonitorCardUrl,omitempty"`
	VoipmonitorMatchStatus   string            `json:"voipmonitorMatchStatus,omitempty"`
	VoipmonitorMatchMethod   string            `json:"voipmonitorMatchMethod,omitempty"`
	VoipmonitorMatchScore    uint8             `json:"voipmonitorMatchScore,omitempty"`
	SortTime                 time.Time         `json:"-"`
}

type SatelRTUCallPage struct {
	Items   []SatelRTUCallRow `json:"items"`
	HasMore bool              `json:"hasMore"`
}

func (c *Client) InsertSatelRTUBatch(
	ctx context.Context, records []SatelRTURecord,
) error {
	if len(records) == 0 {
		return nil
	}
	ctx, release, err := c.queryContext(ctx, workload.Ingest)
	if err != nil {
		return err
	}
	defer release()
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.satel_rtu_cdr
		(record_id,device_id,file_id,row_number,ingested_at,parser_version,template_key,cdr_id,
		cdr_date,setup_time,connect_time,disconnect_time,duration_ms,elapsed_time,outcome,
		in_ani,in_dnis,out_ani,out_dnis,bill_ani,bill_dnis,
		bill_ani_operator,bill_dnis_operator,bill_ani_region,bill_dnis_region,
		src_user,dst_user,radius_user,
		src_name,dst_name,dp_name,in_cpc,out_cpc,in_zone,out_zone,in_orig_dnis,out_orig_dnis,
		in_ani_type_of_number,in_dnis_type_of_number,out_ani_type_of_number,
		out_dnis_type_of_number,in_orig_dnis_type_of_number,out_orig_dnis_type_of_number,
		ext_ani_type_of_number,ext_dnis_type_of_number,ext_orig_dnis_type_of_number,
		in_ani_screening,in_ani_presentation,out_ani_screening,out_ani_presentation,
		in_lrn,retrieved_lrn,lrn,ext_lrn,out_lrn,lnp_server,
		signal_node_name,src_gatekeeper_address,
		remote_src_sig_address,remote_dst_sig_address,
		remote_src_geoip_iso,remote_src_geoip_city,remote_src_asn_org,
		remote_dst_geoip_iso,remote_dst_geoip_city,remote_dst_asn_org,
		remote_src_media_address,
		remote_dst_media_address,local_src_sig_address,local_dst_sig_address,
		local_src_media_address,local_dst_media_address,in_leg_proto,out_leg_proto,
		in_leg_transport_proto,out_leg_transport_proto,conf_id,in_leg_call_id,out_leg_call_id,
		src_in_leg_conf_id,src_in_leg_call_id,src_out_leg_call_id,in_leg_codecs,out_leg_codecs,
		disconnect_code,disconnect_text,disconnect_success,disconnect_initiator,
		src_disconnect_codes,dst_disconnect_codes,src_disconnect_text,dst_disconnect_text,
		pdd,scd,term_elapsed_time,term_setup_time,term_connect_time,term_disconnect_time,
		term_pdd,term_scd,src_media_bytes_in,src_media_bytes_out,dst_media_bytes_in,
		dst_media_bytes_out,src_media_packets,dst_media_packets,src_media_packets_late,
		dst_media_packets_late,src_media_packets_lost,dst_media_packets_lost,
		src_min_jitter,src_max_jitter,dst_min_jitter,dst_max_jitter,route_retries,
		outgoing_pulses,incoming_pulses,looping_cycles,proxy_mode,lar_fault_reason,
		media_group,external_router,radius_group,sip_routing_group,auth_dnis,ext_ani,
		ext_dnis,ext_sig_address,in_partner_id,out_partner_id,in_encryption,out_encryption,
		record_type,last_cdr,
		raw_fields,source_timezone,source_utc_offset_minutes,timezone_revision)`)
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := batch.Append(
			record.RecordID, record.DeviceID, record.FileID, record.RowNumber,
			record.IngestedAt, record.ParserVersion, record.TemplateKey, record.CDRID,
			record.CDRDate, record.SetupTime, record.ConnectTime, record.DisconnectTime,
			record.DurationMS, record.ElapsedTime, record.Outcome, record.InANI, record.InDNIS, record.OutANI,
			record.OutDNIS, record.BillANI, record.BillDNIS,
			record.BillANIOperator, record.BillDNISOperator,
			record.BillANIRegion, record.BillDNISRegion,
			record.SrcUser, record.DstUser,
			record.RadiusUser, record.SrcName, record.DstName, record.DPName,
			record.InCPC, record.OutCPC, record.InZone, record.OutZone,
			record.InOrigDNIS, record.OutOrigDNIS, record.InANITypeOfNumber,
			record.InDNISTypeOfNumber, record.OutANITypeOfNumber,
			record.OutDNISTypeOfNumber, record.InOrigDNISTypeOfNumber,
			record.OutOrigDNISTypeOfNumber, record.ExtANITypeOfNumber,
			record.ExtDNISTypeOfNumber, record.ExtOrigDNISTypeOfNumber,
			record.InANIScreening, record.InANIPresentation, record.OutANIScreening,
			record.OutANIPresentation, record.InLRN, record.RetrievedLRN, record.LRN,
			record.ExtLRN, record.OutLRN, record.LNPServer,
			record.SignalNodeName, record.SrcGatekeeperAddress, record.RemoteSrcSigAddress,
			record.RemoteDstSigAddress,
			record.RemoteSrcGeoipISO, record.RemoteSrcGeoipCity, record.RemoteSrcASNOrg,
			record.RemoteDstGeoipISO, record.RemoteDstGeoipCity, record.RemoteDstASNOrg,
			record.RemoteSrcMediaAddress,
			record.RemoteDstMediaAddress, record.LocalSrcSigAddress,
			record.LocalDstSigAddress, record.LocalSrcMediaAddress,
			record.LocalDstMediaAddress, record.InLegProto, record.OutLegProto,
			record.InLegTransportProto, record.OutLegTransportProto, record.ConfID,
			record.InLegCallID, record.OutLegCallID, record.SrcInLegConfID,
			record.SrcInLegCallID, record.SrcOutLegCallID, record.InLegCodecs,
			record.OutLegCodecs, record.DisconnectCode, record.DisconnectText,
			record.DisconnectSuccess, record.DisconnectInitiator, record.SrcDisconnectCodes,
			record.DstDisconnectCodes, record.SrcDisconnectText, record.DstDisconnectText,
			record.PDD, record.SCD, record.TermElapsedTime, record.TermSetupTime,
			record.TermConnectTime, record.TermDisconnectTime, record.TermPDD, record.TermSCD,
			record.SrcMediaBytesIn, record.SrcMediaBytesOut, record.DstMediaBytesIn,
			record.DstMediaBytesOut, record.SrcMediaPackets, record.DstMediaPackets,
			record.SrcMediaPacketsLate, record.DstMediaPacketsLate,
			record.SrcMediaPacketsLost, record.DstMediaPacketsLost, record.SrcMinJitter,
			record.SrcMaxJitter, record.DstMinJitter, record.DstMaxJitter,
			record.RouteRetries, record.OutgoingPulses, record.IncomingPulses,
			record.LoopingCycles, record.ProxyMode, record.LARFaultReason,
			record.MediaGroup, record.ExternalRouter, record.RadiusGroup,
			record.SIPRoutingGroup, record.AuthDNIS, record.ExtANI, record.ExtDNIS,
			record.ExtSigAddress, record.InPartnerID, record.OutPartnerID,
			record.InEncryption, record.OutEncryption,
			record.RecordType, record.LastCDR, redactStringMap(record.RawFields), record.SourceTimezone,
			record.SourceUTCOffsetMinutes, record.TimezoneRevision,
		); err != nil {
			return err
		}
	}
	if err := batch.Send(); err != nil {
		return err
	}
	return c.insertSatelRTUTimeFacts(ctx, records)
}

func (c *Client) insertSatelRTUTimeFacts(
	ctx context.Context, records []SatelRTURecord,
) error {
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.satel_rtu_cdr_time_facts
		(device_id,timezone_revision,record_id,interpreted_at,cdr_date_utc,setup_time_utc,
		connect_time_utc,disconnect_time_utc,term_setup_time_utc,term_connect_time_utc,
		term_disconnect_time_utc,source_timezone,source_utc_offset_minutes)`)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, record := range records {
		if err := batch.Append(
			record.DeviceID, record.TimezoneRevision, record.RecordID, now, record.CDRDate,
			record.SetupTime, record.ConnectTime, record.DisconnectTime,
			record.TermSetupTime, record.TermConnectTime, record.TermDisconnectTime,
			record.SourceTimezone, record.SourceUTCOffsetMinutes,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *Client) ReinterpretSatelRTUTimes(
	ctx context.Context, deviceID uuid.UUID, revision uint64, timezone string,
) error {
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return fmt.Errorf("invalid Satel RTU timezone %q: %w", timezone, err)
	}
	_ = location
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	return c.Conn.Exec(ctx, `INSERT INTO collector.satel_rtu_cdr_time_facts
		(device_id,timezone_revision,record_id,interpreted_at,cdr_date_utc,setup_time_utc,
		connect_time_utc,disconnect_time_utc,term_setup_time_utc,term_connect_time_utc,
		term_disconnect_time_utc,source_timezone,source_utc_offset_minutes)
		SELECT device_id,?,record_id,now64(6),
			parseDateTime64BestEffortOrNull(raw_fields['cdr_date'],3,?),
			parseDateTime64BestEffortOrNull(raw_fields['setup_time'],3,?),
			parseDateTime64BestEffortOrNull(raw_fields['connect_time'],3,?),
			parseDateTime64BestEffortOrNull(raw_fields['disconnect_time'],3,?),
			parseDateTime64BestEffortOrNull(raw_fields['term_setup_time'],3,?),
			parseDateTime64BestEffortOrNull(raw_fields['term_connect_time'],3,?),
			parseDateTime64BestEffortOrNull(raw_fields['term_disconnect_time'],3,?),
			?,toInt16(ifNull(dateDiff('minute',
				parseDateTime64BestEffortOrNull(raw_fields['setup_time'],3,?),
				parseDateTime64BestEffortOrNull(raw_fields['setup_time'],3,'UTC')),0))
		FROM collector.satel_rtu_cdr FINAL WHERE device_id=?`,
		revision, timezone, timezone, timezone, timezone, timezone, timezone, timezone,
		timezone, timezone, deviceID)
}

func (c *Client) ListSatelRTUCallsPage(
	ctx context.Context, deviceID uuid.UUID, search string, limit uint64, cursor *CallCursor,
) (SatelRTUCallPage, error) {
	return c.ListSatelRTUCallsPageRange(ctx, deviceID, search, limit, cursor, nil)
}

func (c *Client) ListSatelRTUCallsPageRange(
	ctx context.Context, deviceID uuid.UUID, search string, limit uint64, cursor *CallCursor,
	timeRange *TimeRange,
) (SatelRTUCallPage, error) {
	return c.listSatelRTUCallsPage(ctx, deviceID, nil, search, limit, cursor, timeRange)
}

func (c *Client) listSatelRTUCallsPage(
	ctx context.Context, deviceID uuid.UUID, revision *uint64, search string,
	limit uint64, cursor *CallCursor, timeRange *TimeRange,
) (SatelRTUCallPage, error) {
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return SatelRTUCallPage{}, err
	}
	defer release()
	if search != "" && timeRange == nil && !c.admittedAs(ctx, workload.Export) {
		return SatelRTUCallPage{}, ErrSearchRequiresRange
	}
	if limit == 0 || limit > 1000 {
		limit = 200
	}
	query := `WITH times AS
		(
			SELECT record_id,argMax(cdr_date_utc,interpreted_at) AS cdr_date,
				argMax(setup_time_utc,interpreted_at) AS setup_time,
				argMax(connect_time_utc,interpreted_at) AS connect_time,
				argMax(disconnect_time_utc,interpreted_at) AS disconnect_time,
				argMax(term_setup_time_utc,interpreted_at) AS term_setup_time,
				argMax(term_connect_time_utc,interpreted_at) AS term_connect_time,
				argMax(term_disconnect_time_utc,interpreted_at) AS term_disconnect_time,
				argMax(source_timezone,interpreted_at) AS source_timezone,
				argMax(source_utc_offset_minutes,interpreted_at) AS source_offset
			FROM collector.satel_rtu_cdr_time_facts
			WHERE device_id=?`
	args := []any{deviceID}
	if revision != nil {
		query += ` AND timezone_revision=?`
		args = append(args, *revision)
	}
	query += ` GROUP BY record_id
		)
		SELECT c.record_id,c.cdr_id,t.cdr_date,t.setup_time,t.connect_time,t.disconnect_time,
			c.duration_ms,c.elapsed_time,c.outcome,c.in_ani,c.in_dnis,c.out_ani,c.out_dnis,c.bill_ani,c.bill_dnis,
			c.bill_ani_operator,c.bill_dnis_operator,c.bill_ani_region,c.bill_dnis_region,
			c.src_user,c.dst_user,c.radius_user,c.src_name,c.dst_name,c.dp_name,
			c.in_cpc,c.out_cpc,c.in_zone,c.out_zone,c.in_orig_dnis,c.out_orig_dnis,
			c.in_ani_type_of_number,c.in_dnis_type_of_number,c.out_ani_type_of_number,
			c.out_dnis_type_of_number,c.in_orig_dnis_type_of_number,
			c.out_orig_dnis_type_of_number,c.ext_ani_type_of_number,
			c.ext_dnis_type_of_number,c.ext_orig_dnis_type_of_number,
			c.in_ani_screening,c.in_ani_presentation,c.out_ani_screening,
			c.out_ani_presentation,c.in_lrn,c.retrieved_lrn,c.lrn,c.ext_lrn,c.out_lrn,c.lnp_server,
			c.in_leg_proto,c.out_leg_proto,c.in_leg_transport_proto,c.out_leg_transport_proto,
			c.conf_id,c.in_leg_call_id,c.out_leg_call_id,c.src_in_leg_conf_id,
			c.src_in_leg_call_id,c.src_out_leg_call_id,c.signal_node_name,
			c.src_gatekeeper_address,c.remote_src_sig_address,c.remote_dst_sig_address,
			c.remote_src_geoip_iso,c.remote_src_geoip_city,c.remote_src_asn_org,
			c.remote_dst_geoip_iso,c.remote_dst_geoip_city,c.remote_dst_asn_org,
			c.remote_src_media_address,c.remote_dst_media_address,c.local_src_sig_address,
			c.local_dst_sig_address,c.local_src_media_address,c.local_dst_media_address,
			c.in_leg_codecs,c.out_leg_codecs,c.disconnect_code,c.disconnect_text,
			c.disconnect_success,c.disconnect_initiator,c.src_disconnect_codes,
			c.dst_disconnect_codes,c.src_disconnect_text,c.dst_disconnect_text,c.pdd,c.scd,
			c.term_elapsed_time,t.term_setup_time,t.term_connect_time,t.term_disconnect_time,
			c.term_pdd,c.term_scd,c.src_media_bytes_in,c.src_media_bytes_out,
			c.dst_media_bytes_in,c.dst_media_bytes_out,c.src_media_packets,c.dst_media_packets,
			c.src_media_packets_late,c.dst_media_packets_late,c.src_media_packets_lost,
			c.dst_media_packets_lost,c.src_min_jitter,c.src_max_jitter,c.dst_min_jitter,
			c.dst_max_jitter,c.route_retries,c.outgoing_pulses,c.incoming_pulses,
			c.looping_cycles,c.proxy_mode,c.lar_fault_reason,c.media_group,c.external_router,
			c.radius_group,c.sip_routing_group,c.auth_dnis,c.ext_ani,c.ext_dnis,c.ext_sig_address,
			c.in_partner_id,c.out_partner_id,c.in_encryption,c.out_encryption,
			c.record_type,c.last_cdr,c.raw_fields,c.parser_version,
			t.source_timezone,t.source_offset,
			coalesce(t.setup_time,t.cdr_date,c.ingested_at) AS sort_time
		FROM collector.satel_rtu_cdr AS c FINAL
		LEFT JOIN times AS t ON t.record_id=c.record_id
		WHERE c.device_id=?`
	args = append(args, deviceID)
	if revision != nil {
		query += ` AND c.timezone_revision=?`
		args = append(args, *revision)
	}
	if timeRange != nil {
		query += ` AND coalesce(t.setup_time,t.cdr_date,c.ingested_at)>=?
			AND coalesce(t.setup_time,t.cdr_date,c.ingested_at)<?`
		args = append(args, timeRange.From, timeRange.To)
	}
	if search != "" {
		query += ` AND (positionCaseInsensitive(c.in_ani,?)>0
			OR positionCaseInsensitive(c.in_dnis,?)>0
			OR positionCaseInsensitive(c.out_ani,?)>0
			OR positionCaseInsensitive(c.out_dnis,?)>0
			OR positionCaseInsensitive(c.bill_ani,?)>0
			OR positionCaseInsensitive(c.bill_dnis,?)>0
			OR positionCaseInsensitive(c.src_name,?)>0
			OR positionCaseInsensitive(c.dst_name,?)>0
			OR positionCaseInsensitive(c.dp_name,?)>0
			OR positionCaseInsensitive(c.cdr_id,?)>0
			OR positionCaseInsensitive(c.conf_id,?)>0
			OR positionCaseInsensitive(c.in_leg_call_id,?)>0
			OR positionCaseInsensitive(c.out_leg_call_id,?)>0)`
		for range 13 {
			args = append(args, search)
		}
	}
	if cursor != nil {
		query += ` AND (sort_time<? OR (sort_time=? AND c.record_id<?))`
		args = append(args, cursor.SortTime, cursor.SortTime, cursor.RecordID)
	}
	query += ` ORDER BY sort_time DESC,c.record_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return SatelRTUCallPage{}, err
	}
	defer rows.Close()
	items := make([]SatelRTUCallRow, 0, limit+1)
	for rows.Next() {
		var row SatelRTUCallRow
		if err := rows.Scan(
			&row.RecordID, &row.CDRID, &row.CDRDate, &row.SetupTime, &row.ConnectTime,
			&row.DisconnectTime, &row.DurationMS, &row.ElapsedTime, &row.Outcome, &row.InANI, &row.InDNIS,
			&row.OutANI, &row.OutDNIS, &row.BillANI, &row.BillDNIS,
			&row.BillANIOperator, &row.BillDNISOperator, &row.BillANIRegion, &row.BillDNISRegion,
			&row.SrcUser, &row.DstUser, &row.RadiusUser, &row.SrcName, &row.DstName, &row.DPName,
			&row.InCPC, &row.OutCPC, &row.InZone, &row.OutZone,
			&row.InOrigDNIS, &row.OutOrigDNIS, &row.InANITypeOfNumber,
			&row.InDNISTypeOfNumber, &row.OutANITypeOfNumber, &row.OutDNISTypeOfNumber,
			&row.InOrigDNISTypeOfNumber, &row.OutOrigDNISTypeOfNumber,
			&row.ExtANITypeOfNumber, &row.ExtDNISTypeOfNumber,
			&row.ExtOrigDNISTypeOfNumber, &row.InANIScreening, &row.InANIPresentation,
			&row.OutANIScreening, &row.OutANIPresentation, &row.InLRN,
			&row.RetrievedLRN, &row.LRN, &row.ExtLRN, &row.OutLRN, &row.LNPServer,
			&row.InLegProto, &row.OutLegProto, &row.InLegTransportProto,
			&row.OutLegTransportProto, &row.ConfID, &row.InLegCallID, &row.OutLegCallID,
			&row.SrcInLegConfID, &row.SrcInLegCallID, &row.SrcOutLegCallID,
			&row.SignalNodeName, &row.SrcGatekeeperAddress, &row.RemoteSrcSigAddress,
			&row.RemoteDstSigAddress,
			&row.RemoteSrcGeoipISO, &row.RemoteSrcGeoipCity, &row.RemoteSrcASNOrg,
			&row.RemoteDstGeoipISO, &row.RemoteDstGeoipCity, &row.RemoteDstASNOrg,
			&row.RemoteSrcMediaAddress,
			&row.RemoteDstMediaAddress, &row.LocalSrcSigAddress, &row.LocalDstSigAddress,
			&row.LocalSrcMediaAddress, &row.LocalDstMediaAddress, &row.InLegCodecs,
			&row.OutLegCodecs, &row.DisconnectCode, &row.DisconnectText,
			&row.DisconnectSuccess, &row.DisconnectInitiator, &row.SrcDisconnectCodes,
			&row.DstDisconnectCodes, &row.SrcDisconnectText, &row.DstDisconnectText,
			&row.PDD, &row.SCD, &row.TermElapsedTime, &row.TermSetupTime,
			&row.TermConnectTime, &row.TermDisconnectTime, &row.TermPDD, &row.TermSCD,
			&row.SrcMediaBytesIn, &row.SrcMediaBytesOut, &row.DstMediaBytesIn,
			&row.DstMediaBytesOut, &row.SrcMediaPackets, &row.DstMediaPackets,
			&row.SrcMediaPacketsLate, &row.DstMediaPacketsLate,
			&row.SrcMediaPacketsLost, &row.DstMediaPacketsLost, &row.SrcMinJitter,
			&row.SrcMaxJitter, &row.DstMinJitter, &row.DstMaxJitter,
			&row.RouteRetries, &row.OutgoingPulses, &row.IncomingPulses,
			&row.LoopingCycles, &row.ProxyMode, &row.LARFaultReason, &row.MediaGroup,
			&row.ExternalRouter, &row.RadiusGroup, &row.SIPRoutingGroup, &row.AuthDNIS,
			&row.ExtANI, &row.ExtDNIS, &row.ExtSigAddress, &row.InPartnerID,
			&row.OutPartnerID, &row.InEncryption, &row.OutEncryption, &row.RecordType,
			&row.LastCDR, &row.RawFields, &row.ParserVersion, &row.SourceTimezone,
			&row.SourceUTCOffsetMinutes, &row.SortTime,
		); err != nil {
			return SatelRTUCallPage{}, err
		}
		row.SetupTimeLocal = localRFC3339(row.SetupTime, row.SourceTimezone)
		row.RawFields = redactStringMap(row.RawFields)
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		return SatelRTUCallPage{}, err
	}
	hasMore := uint64(len(items)) > limit
	if hasMore {
		items = items[:limit]
	}
	if err := c.AttachVoipmonitorToSatelRows(ctx, deviceID, items); err != nil {
		return SatelRTUCallPage{}, err
	}
	return SatelRTUCallPage{Items: items, HasMore: hasMore}, nil
}

func clampSatelBillANISuggestLimit(limit uint64) uint64 {
	if limit == 0 || limit > 100 {
		return 50
	}
	return limit
}

const satelBillANIValuesBaseQuery = `WITH times AS
		(
			SELECT record_id,argMax(cdr_date_utc,interpreted_at) AS cdr_date,
				argMax(setup_time_utc,interpreted_at) AS setup_time
			FROM collector.satel_rtu_cdr_time_facts
			WHERE device_id=?
			GROUP BY record_id
		)
		SELECT DISTINCT c.bill_ani
		FROM collector.satel_rtu_cdr AS c FINAL
		LEFT JOIN times AS t ON t.record_id=c.record_id
		WHERE c.device_id=?
			AND c.bill_ani!=''
			AND coalesce(t.setup_time,t.cdr_date,c.ingested_at)>=?
			AND coalesce(t.setup_time,t.cdr_date,c.ingested_at)<?`

// ListSatelBillANIValues returns distinct non-empty bill_ani values for a device
// within timeRange (typically one local calendar day), optionally filtered by prefix.
func (c *Client) ListSatelBillANIValues(
	ctx context.Context, deviceID uuid.UUID, prefix string, limit uint64, timeRange TimeRange,
) ([]string, error) {
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return nil, err
	}
	defer release()
	limit = clampSatelBillANISuggestLimit(limit)
	prefix = strings.TrimSpace(prefix)
	query := satelBillANIValuesBaseQuery
	args := []any{deviceID, deviceID, timeRange.From, timeRange.To}
	if prefix != "" {
		query += ` AND positionCaseInsensitive(c.bill_ani,?)>0`
		args = append(args, prefix)
	}
	query += ` ORDER BY c.bill_ani ASC LIMIT ?`
	args = append(args, limit)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]string, 0, limit)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		if value != "" {
			values = append(values, value)
		}
	}
	return values, rows.Err()
}

func (c *Client) SatelRTUStats(
	ctx context.Context, deviceID uuid.UUID,
) (DeviceStats, error) {
	now := time.Now().UTC()
	return c.SatelRTUStatsRange(
		ctx, deviceID, TimeRange{From: now.Add(-24 * time.Hour), To: now},
	)
}

func (c *Client) SatelRTUStatsRange(
	ctx context.Context, deviceID uuid.UUID, timeRange TimeRange,
) (DeviceStats, error) {
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return DeviceStats{}, err
	}
	defer release()
	var result DeviceStats
	query := `WITH times AS
		(
			SELECT record_id,argMax(setup_time_utc,interpreted_at) AS setup_time,
				argMax(cdr_date_utc,interpreted_at) AS cdr_date
			FROM collector.satel_rtu_cdr_time_facts
			WHERE device_id=?`
	args := []any{deviceID}
	query += ` GROUP BY record_id
		)
		SELECT count(),countIf(c.outcome!='answered'),
			ifNull(avgIf(c.duration_ms,c.outcome='answered'),0)
		FROM collector.satel_rtu_cdr AS c FINAL
		LEFT JOIN times AS t ON t.record_id=c.record_id
		WHERE c.device_id=?`
	args = append(args, deviceID)
	query += ` AND coalesce(t.setup_time,t.cdr_date,c.ingested_at)>=?
		AND coalesce(t.setup_time,t.cdr_date,c.ingested_at)<?`
	args = append(args, timeRange.From, timeRange.To)
	err = c.Conn.QueryRow(ctx, query, args...).Scan(
		&result.Calls24h, &result.FailedCalls24h, &result.AverageTalkMS,
	)
	return result, err
}

func localRFC3339(value *time.Time, timezone string) string {
	if value == nil {
		return ""
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		location = time.UTC
	}
	return value.In(location).Format(time.RFC3339Nano)
}
