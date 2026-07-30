package analytics

import (
	"context"
	"fmt"
	"sync"

	"collector/internal/geoiplookup"
	"collector/internal/pstnlookup"
	"collector/internal/workload"

	"github.com/google/uuid"
)

// RecordNeedsPSTNEnrichment reports whether any ANI/DNIS side with digits still
// lacks operator or garTerritory (eligible gaps, ineligible «-», historical gaps).
func RecordNeedsPSTNEnrichment(record SatelRTURecord) bool {
	return sideNeedsPSTNFields(record.BillANI, record.BillANIOperator, record.BillANIRegion) ||
		sideNeedsPSTNFields(record.BillDNIS, record.BillDNISOperator, record.BillDNISRegion)
}

func sideNeedsPSTNFields(phone, operator, region string) bool {
	return pstnlookup.DigitsOnly(phone) != "" && !pstnlookup.SideResolved(operator, region)
}

func applyPSTNIneligibleSides(record *SatelRTURecord, force bool) {
	if op, reg, ok := pstnlookup.MarkIneligible(
		record.BillANI, record.BillANIOperator, record.BillANIRegion, force,
	); ok {
		record.BillANIOperator, record.BillANIRegion = op, reg
	}
	if op, reg, ok := pstnlookup.MarkIneligible(
		record.BillDNIS, record.BillDNISOperator, record.BillDNISRegion, force,
	); ok {
		record.BillDNISOperator, record.BillDNISRegion = op, reg
	}
}

// EnrichSatelRecords fills PSTN operator/garTerritory and GeoIP fields in parallel.
// Only eligible phones (73/74/78/79) with missing operator or garTerritory are
// looked up — including historical gaps for catch-up. Successful API results
// overwrite that side; failures leave existing values untouched. Never fails ingest.
func EnrichSatelRecords(
	ctx context.Context, pstn *pstnlookup.Client, geoip *geoiplookup.Client, records []SatelRTURecord,
	workers int,
) {
	enrichSatelRecords(ctx, pstn, geoip, records, workers, false)
}

// EnrichSatelRecordsForcePSTN re-looks up every eligible phone (73/74/78/79) and
// overwrites operator + garTerritory even when fields already hold old region text.
func EnrichSatelRecordsForcePSTN(
	ctx context.Context, pstn *pstnlookup.Client, geoip *geoiplookup.Client, records []SatelRTURecord,
	workers int,
) {
	enrichSatelRecords(ctx, pstn, geoip, records, workers, true)
}

func enrichSatelRecords(
	ctx context.Context, pstn *pstnlookup.Client, geoip *geoiplookup.Client, records []SatelRTURecord,
	workers int, forcePSTN bool,
) {
	if len(records) == 0 {
		return
	}
	if workers < 1 {
		workers = 8
	}
	if workers > 64 {
		workers = 64
	}
	for index := range records {
		applyPSTNIneligibleSides(&records[index], forcePSTN)
	}
	var wg sync.WaitGroup
	if pstn != nil && pstn.Enabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			phones := make([]string, 0, len(records)*2)
			for _, record := range records {
				if forcePSTN {
					if pstnlookup.EligiblePhone(record.BillANI) {
						phones = append(phones, record.BillANI)
					}
					if pstnlookup.EligiblePhone(record.BillDNIS) {
						phones = append(phones, record.BillDNIS)
					}
					continue
				}
				if pstnlookup.SideNeedsEnrichment(
					record.BillANI, record.BillANIOperator, record.BillANIRegion,
				) {
					phones = append(phones, record.BillANI)
				}
				if pstnlookup.SideNeedsEnrichment(
					record.BillDNIS, record.BillDNISOperator, record.BillDNISRegion,
				) {
					phones = append(phones, record.BillDNIS)
				}
			}
			if len(phones) == 0 {
				return
			}
			byPhone := pstn.LookupMany(ctx, phones, workers)
			for index := range records {
				aniOp, aniReg, dnisOp, dnisReg, aniOK, dnisOK := pstnlookup.ApplyToPhones(
					records[index].BillANI, records[index].BillDNIS, byPhone,
				)
				if aniOK {
					records[index].BillANIOperator = aniOp
					records[index].BillANIRegion = aniReg
				}
				if dnisOK {
					records[index].BillDNISOperator = dnisOp
					records[index].BillDNISRegion = dnisReg
				}
			}
		}()
	}
	if geoip != nil && geoip.Enabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs := make([]string, 0, len(records)*2)
			for _, record := range records {
				if record.RemoteSrcSigAddress != "" {
					addrs = append(addrs, record.RemoteSrcSigAddress)
				}
				if record.RemoteDstSigAddress != "" {
					addrs = append(addrs, record.RemoteDstSigAddress)
				}
			}
			if len(addrs) == 0 {
				return
			}
			byIP := geoip.LookupMany(ctx, addrs, workers)
			for index := range records {
				srcISO, srcCity, srcASN, dstISO, dstCity, dstASN := geoiplookup.ApplyToAddrs(
					records[index].RemoteSrcSigAddress, records[index].RemoteDstSigAddress, byIP,
				)
				records[index].RemoteSrcGeoipISO = srcISO
				records[index].RemoteSrcGeoipCity = srcCity
				records[index].RemoteSrcASNOrg = srcASN
				records[index].RemoteDstGeoipISO = dstISO
				records[index].RemoteDstGeoipCity = dstCity
				records[index].RemoteDstASNOrg = dstASN
			}
		}()
	}
	wg.Wait()
}

func satelEnrichmentSelectColumns() string {
	return `record_id,device_id,file_id,row_number,ingested_at,parser_version,template_key,cdr_id,
		cdr_date,setup_time,connect_time,disconnect_time,duration_ms,elapsed_time,outcome,
		in_ani,in_dnis,out_ani,out_dnis,bill_ani,bill_dnis,
		bill_ani_operator,bill_dnis_operator,bill_ani_region,bill_dnis_region,
		src_user,dst_user,radius_user,src_name,dst_name,dp_name,in_cpc,out_cpc,in_zone,out_zone,
		in_orig_dnis,out_orig_dnis,in_ani_type_of_number,in_dnis_type_of_number,
		out_ani_type_of_number,out_dnis_type_of_number,in_orig_dnis_type_of_number,
		out_orig_dnis_type_of_number,ext_ani_type_of_number,ext_dnis_type_of_number,
		ext_orig_dnis_type_of_number,in_ani_screening,in_ani_presentation,out_ani_screening,
		out_ani_presentation,in_lrn,retrieved_lrn,lrn,ext_lrn,out_lrn,lnp_server,
		signal_node_name,src_gatekeeper_address,remote_src_sig_address,remote_dst_sig_address,
		remote_src_geoip_iso,remote_src_geoip_city,remote_src_asn_org,
		remote_dst_geoip_iso,remote_dst_geoip_city,remote_dst_asn_org,
		remote_src_media_address,remote_dst_media_address,local_src_sig_address,
		local_dst_sig_address,local_src_media_address,local_dst_media_address,
		in_leg_proto,out_leg_proto,in_leg_transport_proto,out_leg_transport_proto,
		conf_id,in_leg_call_id,out_leg_call_id,src_in_leg_conf_id,src_in_leg_call_id,
		src_out_leg_call_id,in_leg_codecs,out_leg_codecs,disconnect_code,disconnect_text,
		disconnect_success,disconnect_initiator,src_disconnect_codes,dst_disconnect_codes,
		src_disconnect_text,dst_disconnect_text,pdd,scd,term_elapsed_time,term_setup_time,
		term_connect_time,term_disconnect_time,term_pdd,term_scd,src_media_bytes_in,
		src_media_bytes_out,dst_media_bytes_in,dst_media_bytes_out,src_media_packets,
		dst_media_packets,src_media_packets_late,dst_media_packets_late,src_media_packets_lost,
		dst_media_packets_lost,src_min_jitter,src_max_jitter,dst_min_jitter,dst_max_jitter,
		route_retries,outgoing_pulses,incoming_pulses,looping_cycles,proxy_mode,lar_fault_reason,
		media_group,external_router,radius_group,sip_routing_group,auth_dnis,ext_ani,ext_dnis,
		ext_sig_address,in_partner_id,out_partner_id,in_encryption,out_encryption,
		record_type,last_cdr,raw_fields,source_timezone,source_utc_offset_minutes,timezone_revision`
}

func scanSatelEnrichmentRecord(scanner interface {
	Scan(dest ...any) error
}) (SatelRTURecord, error) {
	var record SatelRTURecord
	err := scanner.Scan(
		&record.RecordID, &record.DeviceID, &record.FileID, &record.RowNumber,
		&record.IngestedAt, &record.ParserVersion, &record.TemplateKey, &record.CDRID,
		&record.CDRDate, &record.SetupTime, &record.ConnectTime, &record.DisconnectTime,
		&record.DurationMS, &record.ElapsedTime, &record.Outcome, &record.InANI, &record.InDNIS,
		&record.OutANI, &record.OutDNIS, &record.BillANI, &record.BillDNIS,
		&record.BillANIOperator, &record.BillDNISOperator, &record.BillANIRegion,
		&record.BillDNISRegion, &record.SrcUser, &record.DstUser, &record.RadiusUser,
		&record.SrcName, &record.DstName, &record.DPName, &record.InCPC, &record.OutCPC,
		&record.InZone, &record.OutZone, &record.InOrigDNIS, &record.OutOrigDNIS,
		&record.InANITypeOfNumber, &record.InDNISTypeOfNumber, &record.OutANITypeOfNumber,
		&record.OutDNISTypeOfNumber, &record.InOrigDNISTypeOfNumber,
		&record.OutOrigDNISTypeOfNumber, &record.ExtANITypeOfNumber,
		&record.ExtDNISTypeOfNumber, &record.ExtOrigDNISTypeOfNumber,
		&record.InANIScreening, &record.InANIPresentation, &record.OutANIScreening,
		&record.OutANIPresentation, &record.InLRN, &record.RetrievedLRN, &record.LRN,
		&record.ExtLRN, &record.OutLRN, &record.LNPServer, &record.SignalNodeName,
		&record.SrcGatekeeperAddress, &record.RemoteSrcSigAddress,
		&record.RemoteDstSigAddress,
		&record.RemoteSrcGeoipISO, &record.RemoteSrcGeoipCity, &record.RemoteSrcASNOrg,
		&record.RemoteDstGeoipISO, &record.RemoteDstGeoipCity, &record.RemoteDstASNOrg,
		&record.RemoteSrcMediaAddress,
		&record.RemoteDstMediaAddress, &record.LocalSrcSigAddress,
		&record.LocalDstSigAddress, &record.LocalSrcMediaAddress,
		&record.LocalDstMediaAddress, &record.InLegProto, &record.OutLegProto,
		&record.InLegTransportProto, &record.OutLegTransportProto, &record.ConfID,
		&record.InLegCallID, &record.OutLegCallID, &record.SrcInLegConfID,
		&record.SrcInLegCallID, &record.SrcOutLegCallID, &record.InLegCodecs,
		&record.OutLegCodecs, &record.DisconnectCode, &record.DisconnectText,
		&record.DisconnectSuccess, &record.DisconnectInitiator, &record.SrcDisconnectCodes,
		&record.DstDisconnectCodes, &record.SrcDisconnectText, &record.DstDisconnectText,
		&record.PDD, &record.SCD, &record.TermElapsedTime, &record.TermSetupTime,
		&record.TermConnectTime, &record.TermDisconnectTime, &record.TermPDD, &record.TermSCD,
		&record.SrcMediaBytesIn, &record.SrcMediaBytesOut, &record.DstMediaBytesIn,
		&record.DstMediaBytesOut, &record.SrcMediaPackets, &record.DstMediaPackets,
		&record.SrcMediaPacketsLate, &record.DstMediaPacketsLate,
		&record.SrcMediaPacketsLost, &record.DstMediaPacketsLost, &record.SrcMinJitter,
		&record.SrcMaxJitter, &record.DstMinJitter, &record.DstMaxJitter,
		&record.RouteRetries, &record.OutgoingPulses, &record.IncomingPulses,
		&record.LoopingCycles, &record.ProxyMode, &record.LARFaultReason,
		&record.MediaGroup, &record.ExternalRouter, &record.RadiusGroup,
		&record.SIPRoutingGroup, &record.AuthDNIS, &record.ExtANI, &record.ExtDNIS,
		&record.ExtSigAddress, &record.InPartnerID, &record.OutPartnerID,
		&record.InEncryption, &record.OutEncryption, &record.RecordType, &record.LastCDR,
		&record.RawFields, &record.SourceTimezone, &record.SourceUTCOffsetMinutes,
		&record.TimezoneRevision,
	)
	return record, err
}

// satelPSTNDigitsExpr keeps digits only from a phone column.
func satelPSTNDigitsExpr(column string) string {
	return fmt.Sprintf("replaceRegexpAll(%s, '[^0-9]', '')", column)
}

// satelPSTNEligibleSideExpr is true for exactly 11 digits starting with
// 73/74/78/79 (or trunk-8 83/84/88/89, including 7800/8800). Bare 10-digit
// nationals are never eligible.
func satelPSTNEligibleSideExpr(column string) string {
	digits := satelPSTNDigitsExpr(column)
	return fmt.Sprintf(
		`(length(%[1]s)=11 AND match(%[1]s, '^(73|74|78|79|83|84|88|89)'))`,
		digits,
	)
}

func satelPSTNSideCompleteExpr(operatorCol, regionCol string) string {
	return fmt.Sprintf("(%s!='' AND %s!='')", operatorCol, regionCol)
}

// Any side with digits and missing operator/region needs enrich (eligible lookup
// or ineligible «-» sentinel).
func satelPSTNNeedsEnrichmentExpr() string {
	aniDigits := satelPSTNDigitsExpr("bill_ani")
	dnisDigits := satelPSTNDigitsExpr("bill_dnis")
	aniComplete := satelPSTNSideCompleteExpr("bill_ani_operator", "bill_ani_region")
	dnisComplete := satelPSTNSideCompleteExpr("bill_dnis_operator", "bill_dnis_region")
	return fmt.Sprintf(`((length(%s)>0 AND NOT %s) OR (length(%s)>0 AND NOT %s))`,
		aniDigits, aniComplete, dnisDigits, dnisComplete)
}

func satelPSTNCallEligibleExpr() string {
	return fmt.Sprintf("(%s OR %s)",
		satelPSTNEligibleSideExpr("bill_ani"), satelPSTNEligibleSideExpr("bill_dnis"))
}

// Call is PSTN-enriched when every eligible side has both operator and garTerritory.
func satelPSTNCallEnrichedExpr() string {
	aniEligible := satelPSTNEligibleSideExpr("bill_ani")
	dnisEligible := satelPSTNEligibleSideExpr("bill_dnis")
	aniComplete := satelPSTNSideCompleteExpr("bill_ani_operator", "bill_ani_region")
	dnisComplete := satelPSTNSideCompleteExpr("bill_dnis_operator", "bill_dnis_region")
	return fmt.Sprintf(`(%s AND (NOT %s OR %s) AND (NOT %s OR %s))`,
		satelPSTNCallEligibleExpr(), aniEligible, aniComplete, dnisEligible, dnisComplete)
}

// satelPSTNAllColumnsFilledExpr is true when every PSTN API column on the row is set
// (Оператор A/B + Регион A/B). Used by the softswitch Dashboard KPI.
func satelPSTNAllColumnsFilledExpr() string {
	return `(bill_ani_operator!='' AND bill_dnis_operator!=''
		AND bill_ani_region!='' AND bill_dnis_region!='')`
}

// satelGeoipAllColumnsFilledExpr is true when every GeoIP API column on the row is set
// (ISO/City/ASN for src and dst). Used by the softswitch Dashboard KPI.
func satelGeoipAllColumnsFilledExpr() string {
	return `(remote_src_geoip_iso!='' AND remote_dst_geoip_iso!=''
		AND remote_src_geoip_city!='' AND remote_dst_geoip_city!=''
		AND remote_src_asn_org!='' AND remote_dst_asn_org!='')`
}

func satelNeedsEnrichmentPredicate() string {
	return `(` + satelPSTNNeedsEnrichmentExpr() + `)
				OR ((remote_src_sig_address!='' OR remote_dst_sig_address!='')
					AND remote_src_geoip_iso='' AND remote_dst_geoip_iso=''
					AND remote_src_geoip_city='' AND remote_dst_geoip_city=''
					AND remote_src_asn_org='' AND remote_dst_asn_org='')`
}

// ListSatelRTURecordsNeedingEnrichment pages FINAL rows missing PSTN and/or GeoIP
// enrichment when source phone/IP is present.
func (c *Client) ListSatelRTURecordsNeedingEnrichment(
	ctx context.Context, limit uint64, afterRecordID uuid.UUID,
) ([]SatelRTURecord, error) {
	if limit == 0 || limit > 5000 {
		limit = 500
	}
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return nil, err
	}
	defer release()
	query := `SELECT ` + satelEnrichmentSelectColumns() + `
		FROM collector.satel_rtu_cdr FINAL
		WHERE record_id>?
			AND (` + satelNeedsEnrichmentPredicate() + `)
		ORDER BY record_id ASC
		LIMIT ?`
	rows, err := c.Conn.Query(ctx, query, afterRecordID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SatelRTURecord, 0, limit)
	for rows.Next() {
		record, scanErr := scanSatelEnrichmentRecord(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

// ListSatelRTURecordsNeedingPSTNEnrichment is kept for compatibility.
func (c *Client) ListSatelRTURecordsNeedingPSTNEnrichment(
	ctx context.Context, limit uint64, afterRecordID uuid.UUID,
) ([]SatelRTURecord, error) {
	return c.ListSatelRTURecordsNeedingEnrichment(ctx, limit, afterRecordID)
}

// ListSatelRTURecordsForPSTNRefresh pages FINAL rows with at least one eligible
// PSTN phone (73/74/78/79), for one-shot garTerritory rewrite of old region values.
func (c *Client) ListSatelRTURecordsForPSTNRefresh(
	ctx context.Context, limit uint64, afterRecordID uuid.UUID,
) ([]SatelRTURecord, error) {
	if limit == 0 || limit > 5000 {
		limit = 500
	}
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return nil, err
	}
	defer release()
	query := `SELECT ` + satelEnrichmentSelectColumns() + `
		FROM collector.satel_rtu_cdr FINAL
		WHERE record_id>?
			AND ` + satelPSTNCallEligibleExpr() + `
		ORDER BY record_id ASC
		LIMIT ?`
	rows, err := c.Conn.Query(ctx, query, afterRecordID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SatelRTURecord, 0, limit)
	for rows.Next() {
		record, scanErr := scanSatelEnrichmentRecord(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

// EnrichmentCoverageSnapshot is Satel PSTN/GeoIP fill progress for diagnostics.
type EnrichmentCoverageSnapshot struct {
	WindowSeconds  uint64  `json:"windowSeconds"`
	Calls          uint64  `json:"calls"`
	PstnEligible   uint64  `json:"pstnEligible"`
	PstnEnriched   uint64  `json:"pstnEnriched"`
	PstnCoverage   float64 `json:"pstnCoverage"`
	GeoipEligible  uint64  `json:"geoipEligible"`
	GeoipEnriched  uint64  `json:"geoipEnriched"`
	GeoipCoverage  float64 `json:"geoipCoverage"`
	Backlog        uint64  `json:"backlog"`
}

func (c *Client) EnrichmentCoverage(ctx context.Context, windowSeconds uint64) (EnrichmentCoverageSnapshot, error) {
	if windowSeconds == 0 {
		windowSeconds = 24 * 3600
	}
	ctx, release, err := c.queryContext(ctx, workload.Diagnostics)
	if err != nil {
		return EnrichmentCoverageSnapshot{}, err
	}
	defer release()
	out := EnrichmentCoverageSnapshot{WindowSeconds: windowSeconds}
	err = c.Conn.QueryRow(ctx, `
		SELECT
			count(),
			countIf(`+satelPSTNCallEligibleExpr()+`),
			countIf(`+satelPSTNCallEnrichedExpr()+`),
			countIf(remote_src_sig_address!='' OR remote_dst_sig_address!=''),
			countIf(remote_src_geoip_iso!='' OR remote_dst_geoip_iso!=''
				OR remote_src_geoip_city!='' OR remote_dst_geoip_city!=''
				OR remote_src_asn_org!='' OR remote_dst_asn_org!='')
		FROM collector.satel_rtu_cdr FINAL
		WHERE ingested_at>=now()-toIntervalSecond(?)`, windowSeconds).Scan(
		&out.Calls, &out.PstnEligible, &out.PstnEnriched,
		&out.GeoipEligible, &out.GeoipEnriched,
	)
	if err != nil {
		return EnrichmentCoverageSnapshot{}, err
	}
	if out.PstnEligible > 0 {
		out.PstnCoverage = float64(out.PstnEnriched) / float64(out.PstnEligible)
	}
	if out.GeoipEligible > 0 {
		out.GeoipCoverage = float64(out.GeoipEnriched) / float64(out.GeoipEligible)
	}
	if err := c.Conn.QueryRow(ctx, `
		SELECT count()
		FROM collector.satel_rtu_cdr FINAL
		WHERE `+satelNeedsEnrichmentPredicate()).Scan(&out.Backlog); err != nil {
		return EnrichmentCoverageSnapshot{}, err
	}
	return out, nil
}
