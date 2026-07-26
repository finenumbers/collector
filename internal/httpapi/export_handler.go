package httpapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"collector/internal/analytics"
	"collector/internal/equipment"
	"collector/internal/store"

	"github.com/google/uuid"
)

func (s *Server) exportXLSX(writer http.ResponseWriter, request *http.Request) {
	export, err := parseExportRequest(request.URL.Query())
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	device, err := s.Store.Device(request.Context(), deviceID)
	if err != nil {
		writeError(writer, http.StatusNotFound, "device not found")
		return
	}
	if !validateExportCapability(writer, export.Dataset, device) {
		return
	}
	location, err := time.LoadLocation(device.ActiveTimezone)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "invalid device timezone")
		return
	}

	var workbook *exportWorkbook
	switch export.Dataset {
	case "calls":
		if device.TemplateKey == equipment.TemplateSatelRTUCDRV1 {
			workbook, err = s.exportSatelCalls(request, deviceID, export.Search, location)
		} else {
			workbook, err = s.exportEltexCalls(request, deviceID, export.Search, location)
		}
	case "antifraud":
		workbook, err = s.exportAntifraud(request, deviceID, export.Search, location)
	case "events":
		workbook, err = s.exportEvents(
			request, deviceID, export.Category, export.Search, location,
		)
	}
	if err != nil {
		if workbook != nil {
			_ = workbook.Close()
		}
		if request.Context().Err() != nil {
			return
		}
		writeError(writer, http.StatusInternalServerError, "unable to create export")
		return
	}
	defer workbook.Close()
	setExportResponseHeaders(
		writer, deviceID, export, device.TemplateKey, workbook.totalRows, time.Now(),
	)
	if err := workbook.Finish(writer); err != nil {
		slog.Error("XLSX response failed", "error", err)
	}
}

func validateExportCapability(writer http.ResponseWriter, dataset string, device store.Device) bool {
	switch dataset {
	case "calls":
		if !device.Capabilities.TypedCDR {
			writeError(writer, http.StatusConflict,
				"typed CDR calls are not supported by this source template")
			return false
		}
	case "antifraud":
		if !device.Capabilities.Antifraud || !device.Capabilities.Radius {
			writeError(writer, http.StatusConflict,
				"AntiFraud/RADIUS is not supported by this source template")
			return false
		}
	case "events":
		if !device.Capabilities.Syslog {
			writeError(writer, http.StatusConflict,
				"Syslog events are not supported by this source template")
			return false
		}
	}
	return true
}

func (s *Server) exportEltexCalls(
	request *http.Request, deviceID uuid.UUID, search string, location *time.Location,
) (*exportWorkbook, error) {
	headers := []any{
		"Установка", "Входящий маршрут", "Исходящий маршрут", "Номер A вход",
		"Номер A выход", "Номер B вход", "Номер B выход", "Длительность, мс",
		"Q.850", "Результат", "Acct-Session-Id", "UniqueTag",
	}
	workbook, err := newExportWorkbook(headers, excelMaximumRows)
	if err != nil {
		return nil, err
	}
	var cursor *analytics.CallCursor
	for {
		if err := request.Context().Err(); err != nil {
			return workbook, err
		}
		page, err := s.Analytics.ListCallsPage(
			request.Context(), deviceID, search, exportPageSize, cursor,
		)
		if err != nil {
			return workbook, fmt.Errorf("query Eltex calls: %w", err)
		}
		for _, row := range page.Items {
			err = workbook.AddRow(request.Context(), []any{
				formatTimeInLocation(row.SetupTime, location),
				row.IncomingDescription, row.OutgoingDescription, row.IncomingCgPN,
				row.OutgoingCgPN, row.IncomingCdPN, row.OutgoingCdPN, row.DurationMS,
				row.ReleaseCause, row.ReleaseInfo, row.RadiusSessionID, row.UniqueTag,
			})
			if err != nil {
				return workbook, err
			}
		}
		if !page.HasMore || len(page.Items) == 0 {
			return workbook, nil
		}
		last := page.Items[len(page.Items)-1]
		cursor = &analytics.CallCursor{SortTime: last.SortTime, RecordID: last.RecordID}
	}
}

func (s *Server) exportSatelCalls(
	request *http.Request, deviceID uuid.UUID, search string, location *time.Location,
) (*exportWorkbook, error) {
	headers := []any{
		"CDR ID", "CDR date", "Setup", "Connect", "Disconnect", "Duration, ms", "Elapsed",
		"Outcome", "In ANI", "In DNIS", "Out ANI", "Out DNIS", "Bill ANI",
		"Bill DNIS", "Source", "Destination", "Dial plan", "In protocol",
		"Out protocol", "In transport", "Out transport", "Conference ID",
		"In Call-ID", "Out Call-ID", "Source in conference ID", "Source in Call-ID",
		"Source out Call-ID", "Signal node", "Source gatekeeper", "Remote source signal",
		"Remote destination signal", "Remote source media", "Remote destination media",
		"Local source signal", "Local destination signal", "Local source media",
		"Local destination media", "In codecs", "Out codecs", "Disconnect code",
		"Disconnect text", "Disconnect success", "Disconnect initiator", "PDD", "SCD",
		"Term elapsed", "Term setup", "Term connect", "Term disconnect", "Term PDD",
		"Term SCD", "Source bytes in", "Source bytes out", "Destination bytes in",
		"Destination bytes out", "Source packets", "Destination packets",
		"Source packets late", "Destination packets late", "Source packets lost",
		"Destination packets lost", "Source min jitter", "Source max jitter",
		"Destination min jitter", "Destination max jitter", "Record type", "Last CDR",
		"Parser version", "Source timezone", "Raw fields",
	}
	workbook, err := newExportWorkbook(headers, excelMaximumRows)
	if err != nil {
		return nil, err
	}
	var cursor *analytics.CallCursor
	for {
		if err := request.Context().Err(); err != nil {
			return workbook, err
		}
		page, err := s.Analytics.ListSatelRTUCallsPage(
			request.Context(), deviceID, search, exportPageSize, cursor,
		)
		if err != nil {
			return workbook, fmt.Errorf("query Satel calls: %w", err)
		}
		for _, row := range page.Items {
			raw, err := json.Marshal(row.RawFields)
			if err != nil {
				return workbook, fmt.Errorf("encode Satel fields: %w", err)
			}
			err = workbook.AddRow(request.Context(), []any{
				row.CDRID, formatTimeInLocation(row.CDRDate, location),
				formatTimeInLocation(row.SetupTime, location),
				formatTimeInLocation(row.ConnectTime, location),
				formatTimeInLocation(row.DisconnectTime, location), row.DurationMS,
				row.ElapsedTime, row.Outcome, row.InANI, row.InDNIS, row.OutANI, row.OutDNIS,
				row.BillANI, row.BillDNIS, row.SrcName, row.DstName, row.DPName,
				row.InLegProto, row.OutLegProto, row.InLegTransportProto,
				row.OutLegTransportProto, row.ConfID, row.InLegCallID, row.OutLegCallID,
				row.SrcInLegConfID, row.SrcInLegCallID, row.SrcOutLegCallID,
				row.SignalNodeName, row.SrcGatekeeperAddress, row.RemoteSrcSigAddress,
				row.RemoteDstSigAddress, row.RemoteSrcMediaAddress,
				row.RemoteDstMediaAddress, row.LocalSrcSigAddress, row.LocalDstSigAddress,
				row.LocalSrcMediaAddress, row.LocalDstMediaAddress, row.InLegCodecs,
				row.OutLegCodecs, row.DisconnectCode, row.DisconnectText,
				row.DisconnectSuccess, row.DisconnectInitiator, row.PDD, row.SCD,
				row.TermElapsedTime, formatTimeInLocation(row.TermSetupTime, location),
				formatTimeInLocation(row.TermConnectTime, location),
				formatTimeInLocation(row.TermDisconnectTime, location), row.TermPDD,
				row.TermSCD, row.SrcMediaBytesIn, row.SrcMediaBytesOut, row.DstMediaBytesIn,
				row.DstMediaBytesOut, row.SrcMediaPackets, row.DstMediaPackets,
				row.SrcMediaPacketsLate, row.DstMediaPacketsLate, row.SrcMediaPacketsLost,
				row.DstMediaPacketsLost, row.SrcMinJitter, row.SrcMaxJitter, row.DstMinJitter,
				row.DstMaxJitter, row.RecordType, row.LastCDR, row.ParserVersion,
				row.SourceTimezone, string(raw),
			})
			if err != nil {
				return workbook, err
			}
		}
		if !page.HasMore || len(page.Items) == 0 {
			return workbook, nil
		}
		last := page.Items[len(page.Items)-1]
		cursor = &analytics.CallCursor{SortTime: last.SortTime, RecordID: last.RecordID}
	}
}

func (s *Server) exportAntifraud(
	request *http.Request, deviceID uuid.UUID, search string, location *time.Location,
) (*exportWorkbook, error) {
	headers := []any{
		"Первое событие", "Последнее событие", "Call context", "Acct-Session-Id",
		"Операция", "Запрос", "Ответ", "Решение", "Причина", "RADIUS server",
		"Latency, мс", "Повторы", "Calling", "Called", "Номер A вход", "Номер B вход",
		"Номер A выход", "Номер B выход", "Входящий trunk", "Исходящий trunk",
		"Accounting", "Q.850", "Полнота", "CDR legs", "Атрибуты", "CDR setup",
		"CDR Acct-Session-Id", "Метод корреляции", "Confidence", "Delta, мс",
		"Неоднозначность",
	}
	workbook, err := newExportWorkbook(headers, excelMaximumRows)
	if err != nil {
		return nil, err
	}
	var cursor *analytics.AntifraudCursor
	for {
		if err := request.Context().Err(); err != nil {
			return workbook, err
		}
		page, err := s.Analytics.ListAntifraudPage(
			request.Context(), deviceID, search, exportPageSize, cursor,
		)
		if err != nil {
			return workbook, fmt.Errorf("query AntiFraud: %w", err)
		}
		for _, row := range page.Items {
			attributes, err := json.Marshal(row.Attributes)
			if err != nil {
				return workbook, fmt.Errorf("encode AntiFraud attributes: %w", err)
			}
			err = workbook.AddRow(request.Context(), []any{
				formatTimeInLocation(&row.FirstEventAt, location),
				formatTimeInLocation(&row.LastEventAt, location), row.CallContext,
				row.AcctSessionID, row.RequestType, row.RequestCode, row.ResponseCode,
				row.Decision, row.DecisionReason, row.ServerAddress, row.LatencyMS,
				row.Retries, row.CallingStationID, row.CalledStationID, row.SrcNumberIn,
				row.DstNumberIn, row.SrcNumberOut, row.DstNumberOut, row.InTrunkgroupLabel,
				row.OutTrunkgroupLabel, row.AccountingStatus, row.Q850Cause,
				row.Completeness, row.LegCount, string(attributes),
				formatTimeInLocation(row.CDRSetupTime, location), row.CDRSessionID,
				row.CorrelationMethod, row.CorrelationConfidence,
				row.CorrelationTimeDeltaMS, row.AmbiguityReason,
			})
			if err != nil {
				return workbook, err
			}
		}
		if !page.HasMore || len(page.Items) == 0 {
			return workbook, nil
		}
		last := page.Items[len(page.Items)-1]
		cursor = &analytics.AntifraudCursor{
			LastEventAt: last.LastEventAt, TransactionID: last.TransactionID,
		}
	}
}

func (s *Server) exportEvents(
	request *http.Request, deviceID uuid.UUID, category, search string, location *time.Location,
) (*exportWorkbook, error) {
	headers := []any{
		"Получено", "Раздел", "Компонент", "Сообщение", "Исходный Syslog",
		"Статус", "Атрибуты",
	}
	workbook, err := newExportWorkbook(headers, excelMaximumRows)
	if err != nil {
		return nil, err
	}
	var cursor *analytics.EventCursor
	for {
		if err := request.Context().Err(); err != nil {
			return workbook, err
		}
		page, err := s.Analytics.ListEventsPage(
			request.Context(), deviceID, category, search, exportPageSize, cursor,
		)
		if err != nil {
			return workbook, fmt.Errorf("query events: %w", err)
		}
		for _, row := range page.Items {
			attributes, err := json.Marshal(row.Attributes)
			if err != nil {
				return workbook, fmt.Errorf("encode event attributes: %w", err)
			}
			eventTime := row.EventTime
			if eventTime == nil {
				eventTime = &row.ReceivedAt
			}
			err = workbook.AddRow(request.Context(), []any{
				formatTimeInLocation(eventTime, location), row.Category, row.Component,
				row.Message, row.RawPayload, row.Status, string(attributes),
			})
			if err != nil {
				return workbook, err
			}
		}
		if !page.HasMore || len(page.Items) == 0 {
			return workbook, nil
		}
		last := page.Items[len(page.Items)-1]
		cursor = &analytics.EventCursor{ReceivedAt: last.ReceivedAt, EventID: last.EventID}
	}
}
