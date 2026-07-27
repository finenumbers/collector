package httpapi

import (
	"time"

	"collector/internal/analytics"
)

func eltexCallExportHeaders() []string {
	return []string{
		"Установка", "Соединение", "Завершение", "Длительность, мс",
		"Q.850", "Результат", "Сторона разъединения",
		"Входящий маршрут", "Исходящий маршрут", "Тип вход", "Тип выход",
		"IP вход", "IP выход",
		"Номер A вход", "Номер A выход", "Номер B вход", "Номер B выход",
		"Redirecting вход", "Redirecting выход",
		"Numplan вход", "Numplan выход", "NAI A", "NAI B",
		"E1 stream вход", "E1 channel вход", "E1 stream выход", "E1 channel выход",
		"SIP Call-ID вход", "SIP Call-ID выход", "SS7 CIC вход", "SS7 CIC выход",
		"Acct-Session-Id", "Acct-Session-Id norm", "Global Callref", "UniqueTag",
		"Transfer", "Rejecting RADIUS", "Sequence number", "Boot epoch", "Sequence",
		"Timezone", "UTC offset min", "Setup local",
	}
}

func eltexCallExportValues(row analytics.CallRow, location *time.Location) []any {
	return []any{
		formatTimeInLocation(row.SetupTime, location),
		formatTimeInLocation(row.ConnectTime, location),
		formatTimeInLocation(row.DisconnectTime, location),
		row.DurationMS,
		row.ReleaseCause, row.ReleaseInfo, row.ReleaseSide,
		row.IncomingDescription, row.OutgoingDescription, row.IncomingType, row.OutgoingType,
		row.IncomingIP, row.OutgoingIP,
		row.IncomingCgPN, row.OutgoingCgPN, row.IncomingCdPN, row.OutgoingCdPN,
		row.IncomingRedirectingNumber, row.OutgoingRedirectingNumber,
		row.IncomingNumplan, row.OutgoingNumplan, row.CallingNAI, row.CalledNAI,
		row.IncomingE1Stream, row.IncomingE1Channel, row.OutgoingE1Stream, row.OutgoingE1Channel,
		row.IncomingSIPCallID, row.OutgoingSIPCallID, row.IncomingSS7CIC, row.OutgoingSS7CIC,
		row.RadiusSessionID, row.RadiusSessionIDNormalized, row.GlobalCallref, row.UniqueTag,
		row.TransferMark, row.RejectingRadiusServer, row.SequenceNumber, row.BootEpoch, row.Sequence,
		row.SourceTimezone, row.SourceUTCOffsetMinutes, row.SetupTimeLocal,
	}
}

func eltexCallExportHeaderAnys() []any {
	headers := eltexCallExportHeaders()
	out := make([]any, len(headers))
	for i, header := range headers {
		out[i] = header
	}
	return out
}
