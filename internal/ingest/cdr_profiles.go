package ingest

import "collector/internal/store"

// Built-in CDR field-name profiles keyed by firmware processing scheme.
// Order must match Eltex emitted headers for that scheme.

var cdrProfile3232 = []string{
	"Device Sign", "Setup time", "Connect time", "Disconnect time", "Duration",
	"Release cause", "Call release info", "Incoming IP-address", "Incoming type",
	"Incoming description", "Outgoing IP-address", "Outgoing type", "Outgoing description",
	"Incoming CgPN", "Outgoing CgPN", "Incoming CdPN", "Outgoing CdPN",
	"Redirecting mark", "Pickup mark", "Release side mark",
	"Incoming SS7 CIC", "Incoming SIP Call-ID", "Outgoing SS7 CIC", "Outgoing SIP Call-ID",
	"Incoming SS7 category", "Incoming Calling party category (RUS)",
	"Outgoing SS7 category", "Outgoing Calling party category (RUS)",
	"Incoming E1 stream", "Incoming E1 channel", "Outgoing E1 stream", "Outgoing E1 channel",
	"Sequence number", "Incoming redirecting number", "Outgoing redirecting number",
	"RADIUS Accounting-Session-Id", "Global Callref",
	"Incoming numplan", "Outgoing numplan", "UniqueTag identifier",
	"Calling NAI", "Called NAI", "Incoming redirecting NAI", "Outgoing redirecting NAI",
	"Call transfer mark", "Call record path", "IVR call record path",
	"Rejecting RADIUS server address", "Calling NAI original", "Called NAI original",
}

var cdrProfile3410 = []string{
	"Device Sign", "Setup time", "Connect time", "Disconnect time", "Duration",
	"Release cause", "Call release info", "Incoming IP-address", "Incoming type",
	"Incoming description", "Outgoing IP-address", "Outgoing type", "Outgoing description",
	"Incoming CgPN", "Outgoing CgPN", "Incoming CdPN", "Outgoing CdPN",
	"Redirecting mark", "Pickup mark", "Release side mark",
	"Incoming SS7 CIC", "Incoming SIP Call-ID", "Outgoing SS7 CIC", "Outgoing SIP Call-ID",
	"Incoming SS7 category", "Incoming Calling party category (RUS)",
	"Outgoing SS7 category", "Outgoing Calling party category (RUS)",
	"Incoming E1 stream", "Incoming E1 channel", "Outgoing E1 stream", "Outgoing E1 channel",
	"Sequence number", "Incoming redirecting number", "Outgoing redirecting number",
	"RADIUS Accounting-Session-Id", "Global Callref",
	"Incoming numplan", "Outgoing numplan", "UniqueTag identifier",
	"Calling NAI", "Called NAI", "Incoming redirecting NAI", "Outgoing redirecting NAI",
	"Call transfer mark", "Call record path", "IVR call record path",
	"Rejecting RADIUS server address", "Calling NAI original", "Called NAI original",
	"Time in queue", "Redirection type",
}

// CDRProfileForFirmware returns the built-in column profile for a processing scheme.
func CDRProfileForFirmware(firmware string) []string {
	switch store.NormalizeFirmwareScheme(firmware) {
	case store.FirmwareScheme3410:
		return append([]string(nil), cdrProfile3410...)
	default:
		return append([]string(nil), cdrProfile3232...)
	}
}
