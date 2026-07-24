package ingest

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCDRParserFullEltexRow(t *testing.T) {
	const sample = `SMG1016M. CDR. File started at '20260723235757'
Device Sign;Setup time;Connect time;Disconnect time;Duration;Release cause;Call release info;Incoming IP-address;Incoming type;Incoming description;Outgoing IP-address;Outgoing type;Outgoing description;Incoming CgPN;Outgoing CgPN;Incoming CdPN;Outgoing CdPN;Redirecting mark;Pickup mark;Release side mark;Incoming SS7 CIC;Incoming SIP Call-ID;Outgoing SS7 CIC;Outgoing SIP Call-ID;Incoming SS7 category;Incoming Calling party category (RUS);Outgoing SS7 category;Outgoing Calling party category (RUS);Incoming E1 stream;Incoming E1 channel;Outgoing E1 stream;Outgoing E1 channel;Sequence number;Incoming redirecting number;Outgoing redirecting number;RADIUS Accounting-Session-Id;Global Callref;Incoming numplan;Outgoing numplan;UniqueTag identifier;Calling NAI;Called NAI;Incoming redirecting NAI;Outgoing redirecting NAI;Call transfer mark;Call record path;IVR call record path;Rejecting RADIUS server address;Calling NAI original;Called NAI original;
mts;2026-07-23 23:58:33.237;2026-07-23 23:58:37.191;2026-07-23 23:58:46.657;9.466;16;user answer;5.227.161.180;trunk-SIP;PSTN_Novosibirsk_MTS_Local;11.254.255.131;trunk-SIP;11369_Novosibirsk_MTS;73832888803;3832888803;73832188654;3832188654;normal;normal;originate;;6957b57c86f211f1a421005056a36854;;1784-851113-222573;10;1;225;2;;;;;20260628183403-155881;;;11000307 6a62aaa9 c9f5297a 4f6a3001;;0;0;110003076a62aaa9c9f5297a4f6a3001;2;2;2;2;;;;;3;3;
`
	location, err := time.LoadLocation("Asia/Novosibirsk")
	if err != nil {
		t.Fatal(err)
	}
	result, err := (CDRParser{DeviceID: uuid.New(), FileID: uuid.New(), Location: location}).Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected row errors: %v", result.Errors)
	}
	if len(result.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(result.Records))
	}
	record := result.Records[0]
	if record.SequenceNumber != "20260628183403-155881" || record.Sequence != 155881 {
		t.Fatalf("sequence parsed incorrectly: %#v", record)
	}
	if record.RadiusSessionIDNormalized != "110003076a62aaa9c9f5297a4f6a3001" {
		t.Fatalf("session id normalization failed: %q", record.RadiusSessionIDNormalized)
	}
	if record.DurationMS == nil || *record.DurationMS != 9466 {
		t.Fatalf("duration parsed incorrectly: %v", record.DurationMS)
	}
	if record.UniqueTag != "110003076a62aaa9c9f5297a4f6a3001" {
		t.Fatalf("unique tag parsed incorrectly: %q", record.UniqueTag)
	}
}

func TestCDRRequiresProfileWithoutHeader(t *testing.T) {
	_, err := (CDRParser{}).Parse(strings.NewReader("mts;2026-07-23 23:58:33.237;16;"))
	if err == nil {
		t.Fatal("expected an error for a headerless CDR without a configured profile")
	}
}
