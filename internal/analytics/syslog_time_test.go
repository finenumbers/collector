package analytics

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSyslogTimeTruncatesToMicroseconds(t *testing.T) {
	raw := time.Date(2026, 8, 3, 15, 41, 28, 815746123, time.UTC)
	got := syslogTime(raw)
	if got.Nanosecond() != 815746000 {
		t.Fatalf("nanoseconds=%d, want microsecond truncation", got.Nanosecond())
	}
	cursor := normalizeSyslogCursor(&SyslogMessageCursor{
		ReceivedAt: raw, EventID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
	})
	if cursor == nil || cursor.ReceivedAt.Nanosecond() != 815746000 {
		t.Fatalf("normalizeSyslogCursor=%v", cursor)
	}
}
