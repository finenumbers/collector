package customradius

import (
	"testing"

	"github.com/google/uuid"
)

func TestLessEventIDMatchesStringOrder(t *testing.T) {
	left := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	right := uuid.MustParse("00000000-0000-4000-8000-000000000010")
	if !LessEventID(left, right) {
		t.Fatal("expected left < right")
	}
	if LessEventID(right, left) {
		t.Fatal("expected right not < left")
	}
	if (left.String() < right.String()) != LessEventID(left, right) {
		t.Fatalf("string order diverged: %s vs %s", left, right)
	}
	for range 64 {
		a, b := uuid.New(), uuid.New()
		if (a.String() < b.String()) != LessEventID(a, b) {
			t.Fatalf("string/bytes order mismatch: %s vs %s", a, b)
		}
	}
}
