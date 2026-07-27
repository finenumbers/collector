package customradius

import (
	"sort"
	"time"

	"github.com/google/uuid"
)

// RecomputeSession is the pure session-level contract for storage schedulers.
// Callers provide all known raw events for a session and an explicit cutoff;
// the engine retains no hidden clock or cross-batch state.
func (engine *Engine) RecomputeSession(events []RawEvent, cutoff time.Time) Result {
	return engine.ProcessAtCutoff(events, cutoff)
}

// MergeSessionEvents deterministically combines a prior session window with
// newly fetched events. Non-nil event IDs are idempotent across retries.
func MergeSessionEvents(existing, additions []RawEvent) []RawEvent {
	merged := make([]RawEvent, 0, len(existing)+len(additions))
	seen := make(map[uuid.UUID]struct{}, len(existing)+len(additions))
	appendEvent := func(event RawEvent) {
		if event.EventID != uuid.Nil {
			if _, exists := seen[event.EventID]; exists {
				return
			}
			seen[event.EventID] = struct{}{}
		}
		merged = append(merged, event)
	}
	for _, event := range existing {
		appendEvent(event)
	}
	for _, event := range additions {
		appendEvent(event)
	}
	sort.SliceStable(merged, func(left, right int) bool {
		if merged[left].ReceivedAt.Equal(merged[right].ReceivedAt) {
			return eventIDString(merged[left].EventID) < eventIDString(merged[right].EventID)
		}
		return merged[left].ReceivedAt.Before(merged[right].ReceivedAt)
	})
	return merged
}
