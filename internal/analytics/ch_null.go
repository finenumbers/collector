package analytics

import (
	"time"

	"github.com/google/uuid"
)

// ClickHouse/database drivers call driver.Valuer methods on concrete values.
// A typed nil (*uuid.UUID)(nil) or (*time.Time)(nil) panics with:
// "value method ...Value called using nil *UUID pointer".
// These helpers always pass either a non-pointer value or an untyped nil.

func chUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}

func chUUIDPtr(value *uuid.UUID) any {
	if value == nil || *value == uuid.Nil {
		return nil
	}
	return *value
}

func chTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func chTimePtr(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return *value
}
