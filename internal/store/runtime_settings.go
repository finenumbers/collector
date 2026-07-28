package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"collector/internal/runtimesettings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type RuntimeSettingsRow struct {
	Settings  runtimesettings.Document
	UpdatedAt time.Time
	UpdatedBy *uuid.UUID
	Seeded    bool
}

func (s *Store) LoadRuntimeSettings(ctx context.Context) (RuntimeSettingsRow, error) {
	var raw []byte
	var updatedAt time.Time
	var updatedBy *uuid.UUID
	err := s.DB.QueryRow(ctx, `SELECT settings,updated_at,updated_by
		FROM system_runtime_settings WHERE id=1`).Scan(&raw, &updatedAt, &updatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return RuntimeSettingsRow{Settings: runtimesettings.Defaults(), Seeded: false}, nil
	}
	if err != nil {
		return RuntimeSettingsRow{}, err
	}
	row := RuntimeSettingsRow{UpdatedAt: updatedAt, UpdatedBy: updatedBy}
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		row.Settings = runtimesettings.Defaults()
		row.Seeded = false
		return row, nil
	}
	if err := json.Unmarshal(raw, &row.Settings); err != nil {
		return RuntimeSettingsRow{}, err
	}
	if row.Settings.Containers.APICpus == "" {
		row.Settings.Containers = runtimesettings.Defaults().Containers
	}
	row.Seeded = true
	return row, nil
}

func (s *Store) SaveRuntimeSettings(
	ctx context.Context, doc runtimesettings.Document, actor *uuid.UUID,
) (RuntimeSettingsRow, error) {
	if err := doc.Validate(); err != nil {
		return RuntimeSettingsRow{}, err
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return RuntimeSettingsRow{}, err
	}
	var updatedAt time.Time
	var updatedBy *uuid.UUID
	err = s.DB.QueryRow(ctx, `INSERT INTO system_runtime_settings (id,settings,updated_at,updated_by)
		VALUES (1,$1::jsonb,now(),$2)
		ON CONFLICT (id) DO UPDATE SET
			settings=EXCLUDED.settings,updated_at=now(),updated_by=EXCLUDED.updated_by
		RETURNING updated_at,updated_by`, raw, actor).Scan(&updatedAt, &updatedBy)
	if err != nil {
		return RuntimeSettingsRow{}, err
	}
	return RuntimeSettingsRow{Settings: doc, UpdatedAt: updatedAt, UpdatedBy: updatedBy, Seeded: true}, nil
}

// EnsureRuntimeSettings seeds DB from bootstrap when empty, otherwise loads stored values.
func (s *Store) EnsureRuntimeSettings(
	ctx context.Context, bootstrap runtimesettings.Document,
) (runtimesettings.Document, error) {
	row, err := s.LoadRuntimeSettings(ctx)
	if err != nil {
		return runtimesettings.Document{}, err
	}
	if row.Seeded {
		if err := row.Settings.Validate(); err != nil {
			fixed := runtimesettings.Defaults()
			merged, mergeErr := overlayMissing(fixed, row.Settings)
			if mergeErr != nil {
				return runtimesettings.Document{}, mergeErr
			}
			if err := merged.Validate(); err != nil {
				return runtimesettings.Document{}, err
			}
			saved, saveErr := s.SaveRuntimeSettings(ctx, merged, nil)
			return saved.Settings, saveErr
		}
		return row.Settings, nil
	}
	seed := bootstrap.Clone()
	if err := seed.Validate(); err != nil {
		seed = runtimesettings.Defaults()
	}
	saved, err := s.SaveRuntimeSettings(ctx, seed, nil)
	return saved.Settings, err
}

func overlayMissing(base, stored runtimesettings.Document) (runtimesettings.Document, error) {
	raw, err := json.Marshal(stored)
	if err != nil {
		return runtimesettings.Document{}, err
	}
	return runtimesettings.MergePatch(base, raw)
}
