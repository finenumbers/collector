package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"collector/internal/equipment"
	"collector/internal/store"

	"github.com/google/uuid"
)

type satelDetectionStore interface {
	RawDevicesNeedingDetection(context.Context) ([]store.Device, error)
	RecentImmutableIngestObjects(context.Context, uuid.UUID, int) ([]store.ImmutableIngestObject, error)
	RecordTemplateDetection(context.Context, uuid.UUID, string, string, string, string, *time.Time) error
	ActivateDetectedSatel(context.Context, uuid.UUID, string, time.Time) error
	LockDeviceWrites(uuid.UUID) func()
}

func reconcileRawSatelTemplates(
	ctx context.Context, database satelDetectionStore, objects CDRArchive,
) error {
	if database == nil || objects == nil {
		return nil
	}
	devices, err := database.RawDevicesNeedingDetection(ctx)
	if err != nil {
		return err
	}
	for _, device := range devices {
		if err := reconcileRawSatelDevice(ctx, database, objects, device.ID); err != nil {
			slog.Warn("raw CDR template detection failed", "device", device.ID, "error", err)
		}
	}
	return nil
}

func reconcileRawSatelDevice(
	ctx context.Context, database satelDetectionStore, archive CDRArchive, deviceID uuid.UUID,
) error {
	// This per-device lock serializes detection with ingest/replay and excludes
	// purge. The transaction also verifies the latest immutable ledger timestamp
	// before activation.
	release := database.LockDeviceWrites(deviceID)
	defer release()
	samples, err := database.RecentImmutableIngestObjects(ctx, deviceID, 3)
	if err != nil {
		return err
	}
	if len(samples) == 0 {
		return database.RecordTemplateDetection(
			ctx, deviceID, "no_samples", "", "", "no immutable archived CDR samples", nil,
		)
	}
	latest := samples[0].ReceivedAt
	fingerprint := ""
	var mismatches []string
	for _, sample := range samples {
		object, err := archive.OpenObject(ctx, sample.ObjectKey)
		if err != nil {
			message := fmt.Sprintf("open archived sample %s: %v", sample.ID, err)
			_ = database.RecordTemplateDetection(
				ctx, deviceID, "error", "", fingerprint, message, &latest,
			)
			return errors.New(message)
		}
		detection := SatelRTUHeaderFingerprint(io.LimitReader(object.Reader, 256<<10))
		closeErr := object.Reader.Close()
		if closeErr != nil {
			slog.Debug("archived CDR sample close failed", "object", sample.ObjectKey, "error", closeErr)
		}
		if detection.Fingerprint != "" {
			if fingerprint == "" {
				fingerprint = detection.Fingerprint
			} else if detection.Fingerprint != fingerprint {
				mismatches = append(mismatches, fmt.Sprintf("%s: conflicting fingerprint", sample.ID))
			}
		}
		if !detection.Match {
			mismatches = append(mismatches, fmt.Sprintf("%s: %s", sample.ID, detection.Reason))
		}
	}
	if len(mismatches) > 0 {
		return database.RecordTemplateDetection(
			ctx, deviceID, "mixed", "", fingerprint, strings.Join(mismatches, "; "), &latest,
		)
	}
	if err := database.RecordTemplateDetection(
		ctx, deviceID, "matched", equipment.TemplateSatelRTUCDRV1, fingerprint,
		"all inspected immutable samples matched", &latest,
	); err != nil {
		return err
	}
	return database.ActivateDetectedSatel(ctx, deviceID, fingerprint, latest)
}
