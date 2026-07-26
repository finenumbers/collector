package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"collector/internal/analytics"
	"collector/internal/archive"
	"collector/internal/equipment"
	"collector/internal/store"

	"github.com/google/uuid"
	"golang.org/x/text/encoding/charmap"
)

type CDRWatcher struct {
	Root      string
	Store     *store.Store
	Analytics CDRAnalytics
	Archive   CDRArchive
	MinAge    time.Duration
}

type CDRArchive interface {
	Put(context.Context, string, io.Reader, int64, string) error
	OpenObject(context.Context, string) (archive.Object, error)
}

type CDRAnalytics interface {
	InsertCDRBatch(context.Context, []analytics.CDRRecord) error
	InsertSatelRTUBatch(context.Context, []analytics.SatelRTURecord) error
}

func (w *CDRWatcher) Run(ctx context.Context) error {
	if w.MinAge == 0 {
		w.MinAge = 30 * time.Second
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if err := w.scan(ctx); err != nil {
			slog.Error("CDR scan failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (w *CDRWatcher) scan(ctx context.Context) error {
	if err := w.drainIngestReplays(ctx, 100); err != nil {
		slog.Error("CDR archive replay failed", "error", err)
	}
	entries, err := os.ReadDir(w.Root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		deviceID, err := uuid.Parse(entry.Name())
		if err != nil {
			continue
		}
		device, err := w.Store.Device(ctx, deviceID)
		if err != nil || !device.Enabled || device.PurgeState != "active" {
			continue
		}
		deviceDir := filepath.Join(w.Root, entry.Name())
		files, err := os.ReadDir(deviceDir)
		if err != nil {
			slog.Warn("unable to read device CDR directory", "device", deviceID, "error", err)
			continue
		}
		for _, file := range files {
			if file.IsDir() {
				slog.Warn("CDR subdirectory ignored; upload files to FTP home root",
					"device", deviceID, "dir", file.Name())
				continue
			}
			if strings.HasPrefix(file.Name(), ".") || strings.HasSuffix(file.Name(), ".part") {
				continue
			}
			path := filepath.Join(deviceDir, file.Name())
			info, err := file.Info()
			if err != nil || time.Since(info.ModTime()) < w.MinAge {
				continue
			}
			if err := w.process(ctx, device, path, info); err != nil {
				slog.Error("CDR processing failed", "device", deviceID, "file", file.Name(), "error", err)
			}
		}
	}
	return nil
}

func (w *CDRWatcher) process(ctx context.Context, device store.Device, path string, info os.FileInfo) error {
	release := w.Store.LockDeviceWrites(device.ID)
	defer release()
	current, err := w.Store.Device(ctx, device.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !current.Enabled || current.PurgeState != "active" {
		return nil
	}
	device = current
	template, err := equipment.Resolve(device.TemplateKey)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	checksum := hex.EncodeToString(sum[:])
	objectKey := fmt.Sprintf("cdr/%s/%s/%s-%s", device.ID, time.Now().UTC().Format("2006/01/02"), checksum[:16], filepath.Base(path))
	claim, err := w.Store.ClaimIngestFile(ctx, device.ID, filepath.Base(path), objectKey, checksum, info.Size())
	if err != nil {
		return err
	}
	if !claim.Retry {
		return os.Remove(path)
	}
	fileID := claim.ID
	objectKey = claim.ObjectKey
	if err := w.Archive.Put(ctx, objectKey, bytes.NewReader(content), int64(len(content)), "text/csv"); err != nil {
		_ = w.Store.CompleteIngestFile(ctx, fileID, "failed", 0, 0, err.Error())
		return err
	}
	decoded, err := decodeCDR(content)
	if err != nil {
		_ = w.Store.CompleteIngestFile(ctx, fileID, "quarantined", 0, 0, err.Error())
		// Keep the file so a later retry can succeed after content/config fixes.
		return fmt.Errorf("CDR decode failed: %w", err)
	}
	location, err := time.LoadLocation(device.ActiveTimezone)
	if err != nil {
		_ = w.Store.CompleteIngestFile(
			ctx, fileID, "quarantined", 0, 0,
			fmt.Sprintf("invalid active device timezone %q: %v", device.ActiveTimezone, err),
		)
		return fmt.Errorf("invalid active device timezone %q: %w", device.ActiveTimezone, err)
	}
	var rows, valid uint64
	var parseErrors []error
	switch template.Key {
	case equipment.TemplateSatelRTUCDRV1:
		result, parseErr := (SatelRTUCDRParser{
			DeviceID: device.ID, FileID: fileID, Location: location,
			TimezoneRevision: uint64(device.ActiveTimezoneRevision),
		}).Parse(bytes.NewReader(decoded))
		if parseErr != nil {
			_ = w.Store.CompleteIngestFile(ctx, fileID, "quarantined", 0, 0, parseErr.Error())
			return fmt.Errorf("Satel RTU CDR parse failed: %w", parseErr)
		}
		rows, valid, parseErrors = result.Rows, uint64(len(result.Records)), result.Errors
		err = insertSatelRTUForTemplate(ctx, template, w.Analytics, result.Records)
	default:
		result, parseErr := (CDRParser{
			DeviceID: device.ID, FileID: fileID, Location: location,
			TimezoneRevision:   uint64(device.ActiveTimezoneRevision),
			ExpectedHeader:     CDRProfileForFirmware(device.Firmware),
			ExpectedDeviceSign: device.DeviceSign,
		}).Parse(bytes.NewReader(decoded))
		if parseErr != nil {
			_ = w.Store.CompleteIngestFile(ctx, fileID, "quarantined", 0, 0, parseErr.Error())
			// Keep the file for retry after device_sign / column profile corrections.
			return fmt.Errorf("CDR parse failed: %w", parseErr)
		}
		rows, valid, parseErrors = result.Rows, uint64(len(result.Records)), result.Errors
		err = insertCDRForTemplate(ctx, template, w.Analytics, result.Records)
	}
	if err != nil {
		_ = w.Store.CompleteIngestFile(ctx, fileID, "failed", rows, valid, err.Error())
		return err
	}
	status := "processed"
	message := ""
	if len(parseErrors) > 0 {
		status = "quarantined"
		message = summarizeErrors(parseErrors)
	}
	parserVersion := "eltex-cdr-v1"
	if template.Key == equipment.TemplateSatelRTUCDRV1 {
		parserVersion = analytics.SatelRTUParserVersion
	}
	if err := w.Store.CompleteIngestFileWithParser(
		ctx, fileID, status, rows, valid, message, template.Key, parserVersion,
	); err != nil {
		return err
	}
	return os.Remove(path)
}

func (w *CDRWatcher) drainIngestReplays(ctx context.Context, limit int) error {
	if w.Store == nil || w.Archive == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	for range limit {
		claim, err := w.Store.ClaimNextIngestReplay(ctx)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := w.processIngestReplay(ctx, claim); err != nil {
			if retryErr := w.Store.RetryIngestReplay(ctx, claim.ID, err); retryErr != nil {
				return fmt.Errorf("replay failed: %v; queue retry failed: %w", err, retryErr)
			}
			return err
		}
	}
	return nil
}

func (w *CDRWatcher) processIngestReplay(
	ctx context.Context, claim store.IngestReplayClaim,
) error {
	if claim.ReplayTemplate != equipment.TemplateSatelRTUCDRV1 ||
		claim.ReplayVersion != analytics.SatelRTUParserVersion {
		return fmt.Errorf(
			"unsupported CDR replay target %q version %q",
			claim.ReplayTemplate, claim.ReplayVersion,
		)
	}
	release := w.Store.LockDeviceWrites(claim.DeviceID)
	defer release()
	device, err := w.Store.Device(ctx, claim.DeviceID)
	if err != nil {
		return err
	}
	if device.PurgeState != "active" {
		return store.ErrDeviceDeleting
	}
	if device.TemplateKey != equipment.TemplateSatelRTUCDRV1 {
		return fmt.Errorf("device template is %q, expected Satel RTU", device.TemplateKey)
	}
	object, err := w.Archive.OpenObject(ctx, claim.ObjectKey)
	if err != nil {
		return fmt.Errorf("open archived CDR: %w", err)
	}
	defer object.Reader.Close()
	content, err := io.ReadAll(object.Reader)
	if err != nil {
		return fmt.Errorf("read archived CDR: %w", err)
	}
	decoded, err := decodeCDR(content)
	if err != nil {
		return w.completeTerminalReplay(
			ctx, claim, 0, 0, fmt.Errorf("CDR decode failed: %w", err),
		)
	}
	location, err := time.LoadLocation(device.ActiveTimezone)
	if err != nil {
		return fmt.Errorf("invalid active device timezone %q: %w", device.ActiveTimezone, err)
	}
	result, parseErr := (SatelRTUCDRParser{
		DeviceID: device.ID, FileID: claim.ID, Location: location,
		TimezoneRevision: uint64(device.ActiveTimezoneRevision),
	}).Parse(bytes.NewReader(decoded))
	if parseErr != nil {
		return w.completeTerminalReplay(ctx, claim, 0, 0, parseErr)
	}
	if w.Analytics == nil {
		return errors.New("CDR analytics is unavailable")
	}
	if err := w.Analytics.InsertSatelRTUBatch(ctx, result.Records); err != nil {
		return err
	}
	status, message := "processed", ""
	if len(result.Errors) > 0 {
		status, message = "quarantined", summarizeErrors(result.Errors)
	}
	return w.Store.CompleteIngestReplay(
		ctx, claim.ID, status, result.Rows, uint64(len(result.Records)), message,
		equipment.TemplateSatelRTUCDRV1, analytics.SatelRTUParserVersion,
	)
}

func (w *CDRWatcher) completeTerminalReplay(
	ctx context.Context,
	claim store.IngestReplayClaim,
	rows, valid uint64,
	replayErr error,
) error {
	message := ""
	if replayErr != nil {
		message = replayErr.Error()
	}
	return w.Store.CompleteIngestReplay(
		ctx, claim.ID, "quarantined", rows, valid, message,
		equipment.TemplateSatelRTUCDRV1, analytics.SatelRTUParserVersion,
	)
}

func insertCDRForTemplate(
	ctx context.Context, template equipment.Template, client CDRAnalytics, records []analytics.CDRRecord,
) error {
	if !template.Capabilities.TypedCDR {
		return nil
	}
	if client == nil {
		return errors.New("CDR analytics is unavailable")
	}
	return client.InsertCDRBatch(ctx, records)
}

func insertSatelRTUForTemplate(
	ctx context.Context,
	template equipment.Template,
	client CDRAnalytics,
	records []analytics.SatelRTURecord,
) error {
	if template.Key != equipment.TemplateSatelRTUCDRV1 {
		return fmt.Errorf("template %q is not a Satel RTU template", template.Key)
	}
	if client == nil {
		return errors.New("CDR analytics is unavailable")
	}
	return client.InsertSatelRTUBatch(ctx, records)
}

func decodeCDR(content []byte) ([]byte, error) {
	if utf8.Valid(content) {
		return content, nil
	}
	return io.ReadAll(charmap.Windows1251.NewDecoder().Reader(bytes.NewReader(content)))
}

func summarizeErrors(items []error) string {
	const limit = 10
	values := make([]string, 0, min(len(items), limit))
	for index, item := range items {
		if index >= limit {
			break
		}
		values = append(values, item.Error())
	}
	if len(items) > limit {
		values = append(values, fmt.Sprintf("and %d more", len(items)-limit))
	}
	return strings.Join(values, "; ")
}
