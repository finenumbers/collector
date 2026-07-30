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
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"collector/internal/analytics"
	"collector/internal/archive"
	"collector/internal/equipment"
	"collector/internal/pstnlookup"
	"collector/internal/store"

	"github.com/google/uuid"
	"golang.org/x/text/encoding/charmap"
)

type CDRWatcher struct {
	Root                      string
	Store                     *store.Store
	Analytics                 CDRAnalytics
	Archive                   CDRArchive
	PSTN                      *pstnlookup.Client
	MinAge                    time.Duration
	CoverageThresholds        analytics.CoverageThresholds
	CoverageThresholdsFn      func() analytics.CoverageThresholds
	CustomProjectionEnabled   bool
	CustomProjectionEnabledFn func() bool

	retryMu sync.Mutex
	retries map[string]watcherRetry
	now     func() time.Time
}

type watcherRetry struct {
	failures uint
	next     time.Time
	terminal bool
}

func (w *CDRWatcher) projectionEnabled() bool {
	if w.CustomProjectionEnabledFn != nil {
		return w.CustomProjectionEnabledFn()
	}
	return w.CustomProjectionEnabled
}

func (w *CDRWatcher) coverageThresholds() analytics.CoverageThresholds {
	if w.CoverageThresholdsFn != nil {
		return w.CoverageThresholdsFn()
	}
	return w.CoverageThresholds
}

var errTerminalIngest = errors.New("terminal CDR ingest result")

const (
	initialIngestBackoff = 10 * time.Second
	maxIngestBackoff     = 10 * time.Minute
)

type CDRArchive interface {
	Put(context.Context, string, io.Reader, int64, string) error
	OpenObject(context.Context, string) (archive.Object, error)
}

type CDRAnalytics interface {
	InsertCDRBatch(context.Context, []analytics.CDRRecord) error
	InsertSatelRTUBatch(context.Context, []analytics.SatelRTURecord) error
}

type CDRCoverageAnalytics interface {
	InsertCDRBatchWithCoverage(
		context.Context, []analytics.CDRRecord, bool, uint64, analytics.CoverageThresholds,
	) error
}

type VoipmonitorDirtyEnqueuer interface {
	EnqueueVoipmonitorDirtyBuckets(
		ctx context.Context, deviceID uuid.UUID, policyRevision uint64, buckets []time.Time, reason string,
	) error
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
			retryKey := ingestWatchKey(device, path, info)
			if !w.retryReady(retryKey) {
				continue
			}
			if err := w.process(ctx, device, path, info); err != nil {
				w.recordRetry(retryKey, errors.Is(err, errTerminalIngest))
				slog.Error("CDR processing failed", "device", deviceID, "file", file.Name(), "error", err)
			} else {
				w.clearRetry(retryKey)
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
	parserTemplate, parserIdentity := ingestParserIdentity(device, template)
	claim, err := w.Store.ClaimIngestFileForParser(
		ctx, device.ID, filepath.Base(path), objectKey, checksum, info.Size(),
		parserTemplate, parserIdentity,
	)
	if err != nil {
		return err
	}
	if !claim.Retry {
		if claim.RemoveLocal {
			return os.Remove(path)
		}
		return errTerminalIngest
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
		return fmt.Errorf("%w: CDR decode failed: %v", errTerminalIngest, err)
	}
	location, err := time.LoadLocation(device.ActiveTimezone)
	if err != nil {
		_ = w.Store.CompleteIngestFile(
			ctx, fileID, "quarantined", 0, 0,
			fmt.Sprintf("invalid active device timezone %q: %v", device.ActiveTimezone, err),
		)
		return fmt.Errorf("%w: invalid active device timezone %q: %v",
			errTerminalIngest, device.ActiveTimezone, err)
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
			return fmt.Errorf("%w: Satel RTU CDR parse failed: %v", errTerminalIngest, parseErr)
		}
		rows, valid, parseErrors = result.Rows, uint64(len(result.Records)), result.Errors
		analytics.EnrichSatelRecords(ctx, w.PSTN, result.Records)
		err = insertSatelRTUForTemplate(ctx, template, w.Analytics, result.Records)
		if err == nil {
			err = w.enqueueVoipmonitorBuckets(ctx, device.ID, satelRecordBuckets(result.Records))
		}
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
			return fmt.Errorf("%w: CDR parse failed: %v", errTerminalIngest, parseErr)
		}
		rows, valid, parseErrors = result.Rows, uint64(len(result.Records)), result.Errors
		if !w.projectionEnabled() {
			err = w.Analytics.InsertCDRBatch(ctx, result.Records)
		} else {
			policy, policyErr := w.Store.CustomAntifraudPolicy(ctx, device.ID)
			if policyErr != nil {
				err = policyErr
			} else {
				err = insertCDRForTemplate(
					ctx, template, w.Analytics, result.Records, policy.Enabled, policy.Revision,
					w.coverageThresholds(),
				)
				if err == nil && policy.Enabled {
					err = w.Store.EnqueueCDRReconciliationBuckets(
						ctx, device.ID, policy.Revision, cdrRecordBuckets(result.Records),
					)
				}
			}
		}
		if err == nil {
			err = w.enqueueVoipmonitorBuckets(ctx, device.ID, cdrRecordBuckets(result.Records))
		}
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
	if err := w.Store.CompleteIngestFileWithParser(
		ctx, fileID, status, rows, valid, message, parserTemplate, parserIdentity,
	); err != nil {
		return err
	}
	if status == "quarantined" {
		return fmt.Errorf("%w: %s", errTerminalIngest, message)
	}
	return os.Remove(path)
}

func ingestParserIdentity(device store.Device, template equipment.Template) (string, string) {
	version := "eltex-cdr-v2"
	if template.Key == equipment.TemplateSatelRTUCDRV1 {
		version = analytics.SatelRTUParserVersion
	}
	config := strings.Join([]string{
		version,
		template.Key,
		store.NormalizeFirmwareScheme(device.Firmware),
		strings.ToLower(strings.TrimSpace(device.DeviceSign)),
		device.ActiveTimezone,
		fmt.Sprint(device.ActiveTimezoneRevision),
	}, "\x00")
	sum := sha256.Sum256([]byte(config))
	return template.Key, version + "+" + hex.EncodeToString(sum[:8])
}

func ingestWatchKey(device store.Device, path string, info os.FileInfo) string {
	template, err := equipment.Resolve(device.TemplateKey)
	if err != nil {
		return path
	}
	_, identity := ingestParserIdentity(device, template)
	return fmt.Sprintf("%s\x00%d\x00%d\x00%s",
		path, info.Size(), info.ModTime().UnixNano(), identity)
}

func (w *CDRWatcher) retryReady(key string) bool {
	w.retryMu.Lock()
	defer w.retryMu.Unlock()
	state, exists := w.retries[key]
	if !exists {
		return true
	}
	return !state.terminal && !w.currentTime().Before(state.next)
}

func (w *CDRWatcher) recordRetry(key string, terminal bool) {
	w.retryMu.Lock()
	defer w.retryMu.Unlock()
	if w.retries == nil {
		w.retries = make(map[string]watcherRetry)
	}
	state := w.retries[key]
	state.failures++
	state.terminal = terminal
	if !terminal {
		delay := initialIngestBackoff
		for count := uint(1); count < state.failures && delay < maxIngestBackoff; count++ {
			delay *= 2
			if delay > maxIngestBackoff {
				delay = maxIngestBackoff
			}
		}
		state.next = w.currentTime().Add(delay)
	}
	w.retries[key] = state
}

func (w *CDRWatcher) clearRetry(key string) {
	w.retryMu.Lock()
	defer w.retryMu.Unlock()
	delete(w.retries, key)
}

func (w *CDRWatcher) currentTime() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
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
	analytics.EnrichSatelRecords(ctx, w.PSTN, result.Records)
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
	ctx context.Context, template equipment.Template, client CDRAnalytics,
	records []analytics.CDRRecord, policy ...any,
) error {
	if !template.Capabilities.TypedCDR {
		return nil
	}
	if client == nil {
		return errors.New("CDR analytics is unavailable")
	}
	antifraudEnabled := false
	var policyRevision uint64
	if len(policy) > 0 {
		antifraudEnabled, _ = policy[0].(bool)
	}
	if len(policy) > 1 {
		policyRevision, _ = policy[1].(uint64)
	}
	thresholds := analytics.CoverageThresholds{}
	if len(policy) > 2 {
		thresholds, _ = policy[2].(analytics.CoverageThresholds)
	}
	if coverage, ok := client.(CDRCoverageAnalytics); ok {
		return coverage.InsertCDRBatchWithCoverage(
			ctx, records, antifraudEnabled, policyRevision, thresholds,
		)
	}
	return client.InsertCDRBatch(ctx, records)
}

func cdrRecordBuckets(records []analytics.CDRRecord) []time.Time {
	unique := make(map[time.Time]struct{})
	for _, record := range records {
		eventTime := record.IngestedAt
		for _, candidate := range []*time.Time{
			record.SetupTime, record.ConnectTime, record.DisconnectTime,
		} {
			if candidate != nil {
				eventTime = *candidate
				break
			}
		}
		unique[eventTime.UTC().Truncate(time.Hour)] = struct{}{}
	}
	return sortedHourBuckets(unique)
}

func satelRecordBuckets(records []analytics.SatelRTURecord) []time.Time {
	unique := make(map[time.Time]struct{})
	for _, record := range records {
		eventTime := record.IngestedAt
		for _, candidate := range []*time.Time{
			record.SetupTime, record.ConnectTime, record.DisconnectTime,
		} {
			if candidate != nil {
				eventTime = *candidate
				break
			}
		}
		unique[eventTime.UTC().Truncate(time.Hour)] = struct{}{}
	}
	return sortedHourBuckets(unique)
}

func sortedHourBuckets(unique map[time.Time]struct{}) []time.Time {
	result := make([]time.Time, 0, len(unique))
	for bucket := range unique {
		result = append(result, bucket)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Before(result[j]) })
	return result
}

func (w *CDRWatcher) enqueueVoipmonitorBuckets(
	ctx context.Context, deviceID uuid.UUID, buckets []time.Time,
) error {
	if w.Store == nil || len(buckets) == 0 {
		return nil
	}
	enabled, revision, err := w.Store.VoipmonitorPolicy(ctx, deviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if !enabled {
		return nil
	}
	if enqueuer, ok := w.Analytics.(VoipmonitorDirtyEnqueuer); ok {
		if err := enqueuer.EnqueueVoipmonitorDirtyBuckets(
			ctx, deviceID, revision, buckets, "ingest",
		); err != nil {
			return err
		}
	}
	return w.Store.EnqueueVoipmonitorBuckets(ctx, deviceID, revision, buckets)
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
