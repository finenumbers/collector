package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"collector/internal/store"

	"github.com/google/uuid"
	"golang.org/x/text/encoding/charmap"
)

type CDRWatcher struct {
	Root      string
	Store     *store.Store
	Analytics *analytics.Client
	Archive   *archive.Archive
	MinAge    time.Duration
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
		if err != nil || !device.Enabled {
			continue
		}
		files, err := os.ReadDir(filepath.Join(w.Root, entry.Name()))
		if err != nil {
			slog.Warn("unable to read device CDR directory", "device", deviceID, "error", err)
			continue
		}
		for _, file := range files {
			if file.IsDir() || strings.HasPrefix(file.Name(), ".") || strings.HasSuffix(file.Name(), ".part") {
				continue
			}
			path := filepath.Join(w.Root, entry.Name(), file.Name())
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
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	checksum := hex.EncodeToString(sum[:])
	objectKey := fmt.Sprintf("cdr/%s/%s/%s-%s", device.ID, time.Now().UTC().Format("2006/01/02"), checksum[:16], filepath.Base(path))
	fileID, err := w.Store.RegisterIngestFile(ctx, device.ID, filepath.Base(path), objectKey, checksum, info.Size())
	if errors.Is(err, store.ErrNotFound) {
		return os.Remove(path)
	}
	if err != nil {
		return err
	}
	if err := w.Archive.Put(ctx, objectKey, bytes.NewReader(content), int64(len(content)), "text/csv"); err != nil {
		_ = w.Store.CompleteIngestFile(ctx, fileID, "failed", 0, 0, err.Error())
		return err
	}
	decoded, err := decodeCDR(content)
	if err != nil {
		_ = w.Store.CompleteIngestFile(ctx, fileID, "quarantined", 0, 0, err.Error())
		return os.Remove(path)
	}
	location, err := time.LoadLocation(device.Timezone)
	if err != nil {
		location = time.UTC
	}
	var columns []string
	_ = json.Unmarshal(device.CDRColumns, &columns)
	result, err := (CDRParser{
		DeviceID: device.ID, FileID: fileID, Location: location, ExpectedHeader: columns,
	}).Parse(bytes.NewReader(decoded))
	if err != nil {
		_ = w.Store.CompleteIngestFile(ctx, fileID, "quarantined", 0, 0, err.Error())
		return os.Remove(path)
	}
	if err := w.Analytics.InsertCDRBatch(ctx, result.Records); err != nil {
		_ = w.Store.CompleteIngestFile(ctx, fileID, "failed", result.Rows, uint64(len(result.Records)), err.Error())
		return err
	}
	status := "processed"
	message := ""
	if len(result.Errors) > 0 {
		status = "quarantined"
		message = summarizeErrors(result.Errors)
	}
	if err := w.Store.CompleteIngestFile(ctx, fileID, status, result.Rows, uint64(len(result.Records)), message); err != nil {
		return err
	}
	return os.Remove(path)
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
