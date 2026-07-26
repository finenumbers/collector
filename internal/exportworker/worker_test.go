package exportworker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"collector/internal/archive"
	"collector/internal/store"
)

func TestBoundedWriterRejectsSpoolOverflow(t *testing.T) {
	var output bytes.Buffer
	writer := &boundedWriter{writer: &output, limit: 5}
	if _, err := writer.Write([]byte("12345")); err != nil {
		t.Fatalf("write at limit: %v", err)
	}
	if _, err := writer.Write([]byte("6")); err == nil ||
		!strings.Contains(err.Error(), "spool limit") {
		t.Fatalf("overflow error = %v", err)
	}
	if output.String() != "12345" || writer.written.Load() != 5 {
		t.Fatalf("partial overflow was written: %q/%d", output.String(), writer.written.Load())
	}
}

func TestRunRetriesTransientIterationErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	worker := &Worker{
		Store: &store.Store{}, Archive: &archive.Archive{}, WorkerID: "test",
		Poll: time.Millisecond,
		Render: func(
			context.Context, store.ExportJob, io.Writer, ProgressFunc,
		) (RenderResult, error) {
			return RenderResult{}, nil
		},
	}
	worker.runOnce = func(context.Context) (bool, error) {
		attempts++
		if attempts == 1 {
			return false, errors.New("postgres temporarily unavailable")
		}
		cancel()
		return false, context.Canceled
	}
	err := worker.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if attempts < 2 {
		t.Fatalf("worker stopped after %d attempt", attempts)
	}
}
