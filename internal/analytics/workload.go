package analytics

import (
	"context"
	"time"

	"collector/internal/workload"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

type WorkloadOptions struct {
	Capacity int
	Weights  map[workload.Class]int
}

func (c *Client) ConfigureWorkloads(options WorkloadOptions) {
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	c.Admission = workload.New(workload.Options{
		Capacity: options.Capacity,
		Weights:  options.Weights,
	})
}

func (c *Client) WorkloadSnapshot() map[workload.Class]workload.Stats {
	if c == nil {
		return map[workload.Class]workload.Stats{}
	}
	return c.admission().Snapshot()
}

// AdmitWorkload is used when a unit of work spans multiple ClickHouse queries,
// notably exports. The release must run before a device lock is acquired.
func (c *Client) AdmitWorkload(
	ctx context.Context, class workload.Class,
) (context.Context, func(), error) {
	return c.admission().Acquire(ctx, class)
}

func (c *Client) queryContext(
	ctx context.Context, requested workload.Class,
) (context.Context, func(), error) {
	admission := c.admission()
	class := requested
	if current, ok := admission.Current(ctx); ok {
		class = current
	}
	admitted, release, err := admission.Acquire(ctx, class)
	if err != nil {
		return ctx, nil, err
	}
	timeout, threads, memory, resultRows, resultBytes := workloadQueryLimits(class)
	queryCtx, cancel := context.WithTimeout(admitted, timeout)
	queryCtx = clickhouse.Context(queryCtx,
		clickhouse.WithQueryID("collector-"+string(class)+"-"+uuid.NewString()),
		clickhouse.WithSettings(clickhouse.Settings{
			"log_comment":                        "collector workload=" + string(class),
			"max_execution_time":                 uint64(max(timeout/time.Second, 1)),
			"max_threads":                        threads,
			"max_memory_usage":                   memory,
			"max_result_rows":                    resultRows,
			"max_result_bytes":                   resultBytes,
			"result_overflow_mode":               "throw",
			"max_bytes_before_external_group_by": uint64(64 << 20),
			"max_bytes_before_external_sort":     uint64(64 << 20),
		}),
	)
	return queryCtx, func() {
		cancel()
		release()
	}, nil
}

func (c *Client) admission() *workload.Manager {
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	if c.Admission == nil {
		c.Admission = workload.New(workload.Options{})
	}
	return c.Admission
}

func (c *Client) admittedAs(ctx context.Context, class workload.Class) bool {
	current, ok := c.admission().Current(ctx)
	return ok && current == class
}

func workloadQueryLimits(class workload.Class) (time.Duration, uint64, uint64, uint64, uint64) {
	switch class {
	case workload.Export:
		return 45 * time.Second, 2, 512 << 20, 20_000, 64 << 20
	case workload.CustomReplay:
		// Dense SMG hour loads need headroom; single thread lowers peak memory on
		// payload scans. Two-phase session fetch keeps per-query working set small.
		return 90 * time.Second, 1, 1024 << 20, 100_000, 128 << 20
	case workload.CustomReconcile:
		return 30 * time.Second, 2, 256 << 20, 50_000, 64 << 20
	case workload.Ingest:
		return 20 * time.Second, 2, 256 << 20, 10_000, 16 << 20
	case workload.Diagnostics:
		return 10 * time.Second, 1, 128 << 20, 2_000, 8 << 20
	default:
		return 10 * time.Second, 2, 256 << 20, 5_000, 16 << 20
	}
}
