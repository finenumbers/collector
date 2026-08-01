package analytics

import (
	"context"

	"collector/internal/workload"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

type workloadClassKey struct{}

func freshWorkloadQueryID(ctx context.Context) string {
	class := "ch"
	if value, ok := ctx.Value(workloadClassKey{}).(workload.Class); ok && value != "" {
		class = string(value)
	}
	return "collector-" + class + "-" + uuid.NewString()
}

// withFreshQueryID mints a unique ClickHouse query_id for a single Query/Exec/
// PrepareBatch. Reusing one id across multiple ops in the same admission
// context causes code 216 ("already running") on dense CustomReplay paths.
func withFreshQueryID(ctx context.Context) context.Context {
	return clickhouse.Context(ctx, clickhouse.WithQueryID(freshWorkloadQueryID(ctx)))
}

func (c *Client) query(ctx context.Context, query string, args ...any) (driver.Rows, error) {
	return c.Conn.Query(withFreshQueryID(ctx), query, args...)
}

func (c *Client) queryRow(ctx context.Context, query string, args ...any) driver.Row {
	return c.Conn.QueryRow(withFreshQueryID(ctx), query, args...)
}

func (c *Client) exec(ctx context.Context, query string, args ...any) error {
	return c.Conn.Exec(withFreshQueryID(ctx), query, args...)
}

func (c *Client) prepareBatch(ctx context.Context, query string) (driver.Batch, error) {
	return c.Conn.PrepareBatch(withFreshQueryID(ctx), query)
}
