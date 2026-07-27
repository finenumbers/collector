package analytics

import (
	"context"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// withBatch opens exactly one ClickHouse INSERT batch, runs fn, then Send.
// Close is always deferred so a cancelled/failed attempt cannot leak a pool
// connection. Callers must not nest PrepareBatch: each open batch holds a
// connection until Close/Abort/Send.
func (c *Client) withBatch(
	ctx context.Context, query string, fn func(driver.Batch) error,
) error {
	batch, err := c.Conn.PrepareBatch(ctx, query)
	if err != nil {
		return err
	}
	defer func() { _ = batch.Close() }()
	if err := fn(batch); err != nil {
		return err
	}
	return batch.Send()
}
