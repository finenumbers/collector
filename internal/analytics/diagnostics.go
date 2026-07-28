package analytics

import (
	"context"

	"collector/internal/workload"
)

type OperationalDiagnostics struct {
	ProjectionLagSeconds          int64             `json:"projectionLagSeconds"`
	MaxDeviceProjectionLagSeconds int64             `json:"maxDeviceProjectionLagSeconds"`
	Calls                         uint64            `json:"calls"`
	Packets                       uint64            `json:"packets"`
	Orphans                       uint64            `json:"orphans"`
	Ambiguity                     uint64            `json:"ambiguity"`
	Coverage                      map[string]uint64 `json:"coverage"`
	CoverageSLOMet                bool              `json:"coverageSloMet"`
	ProjectionSLOMet              bool              `json:"projectionSloMet"`
	AnyDeviceFailed               bool              `json:"anyDeviceFailed"`
	AnyClassificationGap          bool              `json:"anyClassificationGap"`
}

func (c *Client) OperationalDiagnostics(ctx context.Context) (OperationalDiagnostics, error) {
	ctx, release, err := c.queryContext(ctx, workload.Diagnostics)
	if err != nil {
		return OperationalDiagnostics{}, err
	}
	defer release()
	var result OperationalDiagnostics
	var matched, expected, late, missing, notApplicable, ambiguous uint64
	err = c.Conn.QueryRow(ctx, `SELECT
		(SELECT greatest(0,dateDiff('second',ifNull(max(activated_at),now64(6)),now64(6)))
		 FROM collector.custom_projection_state),
		(SELECT count() FROM collector.custom_antifraud_calls_current),
		(SELECT count() FROM collector.custom_radius_packets_current),
		(SELECT count() FROM collector.custom_radius_packets_current WHERE orphan_reason!=''),
		(SELECT count() FROM collector.custom_radius_packets_current WHERE ambiguity_reason!=''),
		countIf(state='matched'),countIf(state='expected'),countIf(state='late'),
		countIf(state='missing'),countIf(state='not_applicable'),countIf(ambiguous=1)
		FROM collector.cdr_antifraud_coverage_current`).Scan(
		&result.ProjectionLagSeconds, &result.Calls, &result.Packets,
		&result.Orphans, &result.Ambiguity, &matched, &expected, &late,
		&missing, &notApplicable, &ambiguous,
	)
	if err != nil {
		return OperationalDiagnostics{}, err
	}
	result.Coverage = map[string]uint64{
		"matched": matched, "expected": expected, "late": late, "missing": missing,
		"not_applicable": notApplicable, "ambiguous": ambiguous,
	}
	applicable := matched + expected + late + missing
	result.CoverageSLOMet = applicable == 0 || float64(late+missing)/float64(applicable) <= 0.01
	result.ProjectionSLOMet = result.ProjectionLagSeconds <= 300
	return result, nil
}
