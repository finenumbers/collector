package voipmonitor

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"collector/internal/store"

	"github.com/google/uuid"
)

type Warehouse interface {
	LoadVoipmonitorEltexCandidates(
		ctx context.Context, deviceID uuid.UUID, from, to time.Time, policyRevision uint64, limit int,
	) ([]CDRCandidate, error)
	LoadVoipmonitorSatelCandidates(
		ctx context.Context, deviceID uuid.UUID, from, to time.Time, policyRevision uint64, limit int,
	) ([]CDRCandidate, error)
	WriteVoipmonitorLinks(ctx context.Context, links []Link) error
	EnqueueVoipmonitorDirtyBuckets(
		ctx context.Context, deviceID uuid.UUID, policyRevision uint64, buckets []time.Time, reason string,
	) error
}

type Queue interface {
	VoipmonitorPolicy(ctx context.Context, deviceID uuid.UUID) (bool, uint64, error)
	ClaimVoipmonitorJob(ctx context.Context, workerID string, lease time.Duration) (store.VoipmonitorJob, bool, error)
	CompleteVoipmonitorJob(ctx context.Context, job store.VoipmonitorJob) error
	FailVoipmonitorJob(ctx context.Context, job store.VoipmonitorJob, cause error) error
	EnsureVoipmonitorDiscover(ctx context.Context, deviceID uuid.UUID, revision uint64) error
	EnqueueVoipmonitorBuckets(ctx context.Context, deviceID uuid.UUID, revision uint64, buckets []time.Time) error
	Device(ctx context.Context, id uuid.UUID) (store.Device, error)
}

type Worker struct {
	Store     Warehouse
	Queue     Queue
	Matcher   *Matcher
	Sleep     time.Duration
	Lease     time.Duration
	WorkerID  string
	BatchSize int
	Lookback  time.Duration
}

func (w *Worker) Run(ctx context.Context) error {
	sleep := w.Sleep
	if sleep <= 0 {
		sleep = 5 * time.Second
	}
	lease := w.Lease
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		job, ok, err := w.Queue.ClaimVoipmonitorJob(ctx, w.WorkerID, lease)
		if err != nil {
			return err
		}
		if !ok {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleep):
				continue
			}
		}
		if err := w.process(ctx, job); err != nil {
			slog.Error("voipmonitor match job failed", "job", job.ID, "device", job.DeviceID, "error", err)
			if failErr := w.Queue.FailVoipmonitorJob(ctx, job, err); failErr != nil {
				return failErr
			}
			continue
		}
		if err := w.Queue.CompleteVoipmonitorJob(ctx, job); err != nil {
			return err
		}
	}
}

func (w *Worker) process(ctx context.Context, job store.VoipmonitorJob) error {
	enabled, revision, err := w.Queue.VoipmonitorPolicy(ctx, job.DeviceID)
	if err != nil {
		return err
	}
	if !enabled || revision != job.PolicyRevision {
		return nil
	}
	device, err := w.Queue.Device(ctx, job.DeviceID)
	if err != nil {
		return err
	}
	batch := w.BatchSize
	if batch <= 0 {
		batch = 100
	}
	switch job.Kind {
	case "discover":
		lookback := w.Lookback
		if lookback <= 0 {
			lookback = 24 * time.Hour
		}
		now := time.Now().UTC()
		from := now.Add(-lookback).Truncate(time.Hour)
		var buckets []time.Time
		for cursor := from; cursor.Before(now); cursor = cursor.Add(time.Hour) {
			buckets = append(buckets, cursor)
		}
		if err := w.Store.EnqueueVoipmonitorDirtyBuckets(
			ctx, job.DeviceID, revision, buckets, "discover",
		); err != nil {
			return err
		}
		return w.Queue.EnqueueVoipmonitorBuckets(ctx, job.DeviceID, revision, buckets)
	case "bucket":
		if job.BucketStart == nil {
			return errors.New("bucket job missing bucket_start")
		}
		from := job.BucketStart.UTC()
		to := from.Add(time.Hour)
		return w.matchBucket(ctx, device, revision, from, to, batch)
	default:
		return nil
	}
}

func (w *Worker) matchBucket(
	ctx context.Context, device store.Device, revision uint64, from, to time.Time, batch int,
) error {
	var candidates []CDRCandidate
	var err error
	if device.TemplateKey == "satel-rtu-cdr-v1" {
		candidates, err = w.Store.LoadVoipmonitorSatelCandidates(
			ctx, device.ID, from, to, revision, batch,
		)
	} else {
		candidates, err = w.Store.LoadVoipmonitorEltexCandidates(
			ctx, device.ID, from, to, revision, batch,
		)
	}
	if err != nil {
		return err
	}
	links := make([]Link, 0, len(candidates))
	now := time.Now().UTC()
	seq := uint64(now.UnixNano())
	for _, candidate := range candidates {
		result, matchErr := w.Matcher.Match(ctx, candidate)
		if matchErr != nil {
			slog.Warn("voipmonitor match attempt failed",
				"device", device.ID, "record", candidate.SourceRecordID, "error", matchErr)
			result = MatchResult{
				Status: StatusUnmatched, Method: "error", Score: 0,
				EvidenceJSON: mustJSON(map[string]any{"error": matchErr.Error()}),
			}
		}
		link := Link{
			DeviceID: candidate.DeviceID, SourceSystem: candidate.SourceSystem,
			SourceRecordID: candidate.SourceRecordID, SourceCDRID: candidate.SourceCDRID,
			SourceCallID: candidate.SourceCallID, SourceProtocolConfID: candidate.SourceProtocolConfID,
			SourceCallIDOutProto: candidate.SourceCallIDOutProto,
			PolicyRevision: revision, ProjectionSeq: seq,
			MatchMethod: result.Method, MatchScore: result.Score, MatchStatus: result.Status,
			MatchEvidenceJSON: result.EvidenceJSON, MatchedAt: result.MatchedAt,
			VoipmonitorCardURL: result.CardURL, EventMonth: candidate.SetupTime,
		}
		if result.VM != nil {
			link.VoipmonitorCDRID = result.VM.CDRID
			link.VoipmonitorCallID = result.VM.CallID
		}
		links = append(links, link)
		seq++
	}
	return w.Store.WriteVoipmonitorLinks(ctx, links)
}
