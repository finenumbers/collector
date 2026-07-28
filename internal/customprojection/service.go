package customprojection

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"collector/internal/customradius"
	"collector/internal/workload"

	"github.com/google/uuid"
)

type JobKind string

const (
	JobDiscover JobKind = "discover"
	JobBucket   JobKind = "bucket"
	JobDisable  JobKind = "disable"
)

type Policy struct {
	DeviceID uuid.UUID
	Enabled  bool
	Revision uint64
	Timezone string
}

type Job struct {
	ID             uuid.UUID
	DeviceID       uuid.UUID
	PolicyRevision uint64
	ProjectionSeq  uint64
	Kind           JobKind
	BucketStart    time.Time
	CursorTime     time.Time
	CursorEventID  uuid.UUID
	Generation     uint64
	CutoffAt       time.Time
	WorkerID       string
}

type Discovery struct {
	Buckets       []time.Time
	NextTime      time.Time
	NextEventID   uuid.UUID
	HasMore       bool
	WatermarkTime time.Time
	WatermarkID   uuid.UUID
}

type Snapshot struct {
	ID             uuid.UUID
	DeviceID       uuid.UUID
	BucketStart    time.Time
	PolicyRevision uint64
	ProjectionSeq  uint64
	WatermarkTime  time.Time
	WatermarkID    uuid.UUID
	Result         customradius.Result
}

type Queue interface {
	ClaimCustomProjectionJob(context.Context, string, time.Duration) (Job, bool, error)
	CustomAntifraudPolicy(context.Context, uuid.UUID) (Policy, error)
	EnqueueCustomProjectionBuckets(context.Context, uuid.UUID, uint64, []time.Time) error
	AdvanceCustomProjectionDiscovery(context.Context, Job, Discovery) error
	CompleteCustomProjectionJob(context.Context, Job, Snapshot) error
	FailCustomProjectionJob(context.Context, Job, error, time.Duration) error
	ScheduleCustomProjectionDeadline(context.Context, Job, time.Time) error
	CutoverCustomProjection(context.Context, Job, Snapshot, func(context.Context) error) error
	EnqueueCDRReconciliationBuckets(context.Context, uuid.UUID, uint64, []time.Time) error
}

type Warehouse interface {
	DiscoverSyslogBuckets(context.Context, uuid.UUID, time.Time, uuid.UUID, int) (Discovery, error)
	LoadCustomRadiusEvents(context.Context, uuid.UUID, time.Time, time.Time, int) ([]customradius.RawEvent, error)
	LoadCustomRadiusSessionEvents(
		context.Context, uuid.UUID, []string, time.Time, time.Time, time.Duration, int,
	) ([]customradius.RawEvent, error)
	WriteCustomProjectionSnapshot(context.Context, Snapshot) error
	ActivateCustomProjectionSnapshot(context.Context, Snapshot) error
	WriteCustomProjectionDisabled(context.Context, Job) error
}

type workloadAdmitter interface {
	AdmitWorkload(context.Context, workload.Class) (context.Context, func(), error)
}

type heavyLane interface {
	AcquireClickHouseHeavyLane(context.Context) (func(), error)
}

type overflowRequeuer interface {
	RequeueFailedOverflowProjectionJobs(context.Context) (int64, error)
}

type Config struct {
	WorkerID        string
	BatchSize       int
	MaxEvents       int
	Threads         int
	MaxMemoryBytes  int64
	Sleep           time.Duration
	Lease           time.Duration
	ResponseTimeout time.Duration
	PairingHorizon  time.Duration
	RetryHorizon    time.Duration
	AssemblyIdle    time.Duration
}

func (c Config) normalized() Config {
	if c.BatchSize <= 0 {
		c.BatchSize = 128
	}
	if c.MaxEvents <= 0 {
		c.MaxEvents = 20_000
	}
	if c.Threads <= 0 {
		c.Threads = 1
	}
	if c.MaxMemoryBytes <= 0 {
		c.MaxMemoryBytes = 128 << 20
	}
	if c.Sleep <= 0 {
		c.Sleep = time.Second
	}
	if c.Lease <= 0 {
		c.Lease = 2 * time.Minute
	}
	if c.PairingHorizon <= 0 {
		c.PairingHorizon = 5 * time.Minute
	}
	if c.RetryHorizon <= 0 {
		c.RetryHorizon = 7 * 24 * time.Hour
	}
	return c
}

type Metrics struct {
	Processed atomic.Uint64
	Failures  atomic.Uint64
}

type Worker struct {
	Queue     Queue
	Warehouse Warehouse
	Config    Config
	ConfigFn  func() Config
	Metrics   *Metrics
}

func (w *Worker) activeConfig() Config {
	if w.ConfigFn != nil {
		return w.ConfigFn().normalized()
	}
	return w.Config.normalized()
}

func (w *Worker) Run(ctx context.Context) error {
	if w.Queue == nil || w.Warehouse == nil {
		return errors.New("custom projection worker dependencies are required")
	}
	cfg := w.activeConfig()
	if w.Metrics == nil {
		w.Metrics = &Metrics{}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	errs := make(chan error, cfg.Threads)
	for index := 0; index < cfg.Threads; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := w.runLoop(runCtx); err != nil {
				errs <- err
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		<-done
		return nil
	case err := <-errs:
		cancel()
		<-done
		return err
	case <-done:
		return nil
	}
}

func (w *Worker) runLoop(ctx context.Context) error {
	// Discover jobs stay pending every ~2s, so the claim queue is almost never
	// idle. Sweep overflow failures on a cadence instead of only when claim misses.
	var lastOverflowSweep time.Time
	for ctx.Err() == nil {
		cfg := w.activeConfig()
		if time.Since(lastOverflowSweep) >= 30*time.Second {
			if requeuer, has := w.Queue.(overflowRequeuer); has {
				_, _ = requeuer.RequeueFailedOverflowProjectionJobs(ctx)
			}
			lastOverflowSweep = time.Now()
		}
		job, ok, err := w.Queue.ClaimCustomProjectionJob(ctx, cfg.WorkerID, cfg.Lease)
		if err != nil {
			return err
		}
		if !ok {
			if !sleepContext(ctx, cfg.Sleep) {
				break
			}
			continue
		}
		err = func() (processErr error) {
			defer func() {
				if recovered := recover(); recovered != nil {
					processErr = fmt.Errorf("projection panic: %v", recovered)
				}
			}()
			return w.process(ctx, cfg, job)
		}()
		if err != nil {
			w.Metrics.Failures.Add(1)
			if failErr := w.Queue.FailCustomProjectionJob(ctx, job, err, cfg.Sleep); failErr != nil {
				return fmt.Errorf("projection failed: %v; queue failure: %w", err, failErr)
			}
			continue
		}
		w.Metrics.Processed.Add(1)
	}
	return nil
}

func (w *Worker) process(ctx context.Context, cfg Config, job Job) error {
	policy, err := w.Queue.CustomAntifraudPolicy(ctx, job.DeviceID)
	if err != nil {
		return err
	}
	if policy.Revision != job.PolicyRevision {
		return w.Queue.CompleteCustomProjectionJob(ctx, job, Snapshot{})
	}
	if job.Kind == JobDisable || !policy.Enabled {
		releaseHeavy, heavyErr := w.acquireHeavyLane(ctx)
		if heavyErr != nil {
			return heavyErr
		}
		defer releaseHeavy()
		if err := w.Warehouse.WriteCustomProjectionDisabled(ctx, job); err != nil {
			return err
		}
		return w.Queue.CompleteCustomProjectionJob(ctx, job, Snapshot{})
	}
	if job.Kind == JobDiscover {
		discovery, err := w.Warehouse.DiscoverSyslogBuckets(
			ctx, job.DeviceID, job.CursorTime, job.CursorEventID, cfg.BatchSize,
		)
		if err != nil {
			return err
		}
		if err := w.Queue.EnqueueCustomProjectionBuckets(
			ctx, job.DeviceID, job.PolicyRevision, discovery.Buckets,
		); err != nil {
			return err
		}
		return w.Queue.AdvanceCustomProjectionDiscovery(ctx, job, discovery)
	}

	from := job.BucketStart.UTC().Truncate(time.Hour)
	to := from.Add(time.Hour)
	return w.processBucket(ctx, cfg, job, from, to)
}

func (w *Worker) processBucket(
	ctx context.Context, cfg Config, job Job, from, to time.Time,
) error {
	// Prefer a single hour load. On overflow/CH memory pressure do NOT keep a giant
	// merge — rebuild the hour as independent windows.
	events, err := w.Warehouse.LoadCustomRadiusEvents(
		ctx, job.DeviceID, from.Add(-cfg.PairingHorizon), to.Add(cfg.PairingHorizon), cfg.MaxEvents,
	)
	switch {
	case err == nil && eventsExceedLimits(events, cfg) == nil:
		return w.finishBucket(ctx, cfg, job, from, to, events)
	case err != nil && !IsEventLimitError(err) && !IsClickHouseResourceError(err):
		return err
	default:
		return w.processBucketWindows(ctx, cfg, job, from, to)
	}
}

func (w *Worker) processBucketWindows(
	ctx context.Context, cfg Config, job Job, from, to time.Time,
) error {
	span := 5 * time.Minute
	merged := customradius.Result{}
	packetsByID := make(map[uuid.UUID]customradius.Packet)
	callsByID := make(map[uuid.UUID]customradius.Call)
	affected := make(map[time.Time]struct{})
	var watermarkTime time.Time
	var watermarkID uuid.UUID
	var nextDeadline *time.Time
	cutoff := job.CutoffAt.UTC()
	for cursor := from; cursor.Before(to); cursor = cursor.Add(span) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		end := cursor.Add(span)
		if end.After(to) {
			end = to
		}
		events, err := w.loadEventsSplit(ctx, cursor, end, span, func(start, finish time.Time) ([]customradius.RawEvent, error) {
			return w.Warehouse.LoadCustomRadiusEvents(
				ctx, job.DeviceID, start.Add(-cfg.PairingHorizon), finish.Add(cfg.PairingHorizon), cfg.MaxEvents,
			)
		})
		if err != nil {
			return err
		}
		if limitErr := eventsExceedLimits(events, cfg); limitErr != nil {
			return limitErr
		}
		windowCutoff := cutoff
		if windowCutoff.IsZero() {
			windowCutoff = latestEventTime(events)
		}
		engineConfig := customradius.Config{
			Enabled: true, ResponseTimeout: cfg.ResponseTimeout,
			PairingHorizon: cfg.PairingHorizon, RetryHorizon: cfg.RetryHorizon,
			AssemblyIdle: cfg.AssemblyIdle,
		}
		preliminary := customradius.BuildAtCutoff(engineConfig, events, windowCutoff)
		identities := resultIdentities(preliminary)
		if len(identities) != 0 {
			// Keep session expansion inside the local pairing neighborhood for dense
			// hours; a 7-day scan per 5m window would starve ClickHouse.
			sessionEvents, loadErr := w.loadEventsSplit(
				ctx, cursor.Add(-cfg.PairingHorizon), end.Add(cfg.PairingHorizon), span,
				func(windowStart, windowEnd time.Time) ([]customradius.RawEvent, error) {
					return w.Warehouse.LoadCustomRadiusSessionEvents(
						ctx, job.DeviceID, identities, windowStart, windowEnd, cfg.PairingHorizon, cfg.MaxEvents,
					)
				},
			)
			if loadErr != nil {
				if !IsClickHouseResourceError(loadErr) {
					return loadErr
				}
				sessionEvents = nil
			}
			if len(sessionEvents) != 0 {
				events = mergeEvents(events, sessionEvents)
				if limitErr := eventsExceedLimits(events, cfg); limitErr != nil {
					return limitErr
				}
			}
		}
		for _, event := range events {
			affected[event.ReceivedAt.UTC().Truncate(time.Hour)] = struct{}{}
			if event.ReceivedAt.After(watermarkTime) ||
				(event.ReceivedAt.Equal(watermarkTime) && event.EventID.String() > watermarkID.String()) {
				watermarkTime, watermarkID = event.ReceivedAt, event.EventID
			}
		}
		if windowCutoff.IsZero() {
			windowCutoff = watermarkTime
		}
		result := customradius.BuildAtCutoff(engineConfig, events, windowCutoff)
		if result.NextDeadline != nil {
			if nextDeadline == nil || result.NextDeadline.Before(*nextDeadline) {
				deadline := *result.NextDeadline
				nextDeadline = &deadline
			}
		}
		for _, packet := range result.Packets {
			if packet.FirstSeenAt.Before(from) || !packet.FirstSeenAt.Before(to) {
				continue
			}
			// Own packets by first-seen window so multi-window rebuilds stay disjoint.
			if packet.FirstSeenAt.Before(cursor) || !packet.FirstSeenAt.Before(end) {
				continue
			}
			packetsByID[packet.ID] = packet
		}
		for _, call := range result.Calls {
			if len(call.Packets) == 0 {
				continue
			}
			first := call.Packets[0].FirstSeenAt
			for _, packet := range call.Packets[1:] {
				if packet.FirstSeenAt.Before(first) {
					first = packet.FirstSeenAt
				}
			}
			if first.Before(from) || !first.Before(to) {
				continue
			}
			if first.Before(cursor) || !first.Before(end) {
				continue
			}
			callsByID[call.ID] = call
		}
	}
	merged.Packets = make([]customradius.Packet, 0, len(packetsByID))
	for _, packet := range packetsByID {
		merged.Packets = append(merged.Packets, packet)
	}
	sort.SliceStable(merged.Packets, func(i, j int) bool {
		if merged.Packets[i].FirstSeenAt.Equal(merged.Packets[j].FirstSeenAt) {
			return merged.Packets[i].ID.String() < merged.Packets[j].ID.String()
		}
		return merged.Packets[i].FirstSeenAt.Before(merged.Packets[j].FirstSeenAt)
	})
	merged.Calls = make([]customradius.Call, 0, len(callsByID))
	for _, call := range callsByID {
		merged.Calls = append(merged.Calls, call)
	}
	sort.SliceStable(merged.Calls, func(i, j int) bool {
		left, right := callFirstSeen(merged.Calls[i]), callFirstSeen(merged.Calls[j])
		if left.Equal(right) {
			return merged.Calls[i].ID.String() < merged.Calls[j].ID.String()
		}
		return left.Before(right)
	})
	merged.NextDeadline = nextDeadline
	return w.publishBucket(ctx, cfg, job, from, merged, watermarkTime, watermarkID, affected)
}

func callFirstSeen(call customradius.Call) time.Time {
	if len(call.Packets) == 0 {
		return time.Time{}
	}
	first := call.Packets[0].FirstSeenAt
	for _, packet := range call.Packets[1:] {
		if packet.FirstSeenAt.Before(first) {
			first = packet.FirstSeenAt
		}
	}
	return first
}

func (w *Worker) finishBucket(
	ctx context.Context, cfg Config, job Job, from, to time.Time, events []customradius.RawEvent,
) error {
	cutoff := job.CutoffAt.UTC()
	if cutoff.IsZero() {
		cutoff = latestEventTime(events)
	}
	engineConfig := customradius.Config{
		Enabled: true, ResponseTimeout: cfg.ResponseTimeout,
		PairingHorizon: cfg.PairingHorizon, RetryHorizon: cfg.RetryHorizon,
		AssemblyIdle: cfg.AssemblyIdle,
	}
	preliminary := customradius.BuildAtCutoff(engineConfig, events, cutoff)
	identities := resultIdentities(preliminary)
	if len(identities) != 0 {
		sessionEvents, loadErr := w.loadSessionEvents(
			ctx, cfg, job.DeviceID, identities, from, to,
		)
		if loadErr != nil {
			if !IsClickHouseResourceError(loadErr) {
				return loadErr
			}
			// Prefer advancing the hour without cross-bucket session expansion over
			// terminal-failing on ClickHouse memory/cancel; deadlines recompute later.
			sessionEvents = nil
		}
		if len(sessionEvents) != 0 {
			events = mergeEvents(events, sessionEvents)
			if limitErr := eventsExceedLimits(events, cfg); limitErr != nil {
				return w.processBucketWindows(ctx, cfg, job, from, to)
			}
		}
	}
	var watermarkTime time.Time
	var watermarkID uuid.UUID
	affected := make(map[time.Time]struct{})
	for _, event := range events {
		affected[event.ReceivedAt.UTC().Truncate(time.Hour)] = struct{}{}
		if event.ReceivedAt.After(watermarkTime) ||
			(event.ReceivedAt.Equal(watermarkTime) && event.EventID.String() > watermarkID.String()) {
			watermarkTime, watermarkID = event.ReceivedAt, event.EventID
		}
	}
	if cutoff.IsZero() {
		cutoff = watermarkTime
	}
	result := customradius.BuildAtCutoff(engineConfig, events, cutoff)
	return w.publishBucket(ctx, cfg, job, from, result, watermarkTime, watermarkID, affected)
}

func (w *Worker) publishBucket(
	ctx context.Context,
	cfg Config,
	job Job,
	from time.Time,
	result customradius.Result,
	watermarkTime time.Time,
	watermarkID uuid.UUID,
	affected map[time.Time]struct{},
) error {
	snapshot := Snapshot{
		ID: stableSnapshotID(job, resultEventIDs(result)), DeviceID: job.DeviceID, BucketStart: from,
		PolicyRevision: job.PolicyRevision, ProjectionSeq: job.ProjectionSeq,
		WatermarkTime: watermarkTime, WatermarkID: watermarkID,
		Result: result,
	}
	if result.NextDeadline != nil {
		if err := w.Queue.ScheduleCustomProjectionDeadline(ctx, job, *result.NextDeadline); err != nil {
			return err
		}
	}
	otherBuckets := make([]time.Time, 0, len(affected))
	allBuckets := make([]time.Time, 0, len(affected))
	for bucket := range affected {
		allBuckets = append(allBuckets, bucket)
		if bucket != from {
			otherBuckets = append(otherBuckets, bucket)
		}
	}
	if err := w.Queue.EnqueueCustomProjectionBuckets(
		ctx, job.DeviceID, job.PolicyRevision, otherBuckets,
	); err != nil {
		return err
	}
	releaseHeavy, err := w.acquireHeavyLane(ctx)
	if err != nil {
		return err
	}
	defer releaseHeavy()
	if err := w.Warehouse.WriteCustomProjectionSnapshot(ctx, snapshot); err != nil {
		return err
	}
	cutoverCtx := ctx
	releaseAdmission := func() {}
	if admitter, ok := w.Warehouse.(workloadAdmitter); ok {
		cutoverCtx, releaseAdmission, err = admitter.AdmitWorkload(ctx, workload.CustomReplay)
		if err != nil {
			return err
		}
	}
	defer releaseAdmission()
	if err := w.Queue.CutoverCustomProjection(
		cutoverCtx, job, snapshot,
		func(activateCtx context.Context) error {
			return w.Warehouse.ActivateCustomProjectionSnapshot(activateCtx, snapshot)
		},
	); err != nil {
		return err
	}
	return w.Queue.EnqueueCDRReconciliationBuckets(
		cutoverCtx, job.DeviceID, job.PolicyRevision, allBuckets,
	)
}

func resultEventIDs(result customradius.Result) []customradius.RawEvent {
	unique := make(map[uuid.UUID]struct{})
	events := make([]customradius.RawEvent, 0)
	for _, packet := range result.Packets {
		for _, member := range packet.Provenance {
			if _, seen := unique[member.EventID]; seen {
				continue
			}
			unique[member.EventID] = struct{}{}
			events = append(events, customradius.RawEvent{
				EventID: member.EventID, ReceivedAt: member.ReceivedAt,
			})
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].ReceivedAt.Equal(events[j].ReceivedAt) {
			return events[i].EventID.String() < events[j].EventID.String()
		}
		return events[i].ReceivedAt.Before(events[j].ReceivedAt)
	})
	return events
}

func eventsExceedLimits(events []customradius.RawEvent, cfg Config) error {
	var eventBytes int64
	for _, event := range events {
		eventBytes += int64(len(event.Payload))
	}
	if len(events) > cfg.MaxEvents {
		return fmt.Errorf("custom projection bucket exceeds %d events", cfg.MaxEvents)
	}
	if eventBytes > cfg.MaxMemoryBytes {
		return fmt.Errorf("bucket payload bytes %d exceed memory bound %d", eventBytes, cfg.MaxMemoryBytes)
	}
	return nil
}

func (w *Worker) acquireHeavyLane(ctx context.Context) (func(), error) {
	if lane, ok := w.Queue.(heavyLane); ok {
		return lane.AcquireClickHouseHeavyLane(ctx)
	}
	return func() {}, nil
}

func IsEventLimitError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "exceeds") && strings.Contains(message, "events")
}

func IsClickHouseResourceError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "memory limit exceeded") ||
		strings.Contains(message, "query was cancelled") ||
		strings.Contains(message, "timeout exceeded") ||
		strings.Contains(message, "context deadline exceeded")
}

func (w *Worker) loadSessionEvents(
	ctx context.Context, cfg Config, deviceID uuid.UUID, identities []string, from, to time.Time,
) ([]customradius.RawEvent, error) {
	// Engine RetryHorizon may be 7d for assembly deadlines; loading ±7d of syslog
	// payloads per identity set OOMs ClickHouse on dense SMG. Cap the fetch window.
	horizon := cfg.RetryHorizon
	if horizon <= 0 || horizon > 48*time.Hour {
		horizon = 48 * time.Hour
	}
	start := from.Add(-horizon)
	end := to.Add(horizon)
	return w.loadEventsSplit(ctx, start, end, time.Hour, func(windowStart, windowEnd time.Time) ([]customradius.RawEvent, error) {
		return w.Warehouse.LoadCustomRadiusSessionEvents(
			ctx, deviceID, identities, windowStart, windowEnd, cfg.PairingHorizon, cfg.MaxEvents,
		)
	})
}

func (w *Worker) loadEventsSplit(
	ctx context.Context,
	from, to time.Time,
	span time.Duration,
	load func(time.Time, time.Time) ([]customradius.RawEvent, error),
) ([]customradius.RawEvent, error) {
	events, err := load(from, to)
	if err == nil || !IsEventLimitError(err) {
		return events, err
	}
	nextSpan := time.Duration(0)
	switch {
	case span > 15*time.Minute:
		nextSpan = 15 * time.Minute
	case span > 5*time.Minute:
		nextSpan = 5 * time.Minute
	case span > time.Minute:
		nextSpan = time.Minute
	default:
		return nil, err
	}
	merged := make([]customradius.RawEvent, 0)
	for cursor := from; cursor.Before(to); cursor = cursor.Add(nextSpan) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		end := cursor.Add(nextSpan)
		if end.After(to) {
			end = to
		}
		part, partErr := w.loadEventsSplit(ctx, cursor, end, nextSpan, load)
		if partErr != nil {
			return nil, partErr
		}
		merged = mergeEvents(merged, part)
	}
	return merged, nil
}

func latestEventTime(events []customradius.RawEvent) time.Time {
	var latest time.Time
	for _, event := range events {
		if event.ReceivedAt.After(latest) {
			latest = event.ReceivedAt
		}
	}
	return latest
}

func resultIdentities(result customradius.Result) []string {
	unique := make(map[string]struct{})
	for _, packet := range result.Packets {
		if packet.CallKey.AcctSessionID != "" {
			unique[packet.CallKey.AcctSessionID] = struct{}{}
		}
		if packet.CallKey.H323ConfID != "" {
			unique[packet.CallKey.H323ConfID] = struct{}{}
		}
	}
	identities := make([]string, 0, len(unique))
	for identity := range unique {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	return identities
}

func mergeEvents(groups ...[]customradius.RawEvent) []customradius.RawEvent {
	unique := make(map[uuid.UUID]customradius.RawEvent)
	for _, events := range groups {
		for _, event := range events {
			unique[event.EventID] = event
		}
	}
	result := make([]customradius.RawEvent, 0, len(unique))
	for _, event := range unique {
		result = append(result, event)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].ReceivedAt.Equal(result[j].ReceivedAt) {
			return result[i].EventID.String() < result[j].EventID.String()
		}
		return result[i].ReceivedAt.Before(result[j].ReceivedAt)
	})
	return result
}

func stableSnapshotID(job Job, events []customradius.RawEvent) uuid.UUID {
	hash := sha1.New()
	_, _ = hash.Write(job.DeviceID[:])
	_, _ = hash.Write([]byte(job.BucketStart.UTC().Format(time.RFC3339Nano)))
	var revision [8]byte
	binary.BigEndian.PutUint64(revision[:], job.PolicyRevision)
	_, _ = hash.Write(revision[:])
	for _, event := range events {
		_, _ = hash.Write(event.EventID[:])
	}
	return uuid.NewHash(sha1.New(), uuid.NameSpaceOID, hash.Sum(nil), 5)
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
