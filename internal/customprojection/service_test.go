package customprojection

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"collector/internal/customradius"
	"collector/internal/workload"

	"github.com/google/uuid"
)

type projectionQueueMock struct {
	policy            Policy
	completed         int
	failed            int
	advanced          int
	progressed        int
	refreshed         int
	lastProgressLease time.Duration
	seq               uint64
	enqueueErr        error
	beforeLock        func()
	deadlines         []time.Time
	buckets           []time.Time
	projectionBuckets []time.Time
}

func (m *projectionQueueMock) ClaimCustomProjectionJob(context.Context, string, time.Duration) (Job, bool, error) {
	return Job{}, false, nil
}
func (m *projectionQueueMock) CustomAntifraudPolicy(context.Context, uuid.UUID) (Policy, error) {
	return m.policy, nil
}
func (m *projectionQueueMock) EnqueueCustomProjectionBuckets(
	_ context.Context, _ uuid.UUID, _ uint64, buckets []time.Time,
) error {
	m.projectionBuckets = append(m.projectionBuckets, buckets...)
	return m.enqueueErr
}
func (m *projectionQueueMock) AdvanceCustomProjectionDiscovery(context.Context, Job, Discovery) error {
	m.advanced++
	return nil
}
func (m *projectionQueueMock) CompleteCustomProjectionJob(context.Context, Job, Snapshot) error {
	m.completed++
	return nil
}
func (m *projectionQueueMock) FailCustomProjectionJob(context.Context, Job, error, time.Duration) error {
	m.failed++
	return nil
}
func (m *projectionQueueMock) ScheduleCustomProjectionDeadline(
	_ context.Context, _ Job, deadline time.Time,
) error {
	m.deadlines = append(m.deadlines, deadline)
	return nil
}
func (m *projectionQueueMock) NextCustomProjectionSeq(context.Context) (uint64, error) {
	m.seq++
	return m.seq + 100, nil
}
func (m *projectionQueueMock) RefreshCustomProjectionLease(
	_ context.Context, _ Job, _ time.Duration,
) error {
	m.refreshed++
	return nil
}
func (m *projectionQueueMock) ProgressCustomProjection(
	ctx context.Context, job Job, snapshot Snapshot, lease time.Duration,
	activate func(context.Context) error,
) error {
	if m.beforeLock != nil {
		m.beforeLock()
	}
	if m.policy.Revision != job.PolicyRevision || !m.policy.Enabled {
		return errors.New("policy changed")
	}
	if err := activate(ctx); err != nil {
		return err
	}
	m.lastProgressLease = lease
	m.progressed++
	return nil
}
func (m *projectionQueueMock) CutoverCustomProjection(
	ctx context.Context, job Job, snapshot Snapshot, activate func(context.Context) error,
) error {
	if m.beforeLock != nil {
		m.beforeLock()
	}
	if m.policy.Revision != job.PolicyRevision || !m.policy.Enabled {
		return errors.New("policy changed")
	}
	if err := activate(ctx); err != nil {
		return err
	}
	return m.CompleteCustomProjectionJob(ctx, job, snapshot)
}
func (m *projectionQueueMock) EnqueueCDRReconciliationBuckets(
	_ context.Context, _ uuid.UUID, _ uint64, buckets []time.Time,
) error {
	m.buckets = append(m.buckets, buckets...)
	return nil
}
func (m *projectionQueueMock) LockDeviceWrites(uuid.UUID) func() {
	if m.beforeLock != nil {
		m.beforeLock()
	}
	return func() {}
}

type projectionWarehouseMock struct {
	events         []customradius.RawEvent
	sessionEvents  []customradius.RawEvent
	discovery      Discovery
	writes         []uuid.UUID
	snapshots      []Snapshot
	activations    []uuid.UUID
	disabled       int
	beforeActivate func()
	admitted       bool
	loadCalls      int
	loadFn         func(from, to time.Time, limit int) ([]customradius.RawEvent, error)
}

func (m *projectionWarehouseMock) DiscoverSyslogBuckets(context.Context, uuid.UUID, time.Time, uuid.UUID, int) (Discovery, error) {
	return m.discovery, nil
}
func (m *projectionWarehouseMock) LoadCustomRadiusEvents(
	_ context.Context, _ uuid.UUID, from, to time.Time, limit int,
) ([]customradius.RawEvent, error) {
	m.loadCalls++
	if m.loadFn != nil {
		return m.loadFn(from, to, limit)
	}
	return m.events, nil
}
func (m *projectionWarehouseMock) LoadCustomRadiusSessionEvents(
	context.Context, uuid.UUID, []string, time.Time, time.Time, time.Duration, int,
) ([]customradius.RawEvent, error) {
	return m.sessionEvents, nil
}
func (m *projectionWarehouseMock) WriteCustomProjectionSnapshot(_ context.Context, snapshot Snapshot) error {
	m.writes = append(m.writes, snapshot.ID)
	m.snapshots = append(m.snapshots, snapshot)
	if m.beforeActivate != nil {
		m.beforeActivate()
	}
	return nil
}

func projectionRaw(device uuid.UUID, id uuid.UUID, at time.Time, payload string) customradius.RawEvent {
	return customradius.RawEvent{
		EventID: id, DeviceID: device, ReceivedAt: at,
		SourceIP: "192.0.2.1", SourcePort: 514, Payload: []byte(payload),
	}
}
func (m *projectionWarehouseMock) ActivateCustomProjectionSnapshot(_ context.Context, snapshot Snapshot) error {
	m.activations = append(m.activations, snapshot.ID)
	return nil
}
func (m *projectionWarehouseMock) WriteCustomProjectionDisabled(context.Context, Job) error {
	m.disabled++
	return nil
}
func (m *projectionWarehouseMock) AdmitWorkload(
	ctx context.Context, class workload.Class,
) (context.Context, func(), error) {
	if class != workload.CustomReplay {
		panic("unexpected workload class")
	}
	m.admitted = true
	return ctx, func() { m.admitted = false }, nil
}

func TestBucketRetryProducesSameSnapshot(t *testing.T) {
	deviceID, eventID := uuid.New(), uuid.New()
	bucket := time.Date(2026, 7, 27, 3, 0, 0, 0, time.UTC)
	queue := &projectionQueueMock{policy: Policy{DeviceID: deviceID, Enabled: true, Revision: 2}}
	warehouse := &projectionWarehouseMock{events: []customradius.RawEvent{{
		EventID: eventID, DeviceID: deviceID, ReceivedAt: bucket.Add(time.Second),
		SourceIP: "192.0.2.1", Payload: []byte("not radius"),
	}}}
	worker := &Worker{Queue: queue, Warehouse: warehouse}
	job := Job{
		ID: uuid.New(), DeviceID: deviceID, PolicyRevision: 2, ProjectionSeq: 10,
		Kind: JobBucket, BucketStart: bucket,
	}
	if err := worker.process(context.Background(), worker.Config.normalized(), job); err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), worker.Config.normalized(), job); err != nil {
		t.Fatal(err)
	}
	if len(warehouse.writes) != 2 || warehouse.writes[0] != warehouse.writes[1] {
		t.Fatalf("retry snapshots are not deterministic: %v", warehouse.writes)
	}
}

func TestPolicyRacePreventsCutover(t *testing.T) {
	deviceID := uuid.New()
	queue := &projectionQueueMock{policy: Policy{DeviceID: deviceID, Enabled: true, Revision: 4}}
	warehouse := &projectionWarehouseMock{}
	warehouse.beforeActivate = func() {
		queue.policy.Enabled = false
		queue.policy.Revision = 5
	}
	worker := &Worker{Queue: queue, Warehouse: warehouse}
	err := worker.process(context.Background(), worker.Config.normalized(), Job{
		ID: uuid.New(), DeviceID: deviceID, PolicyRevision: 4, ProjectionSeq: 1,
		Kind: JobBucket, BucketStart: time.Now().UTC().Truncate(time.Hour),
	})
	if err == nil {
		t.Fatal("policy race should reject cutover")
	}
	if len(warehouse.activations) != 0 || queue.completed != 0 {
		t.Fatal("raced projection became visible")
	}
}

func TestAdmissionPrecedesDeviceCutoverLock(t *testing.T) {
	deviceID := uuid.New()
	queue := &projectionQueueMock{
		policy: Policy{DeviceID: deviceID, Enabled: true, Revision: 1},
	}
	warehouse := &projectionWarehouseMock{}
	queue.beforeLock = func() {
		if !warehouse.admitted {
			t.Fatal("device lock was acquired before workload admission")
		}
	}
	worker := &Worker{Queue: queue, Warehouse: warehouse}
	if err := worker.process(context.Background(), worker.Config.normalized(), Job{
		ID: uuid.New(), DeviceID: deviceID, PolicyRevision: 1, ProjectionSeq: 1,
		Kind: JobBucket, BucketStart: time.Now().UTC().Truncate(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if warehouse.admitted {
		t.Fatal("workload admission was not released")
	}
}

func TestDiscoveryEnqueueFailureDoesNotAdvanceCursor(t *testing.T) {
	deviceID := uuid.New()
	queue := &projectionQueueMock{
		policy:     Policy{DeviceID: deviceID, Enabled: true, Revision: 3},
		enqueueErr: errors.New("postgres unavailable"),
	}
	warehouse := &projectionWarehouseMock{discovery: Discovery{
		Buckets:  []time.Time{time.Now().UTC().Truncate(time.Hour)},
		NextTime: time.Now().UTC(), NextEventID: uuid.New(),
	}}
	worker := &Worker{Queue: queue, Warehouse: warehouse}
	job := Job{
		ID: uuid.New(), DeviceID: deviceID, PolicyRevision: 3, Kind: JobDiscover,
	}
	if err := worker.process(context.Background(), worker.Config.normalized(), job); err == nil {
		t.Fatal("enqueue failure was ignored")
	}
	if queue.advanced != 0 {
		t.Fatal("discovery cursor advanced despite enqueue failure")
	}
	queue.enqueueErr = nil
	if err := worker.process(context.Background(), worker.Config.normalized(), job); err != nil {
		t.Fatal(err)
	}
	if queue.advanced != 1 {
		t.Fatal("discovery did not retry after enqueue recovered")
	}
}

func TestCrossDaySessionRecomputesSingleCall(t *testing.T) {
	device := uuid.New()
	base := time.Date(2026, 7, 27, 23, 55, 0, 0, time.UTC)
	initial := []customradius.RawEvent{
		projectionRaw(device, uuid.New(), base,
			"[C1] Access-Request [1] Cisco-AVPair='xpgk-request-type=number' Acct-Session-Id=long"),
		projectionRaw(device, uuid.New(), base.Add(time.Millisecond), "[C1] Access-Accept [1]"),
	}
	later := []customradius.RawEvent{
		projectionRaw(device, uuid.New(), base.Add(26*time.Hour),
			"[C2] Accounting-Request [2] Acct-Session-Id=long Acct-Status-Type=Start"),
		projectionRaw(device, uuid.New(), base.Add(26*time.Hour+time.Millisecond),
			"[C2] Accounting-Response [2]"),
		projectionRaw(device, uuid.New(), base.Add(30*time.Hour),
			"[C3] Accounting-Request [3] Acct-Session-Id=long Acct-Status-Type=Stop"),
		projectionRaw(device, uuid.New(), base.Add(30*time.Hour+time.Millisecond),
			"[C3] Accounting-Response [3]"),
	}
	queue := &projectionQueueMock{
		policy: Policy{DeviceID: device, Enabled: true, Revision: 7},
	}
	warehouse := &projectionWarehouseMock{
		events: initial, sessionEvents: append(append([]customradius.RawEvent{}, initial...), later...),
	}
	worker := &Worker{Queue: queue, Warehouse: warehouse}
	job := Job{
		ID: uuid.New(), DeviceID: device, PolicyRevision: 7, ProjectionSeq: 10,
		Generation: 1, Kind: JobBucket, BucketStart: base.Truncate(time.Hour),
		CutoffAt: base.Add(31 * time.Hour),
	}
	if err := worker.process(context.Background(), worker.Config.normalized(), job); err != nil {
		t.Fatal(err)
	}
	if len(warehouse.snapshots) != 1 || len(warehouse.snapshots[0].Result.Calls) != 1 ||
		warehouse.snapshots[0].Result.Calls[0].Status != customradius.CallCompleted {
		t.Fatalf("cross-day session was not recomputed once: %+v", warehouse.snapshots)
	}
	if len(queue.projectionBuckets) < 2 {
		t.Fatalf("affected cross-day buckets were not enqueued: %v", queue.projectionBuckets)
	}
}

func TestOverflowSplitsHourLoad(t *testing.T) {
	deviceID := uuid.New()
	bucket := time.Date(2026, 7, 27, 3, 0, 0, 0, time.UTC)
	queue := &projectionQueueMock{policy: Policy{DeviceID: deviceID, Enabled: true, Revision: 1}}
	warehouse := &projectionWarehouseMock{
		loadFn: func(from, to time.Time, limit int) ([]customradius.RawEvent, error) {
			if to.Sub(from) > 30*time.Minute {
				return nil, fmt.Errorf("custom projection bucket exceeds %d events", limit)
			}
			return []customradius.RawEvent{
				projectionRaw(deviceID, uuid.New(), from.Add(time.Minute), "not radius"),
			}, nil
		},
	}
	worker := &Worker{Queue: queue, Warehouse: warehouse, Config: Config{MaxEvents: 100}}
	if err := worker.process(context.Background(), worker.Config.normalized(), Job{
		ID: uuid.New(), DeviceID: deviceID, PolicyRevision: 1, ProjectionSeq: 1,
		Kind: JobBucket, BucketStart: bucket,
	}); err != nil {
		t.Fatal(err)
	}
	if warehouse.loadCalls < 2 {
		t.Fatalf("expected windowed loads after overflow, got %d", warehouse.loadCalls)
	}
	if len(warehouse.activations) != 1 || queue.completed != 1 {
		t.Fatalf("non-AF overflow rebuild should finalize once: activations=%v completed=%d",
			warehouse.activations, queue.completed)
	}
}

func TestDenseHourProgressiveActivatesDuringWindowedRebuild(t *testing.T) {
	deviceID := uuid.New()
	bucket := time.Date(2026, 7, 27, 4, 0, 0, 0, time.UTC)
	queue := &projectionQueueMock{policy: Policy{DeviceID: deviceID, Enabled: true, Revision: 1}}
	warehouse := &projectionWarehouseMock{
		loadFn: func(from, to time.Time, limit int) ([]customradius.RawEvent, error) {
			if to.Sub(from) >= time.Hour {
				return nil, fmt.Errorf("custom projection bucket exceeds %d events", limit)
			}
			slot := from.UTC().Truncate(5 * time.Minute)
			if slot.Before(bucket) {
				slot = bucket
			}
			if !slot.Before(bucket.Add(time.Hour)) || !slot.Before(to) || slot.Before(from) {
				return nil, nil
			}
			session := fmt.Sprintf("s-%d", slot.Unix())
			req := projectionRaw(deviceID, uuid.NewSHA1(uuid.NameSpaceOID, []byte(session+"-req")),
				slot.Add(time.Second),
				"[C1] Access-Request [9] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id="+session)
			acc := projectionRaw(deviceID, uuid.NewSHA1(uuid.NameSpaceOID, []byte(session+"-acc")),
				slot.Add(2*time.Second), "[C1] Access-Accept [9]")
			return []customradius.RawEvent{req, acc}, nil
		},
	}
	worker := &Worker{Queue: queue, Warehouse: warehouse, Config: Config{MaxEvents: 10, MaxMemoryBytes: 1 << 20}}
	if err := worker.process(context.Background(), worker.Config.normalized(), Job{
		ID: uuid.New(), DeviceID: deviceID, PolicyRevision: 1, ProjectionSeq: 1,
		Kind: JobBucket, BucketStart: bucket, WorkerID: "test-worker",
	}); err != nil {
		t.Fatal(err)
	}
	if len(warehouse.activations) < 2 || queue.progressed < 1 || queue.completed != 1 {
		t.Fatalf("dense hour should progressive-activate then finalize: activations=%v progressed=%d completed=%d",
			warehouse.activations, queue.progressed, queue.completed)
	}
	if queue.refreshed < len(warehouse.activations) {
		t.Fatalf("expected lease refresh before each CH publish: refreshed=%d activations=%d",
			queue.refreshed, len(warehouse.activations))
	}
	if queue.lastProgressLease != 2*time.Minute {
		t.Fatalf(" progressive lease=%s, want default cfg.Lease", queue.lastProgressLease)
	}
	// CDR reconciliation must not run on progressive publishes (finalize only).
	if len(queue.buckets) == 0 {
		t.Fatal("finalize should enqueue CDR reconciliation")
	}
	if len(queue.buckets) > queue.progressed {
		t.Fatalf("CDR reconciliation ran on progressive windows: stamps=%d progressed=%d",
			len(queue.buckets), queue.progressed)
	}
}

func TestIsEventLimitError(t *testing.T) {
	if !IsEventLimitError(fmt.Errorf("custom projection bucket exceeds %d events", 5000)) {
		t.Fatal("overflow error not detected")
	}
	if IsEventLimitError(fmt.Errorf("clickhouse unavailable")) {
		t.Fatal("non-overflow error misclassified")
	}
	if !IsClickHouseResourceError(fmt.Errorf("code: 241, message: Query memory limit exceeded: would use 512.85 MiB")) {
		t.Fatal("clickhouse memory error not detected")
	}
	if !IsClickHouseResourceError(fmt.Errorf("code: 394, message: Query was cancelled")) {
		t.Fatal("clickhouse cancel error not detected")
	}
}

func TestUnansweredRequestSchedulesDurableDeadline(t *testing.T) {
	device := uuid.New()
	base := time.Date(2026, 7, 27, 3, 0, 0, 0, time.UTC)
	queue := &projectionQueueMock{
		policy: Policy{DeviceID: device, Enabled: true, Revision: 1},
	}
	warehouse := &projectionWarehouseMock{events: []customradius.RawEvent{
		projectionRaw(device, uuid.New(), base,
			"[C1] Access-Request [9] Cisco-AVPair='xpgk-request-type=check_call' Acct-Session-Id=pending"),
	}}
	worker := &Worker{Queue: queue, Warehouse: warehouse}
	if err := worker.process(context.Background(), worker.Config.normalized(), Job{
		ID: uuid.New(), DeviceID: device, PolicyRevision: 1, ProjectionSeq: 1,
		Generation: 1, Kind: JobBucket, BucketStart: base,
	}); err != nil {
		t.Fatal(err)
	}
	if len(queue.deadlines) != 1 || !queue.deadlines[0].Equal(base.Add(5*time.Second)) {
		t.Fatalf("deadline=%v", queue.deadlines)
	}
	if err := worker.process(context.Background(), worker.Config.normalized(), Job{
		ID: uuid.New(), DeviceID: device, PolicyRevision: 1, ProjectionSeq: 2,
		Generation: 2, Kind: JobBucket, BucketStart: base, CutoffAt: queue.deadlines[0],
	}); err != nil {
		t.Fatal(err)
	}
	last := warehouse.snapshots[len(warehouse.snapshots)-1]
	if last.Result.NextDeadline != nil ||
		last.Result.Packets[0].Decision != customradius.DecisionUnavailableFallback {
		t.Fatalf("deadline recompute was not deterministic: %+v", last.Result)
	}
}
