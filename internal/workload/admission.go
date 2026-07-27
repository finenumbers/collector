// Package workload provides process-wide ClickHouse workload admission.
//
// Lock order is strict: callers acquire admission before executing warehouse
// work and must release it before taking a device write/purge lock. Admission
// itself never calls application code while holding its mutex.
package workload

import (
	"context"
	"errors"
	"sync"
	"time"
)

type Class string

const (
	Interactive     Class = "interactive"
	Export          Class = "export"
	CustomReplay    Class = "custom_replay"
	CustomReconcile Class = "custom_reconcile"
	Ingest          Class = "ingest"
	Diagnostics     Class = "diagnostics"
)

var (
	ErrInvalidClass = errors.New("invalid workload class")
	ErrRejected     = errors.New("workload admission queue is full")
)

type Options struct {
	Capacity   int
	MaxWaiting int
	Weights    map[Class]int
}

type Stats struct {
	Active         int           `json:"active"`
	Waiting        int           `json:"waiting"`
	Admitted       uint64        `json:"admitted"`
	Rejected       uint64        `json:"rejected"`
	WaitDuration   time.Duration `json:"waitDuration"`
	ActiveDuration time.Duration `json:"activeDuration"`
}

type counters struct {
	active, waiting    int
	admitted, rejected uint64
	waitDuration       time.Duration
	activeDuration     time.Duration
}

type waiter struct {
	class   Class
	weight  int
	heavy   bool
	queued  time.Time
	granted chan struct{}
}

type Manager struct {
	mu          sync.Mutex
	capacity    int
	maxWaiting  int
	used        int
	heavyActive bool
	weights     map[Class]int
	interactive []*waiter
	regular     []*waiter
	stats       map[Class]*counters
}

type leaseKey struct{}

type lease struct {
	manager *Manager
	class   Class
}

func New(options Options) *Manager {
	if options.Capacity <= 0 {
		options.Capacity = 8
	}
	if options.MaxWaiting <= 0 {
		options.MaxWaiting = options.Capacity * 32
	}
	defaults := map[Class]int{
		Interactive: 1, Export: 4, CustomReplay: 4,
		CustomReconcile: 2, Ingest: 1, Diagnostics: 1,
	}
	for class, weight := range options.Weights {
		if weight > 0 && weight <= options.Capacity {
			defaults[class] = weight
		}
	}
	stats := make(map[Class]*counters, len(defaults))
	for class := range defaults {
		stats[class] = &counters{}
	}
	return &Manager{
		capacity: options.Capacity, maxWaiting: options.MaxWaiting,
		weights: defaults, stats: stats,
	}
}

// Acquire is cancellation-safe. A context already admitted by this manager is
// returned unchanged so composed warehouse operations cannot self-deadlock.
func (m *Manager) Acquire(ctx context.Context, class Class) (context.Context, func(), error) {
	if existing, ok := ctx.Value(leaseKey{}).(lease); ok && existing.manager == m {
		return ctx, func() {}, nil
	}
	weight, ok := m.weights[class]
	if !ok {
		return ctx, nil, ErrInvalidClass
	}
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	item := &waiter{
		class: class, weight: weight, heavy: class == Export || class == CustomReplay,
		queued: time.Now(), granted: make(chan struct{}),
	}
	m.mu.Lock()
	if len(m.interactive)+len(m.regular) >= m.maxWaiting {
		m.stats[class].rejected++
		m.mu.Unlock()
		return ctx, nil, ErrRejected
	}
	m.stats[class].waiting++
	if class == Interactive {
		m.interactive = append(m.interactive, item)
	} else {
		m.regular = append(m.regular, item)
	}
	m.scheduleLocked()
	m.mu.Unlock()

	select {
	case <-item.granted:
		if err := ctx.Err(); err != nil {
			m.release(item, time.Now())
			return ctx, nil, err
		}
	case <-ctx.Done():
		m.mu.Lock()
		if m.removeLocked(item) {
			counter := m.stats[class]
			counter.waiting--
			counter.rejected++
			counter.waitDuration += time.Since(item.queued)
			m.scheduleLocked()
			m.mu.Unlock()
			return ctx, nil, ctx.Err()
		}
		m.mu.Unlock()
		// Grant raced cancellation. Consume it and release its capacity.
		<-item.granted
		m.release(item, time.Now())
		return ctx, nil, ctx.Err()
	}

	started := time.Now()
	var once sync.Once
	release := func() {
		once.Do(func() { m.release(item, started) })
	}
	return context.WithValue(ctx, leaseKey{}, lease{manager: m, class: class}), release, nil
}

func (m *Manager) Current(ctx context.Context) (Class, bool) {
	current, ok := ctx.Value(leaseKey{}).(lease)
	return current.class, ok && current.manager == m
}

func (m *Manager) release(item *waiter, started time.Time) {
	m.mu.Lock()
	counter := m.stats[item.class]
	counter.active--
	counter.activeDuration += time.Since(started)
	m.used -= item.weight
	if item.heavy {
		m.heavyActive = false
	}
	m.scheduleLocked()
	m.mu.Unlock()
}

func (m *Manager) scheduleLocked() {
	for {
		var queue *[]*waiter
		if len(m.interactive) > 0 {
			queue = &m.interactive
		} else if len(m.regular) > 0 {
			queue = &m.regular
		} else {
			return
		}
		index := m.firstFittingLocked(*queue)
		if index < 0 {
			return
		}
		item := (*queue)[index]
		*queue = append((*queue)[:index], (*queue)[index+1:]...)
		counter := m.stats[item.class]
		counter.waiting--
		counter.active++
		counter.admitted++
		counter.waitDuration += time.Since(item.queued)
		m.used += item.weight
		if item.heavy {
			m.heavyActive = true
		}
		close(item.granted)
	}
}

func (m *Manager) firstFittingLocked(queue []*waiter) int {
	for index, item := range queue {
		if m.used+item.weight <= m.capacity && (!item.heavy || !m.heavyActive) {
			return index
		}
	}
	return -1
}

func (m *Manager) removeLocked(target *waiter) bool {
	for _, queue := range []*[]*waiter{&m.interactive, &m.regular} {
		for index, item := range *queue {
			if item == target {
				*queue = append((*queue)[:index], (*queue)[index+1:]...)
				return true
			}
		}
	}
	return false
}

func (m *Manager) Snapshot() map[Class]Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[Class]Stats, len(m.stats))
	for class, counter := range m.stats {
		result[class] = Stats{
			Active: counter.active, Waiting: counter.waiting,
			Admitted: counter.admitted, Rejected: counter.rejected,
			WaitDuration: counter.waitDuration, ActiveDuration: counter.activeDuration,
		}
	}
	return result
}
