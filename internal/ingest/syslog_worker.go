package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"sort"
	"time"

	"collector/internal/analytics"
	"collector/internal/customprojection"
	"collector/internal/spool"
	"collector/internal/store"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const (
	syslogSubject    = "collector.raw.syslog"
	syslogDLQSubject = "collector.dlq.syslog"
)

// RawSyslog is the durable transport envelope shared by ingress, spool, and
// JetStream. Timezone and template provenance remain available for future
// Custom consumers but are not persisted as derived classification.
type RawSyslog struct {
	EventID          uuid.UUID `json:"eventId"`
	DeviceID         uuid.UUID `json:"deviceId"`
	ReceivedAt       time.Time `json:"receivedAt"`
	SourceIP         string    `json:"sourceIp"`
	SourcePort       uint16    `json:"sourcePort"`
	Payload          []byte    `json:"payload"`
	Timezone         string    `json:"timezone,omitempty"`
	TimezoneRevision uint64    `json:"timezoneRevision,omitempty"`
	TemplateKey      string    `json:"templateKey,omitempty"`
	Firmware         string    `json:"firmware,omitempty"`
}

type DeviceTimeConfigResolver interface {
	DeviceTimeConfig(context.Context, uuid.UUID) (store.DeviceTimeConfig, error)
}

type deviceWriteLocker interface {
	LockDeviceWrites(uuid.UUID) func()
}

type customProjectionEnqueuer interface {
	CustomAntifraudPolicy(context.Context, uuid.UUID) (customprojection.Policy, error)
	EnqueueCustomProjectionBuckets(context.Context, uuid.UUID, uint64, []time.Time) error
}

func EnsureStreams(nc *nats.Conn) error {
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	if err := ensureStream(js, &nats.StreamConfig{
		Name:       "SYSLOG",
		Subjects:   []string{syslogSubject},
		Storage:    nats.FileStorage,
		Retention:  nats.WorkQueuePolicy,
		MaxBytes:   20 << 30,
		Discard:    nats.DiscardNew,
		Duplicates: 72 * time.Hour,
	}); err != nil {
		return err
	}
	return ensureStream(js, &nats.StreamConfig{
		Name:       "SYSLOG_DLQ",
		Subjects:   []string{syslogDLQSubject},
		Storage:    nats.FileStorage,
		Retention:  nats.LimitsPolicy,
		MaxBytes:   1 << 30,
		Discard:    nats.DiscardNew,
		Duplicates: 72 * time.Hour,
	})
}

func PurgeDeviceNATS(ctx context.Context, nc *nats.Conn, deviceID uuid.UUID) error {
	if nc == nil {
		return nil
	}
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	for _, stream := range []string{"SYSLOG", "SYSLOG_DLQ"} {
		info, err := js.StreamInfo(stream, nats.Context(ctx))
		if err != nil {
			return err
		}
		for sequence := info.State.FirstSeq; sequence <= info.State.LastSeq && sequence != 0; sequence++ {
			message, err := js.GetMsg(stream, sequence, nats.Context(ctx))
			if errors.Is(err, nats.ErrMsgNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			var raw RawSyslog
			if json.Unmarshal(message.Data, &raw) != nil || raw.DeviceID != deviceID {
				continue
			}
			if err := js.DeleteMsg(stream, sequence, nats.Context(ctx)); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureStream(js nats.JetStreamContext, config *nats.StreamConfig) error {
	_, err := js.StreamInfo(config.Name)
	if err == nil {
		_, err = js.UpdateStream(config)
		return err
	}
	if !errors.Is(err, nats.ErrStreamNotFound) {
		return err
	}
	_, err = js.AddStream(config)
	return err
}

func RunSpoolPublisher(ctx context.Context, queue *spool.Queue, nc *nats.Conn) error {
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	for ctx.Err() == nil {
		items, err := queue.Peek(500)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		processed := make([][]byte, 0, len(items))
		for _, item := range items {
			var raw RawSyslog
			if err := json.Unmarshal(item.Data, &raw); err != nil {
				if quarantineErr := queue.Quarantine(item.Key, item.Data, err.Error()); quarantineErr != nil {
					return quarantineErr
				}
				slog.Error("invalid durable spool record moved to quarantine", "error", err)
				continue
			}
			if _, err := js.Publish(syslogSubject, item.Data, nats.MsgId(raw.EventID.String())); err != nil {
				slog.Warn("NATS unavailable; retaining syslog spool", "error", err)
				break
			}
			processed = append(processed, item.Key)
		}
		if err := queue.Delete(processed); err != nil {
			return err
		}
	}
	return nil
}

func RunSyslogWorker(
	ctx context.Context,
	nc *nats.Conn,
	client *analytics.Client,
	timeResolver DeviceTimeConfigResolver,
	customProjectionEnabled func() bool,
) error {
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	// The durable name is retained so an upgrade continues from the existing
	// acknowledgement position without replaying or losing queued envelopes.
	subscription, err := js.PullSubscribe(syslogSubject, "syslog-parser",
		nats.BindStream("SYSLOG"), nats.ManualAck(), nats.AckExplicit())
	if err != nil {
		return err
	}
	for ctx.Err() == nil {
		messages, err := subscription.Fetch(250, nats.MaxWait(time.Second))
		if errors.Is(err, nats.ErrTimeout) {
			continue
		}
		if err != nil {
			return err
		}
		type rawMessage struct {
			message *nats.Msg
			raw     RawSyslog
		}
		pending := make([]rawMessage, 0, len(messages))
		for _, message := range messages {
			var raw RawSyslog
			if err := json.Unmarshal(message.Data, &raw); err != nil {
				if _, publishErr := js.Publish(syslogDLQSubject, message.Data); publishErr != nil {
					slog.Error("invalid NATS envelope could not be quarantined", "error", publishErr)
					_ = message.NakWithDelay(5 * time.Second)
					continue
				}
				slog.Error("invalid NATS envelope moved to dead-letter stream", "error", err)
				_ = message.Term()
				continue
			}
			pending = append(pending, rawMessage{message: message, raw: raw})
		}
		retry := func() bool {
			ids := make([]uuid.UUID, 0, len(pending))
			for _, item := range pending {
				ids = append(ids, item.raw.DeviceID)
			}
			release := lockRawSyslogDevices(timeResolver, ids)
			defer release()

			active := make([]rawMessage, 0, len(pending))
			records := make([]analytics.SyslogMessage, 0, len(pending))
			for _, item := range pending {
				if timeResolver != nil {
					if _, configErr := timeResolver.DeviceTimeConfig(ctx, item.raw.DeviceID); configErr != nil {
						if errors.Is(configErr, store.ErrDeviceDeleting) ||
							errors.Is(configErr, store.ErrNotFound) {
							_ = item.message.Term()
							continue
						}
						_ = item.message.NakWithDelay(5 * time.Second)
						continue
					}
				}
				active = append(active, item)
				records = append(records, analytics.SyslogMessage{
					EventID: item.raw.EventID, DeviceID: item.raw.DeviceID,
					ReceivedAt: item.raw.ReceivedAt, SourceIP: net.ParseIP(item.raw.SourceIP),
					SourcePort: item.raw.SourcePort, Transport: "udp", Payload: item.raw.Payload,
				})
			}
			if len(records) == 0 {
				return false
			}
			if err := client.InsertSyslogMessagesBatch(ctx, records); err != nil {
				slog.Error("raw Syslog batch persistence failed", "count", len(records), "error", err)
				for _, item := range active {
					_ = item.message.NakWithDelay(5 * time.Second)
				}
				return true
			}
			if customProjectionEnabled != nil && customProjectionEnabled() {
				enqueuer, ok := timeResolver.(customProjectionEnqueuer)
				if !ok {
					for _, item := range active {
						_ = item.message.NakWithDelay(5 * time.Second)
					}
					return true
				}
				buckets := make(map[uuid.UUID]map[time.Time]struct{})
				revisions := make(map[uuid.UUID]uint64)
				for _, item := range active {
					policy, policyErr := enqueuer.CustomAntifraudPolicy(ctx, item.raw.DeviceID)
					if policyErr != nil {
						if errors.Is(policyErr, store.ErrNotFound) ||
							errors.Is(policyErr, store.ErrDeviceDeleting) {
							continue
						}
						for _, pendingItem := range active {
							_ = pendingItem.message.NakWithDelay(5 * time.Second)
						}
						return true
					}
					if !policy.Enabled {
						continue
					}
					revisions[item.raw.DeviceID] = policy.Revision
					if buckets[item.raw.DeviceID] == nil {
						buckets[item.raw.DeviceID] = make(map[time.Time]struct{})
					}
					buckets[item.raw.DeviceID][item.raw.ReceivedAt.UTC().Truncate(time.Hour)] = struct{}{}
				}
				for deviceID, values := range buckets {
					deviceBuckets := make([]time.Time, 0, len(values))
					for bucket := range values {
						deviceBuckets = append(deviceBuckets, bucket)
					}
					if enqueueErr := enqueuer.EnqueueCustomProjectionBuckets(
						ctx, deviceID, revisions[deviceID], deviceBuckets,
					); enqueueErr != nil {
						for _, item := range active {
							_ = item.message.NakWithDelay(5 * time.Second)
						}
						return true
					}
				}
			}
			for _, item := range active {
				_ = item.message.Ack()
			}
			return false
		}()
		if retry {
			continue
		}
	}
	return nil
}

func lockRawSyslogDevices(resolver DeviceTimeConfigResolver, deviceIDs []uuid.UUID) func() {
	locker, ok := resolver.(deviceWriteLocker)
	if !ok {
		return func() {}
	}
	unique := make(map[uuid.UUID]struct{}, len(deviceIDs))
	for _, id := range deviceIDs {
		unique[id] = struct{}{}
	}
	ids := make([]uuid.UUID, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool {
		return ids[left].String() < ids[right].String()
	})
	releases := make([]func(), 0, len(ids))
	for _, id := range ids {
		releases = append(releases, locker.LockDeviceWrites(id))
	}
	return func() {
		for index := len(releases) - 1; index >= 0; index-- {
			releases[index]()
		}
	}
}
