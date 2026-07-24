package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"collector/internal/spool"

	"github.com/google/uuid"
)

type IngressDatagram struct {
	EventID    uuid.UUID `json:"eventId"`
	ReceivedAt time.Time `json:"receivedAt"`
	SourceIP   string    `json:"sourceIp"`
	SourcePort uint16    `json:"sourcePort"`
	Payload    []byte    `json:"payload"`
}

type IngressStatus struct {
	UpdatedAt       time.Time       `json:"updatedAt"`
	Runtime         MetricsSnapshot `json:"runtime"`
	SpoolDepth      uint64          `json:"spoolDepth"`
	QuarantineDepth uint64          `json:"quarantineDepth"`
}

type IngressReceiver struct {
	Addr    string
	Spool   *spool.Queue
	Metrics *Metrics
}

func (r *IngressReceiver) Run(ctx context.Context) error {
	address, err := net.ResolveUDPAddr("udp", r.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetReadBuffer(16 << 20); err != nil {
		slog.Warn("unable to enlarge ingress UDP receive buffer", "error", err)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	const (
		maxBatch    = 256
		batchWindow = 2 * time.Millisecond
	)
	pending := make([]spool.Entry, 0, maxBatch)
	var flushAt time.Time
	flush := func() error {
		for len(pending) > 0 {
			count := uint64(len(pending))
			if err := r.Spool.EnqueueBatch(pending); err == nil {
				pending = pending[:0]
				flushAt = time.Time{}
				r.Metrics.RecordAcceptedN(count)
				return nil
			} else {
				r.Metrics.RecordSpoolError()
				slog.Error("ingress durable spool batch failed; retrying", "count", len(pending), "error", err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
		return nil
	}

	buffer := make([]byte, 64*1024)
	for {
		if len(pending) > 0 {
			_ = conn.SetReadDeadline(flushAt)
		} else {
			_ = conn.SetReadDeadline(time.Time{})
		}
		size, source, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				_ = flush()
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if err := flush(); err != nil && !errors.Is(err, context.Canceled) {
					return err
				}
				continue
			}
			slog.Error("syslog ingress read failed", "error", err)
			continue
		}
		sourceIP := source.IP.String()
		if ipv4 := source.IP.To4(); ipv4 != nil {
			sourceIP = ipv4.String()
		}
		now := time.Now().UTC()
		record := IngressDatagram{
			EventID: uuid.New(), ReceivedAt: now, SourceIP: sourceIP,
			SourcePort: uint16(source.Port), Payload: append([]byte(nil), buffer[:size]...),
		}
		payload, err := json.Marshal(record)
		if err != nil {
			return err
		}
		pending = append(pending, spool.Entry{
			ReceivedAt: record.ReceivedAt, EventID: record.EventID.String(), Payload: payload,
		})
		if len(pending) == 1 {
			flushAt = time.Now().Add(batchWindow)
		}
		if len(pending) >= maxBatch {
			if err := flush(); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
		}
	}
}

func RunIngressStatusWriter(ctx context.Context, path string, queue *spool.Queue, metrics *Metrics) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := writeIngressStatus(path, queue, metrics); err != nil {
			slog.Warn("unable to write ingress status", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func ReadIngressStatus(path string) (IngressStatus, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return IngressStatus{}, err
	}
	var status IngressStatus
	err = json.Unmarshal(payload, &status)
	return status, err
}

func writeIngressStatus(path string, queue *spool.Queue, metrics *Metrics) error {
	depth, err := queue.Depth()
	if err != nil {
		return err
	}
	quarantineDepth, err := queue.QuarantineDepth()
	if err != nil {
		return err
	}
	status := IngressStatus{
		UpdatedAt: time.Now().UTC(), Runtime: metrics.Snapshot(),
		SpoolDepth: depth, QuarantineDepth: quarantineDepth,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".ingress-status-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if err := json.NewEncoder(file).Encode(status); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
