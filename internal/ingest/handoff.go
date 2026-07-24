package ingest

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"collector/internal/spool"
	"collector/internal/store"

	"github.com/google/uuid"
)

const maxHandoffFrame = 16 << 20

type handoffRequest struct {
	Items []IngressDatagram `json:"items"`
}

type handoffResponse struct {
	CompletedEventIDs []uuid.UUID `json:"completedEventIds"`
}

type cachedHandoffDevice struct {
	id       uuid.UUID
	timezone string
	expires  time.Time
}

type DeviceResolver interface {
	DeviceIdentityBySourceIP(context.Context, string) (uuid.UUID, string, error)
}

func RunIngressHandoffPublisher(
	ctx context.Context, queue *spool.Queue, socketPath string, metrics *Metrics,
) error {
	var lastUnavailableLog time.Time
	for ctx.Err() == nil {
		items, err := queue.Peek(128)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		request := handoffRequest{Items: make([]IngressDatagram, 0, len(items))}
		keys := make(map[uuid.UUID][]byte, len(items))
		for _, item := range items {
			var datagram IngressDatagram
			if err := json.Unmarshal(item.Data, &datagram); err != nil {
				if quarantineErr := queue.Quarantine(item.Key, item.Data, err.Error()); quarantineErr != nil {
					return quarantineErr
				}
				continue
			}
			request.Items = append(request.Items, datagram)
			keys[datagram.EventID] = item.Key
		}
		if len(request.Items) == 0 {
			continue
		}
		var response handoffResponse
		if err := exchangeHandoff(socketPath, request, &response); err != nil {
			metrics.RecordHandoffError()
			if time.Since(lastUnavailableLog) >= time.Minute {
				slog.Warn("Syslog handoff unavailable; retaining ingress spool", "error", err)
				lastUnavailableLog = time.Now()
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(250 * time.Millisecond):
			}
			continue
		}
		completed := make([][]byte, 0, len(response.CompletedEventIDs))
		for _, eventID := range response.CompletedEventIDs {
			if key, ok := keys[eventID]; ok {
				completed = append(completed, key)
				metrics.RecordHandedOff()
			}
		}
		if err := queue.Delete(completed); err != nil {
			return err
		}
	}
	return nil
}

func RunHandoffReceiver(
	ctx context.Context, socketPath string, control DeviceResolver, queue *spool.Queue, metrics *Metrics,
) error {
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	address, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return err
	}
	defer func() {
		listener.Close()
		os.Remove(socketPath)
	}()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	cache := make(map[string]cachedHandoffDevice)
	rejectedLog := make(map[string]time.Time)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if err := handleHandoffConnection(ctx, connection, control, queue, metrics, cache, rejectedLog); err != nil {
			slog.Warn("Syslog handoff batch failed; ingress will retry", "error", err)
		}
		_ = connection.Close()
	}
}

func handleHandoffConnection(
	ctx context.Context,
	connection *net.UnixConn,
	control DeviceResolver,
	queue *spool.Queue,
	metrics *Metrics,
	cache map[string]cachedHandoffDevice,
	rejectedLog map[string]time.Time,
) error {
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	var request handoffRequest
	if err := readHandoffFrame(connection, &request); err != nil {
		return err
	}
	if len(request.Items) == 0 || len(request.Items) > 128 {
		return fmt.Errorf("invalid handoff batch size %d", len(request.Items))
	}
	now := time.Now()
	completed := make([]uuid.UUID, 0, len(request.Items))
	entries := make([]spool.Entry, 0, len(request.Items))
	acceptedIDs := make([]uuid.UUID, 0, len(request.Items))
	for _, datagram := range request.Items {
		sourceIP := net.ParseIP(datagram.SourceIP)
		if sourceIP == nil || datagram.EventID == uuid.Nil || datagram.ReceivedAt.IsZero() {
			completed = append(completed, datagram.EventID)
			metrics.RecordRejected()
			continue
		}
		normalizedIP := sourceIP.String()
		if ipv4 := sourceIP.To4(); ipv4 != nil {
			normalizedIP = ipv4.String()
		}
		deviceID := uuid.Nil
		timezone := ""
		if cached, ok := cache[normalizedIP]; ok && now.Before(cached.expires) {
			deviceID = cached.id
			timezone = cached.timezone
		} else {
			resolved, resolvedTimezone, err := control.DeviceIdentityBySourceIP(ctx, normalizedIP)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					completed = append(completed, datagram.EventID)
					metrics.RecordRejected()
					if last := rejectedLog[normalizedIP]; now.Sub(last) >= time.Minute {
						slog.Warn("syslog from unknown source rejected",
							"source", normalizedIP, "source_port", datagram.SourcePort)
						rejectedLog[normalizedIP] = now
					}
					continue
				}
				return err
			}
			deviceID = resolved
			timezone = resolvedTimezone
			cache[normalizedIP] = cachedHandoffDevice{
				id: deviceID, timezone: timezone, expires: now.Add(30 * time.Second),
			}
		}
		raw := RawSyslog{
			EventID: datagram.EventID, DeviceID: deviceID, ReceivedAt: datagram.ReceivedAt,
			SourceIP: normalizedIP, SourcePort: datagram.SourcePort, Payload: datagram.Payload,
			Timezone: timezone,
		}
		payload, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		entries = append(entries, spool.Entry{
			ReceivedAt: raw.ReceivedAt, EventID: raw.EventID.String(), Payload: payload,
		})
		acceptedIDs = append(acceptedIDs, raw.EventID)
	}
	if err := queue.EnqueueBatch(entries); err != nil {
		metrics.RecordSpoolError()
		return err
	}
	for range acceptedIDs {
		metrics.RecordAccepted()
	}
	completed = append(completed, acceptedIDs...)
	return writeHandoffFrame(connection, handoffResponse{CompletedEventIDs: completed})
}

func exchangeHandoff(socketPath string, request handoffRequest, response *handoffResponse) error {
	connection, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if err := writeHandoffFrame(connection, request); err != nil {
		return err
	}
	return readHandoffFrame(connection, response)
}

func writeHandoffFrame(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) > maxHandoffFrame {
		return fmt.Errorf("handoff frame too large: %d", len(payload))
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if err := writeHandoffBytes(writer, header); err != nil {
		return err
	}
	return writeHandoffBytes(writer, payload)
}

func writeHandoffBytes(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func readHandoffFrame(reader io.Reader, value any) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > maxHandoffFrame {
		return fmt.Errorf("invalid handoff frame size %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	return json.Unmarshal(payload, value)
}
