package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"collector/internal/spool"
	"collector/internal/store"

	"github.com/google/uuid"
)

type fakeDeviceResolver struct {
	devices map[string]uuid.UUID
}

func (r fakeDeviceResolver) DeviceBySourceIP(_ context.Context, sourceIP string) (uuid.UUID, error) {
	if id, ok := r.devices[sourceIP]; ok {
		return id, nil
	}
	return uuid.Nil, store.ErrNotFound
}

func TestHandoffPreservesSourceAndIsolatesDevices(t *testing.T) {
	directory := t.TempDir()
	ingressQueue, err := spool.Open(filepath.Join(directory, "ingress.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ingressQueue.Close()
	appQueue, err := spool.Open(filepath.Join(directory, "syslog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer appQueue.Close()

	firstDevice, secondDevice := uuid.New(), uuid.New()
	resolver := fakeDeviceResolver{devices: map[string]uuid.UUID{
		"5.227.161.181": firstDevice,
		"5.227.161.188": secondDevice,
	}}
	now := time.Now().UTC()
	datagrams := []IngressDatagram{
		{EventID: uuid.New(), ReceivedAt: now, SourceIP: "5.227.161.181", SourcePort: 10003, Payload: []byte("SIP")},
		{EventID: uuid.New(), ReceivedAt: now.Add(time.Nanosecond), SourceIP: "5.227.161.188", SourcePort: 514, Payload: []byte("WEBS")},
		{EventID: uuid.New(), ReceivedAt: now.Add(2 * time.Nanosecond), SourceIP: "203.0.113.10", SourcePort: 9999, Payload: []byte("unknown")},
	}
	enqueueIngressDatagrams(t, ingressQueue, datagrams)

	socketPath := filepath.Join(directory, "handoff.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	receiverErrors := make(chan error, 1)
	go func() {
		receiverErrors <- RunHandoffReceiver(ctx, socketPath, resolver, appQueue, &Metrics{})
	}()
	waitFor(t, 2*time.Second, func() bool {
		_, err := os.Stat(socketPath)
		return err == nil
	})
	publisherMetrics := &Metrics{}
	publisherErrors := make(chan error, 1)
	go func() {
		publisherErrors <- RunIngressHandoffPublisher(ctx, ingressQueue, socketPath, publisherMetrics)
	}()
	waitFor(t, 3*time.Second, func() bool {
		ingressDepth, _ := ingressQueue.Depth()
		appDepth, _ := appQueue.Depth()
		return ingressDepth == 0 && appDepth == 2
	})

	items, err := appQueue.Peek(10)
	if err != nil {
		t.Fatal(err)
	}
	records := make(map[string]RawSyslog)
	for _, item := range items {
		var raw RawSyslog
		if err := json.Unmarshal(item.Data, &raw); err != nil {
			t.Fatal(err)
		}
		records[raw.SourceIP] = raw
	}
	if records["5.227.161.181"].DeviceID != firstDevice ||
		records["5.227.161.181"].SourcePort != 10003 ||
		string(records["5.227.161.181"].Payload) != "SIP" {
		t.Fatalf("first device metadata changed: %#v", records["5.227.161.181"])
	}
	if records["5.227.161.188"].DeviceID != secondDevice ||
		records["5.227.161.188"].SourcePort != 514 {
		t.Fatalf("second device was mixed: %#v", records["5.227.161.188"])
	}
	if snapshot := publisherMetrics.Snapshot(); snapshot.HandedOff != 3 {
		t.Fatalf("got %d completed handoffs, want 3", snapshot.HandedOff)
	}
	cancel()
	assertStopped(t, receiverErrors)
	assertStopped(t, publisherErrors)
}

func TestHandoffRetainsSpoolUntilAppReturns(t *testing.T) {
	directory := t.TempDir()
	ingressQueue, err := spool.Open(filepath.Join(directory, "ingress.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ingressQueue.Close()
	appQueue, err := spool.Open(filepath.Join(directory, "syslog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer appQueue.Close()
	deviceID := uuid.New()
	datagram := IngressDatagram{
		EventID: uuid.New(), ReceivedAt: time.Now().UTC(), SourceIP: "5.227.161.181",
		SourcePort: 10003, Payload: []byte("RADIUS"),
	}
	enqueueIngressDatagrams(t, ingressQueue, []IngressDatagram{datagram})

	socketPath := filepath.Join(directory, "handoff.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metrics := &Metrics{}
	publisherErrors := make(chan error, 1)
	go func() {
		publisherErrors <- RunIngressHandoffPublisher(ctx, ingressQueue, socketPath, metrics)
	}()
	waitFor(t, 2*time.Second, func() bool {
		return metrics.Snapshot().HandoffErrors > 0
	})
	if depth, _ := ingressQueue.Depth(); depth != 1 {
		t.Fatalf("ingress item was deleted while app was down: %d", depth)
	}

	receiverErrors := make(chan error, 1)
	go func() {
		receiverErrors <- RunHandoffReceiver(ctx, socketPath,
			fakeDeviceResolver{devices: map[string]uuid.UUID{"5.227.161.181": deviceID}},
			appQueue, &Metrics{})
	}()
	waitFor(t, 3*time.Second, func() bool {
		ingressDepth, _ := ingressQueue.Depth()
		appDepth, _ := appQueue.Depth()
		return ingressDepth == 0 && appDepth == 1
	})
	cancel()
	assertStopped(t, receiverErrors)
	assertStopped(t, publisherErrors)
}

func enqueueIngressDatagrams(t *testing.T, queue *spool.Queue, datagrams []IngressDatagram) {
	t.Helper()
	entries := make([]spool.Entry, 0, len(datagrams))
	for _, datagram := range datagrams {
		payload, err := json.Marshal(datagram)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, spool.Entry{
			ReceivedAt: datagram.ReceivedAt, EventID: datagram.EventID.String(), Payload: payload,
		})
	}
	if err := queue.EnqueueBatch(entries); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func assertStopped(t *testing.T, errorsChannel <-chan error) {
	t.Helper()
	select {
	case err := <-errorsChannel:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine did not stop")
	}
}
