package ingest

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"collector/internal/spool"
)

func TestIngressReceiverPersistsOriginalUDPPeer(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	probe.Close()

	queue, err := spool.Open(filepath.Join(t.TempDir(), "ingress.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	receiverErrors := make(chan error, 1)
	go func() {
		receiverErrors <- (&IngressReceiver{Addr: address, Spool: queue, Metrics: &Metrics{}}).Run(ctx)
	}()

	remote, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	senderPort := uint16(sender.LocalAddr().(*net.UDPAddr).Port)
	waitFor(t, 2*time.Second, func() bool {
		_, _ = sender.Write([]byte("<14> original source"))
		depth, _ := queue.Depth()
		return depth > 0
	})
	items, err := queue.Peek(1)
	if err != nil {
		t.Fatal(err)
	}
	var datagram IngressDatagram
	if err := json.Unmarshal(items[0].Data, &datagram); err != nil {
		t.Fatal(err)
	}
	if datagram.SourceIP != "127.0.0.1" || datagram.SourcePort != senderPort ||
		string(datagram.Payload) != "<14> original source" {
		t.Fatalf("UDP peer metadata changed: %#v", datagram)
	}
	cancel()
	assertStopped(t, receiverErrors)
}
