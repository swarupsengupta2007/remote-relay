//go:build linux

package relay

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a.(*net.TCPConn), b.(*net.TCPConn)
}

// TestSpliceCarrierResetMidFrameCountsDelivered cuts a DATA frame part way
// through the splice. The bytes already in the sink must count as delivered,
// or resume retransmits them and the sink receives them twice.
func TestSpliceCarrierResetMidFrameCountsDelivered(t *testing.T) {
	destRelay, destPeer := tcpPair(t)
	carrierPeer, carrierRelay := tcpPair(t)
	go func() { _, _ = io.Copy(io.Discard, carrierPeer) }()

	srcR, srcW := io.Pipe()
	defer srcW.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newPump(ctx, sessionIO{
		src:     srcR,
		sink:    destRelay,
		rawSink: destRelay,
		outDir:  proto.DirDown,
		inDir:   proto.DirUp,
	}, pumpConfig{
		chunk:         32 << 10,
		heartbeat:     time.Second,
		deadThreshold: 3,
		splice:        true,
		log:           logging.New(io.Discard, "error", "text"),
	}, nil)
	defer p.shutdown()
	p.startIO()

	conn, err := transport.WrapTCP(carrierRelay)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- p.serveConn(ctx, conn, 0) }()

	const frameData = 64 << 10
	const sent = 20000
	hdr := make([]byte, 5+8)
	hdr[0] = byte(proto.TypeData)
	binary.BigEndian.PutUint32(hdr[1:5], uint32(8+frameData))
	binary.BigEndian.PutUint64(hdr[5:], 0)
	if _, err := carrierPeer.Write(hdr); err != nil {
		t.Fatal(err)
	}
	// Let the relay take the splice path for this frame before the data lands.
	time.Sleep(50 * time.Millisecond)
	body := make([]byte, sent)
	for i := range body {
		body[i] = byte(i)
	}
	if _, err := carrierPeer.Write(body); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, sent)
	_ = destPeer.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(destPeer, got); err != nil {
		t.Fatalf("sink read: %v", err)
	}
	_ = carrierPeer.SetLinger(0)
	_ = carrierPeer.Close()

	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("serveConn did not end after carrier reset")
	}
	if e := p.expected.Load(); e != sent {
		t.Fatalf("expected offset %d after mid-frame reset, want %d", e, sent)
	}
	if d := p.delivered.Load(); d != sent {
		t.Fatalf("delivered %d after mid-frame reset, want %d", d, sent)
	}
}
