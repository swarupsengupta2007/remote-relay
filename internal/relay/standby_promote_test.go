package relay

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/bfd"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

func TestClientStandbyKeepsNonPingAndPromotes(t *testing.T) {
	sess := bfd.NewSessionWithDisc(bfd.Config{
		DesiredMinTxInterval:  30 * time.Second,
		RequiredMinRxInterval: 30 * time.Second,
		DetectMultiplier:      3,
	}, 0x11111111)
	if _, err := sess.Receive(bfd.Packet{
		State:                 bfd.StateUp,
		DetectMult:            3,
		MyDisc:                0x22222222,
		YourDisc:              0,
		DesiredMinTxInterval:  30 * time.Second,
		RequiredMinRxInterval: 30 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if !sess.IsUp() {
		t.Fatal("bfd session did not reach Up")
	}
	deadAfter := sess.DetectionTimeout()
	if deadAfter < time.Second {
		t.Fatalf("detection timeout %s is too short to prove immediate promotion", deadAfter)
	}

	in := make(chan proto.Frame, 4)
	out := make(chan proto.Frame, 4)
	conn := &mockFrameConn{in: in, out: out}

	gotData := make(chan struct{})
	cs := startClientStandby(t.Context(), conn, sess, nil, func() {
		close(gotData)
	})

	payload := []byte("standby-data-kept")
	start := time.Now()
	in <- proto.Frame{Type: proto.TypeData, Payload: payload}

	select {
	case <-gotData:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("non-ping frame was not promoted within 500ms (detection timeout %s)", deadAfter)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("promotion took %s, detection timeout is %s", elapsed, deadAfter)
	}

	promoted, promotedSess, frames, ok := cs.promote()
	if !ok {
		t.Fatal("promote returned false")
	}
	if promoted != conn {
		t.Fatal("promote did not return the standby conn")
	}
	if promotedSess != sess || !promotedSess.IsUp() {
		t.Fatal("promoted session is not the live BFD session")
	}
	if len(frames) != 1 || frames[0].Type != proto.TypeData || !bytes.Equal(frames[0].Payload, payload) {
		t.Fatalf("promoted frames = %+v, want data %q", frames, payload)
	}
}

func upBFDSession(t *testing.T) *bfd.Session {
	t.Helper()
	sess := bfd.NewSessionWithDisc(bfd.Config{
		DesiredMinTxInterval:  30 * time.Second,
		RequiredMinRxInterval: 30 * time.Second,
		DetectMultiplier:      3,
	}, 0x11111111)
	if _, err := sess.Receive(bfd.Packet{
		State:                 bfd.StateUp,
		DetectMult:            3,
		MyDisc:                0x22222222,
		DesiredMinTxInterval:  30 * time.Second,
		RequiredMinRxInterval: 30 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if !sess.IsUp() {
		t.Fatal("bfd session did not reach Up")
	}
	return sess
}

func tcpConnPair(t *testing.T) (transport.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peerc := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		peerc <- c
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.WrapTCP(raw)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-peerc
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	return conn, peer
}

func encodeFrames(t *testing.T, frames ...proto.Frame) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, f := range frames {
		if err := proto.WriteFrame(&b, f); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func dataFrame(seq uint64, s string) proto.Frame {
	return proto.Frame{Type: proto.TypeData, Payload: proto.EncodeData(seq, []byte(s))}
}

// The peer promotes and sends a burst; the standby reader takes the first
// frame and the rest are already in its read buffer. Promotion must leave
// them for the pump instead of discarding the buffer.
func TestClientStandbyPromotionKeepsBufferedFrames(t *testing.T) {
	conn, peer := tcpConnPair(t)
	gotData := make(chan struct{})
	cs := startClientStandby(t.Context(), conn, upBFDSession(t), nil, func() { close(gotData) })

	want := []proto.Frame{dataFrame(0, "one"), dataFrame(3, "two"), dataFrame(6, "three")}
	if _, err := peer.Write(encodeFrames(t, want...)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gotData:
	case <-time.After(2 * time.Second):
		t.Fatal("standby did not see the data frame")
	}
	promoted, _, prefetched, ok := cs.promote()
	if !ok {
		t.Fatal("promote returned false")
	}
	got := append([]proto.Frame(nil), prefetched...)
	_ = promoted.SetDeadline(time.Now().Add(2 * time.Second))
	for len(got) < len(want) {
		f, err := promoted.ReadFrame()
		if err != nil {
			t.Fatalf("after %d frames: %v", len(got), err)
		}
		got = append(got, f)
	}
	for i := range want {
		if got[i].Type != want[i].Type || !bytes.Equal(got[i].Payload, want[i].Payload) {
			t.Fatalf("frame %d = %v %q, want %v %q", i, got[i].Type, got[i].Payload, want[i].Type, want[i].Payload)
		}
	}
}

// Promotion while the reader is partway through a frame must not cut the
// frame short: the reader finishes it and the frame is handed over.
func TestClientStandbyPromotionMidFrame(t *testing.T) {
	conn, peer := tcpConnPair(t)
	cs := startClientStandby(t.Context(), conn, upBFDSession(t), nil, nil)

	wire := encodeFrames(t, dataFrame(0, "split-across-promotion"), dataFrame(22, "next"))
	if _, err := peer.Write(wire[:7]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // let the reader consume the header

	type result struct {
		conn       transport.Conn
		prefetched []proto.Frame
		ok         bool
	}
	done := make(chan result, 1)
	go func() {
		c, _, pf, ok := cs.promote()
		done <- result{c, pf, ok}
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := peer.Write(wire[7:]); err != nil {
		t.Fatal(err)
	}
	var r result
	select {
	case r = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("promote did not return")
	}
	if !r.ok {
		t.Fatal("promote returned false")
	}
	got := append([]proto.Frame(nil), r.prefetched...)
	_ = r.conn.SetDeadline(time.Now().Add(2 * time.Second))
	for len(got) < 2 {
		f, err := r.conn.ReadFrame()
		if err != nil {
			t.Fatalf("after %d frames: %v", len(got), err)
		}
		got = append(got, f)
	}
	want := []proto.Frame{dataFrame(0, "split-across-promotion"), dataFrame(22, "next")}
	for i := range want {
		if !bytes.Equal(got[i].Payload, want[i].Payload) {
			t.Fatalf("frame %d = %q, want %q", i, got[i].Payload, want[i].Payload)
		}
	}
}
