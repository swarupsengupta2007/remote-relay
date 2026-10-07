package transport

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

// dropPacketConn pretends UDP writes succeeded once drop is set, so the
// session's send buffer retransmits without the peer ever ACKing them.
type dropPacketConn struct {
	net.PacketConn
	drop atomic.Bool
}

func (d *dropPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if d.drop.Load() {
		return len(p), nil
	}
	return d.PacketConn.WriteTo(p, addr)
}

func TestKCPLossIsIsolatedPerSession(t *testing.T) {
	srvMux, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvMux.Close()
	ln, err := ListenKCP(srvMux.KCP())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	readErr := make(chan error, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				readErr <- err
				return
			}
			go func(c Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_, err := c.ReadFrame()
				readErr <- err
			}(c)
		}
	}()

	rawA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rawA.Close()
	dropA := &dropPacketConn{PacketConn: rawA}
	cliMuxA := NewUDPMux(dropA)
	defer cliMuxA.Close()

	cliMuxB, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cliMuxB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	connA, err := DialKCP(ctx, cliMuxA.KCP(), srvMux.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	connB, err := DialKCP(ctx, cliMuxB.KCP(), srvMux.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()

	hello := proto.Frame{Type: proto.TypePing, Payload: []byte("hello-both")}
	if err := connA.WriteFrame(hello); err != nil {
		t.Fatal(err)
	}
	if err := connB.WriteFrame(hello); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := <-readErr; err != nil {
			t.Fatalf("server read: %v", err)
		}
	}

	tunerA := connA.(*kcpConn).Tuner()
	tunerB := connB.(*kcpConn).Tuner()
	if tunerA == nil || tunerB == nil {
		t.Fatal("expected default adaptive tuners")
	}
	waitUntilState(t, tunerA, StateLowLoss, 2*time.Second)
	waitUntilState(t, tunerB, StateLowLoss, 2*time.Second)

	dropA.drop.Store(true)
	go func() {
		payload := proto.Frame{Type: proto.TypeData, Payload: bytesRepeat(1200)}
		for i := 0; i < 8; i++ {
			_ = connA.SetDeadline(time.Now().Add(200 * time.Millisecond))
			_ = connA.WriteFrame(payload)
		}
	}()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if tunerA.Stats().State == StateHighLoss {
			if got := tunerB.Stats().State; got != StateLowLoss {
				t.Fatalf("session B left low_loss for %s when only session A dropped", got)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("session A stayed in %s (loss %v); session B is %s",
		tunerA.Stats().State, tunerA.Stats().MovingLossRate, tunerB.Stats().State)
}

func waitUntilState(t *testing.T, tuner *AdaptiveTuner, want TunerState, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if tuner.Stats().State == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("tuner state %s, want %s", tuner.Stats().State, want)
}

func bytesRepeat(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}
