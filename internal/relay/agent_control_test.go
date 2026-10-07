package relay

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

type pipeFrameConn struct {
	c  net.Conn
	br *bufio.Reader
	bw *bufio.Writer
}

func newPipeFrameConn(c net.Conn) *pipeFrameConn {
	return &pipeFrameConn{c: c, br: bufio.NewReader(c), bw: bufio.NewWriter(c)}
}

func (p *pipeFrameConn) ReadFrame() (proto.Frame, error) { return proto.ReadFrame(p.br) }
func (p *pipeFrameConn) WriteFrame(f proto.Frame) error {
	if err := proto.WriteFrame(p.bw, f); err != nil {
		return err
	}
	return p.bw.Flush()
}
func (p *pipeFrameConn) SetDeadline(t time.Time) error { return p.c.SetDeadline(t) }
func (p *pipeFrameConn) LocalAddr() net.Addr           { return p.c.LocalAddr() }
func (p *pipeFrameConn) RemoteAddr() net.Addr          { return p.c.RemoteAddr() }
func (p *pipeFrameConn) Kind() transport.Kind          { return transport.KindTCP }
func (p *pipeFrameConn) Close() error                  { return p.c.Close() }
func (p *pipeFrameConn) ResetReader()                  { p.br.Reset(p.c) }

func testAgentServer(t *testing.T, hb time.Duration) *Server {
	t.Helper()
	cfg := config.DefaultServer()
	cfg.HeartbeatInterval = config.Duration(hb)
	cfg.Splice = false
	return NewServer(cfg, logging.New(io.Discard, "error", "text"))
}

func TestSilentAgentControlDropsWithinTwoHeartbeats(t *testing.T) {
	const hb = 100 * time.Millisecond
	srv := testAgentServer(t, hb)
	defer srv.Close()

	serverSide, peer := net.Pipe()
	defer peer.Close()
	conn := newPipeFrameConn(serverSide)
	reg, err := srv.agentReg.Register("silent-lab", "fp", nil, "127.0.0.1:22", nil, nil, conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	go srv.runAgentControlLoop(ctx, conn, "silent-lab")

	time.Sleep(hb / 2)
	if !reg.IsConnected() {
		t.Fatal("silent agent was dropped before one heartbeat")
	}
	deadline := time.Now().Add(2*hb + 500*time.Millisecond)
	for time.Now().Before(deadline) {
		if !reg.IsConnected() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("silent agent still registered as healthy after 2 heartbeats")
}

func TestLiveAgentControlStaysRegistered(t *testing.T) {
	const hb = 100 * time.Millisecond
	srv := testAgentServer(t, hb)
	defer srv.Close()

	serverSide, peer := net.Pipe()
	defer peer.Close()
	conn := newPipeFrameConn(serverSide)
	reg, err := srv.agentReg.Register("live-lab", "fp", nil, "127.0.0.1:22", nil, nil, conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	go srv.runAgentControlLoop(ctx, conn, "live-lab")

	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		pr := bufio.NewReader(peer)
		ping := proto.Frame{Type: proto.TypePing, Payload: []byte("ping")}
		for {
			_ = peer.SetDeadline(time.Now().Add(time.Second))
			if err := proto.WriteFrame(peer, ping); err != nil {
				return
			}
			if _, err := proto.ReadFrame(pr); err != nil {
				return
			}
			time.Sleep(hb / 2)
		}
	}()

	time.Sleep(5 * hb)
	if !reg.IsConnected() {
		t.Fatal("agent that kept sending frames was dropped")
	}
	_ = peer.Close()
	<-peerDone
}

func TestAgentBindDuringSilentReadStillDrops(t *testing.T) {
	const hb = 100 * time.Millisecond
	srv := testAgentServer(t, hb)
	defer srv.Close()

	serverSide, peer := net.Pipe()
	defer peer.Close()
	conn := newPipeFrameConn(serverSide)
	reg, err := srv.agentReg.Register("bind-silent", "fp", nil, "127.0.0.1:22", nil, nil, conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	go srv.runAgentControlLoop(ctx, conn, "bind-silent")

	// Let the control loop block in Read with the idle deadline armed.
	time.Sleep(hb / 2)
	if !reg.IsConnected() {
		t.Fatal("silent agent was dropped before bind")
	}

	readDone := make(chan error, 1)
	go func() {
		pr := bufio.NewReader(peer)
		_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
		_, readErr := proto.ReadFrame(pr)
		readDone <- readErr
	}()

	_, clientPipe, err := srv.agentReg.CreateBind("bind-silent", "127.0.0.1:9", "192.0.2.10", serverSide.RemoteAddr())
	if err != nil {
		t.Fatalf("CreateBind: %v", err)
	}
	defer clientPipe.Close()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("peer did not accept bind frame: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bind frame")
	}

	if !reg.IsConnected() {
		t.Fatal("bind write disconnected the agent immediately")
	}
	deadline := time.Now().Add(2*hb + 500*time.Millisecond)
	for time.Now().Before(deadline) {
		if !reg.IsConnected() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("silent agent stayed healthy after AgentBind")
}
