package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
)

func TestShutdownDrainsNoHang(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(30 * time.Second)
	srv, addr, _ := startRelayCfg(t, cfg)

	startHeldClients(t, 3, addr, dest)
	waitUntil(t, 5*time.Second, func() bool { return srv.sessionCount() == 3 })

	start := time.Now()
	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("Shutdown hung: %s", d)
	}
	waitUntil(t, 2*time.Second, func() bool { return srv.sessionCount() == 0 })
	if used := srv.budgetUsed(); used != 0 {
		t.Fatalf("buffers not released: %d", used)
	}
}

func TestServeCancelDrains(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(30 * time.Second)
	log := logging.New(io.Discard, "error", "text")
	srv := NewServer(cfg, log)
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })

	addr := srv.Addr()
	startHeldClients(t, 2, addr, dest)
	waitUntil(t, 5*time.Second, func() bool { return srv.sessionCount() == 2 })

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Serve hung after cancel (SIGTERM path)")
	}
	if srv.sessionCount() != 0 {
		t.Fatalf("sessions left: %d", srv.sessionCount())
	}
	if used := srv.budgetUsed(); used != 0 {
		t.Fatalf("buffers not released: %d", used)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, s.b.Len())
	copy(out, s.b.Bytes())
	return out
}

func TestShutdownWritesBye(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(30 * time.Second)
	srv, addr, _ := startRelayCfg(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, _, err := rawHello(ctx, addr, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitUntil(t, 5*time.Second, func() bool { return srv.sessionCount() == 1 })

	go func() {
		shutCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = srv.Shutdown(shutCtx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetDeadline(deadline)
		f, err := conn.ReadFrame()
		if err != nil {
			t.Fatalf("read after Shutdown: %v", err)
		}
		switch f.Type {
		case proto.TypeBye:
			var bye proto.Bye
			if err := proto.UnmarshalPayload(f, &bye); err != nil {
				t.Fatal(err)
			}
			if bye.Code != proto.CodeShutdown {
				t.Fatalf("BYE code %q want %s", bye.Code, proto.CodeShutdown)
			}
			return
		case proto.TypePing, proto.TypePong, proto.TypeAck, proto.TypeData:
			continue
		default:
			t.Fatalf("unexpected frame %s", f.Type)
		}
	}
	t.Fatal("no BYE{ERR_SHUTDOWN} on the wire")
}

func TestClientReturnsOnServerShutdown(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(30 * time.Second)
	srv, addr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	defer inW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ccfg := config.DefaultClient()
	ccfg.Server = addr
	ccfg.Destination = dest
	ccfg.Transport = "tcp"
	ccfg.ReconnectMaxElapsed = config.Duration(500 * time.Millisecond)
	ccfg.ReconnectBackoff = []string{"10ms"}
	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, ccfg, inR, io.Discard, logging.New(io.Discard, "error", "text"))
	}()
	waitUntil(t, 5*time.Second, func() bool { return srv.sessionCount() == 1 })

	shutCtx, scancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer scancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-errc:
	case <-ctx.Done():
		t.Fatal("RunClient hung after server Shutdown (stdin left open)")
	}
}

func TestShutdownUnblocksFullCtrlQ(t *testing.T) {
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destLn.Close() })
	go func() {
		c, err := destLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		chunk := bytes.Repeat([]byte("n"), 32*1024)
		for {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	}()

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = destLn.Addr().String()
	cfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	cfg.Transports = []string{"tcp"}
	cfg.BufferBytes = 64 * 1024
	cfg.TotalBufferBytes = 256 * 1024
	cfg.SendWindow = 256 * 1024
	cfg.DataChunkBytes = 1024
	cfg.KeepaliveInterval = config.Duration(time.Millisecond)
	cfg.IdleTimeout = config.Duration(time.Minute)
	cfg.HoldTimeout = config.Duration(30 * time.Second)
	srv, addr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	defer inW.Close()
	outR, outW := io.Pipe()
	t.Cleanup(func() { _ = outR.Close(); _ = outW.Close() })
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	ccfg := config.DefaultClient()
	ccfg.Server = addr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	go func() {
		_ = RunClient(cctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
	}()
	waitUntil(t, 5*time.Second, func() bool { return srv.sessionCount() == 1 })
	waitUntil(t, 3*time.Second, func() bool {
		return maxLens(srv.sessionBufferLens()) > 0 || srv.budgetUsed() > 0
	})
	time.Sleep(150 * time.Millisecond)

	start := time.Now()
	shutCtx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer scancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Shutdown hung with full ctrlQ/down path: %s", d)
	}
}

func TestStructuredLogsOmitSecrets(t *testing.T) {
	var buf syncBuffer
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.LogLevel = "info"
	cfg.LogFormat = "json"
	log := logging.New(&buf, "info", "json")
	srv := NewServer(cfg, log)
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
		}
	})

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	cctx, ccancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer ccancel()
	ccfg := config.DefaultClient()
	ccfg.Server = srv.Addr()
	ccfg.Destination = dest
	ccfg.Transport = "tcp"
	go func() {
		_ = RunClient(cctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
	}()
	go func() { _, _ = io.Copy(io.Discard, outR) }()
	waitUntil(t, 5*time.Second, func() bool { return srv.sessionCount() == 1 })
	_ = inW.Close()

	body := buf.Bytes()
	if bytes.Contains(body, []byte("resumeToken")) || bytes.Contains(body, []byte("ResumeToken")) {
		t.Fatalf("logs leaked resumeToken: %s", body)
	}
	if !bytes.Contains(body, []byte(`"sessionId"`)) {
		t.Fatalf("missing sessionId in logs: %s", body)
	}
}
