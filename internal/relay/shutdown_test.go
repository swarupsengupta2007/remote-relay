package relay

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
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
