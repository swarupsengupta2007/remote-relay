package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
)

func startHeldClients(t *testing.T, n int, server, dest string) {
	t.Helper()
	for i := 0; i < n; i++ {
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		ccfg := config.DefaultClient()
		ccfg.Server = server
		ccfg.Destination = dest
		ccfg.Transport = "tcp"
		errc := make(chan error, 1)
		go func() {
			err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
			_ = outW.Close()
			errc <- err
		}()
		go func() { _, _ = io.Copy(io.Discard, outR) }()
		t.Cleanup(func() {
			_ = inW.Close()
			cancel()
			select {
			case <-errc:
			case <-time.After(2 * time.Second):
			}
		})
	}
}

func TestMaxSessionsRefusesHELLO(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.MaxSessions = 2
	cfg.MaxConnsPerIP = 8
	srv, addr, _ := startRelayCfg(t, cfg)

	startHeldClients(t, 2, addr, dest)
	waitUntil(t, 5*time.Second, func() bool { return srv.sessionCount() == 2 })

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ccfg := config.DefaultClient()
	ccfg.Server = addr
	ccfg.Destination = dest
	ccfg.Transport = "tcp"
	err := RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	if !errors.Is(err, proto.ErrNoCapacity) {
		t.Fatalf("got %v want ERR_NO_CAPACITY", err)
	}
	if srv.sessionCount() != 2 {
		t.Fatalf("existing sessions died, count=%d", srv.sessionCount())
	}
}

func TestMaxConnsPerIPRefusesNinth(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.MaxSessions = 1024
	cfg.MaxConnsPerIP = 8
	srv, addr, _ := startRelayCfg(t, cfg)

	startHeldClients(t, 8, addr, dest)
	waitUntil(t, 8*time.Second, func() bool { return srv.sessionCount() == 8 })

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ccfg := config.DefaultClient()
	ccfg.Server = addr
	ccfg.Destination = dest
	ccfg.Transport = "tcp"
	err := RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	if !errors.Is(err, proto.ErrNoCapacity) {
		t.Fatalf("9th connection: got %v want ERR_NO_CAPACITY", err)
	}
	if srv.sessionCount() != 8 {
		t.Fatalf("existing sessions died, count=%d", srv.sessionCount())
	}
}

func TestClientIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sc, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	ip := clientIP(sc.RemoteAddr())
	if ip != "127.0.0.1" && ip != "::1" {
		t.Fatalf("clientIP=%q", ip)
	}
	if clientIP(nil) != "" {
		t.Fatal("nil addr")
	}
}
