package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"math/rand/v2"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/transport"
)

func startEchoDest(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				_, _ = io.CopyBuffer(c, c, buf)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func dropRandomLives(s *Server, frac float64) {
	s.livesMu.Lock()
	lives := make([]*live, 0, len(s.lives))
	for _, l := range s.lives {
		lives = append(lives, l)
	}
	s.livesMu.Unlock()
	for _, l := range lives {
		if rand.Float64() < frac {
			l.dropConn()
		}
	}
}

func TestConcurrency64SessionsLeak(t *testing.T) {
	runtime.GC()
	base := runtime.NumGoroutine()

	dest := startEchoDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.UDPListen = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"quic", "kcp"}
	cfg.MaxSessions = 128
	cfg.MaxConnsPerIP = 128
	cfg.BufferBytes = 1 << 20
	cfg.TotalBufferBytes = 64 << 20
	cfg.SendWindow = 64 << 10
	cfg.DataChunkBytes = 1024
	cfg.HoldTimeout = config.Duration(30 * time.Second)
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.KeepaliveInterval = config.Duration(2 * time.Second)
	cfg.ProbeTimeout = config.Duration(400 * time.Millisecond)
	cfg.ProbeAttempts = 2
	cfg.SwitchTimeout = config.Duration(5 * time.Second)
	cfg.LogLevel = "error"
	srv, relayAddr, cancelServe := startRelayCfg(t, cfg)

	const (
		nSessions = 64
		payload   = 32 << 10
		chunk     = 1024
		traffic   = 10 * time.Second
	)
	upWant := makePattern(payload)

	var wg sync.WaitGroup
	var fail atomic.Int32
	gotOK := make([][]byte, nSessions)

	// KCP is too heavy at this concurrency with random kills (sessions
	// expire instead of resuming). Mix TCP + QUIC on the shared UDP mux.
	for i := 0; i < nSessions; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			inR, inW := io.Pipe()
			outR, outW := io.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			ccfg := config.DefaultClient()
			ccfg.Server = relayAddr
			ccfg.Destination = dest
			ccfg.ReconnectMaxElapsed = config.Duration(20 * time.Second)
			ccfg.ReconnectBackoff = []string{"20ms", "50ms", "100ms", "200ms"}
			ccfg.ProbeTimeout = config.Duration(400 * time.Millisecond)
			ccfg.BufferBytes = 1 << 20
			ccfg.SendWindow = 64 << 10
			ccfg.IdleTimeout = config.Duration(30 * time.Second)
			ccfg.KeepaliveInterval = config.Duration(2 * time.Second)
			if i%2 == 0 {
				ccfg.Transport = "quic"
			} else {
				ccfg.Transport = "tcp"
			}
			errc := make(chan error, 1)
			go func() {
				err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
				_ = outW.Close()
				errc <- err
			}()

			var readBuf bytes.Buffer
			readDone := make(chan error, 1)
			go func() {
				_, err := io.Copy(&readBuf, outR)
				readDone <- err
			}()

			deadline := time.Now().Add(traffic)
			off := 0
			for off < len(upWant) {
				n := chunk
				if off+n > len(upWant) {
					n = len(upWant) - off
				}
				if _, err := inW.Write(upWant[off : off+n]); err != nil {
					fail.Add(1)
					t.Errorf("session %d write: %v", i, err)
					_ = inW.Close()
					return
				}
				off += n
				if time.Now().Before(deadline) {
					time.Sleep(traffic / time.Duration(payload/chunk))
				}
			}
			_ = inW.Close()

			select {
			case err := <-errc:
				if err != nil {
					fail.Add(1)
					t.Errorf("session %d client: %v", i, err)
				}
			case <-ctx.Done():
				fail.Add(1)
				t.Errorf("session %d timeout", i)
			}
			<-readDone
			gotOK[i] = readBuf.Bytes()
		}()
	}

	waitUntil(t, 15*time.Second, func() bool { return srv.sessionCount() == nSessions })

	killDone := make(chan struct{})
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-killDone:
				return
			case <-tick.C:
				dropRandomLives(srv, 0.3)
			}
		}
	}()

	wg.Wait()
	close(killDone)

	if fail.Load() != 0 {
		t.Fatalf("%d sessions failed", fail.Load())
	}
	for i, got := range gotOK {
		if !bytes.Equal(got, upWant) {
			t.Errorf("session %d byte mismatch got=%d want=%d", i, len(got), len(upWant))
			if len(got) == len(upWant) {
				checkPattern(t, got)
			}
		}
	}

	waitUntil(t, 8*time.Second, func() bool { return srv.sessionCount() == 0 })
	if used := srv.budgetUsed(); used != 0 {
		t.Fatalf("buffer leak: %d", used)
	}

	kinds := 0
	for _, p := range srv.pathHistory() {
		if p.Kind == transport.KindQUIC || p.Kind == transport.KindKCP {
			kinds++
		}
	}
	if kinds == 0 {
		t.Log("warning: no QUIC/KCP in path history (stayed on TCP)")
	}

	cancelServe()
	_ = srv.Close()

	deadline := time.Now().Add(4 * time.Second)
	var got int
	for {
		runtime.GC()
		got = runtime.NumGoroutine()
		if got <= base+32 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got > base+32 {
		t.Fatalf("goroutine leak: baseline=%d now=%d", base, got)
	}
}
