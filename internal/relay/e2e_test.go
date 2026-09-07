package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
)

const recordSize = 16

func makePattern(n int) []byte {
	b := make([]byte, n)
	var counter uint64
	for off := 0; off < n; off += recordSize {
		var rec [recordSize]byte
		binary.BigEndian.PutUint64(rec[0:8], uint64(off))
		binary.BigEndian.PutUint64(rec[8:16], counter)
		end := off + recordSize
		if end > n {
			end = n
		}
		copy(b[off:end], rec[:end-off])
		counter++
	}
	return b
}

func checkPattern(t *testing.T, b []byte) {
	t.Helper()
	want := makePattern(len(b))
	if bytes.Equal(b, want) {
		return
	}
	n := len(b)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		if b[i] != want[i] {
			rec := i / recordSize * recordSize
			t.Fatalf("pattern mismatch at byte %d (record %d): got 0x%02x want 0x%02x", i, rec, b[i], want[i])
		}
	}
	t.Fatalf("pattern length mismatch got=%d want=%d", len(b), len(want))
}

func startRelay(t *testing.T, dest string) (*Server, string, context.CancelFunc) {
	t.Helper()
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.LogLevel = "error"
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	return startRelayCfg(t, cfg)
}

func startRelayCfg(t *testing.T, cfg config.Server) (*Server, string, context.CancelFunc) {
	t.Helper()
	log := logging.New(io.Discard, "error", "text")
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
	addr := srv.Addr()
	if addr == "" {
		t.Fatal("empty listen addr")
	}
	return srv, addr, cancel
}

func runClientTo(t *testing.T, server, dest string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ccfg := config.DefaultClient()
	ccfg.Server = server
	ccfg.Destination = dest
	ccfg.Transport = "tcp"
	log := logging.New(io.Discard, "error", "text")
	return RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, log)
}

func TestE2EByteExactBothDirections(t *testing.T) {
	const n = 1 << 20 // 1 MiB

	upWant := makePattern(n)
	downWant := makePattern(n)
	upHash := sha256.Sum256(upWant)
	downHash := sha256.Sum256(downWant)

	gotUpCh := make(chan []byte, 1)
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	go func() {
		c, err := destLn.Accept()
		if err != nil {
			gotUpCh <- nil
			return
		}
		defer c.Close()
		tc := c.(*net.TCPConn)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = tc.Write(downWant)
			_ = tc.CloseWrite()
		}()
		go func() {
			defer wg.Done()
			b, _ := io.ReadAll(tc)
			gotUpCh <- b
		}()
		wg.Wait()
	}()

	_, relayAddr, _ := startRelay(t, destLn.Addr().String())

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := config.DefaultClient()
	cfg.Server = relayAddr
	cfg.Destination = destLn.Addr().String()
	cfg.Transport = "tcp"
	cfg.LogLevel = "error"
	log := logging.New(io.Discard, "error", "text")

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, cfg, inR, outW, log)
		_ = outW.Close()
		errc <- err
	}()

	var gotDown []byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer inW.Close()
		if _, err := inW.Write(upWant); err != nil {
			t.Errorf("stdin write: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		b, err := io.ReadAll(outR)
		if err != nil {
			t.Errorf("stdout read: %v", err)
		}
		gotDown = b
	}()
	wg.Wait()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("client: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for client")
	}

	var gotUp []byte
	select {
	case gotUp = <-gotUpCh:
	case <-ctx.Done():
		t.Fatal("timeout waiting for dest")
	}

	if len(gotUp) != n {
		t.Fatalf("up len=%d want %d", len(gotUp), n)
	}
	if len(gotDown) != n {
		t.Fatalf("down len=%d want %d", len(gotDown), n)
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
	if sha256.Sum256(gotUp) != upHash {
		t.Fatal("up SHA-256 mismatch")
	}
	if sha256.Sum256(gotDown) != downHash {
		t.Fatal("down SHA-256 mismatch")
	}
}

func TestHalfClose(t *testing.T) {
	const downN = 256 << 10
	downWant := makePattern(downN)
	upWant := []byte("hello-up")

	upEOF := make(chan []byte, 1)
	downStarted := make(chan struct{})

	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	go func() {
		c, err := destLn.Accept()
		if err != nil {
			upEOF <- nil
			return
		}
		defer c.Close()
		tc := c.(*net.TCPConn)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			close(downStarted)
			_, _ = tc.Write(downWant)
			_ = tc.CloseWrite()
		}()
		go func() {
			defer wg.Done()
			b, _ := io.ReadAll(tc)
			upEOF <- b
		}()
		wg.Wait()
	}()

	_, relayAddr, _ := startRelay(t, destLn.Addr().String())

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cfg := config.DefaultClient()
	cfg.Server = relayAddr
	cfg.Destination = destLn.Addr().String()
	cfg.Transport = "tcp"
	log := logging.New(io.Discard, "error", "text")

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, cfg, inR, outW, log)
		_ = outW.Close()
		errc <- err
	}()

	downCh := make(chan []byte, 1)
	go func() {
		b, err := io.ReadAll(outR)
		if err != nil {
			t.Errorf("stdout read: %v", err)
		}
		downCh <- b
	}()

	select {
	case <-downStarted:
	case <-ctx.Done():
		t.Fatal("dest did not start writing")
	}

	if _, err := inW.Write(upWant); err != nil {
		t.Fatal(err)
	}
	if err := inW.Close(); err != nil {
		t.Fatal(err)
	}

	var gotDown []byte
	select {
	case gotDown = <-downCh:
	case <-ctx.Done():
		t.Fatal("timeout reading stdout")
	}

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("client: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}

	var gotUp []byte
	select {
	case gotUp = <-upEOF:
	case <-ctx.Done():
		t.Fatal("dest did not see EOF")
	}
	if !bytes.Equal(gotUp, upWant) {
		t.Fatalf("dest got %q want %q", gotUp, upWant)
	}
	if len(gotDown) != downN {
		t.Fatalf("down truncated: got %d want %d", len(gotDown), downN)
	}
	checkPattern(t, gotDown)
}

func TestDestForbidden(t *testing.T) {
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.AllowDestinations = []string{"127.0.0.1:22"}
	cfg.DefaultDestination = "127.0.0.1:22"
	cfg.Transports = []string{"tcp"}
	_, addr, _ := startRelayCfg(t, cfg)

	err := runClientTo(t, addr, "127.0.0.1:1")
	if !errors.Is(err, proto.ErrDestForbidden) {
		t.Fatalf("got %v, want ERR_DEST_FORBIDDEN", err)
	}
}

func TestDestRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dest := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.AllowDestinations = []string{dest}
	cfg.DefaultDestination = dest
	cfg.Transports = []string{"tcp"}
	cfg.DialTimeout = config.Duration(2 * time.Second)
	_, addr, _ := startRelayCfg(t, cfg)

	err = runClientTo(t, addr, dest)
	if !errors.Is(err, proto.ErrDestRefused) {
		t.Fatalf("got %v, want ERR_DEST_REFUSED", err)
	}
}

func TestDestRefusedDialTimeout(t *testing.T) {
	// TEST-NET-1 is not on the loopback; connect waits until DialTimeout.
	const blackhole = "192.0.2.1:1"
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.AllowDestinations = []string{blackhole}
	cfg.DefaultDestination = blackhole
	cfg.Transports = []string{"tcp"}
	cfg.DialTimeout = config.Duration(300 * time.Millisecond)
	_, addr, _ := startRelayCfg(t, cfg)

	start := time.Now()
	err := runClientTo(t, addr, blackhole)
	if !errors.Is(err, proto.ErrDestRefused) {
		t.Fatalf("got %v, want ERR_DEST_REFUSED (not a handshake I/O timeout)", err)
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Fatalf("dial failed too quickly to be a timeout: %s", time.Since(start))
	}
}

func TestClampChunk(t *testing.T) {
	if got := clampChunk(0); got != 65536 {
		t.Fatalf("zero: %d", got)
	}
	if got := clampChunk(-1); got != 65536 {
		t.Fatalf("neg: %d", got)
	}
	if got := clampChunk(1024); got != 1024 {
		t.Fatalf("ok: %d", got)
	}
	if got := clampChunk(proto.MaxFrameLen); got != proto.MaxFrameLen-8 {
		t.Fatalf("oversize: %d", got)
	}
}
