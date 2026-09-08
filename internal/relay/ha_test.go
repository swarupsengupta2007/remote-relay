package relay

import (
	"context"
	"crypto/sha256"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/transport"
)

func TestHAStrictUDPProbeFails(t *testing.T) {
	testDropUDPProbe.Store(true)
	t.Cleanup(func() { testDropUDPProbe.Store(false) })

	dest, _ := startBidiDest(t, 1024, 1024)
	_, relayAddr, _ := startRelayQUIC(t, dest)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer inW.Close()
	defer outR.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ccfg := defaultQUICClient(relayAddr, dest)
	ccfg.AllowHA = false
	ccfg.ProbeTimeout = config.Duration(50 * time.Millisecond)

	err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
	if err == nil {
		t.Fatal("expected error in strict mode when UDP probe fails, got nil")
	}
	if !strings.Contains(err.Error(), "udp route unavailable and --allow-ha not specified") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestHAStrictServerNoUDP(t *testing.T) {
	dest, _ := startBidiDest(t, 1024, 1024)
	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = dest
	scfg.AllowDestinations = []string{dest, "*"}
	scfg.Transports = []string{"tcp"} // TCP only, no UDP!
	_, relayAddr, _ := startRelayCfg(t, scfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer inW.Close()
	defer outR.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ccfg := defaultQUICClient(relayAddr, dest)
	ccfg.AllowHA = false

	err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
	if err == nil {
		t.Fatal("expected error in strict mode when server provides no UDP, got nil")
	}
	if !strings.Contains(err.Error(), "udp route unavailable and --allow-ha not specified") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestHAUpgradeSeamless(t *testing.T) {
	testDropUDPProbe.Store(true)
	t.Cleanup(func() { testDropUDPProbe.Store(false) })

	const n = 512 << 10
	upWant := makePattern(n)
	downWant := makePattern(n)
	upHash := sha256.Sum256(upWant)
	downHash := sha256.Sum256(downWant)

	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayQUIC(t, dest)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ccfg := defaultQUICClient(relayAddr, dest)
	ccfg.AllowHA = true
	ccfg.HAProbeInterval = config.Duration(100 * time.Millisecond)
	ccfg.ProbeTimeout = config.Duration(50 * time.Millisecond)

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "info", "text"))
		_ = outW.Close()
		errc <- err
	}()

	downCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		downCh <- b
	}()

	// Write first 128 KiB while UDP is blocked
	const firstChunk = 128 << 10
	if _, err := inW.Write(upWant[:firstChunk]); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}

	// Verify server initially serves on TCP
	waitUntil(t, 2*time.Second, func() bool {
		for _, k := range srv.liveKinds() {
			if k == transport.KindTCP {
				return true
			}
		}
		return false
	})

	// Now unblock UDP! The background prober should detect UDP and upgrade to QUIC!
	testDropUDPProbe.Store(false)

	// Verify server switches to QUIC
	waitKind(t, srv, transport.KindQUIC, 8*time.Second)

	// Stream the remaining data over QUIC
	go func() {
		defer inW.Close()
		_, _ = inW.Write(upWant[firstChunk:])
	}()

	gotDown := <-downCh
	gotUp := <-gotUpCh

	if err := <-errc; err != nil {
		t.Fatalf("client error: %v", err)
	}

	if got := sha256.Sum256(gotUp); got != upHash {
		t.Fatalf("upstream payload mismatch: got %x want %x (len %d vs %d)", got, upHash, len(gotUp), len(upWant))
	}
	if got := sha256.Sum256(gotDown); got != downHash {
		t.Fatalf("downstream payload mismatch: got %x want %x (len %d vs %d)", got, downHash, len(gotDown), len(downWant))
	}
}

func TestHADowngradeToTCP(t *testing.T) {
	const n = 512 << 10
	upWant := makePattern(n)
	downWant := makePattern(n)
	upHash := sha256.Sum256(upWant)
	downHash := sha256.Sum256(downWant)

	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayQUIC(t, dest)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ccfg := defaultQUICClient(relayAddr, dest)
	ccfg.AllowHA = true
	ccfg.HAProbeInterval = config.Duration(100 * time.Millisecond)
	ccfg.ProbeTimeout = config.Duration(50 * time.Millisecond)

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "info", "text"))
		_ = outW.Close()
		errc <- err
	}()

	downCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		downCh <- b
	}()

	// Wait until session is running on QUIC
	waitKind(t, srv, transport.KindQUIC, 8*time.Second)

	// Write first chunk on QUIC
	const head = 128 << 10
	if _, err := inW.Write(upWant[:head]); err != nil {
		t.Fatalf("write head: %v", err)
	}

	// Simulate UDP dropping: drop QUIC conn and prevent UDP probe from succeeding
	testDropUDPProbe.Store(true)
	t.Cleanup(func() { testDropUDPProbe.Store(false) })
	srv.dropLiveKind(transport.KindQUIC)

	// Wait for session to downgrade to TCP
	waitKind(t, srv, transport.KindTCP, 8*time.Second)

	// Finish writing the remainder on TCP
	go func() {
		defer inW.Close()
		_, _ = inW.Write(upWant[head:])
	}()

	gotDown := <-downCh
	gotUp := <-gotUpCh

	if err := <-errc; err != nil {
		t.Fatalf("client error: %v", err)
	}

	if got := sha256.Sum256(gotUp); got != upHash {
		t.Fatalf("upstream payload mismatch: got %x want %x (len %d vs %d)", got, upHash, len(gotUp), len(upWant))
	}
	if got := sha256.Sum256(gotDown); got != downHash {
		t.Fatalf("downstream payload mismatch: got %x want %x (len %d vs %d)", got, downHash, len(gotDown), len(downWant))
	}
}

func TestHAFlappingOscillate(t *testing.T) {
	const n = 1 << 20 // 1 MiB
	upWant := makePattern(n)
	downWant := makePattern(n)
	upHash := sha256.Sum256(upWant)
	downHash := sha256.Sum256(downWant)

	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayQUIC(t, dest)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	ccfg := defaultQUICClient(relayAddr, dest)
	ccfg.AllowHA = true
	ccfg.HAProbeInterval = config.Duration(80 * time.Millisecond)
	ccfg.ProbeTimeout = config.Duration(40 * time.Millisecond)

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "info", "text"))
		_ = outW.Close()
		errc <- err
	}()

	downCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		downCh <- b
	}()

	// 1. Initially connects on QUIC
	waitKind(t, srv, transport.KindQUIC, 8*time.Second)

	// Stream 256 KiB
	const chunk = 256 << 10
	offset := 0
	if _, err := inW.Write(upWant[offset : offset+chunk]); err != nil {
		t.Fatalf("write chunk 1: %v", err)
	}
	offset += chunk

	// 2. Drop UDP -> Downgrades to TCP
	testDropUDPProbe.Store(true)
	t.Cleanup(func() { testDropUDPProbe.Store(false) })
	srv.dropLiveKind(transport.KindQUIC)
	waitKind(t, srv, transport.KindTCP, 8*time.Second)

	// Stream 256 KiB on TCP
	if _, err := inW.Write(upWant[offset : offset+chunk]); err != nil {
		t.Fatalf("write chunk 2: %v", err)
	}
	offset += chunk

	// 3. Restore UDP -> Upgrades back to QUIC
	testDropUDPProbe.Store(false)
	waitKind(t, srv, transport.KindQUIC, 8*time.Second)

	// Stream 256 KiB on QUIC
	if _, err := inW.Write(upWant[offset : offset+chunk]); err != nil {
		t.Fatalf("write chunk 3: %v", err)
	}
	offset += chunk

	// 4. Drop UDP again -> Downgrades to TCP
	testDropUDPProbe.Store(true)
	srv.dropLiveKind(transport.KindQUIC)
	waitKind(t, srv, transport.KindTCP, 8*time.Second)

	// Finish remaining on TCP
	go func() {
		defer inW.Close()
		_, _ = inW.Write(upWant[offset:])
	}()

	gotDown := <-downCh
	gotUp := <-gotUpCh

	if err := <-errc; err != nil {
		t.Fatalf("client error: %v", err)
	}

	if got := sha256.Sum256(gotUp); got != upHash {
		t.Fatalf("upstream payload mismatch: got %x want %x (len %d vs %d)", got, upHash, len(gotUp), len(upWant))
	}
	if got := sha256.Sum256(gotDown); got != downHash {
		t.Fatalf("downstream payload mismatch: got %x want %x (len %d vs %d)", got, downHash, len(gotDown), len(downWant))
	}
}
