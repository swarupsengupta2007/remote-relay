package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/transport"
)

func startRelayQUIC(t *testing.T, dest string) (*Server, string, context.CancelFunc) {
	t.Helper()
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.UDPListen = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"quic"}
	cfg.LogLevel = "error"
	cfg.ProbeTimeout = config.Duration(400 * time.Millisecond)
	cfg.ProbeAttempts = 2
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.HoldTimeout = config.Duration(30 * time.Second)
	cfg.KeepaliveInterval = config.Duration(5 * time.Second)
	cfg.SwitchTimeout = config.Duration(5 * time.Second)
	return startRelayCfg(t, cfg)
}

func defaultQUICClient(server, dest string) config.Client {
	ccfg := config.DefaultClient()
	ccfg.Server = server
	ccfg.Destination = dest
	ccfg.Transport = "quic"
	ccfg.LogLevel = "error"
	ccfg.ReconnectMaxElapsed = config.Duration(20 * time.Second)
	ccfg.ReconnectBackoff = []string{"20ms", "50ms", "100ms"}
	ccfg.ProbeTimeout = config.Duration(400 * time.Millisecond)
	return ccfg
}

func startBidiDest(t *testing.T, upN, downN int) (dest string, gotUp <-chan []byte) {
	t.Helper()
	downWant := makePattern(downN)
	ch := make(chan []byte, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- nil
			return
		}
		t.Cleanup(func() { _ = c.Close() })
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
			ch <- b
		}()
		wg.Wait()
	}()
	return ln.Addr().String(), ch
}

func waitKind(t *testing.T, srv *Server, k transport.Kind, d time.Duration) {
	t.Helper()
	waitUntil(t, d, func() bool {
		for _, got := range srv.liveKinds() {
			if got == k {
				return true
			}
		}
		return false
	})
}

func TestDefaultPathIsQUIC(t *testing.T) {
	const n = 256 << 10
	upWant := makePattern(n)
	downWant := makePattern(n)
	upHash := sha256.Sum256(upWant)
	downHash := sha256.Sum256(downWant)

	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayQUIC(t, dest)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ccfg := defaultQUICClient(relayAddr, dest)
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()

	waitKind(t, srv, transport.KindQUIC, 8*time.Second)

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
	if len(gotUp) != n || len(gotDown) != n {
		t.Fatalf("up=%d down=%d want %d", len(gotUp), len(gotDown), n)
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
	if sha256.Sum256(gotUp) != upHash || sha256.Sum256(gotDown) != downHash {
		t.Fatal("SHA-256 mismatch")
	}
	sawQUIC := false
	for _, p := range srv.pathHistory() {
		if p.Kind == transport.KindQUIC {
			sawQUIC = true
		}
	}
	if !sawQUIC {
		t.Fatalf("path history never QUIC: %v", srv.pathHistory())
	}
}

func TestProbeFailureStaysTCP(t *testing.T) {
	const n = 64 << 10
	upWant := makePattern(n)

	dest, gotUpCh := startBidiDest(t, n, n)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.UDPListen = "127.0.0.1:0"
	cfg.UDPAnnounce = "127.0.0.1:1"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"quic"}
	cfg.ProbeTimeout = config.Duration(150 * time.Millisecond)
	cfg.ProbeAttempts = 2
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.HoldTimeout = config.Duration(15 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ccfg := defaultQUICClient(relayAddr, dest)
	ccfg.AllowHA = true
	ccfg.ProbeTimeout = config.Duration(150 * time.Millisecond)
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()

	time.Sleep(500 * time.Millisecond)
	for _, k := range srv.liveKinds() {
		if k == transport.KindQUIC {
			t.Fatal("probe should have failed; session upgraded to QUIC")
		}
	}

	var gotDown []byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer inW.Close()
		if _, err := inW.Write(upWant); err != nil {
			t.Errorf("stdin: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		b, _ := io.ReadAll(outR)
		gotDown = b
	}()
	wg.Wait()
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
	case gotUp = <-gotUpCh:
	case <-ctx.Done():
		t.Fatal("dest timeout")
	}
	if len(gotUp) != n || len(gotDown) != n {
		t.Fatalf("up=%d down=%d want %d", len(gotUp), len(gotDown), n)
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
	for _, p := range srv.pathHistory() {
		if p.Kind == transport.KindQUIC {
			t.Fatalf("unexpected QUIC path: %v", srv.pathHistory())
		}
	}
}

func runKillUDP(t *testing.T, n int, afterDrop func(srv *Server)) []pathInfo {
	t.Helper()
	upWant := makePattern(n)
	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayQUIC(t, dest)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	ccfg := defaultQUICClient(relayAddr, dest)
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()

	downCh := make(chan []byte, 1)
	go func() {
		b, err := io.ReadAll(outR)
		if err != nil {
			t.Errorf("stdout: %v", err)
		}
		downCh <- b
	}()

	waitKind(t, srv, transport.KindQUIC, 8*time.Second)
	const head = 64 * 1024
	if _, err := inW.Write(upWant[:head]); err != nil {
		t.Fatal(err)
	}
	srv.dropLiveKind(transport.KindQUIC)
	if afterDrop != nil {
		afterDrop(srv)
	}
	go func() {
		defer inW.Close()
		if _, err := inW.Write(upWant[head:]); err != nil {
			t.Errorf("stdin write: %v", err)
		}
	}()
	var gotDown []byte
	select {
	case gotDown = <-downCh:
	case <-ctx.Done():
		t.Fatal("timeout reading stdout")
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("client: %v hist=%v", err, srv.pathHistory())
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
	if len(gotUp) != n || len(gotDown) != n {
		t.Fatalf("up=%d down=%d want %d hist=%v", len(gotUp), len(gotDown), n, srv.pathHistory())
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
	if sha256.Sum256(gotUp) != sha256.Sum256(upWant) || sha256.Sum256(gotDown) != sha256.Sum256(makePattern(n)) {
		t.Fatal("SHA-256 mismatch")
	}
	return srv.pathHistory()
}

func TestKillUDPResumeByteExact(t *testing.T) {
	hist := runKillUDP(t, 1<<20, nil)
	sawQUIC, sawTCPAfter := false, false
	for _, p := range hist {
		if p.Kind == transport.KindQUIC {
			sawQUIC = true
		}
		if sawQUIC && p.Kind == transport.KindTCP {
			sawTCPAfter = true
		}
	}
	if !sawQUIC || !sawTCPAfter {
		t.Fatalf("expected QUIC then TCP resume, history=%v", hist)
	}
}

func TestKillUDPReupgradeQUIC(t *testing.T) {
	hist := runKillUDP(t, 1<<20, func(srv *Server) {
		waitUntil(t, 8*time.Second, func() bool {
			quic, tcp := 0, 0
			for _, p := range srv.pathHistory() {
				if p.Kind == transport.KindQUIC {
					quic++
				}
				if p.Kind == transport.KindTCP {
					tcp++
				}
			}
			return quic >= 2 && tcp >= 1
		})
	})
	quicCount, sawTCP := 0, false
	for _, p := range hist {
		if p.Kind == transport.KindQUIC {
			quicCount++
		}
		if p.Kind == transport.KindTCP && quicCount > 0 {
			sawTCP = true
		}
	}
	if quicCount < 2 || !sawTCP {
		t.Fatalf("expected re-upgrade QUIC→TCP→QUIC, history=%v", hist)
	}
}

func TestNATRebindResume(t *testing.T) {
	hist := runKillUDP(t, 1<<20, func(srv *Server) {
		waitUntil(t, 8*time.Second, func() bool {
			n := 0
			for _, p := range srv.pathHistory() {
				if p.Kind == transport.KindQUIC {
					n++
				}
			}
			return n >= 2
		})
	})
	var quicRemotes []string
	for _, p := range hist {
		if p.Kind == transport.KindQUIC && p.Remote != "" {
			quicRemotes = append(quicRemotes, p.Remote)
		}
	}
	if len(quicRemotes) < 2 {
		t.Fatalf("expected two QUIC remotes after NAT rebind, history=%v", hist)
	}
	if quicRemotes[0] == quicRemotes[len(quicRemotes)-1] {
		t.Fatalf("client UDP source address did not change: %v", quicRemotes)
	}
}

func TestQUICDialFailKeepsTCP(t *testing.T) {
	testFailQUICDial.Store(true)
	t.Cleanup(func() { testFailQUICDial.Store(false) })
	const n = 64 << 10
	upWant := makePattern(n)
	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayQUIC(t, dest)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, defaultQUICClient(relayAddr, dest), inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()
	time.Sleep(400 * time.Millisecond)
	for _, k := range srv.liveKinds() {
		if k == transport.KindQUIC {
			t.Fatal("failed QUIC dial upgraded")
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer inW.Close()
		if _, err := inW.Write(upWant); err != nil {
			t.Errorf("stdin: %v", err)
		}
	}()
	var gotDown []byte
	go func() {
		defer wg.Done()
		gotDown, _ = io.ReadAll(outR)
	}()
	wg.Wait()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	gotUp := <-gotUpCh
	if len(gotUp) != n || len(gotDown) != n {
		t.Fatalf("up=%d down=%d", len(gotUp), len(gotDown))
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
	for _, p := range srv.pathHistory() {
		if p.Kind == transport.KindQUIC {
			t.Fatalf("unexpected QUIC: %v", srv.pathHistory())
		}
	}
}

func TestUpgradeDestReadsFirst(t *testing.T) {
	const n = 32 << 10
	upWant := makePattern(n)
	downWant := makePattern(n)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	gotUpCh := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			gotUpCh <- nil
			return
		}
		defer c.Close()
		tc := c.(*net.TCPConn)
		b, _ := io.ReadAll(tc)
		gotUpCh <- b
		_, _ = tc.Write(downWant)
		_ = tc.CloseWrite()
	}()
	dest := ln.Addr().String()
	srv, relayAddr, _ := startRelayQUIC(t, dest)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	start := time.Now()
	go func() {
		err := RunClient(ctx, defaultQUICClient(relayAddr, dest), inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()
	waitKind(t, srv, transport.KindQUIC, 2*time.Second)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("upgrade took %s, want well under switch_timeout", d)
	}
	go func() {
		defer inW.Close()
		_, _ = inW.Write(upWant)
	}()
	gotDown, _ := io.ReadAll(outR)
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	gotUp := <-gotUpCh
	if len(gotUp) != n || len(gotDown) != n {
		t.Fatalf("up=%d down=%d hist=%v", len(gotUp), len(gotDown), srv.pathHistory())
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
}

func TestUpgradeInFlightDown(t *testing.T) {
	const n = 256 << 10
	upWant := makePattern(n)
	downWant := makePattern(n)
	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayQUIC(t, dest)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, defaultQUICClient(relayAddr, dest), inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()
	downCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		downCh <- b
	}()
	waitKind(t, srv, transport.KindQUIC, 8*time.Second)
	go func() {
		defer inW.Close()
		_, _ = inW.Write(upWant)
	}()
	gotDown := <-downCh
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	gotUp := <-gotUpCh
	if len(gotUp) != n || len(gotDown) != n {
		t.Fatalf("up=%d down=%d", len(gotUp), len(gotDown))
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
	if sha256.Sum256(gotDown) != sha256.Sum256(downWant) {
		t.Fatal("down hash")
	}
	sawQUIC := false
	for _, p := range srv.pathHistory() {
		if p.Kind == transport.KindQUIC {
			sawQUIC = true
		}
	}
	if !sawQUIC {
		t.Fatal("expected QUIC")
	}
}

func TestSwitchTimeoutStaysTCP(t *testing.T) {
	const n = 1 << 20
	upWant := makePattern(n)
	downWant := makePattern(n)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	unblock := make(chan struct{})
	gotUpCh := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			gotUpCh <- nil
			return
		}
		defer c.Close()
		tc := c.(*net.TCPConn)
		<-unblock
		_, _ = tc.Write(downWant)
		_ = tc.CloseWrite()
		b, _ := io.ReadAll(tc)
		gotUpCh <- b
	}()
	dest := ln.Addr().String()
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.UDPListen = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"quic"}
	cfg.SwitchTimeout = config.Duration(200 * time.Millisecond)
	cfg.ProbeTimeout = config.Duration(200 * time.Millisecond)
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.HoldTimeout = config.Duration(15 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	testSuppressAck.Store(true)
	t.Cleanup(func() { testSuppressAck.Store(false) })
	gate := make(chan struct{})
	testGateUpgrade.Store(&gate)
	t.Cleanup(func() { testGateUpgrade.Store(nil) })

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, defaultQUICClient(relayAddr, dest), inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()
	downCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		downCh <- b
	}()
	const stall = 512 << 10
	wrote := make(chan struct{})
	go func() {
		_, _ = inW.Write(upWant[:stall])
		close(wrote)
	}()
	<-wrote
	time.Sleep(100 * time.Millisecond)
	close(gate)
	time.Sleep(600 * time.Millisecond)
	for _, k := range srv.liveKinds() {
		if k == transport.KindQUIC {
			t.Fatal("stalled ACK should abort switch and stay on TCP")
		}
	}
	testSuppressAck.Store(false)
	close(unblock)
	go func() {
		defer inW.Close()
		_, _ = inW.Write(upWant[stall:])
	}()
	gotDown := <-downCh
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	gotUp := <-gotUpCh
	if len(gotUp) != n || len(gotDown) != n {
		t.Fatalf("up=%d down=%d hist=%v", len(gotUp), len(gotDown), srv.pathHistory())
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
	for _, p := range srv.pathHistory() {
		if p.Kind == transport.KindQUIC {
			t.Fatalf("R6 expected TCP-only history: %v", srv.pathHistory())
		}
	}
}

func TestHostnameServerUpgrades(t *testing.T) {
	const n = 32 << 10
	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayQUIC(t, dest)
	_, port, err := net.SplitHostPort(relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ccfg := defaultQUICClient(net.JoinHostPort("localhost", port), dest)
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()
	waitKind(t, srv, transport.KindQUIC, 8*time.Second)
	go func() {
		defer inW.Close()
		_, _ = inW.Write(makePattern(n))
	}()
	gotDown, _ := io.ReadAll(outR)
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	gotUp := <-gotUpCh
	if len(gotUp) != n || len(gotDown) != n {
		t.Fatalf("up=%d down=%d", len(gotUp), len(gotDown))
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
}

func TestTCPFlagSkipsUpgrade(t *testing.T) {
	dest, gotUpCh := startBidiDest(t, 1024, 1024)
	srv, relayAddr, _ := startRelayQUIC(t, dest)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ccfg := defaultQUICClient(relayAddr, dest)
	ccfg.Transport = "tcp"
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()
	_, _ = inW.Write(makePattern(1024))
	_ = inW.Close()
	gotDown, _ := io.ReadAll(outR)
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	select {
	case gotUp := <-gotUpCh:
		if !bytes.Equal(gotUp, makePattern(1024)) || !bytes.Equal(gotDown, makePattern(1024)) {
			t.Fatal("byte mismatch")
		}
	case <-ctx.Done():
		t.Fatal("dest")
	}
	for _, p := range srv.pathHistory() {
		if p.Kind != transport.KindTCP {
			t.Fatalf("tcp flag upgraded: %v", srv.pathHistory())
		}
	}
}
