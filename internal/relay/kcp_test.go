package relay

import (
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

func startRelayKCP(t *testing.T, dest string) (*Server, string, context.CancelFunc) {
	t.Helper()
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.UDPListen = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"kcp"}
	cfg.LogLevel = "error"
	cfg.ProbeTimeout = config.Duration(400 * time.Millisecond)
	cfg.ProbeAttempts = 2
	cfg.IdleTimeout = config.Duration(2 * time.Second)
	cfg.HoldTimeout = config.Duration(30 * time.Second)
	cfg.KeepaliveInterval = config.Duration(200 * time.Millisecond)
	cfg.SwitchTimeout = config.Duration(5 * time.Second)
	return startRelayCfg(t, cfg)
}

func defaultKCPClient(server, dest string) config.Client {
	ccfg := defaultQUICClient(server, dest)
	ccfg.Transport = "kcp"
	ccfg.IdleTimeout = config.Duration(2 * time.Second)
	ccfg.KeepaliveInterval = config.Duration(200 * time.Millisecond)
	return ccfg
}

func TestDefaultPathIsKCP(t *testing.T) {
	const n = 256 << 10
	upWant := makePattern(n)
	downWant := makePattern(n)
	upHash := sha256.Sum256(upWant)
	downHash := sha256.Sum256(downWant)

	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayKCP(t, dest)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ccfg := defaultKCPClient(relayAddr, dest)
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()

	waitKind(t, srv, transport.KindKCP, 8*time.Second)

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
	sawKCP := false
	for _, p := range srv.pathHistory() {
		if p.Kind == transport.KindKCP {
			sawKCP = true
		}
	}
	if !sawKCP {
		t.Fatalf("path history never KCP: %v", srv.pathHistory())
	}
}

func TestKCPProbeFailureStaysTCP(t *testing.T) {
	const n = 64 << 10
	upWant := makePattern(n)

	dest, gotUpCh := startBidiDest(t, n, n)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.UDPListen = "127.0.0.1:0"
	cfg.UDPAnnounce = "127.0.0.1:1"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"kcp"}
	cfg.ProbeTimeout = config.Duration(150 * time.Millisecond)
	cfg.ProbeAttempts = 2
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.HoldTimeout = config.Duration(15 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ccfg := defaultKCPClient(relayAddr, dest)
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
		if k == transport.KindKCP {
			t.Fatal("probe should have failed; session upgraded to KCP")
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
		if p.Kind == transport.KindKCP {
			t.Fatalf("unexpected KCP path: %v", srv.pathHistory())
		}
	}
}

func runKillKCP(t *testing.T, n int, afterDrop func(srv *Server)) []pathInfo {
	t.Helper()
	upWant := makePattern(n)
	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayKCP(t, dest)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	ccfg := defaultKCPClient(relayAddr, dest)
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

	waitKind(t, srv, transport.KindKCP, 15*time.Second)
	const head = 64 * 1024
	if _, err := inW.Write(upWant[:head]); err != nil {
		t.Fatal(err)
	}
	srv.dropLiveKind(transport.KindKCP)
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

func TestKillKCPResumeByteExact(t *testing.T) {
	hist := runKillKCP(t, 1<<20, nil)
	sawKCP, sawTCPAfter := false, false
	for _, p := range hist {
		if p.Kind == transport.KindKCP {
			sawKCP = true
		}
		if sawKCP && p.Kind == transport.KindTCP {
			sawTCPAfter = true
		}
	}
	if !sawKCP || !sawTCPAfter {
		t.Fatalf("expected KCP then TCP resume, history=%v", hist)
	}
}

func TestKillKCPReupgradeKCP(t *testing.T) {
	hist := runKillKCP(t, 1<<20, func(srv *Server) {
		waitUntil(t, 12*time.Second, func() bool {
			kcpN, tcp := 0, 0
			for _, p := range srv.pathHistory() {
				if p.Kind == transport.KindKCP {
					kcpN++
				}
				if p.Kind == transport.KindTCP {
					tcp++
				}
			}
			return kcpN >= 2 && tcp >= 1
		})
	})
	kcpCount, sawTCP := 0, false
	for _, p := range hist {
		if p.Kind == transport.KindKCP {
			kcpCount++
		}
		if p.Kind == transport.KindTCP && kcpCount > 0 {
			sawTCP = true
		}
	}
	if kcpCount < 2 || !sawTCP {
		t.Fatalf("expected re-upgrade KCP→TCP→KCP, history=%v", hist)
	}
}

func TestKCPNATRebindResume(t *testing.T) {
	hist := runKillKCP(t, 1<<20, func(srv *Server) {
		waitUntil(t, 12*time.Second, func() bool {
			n := 0
			for _, p := range srv.pathHistory() {
				if p.Kind == transport.KindKCP {
					n++
				}
			}
			return n >= 2
		})
	})
	var remotes []string
	for _, p := range hist {
		if p.Kind == transport.KindKCP && p.Remote != "" {
			remotes = append(remotes, p.Remote)
		}
	}
	if len(remotes) < 2 {
		t.Fatalf("expected two KCP remotes after NAT rebind, history=%v", hist)
	}
	if remotes[0] == remotes[len(remotes)-1] {
		t.Fatalf("client UDP source address did not change: %v", remotes)
	}
}

func TestKCPFlagOverridesQUICConfig(t *testing.T) {
	const n = 32 << 10
	dest, gotUpCh := startBidiDest(t, n, n)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.UDPListen = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"quic", "kcp"}
	cfg.LogLevel = "error"
	cfg.ProbeTimeout = config.Duration(400 * time.Millisecond)
	cfg.IdleTimeout = config.Duration(2 * time.Second)
	cfg.HoldTimeout = config.Duration(15 * time.Second)
	cfg.KeepaliveInterval = config.Duration(200 * time.Millisecond)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ccfg := defaultKCPClient(relayAddr, dest)
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()
	waitKind(t, srv, transport.KindKCP, 8*time.Second)
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
		t.Fatalf("up=%d down=%d hist=%v", len(gotUp), len(gotDown), srv.pathHistory())
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
	for _, p := range srv.pathHistory() {
		if p.Kind == transport.KindQUIC {
			t.Fatalf("--kcp selected QUIC: %v", srv.pathHistory())
		}
	}
}

func TestHostnameServerUpgradesKCP(t *testing.T) {
	const n = 32 << 10
	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayKCP(t, dest)
	_, port, err := net.SplitHostPort(relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ccfg := defaultKCPClient(net.JoinHostPort("localhost", port), dest)
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()
	waitKind(t, srv, transport.KindKCP, 8*time.Second)
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

func TestSingleSessionKCPRepeatedKillsSoak(t *testing.T) {
	runSoak := func(t *testing.T, allowHA bool) {
		const (
			totalBytes = 256 << 10 // 256 KiB
			chunkSize  = 8 << 10   // 8 KiB
			numKills   = 5
		)
		upWant := makePattern(totalBytes)
		dest, gotUpCh := startBidiDest(t, totalBytes, totalBytes)

		cfg := config.DefaultServer()
		cfg.ListenTCP = "127.0.0.1:0"
		cfg.UDPListen = "127.0.0.1:0"
		cfg.DefaultDestination = dest
		cfg.AllowDestinations = []string{dest, "*"}
		cfg.Transports = []string{"kcp"}
		cfg.LogLevel = "error"
		cfg.ProbeTimeout = config.Duration(300 * time.Millisecond)
		cfg.ProbeAttempts = 2
		cfg.IdleTimeout = config.Duration(10 * time.Second)
		cfg.HoldTimeout = config.Duration(20 * time.Second)
		cfg.KeepaliveInterval = config.Duration(150 * time.Millisecond)
		cfg.HeartbeatInterval = config.Duration(100 * time.Millisecond)
		cfg.DeadPeerThreshold = 3
		cfg.SwitchTimeout = config.Duration(5 * time.Second)
		srv, relayAddr, _ := startRelayCfg(t, cfg)

		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()

		ccfg := defaultKCPClient(relayAddr, dest)
		ccfg.AllowHA = allowHA
		ccfg.ProbeTimeout = config.Duration(300 * time.Millisecond)
		ccfg.HeartbeatInterval = config.Duration(100 * time.Millisecond)
		ccfg.DeadPeerThreshold = 3
		ccfg.ReconnectMaxElapsed = config.Duration(20 * time.Second)
		ccfg.ReconnectBackoff = []string{"20ms", "50ms", "100ms"}

		errc := make(chan error, 1)
		go func() {
			err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
			_ = outW.Close()
			errc <- err
		}()

		waitKind(t, srv, transport.KindKCP, 15*time.Second)

		downCh := make(chan []byte, 1)
		go func() {
			b, err := io.ReadAll(outR)
			if err != nil {
				t.Errorf("stdout read: %v", err)
			}
			downCh <- b
		}()

		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			defer inW.Close()
			off := 0
			for off < len(upWant) {
				n := chunkSize
				if off+n > len(upWant) {
					n = len(upWant) - off
				}
				if _, err := inW.Write(upWant[off : off+n]); err != nil {
					t.Errorf("stdin write: %v", err)
					return
				}
				off += n
				time.Sleep(10 * time.Millisecond)
			}
		}()

		go func() {
			for k := 0; k < numKills; k++ {
				select {
				case <-writeDone:
					return
				case <-time.After(200 * time.Millisecond):
					srv.dropLiveKind(transport.KindKCP)
				}
			}
		}()

		<-writeDone
		var gotDown []byte
		select {
		case gotDown = <-downCh:
		case <-ctx.Done():
			t.Fatal("timeout reading stdout")
		}

		select {
		case err := <-errc:
			if err != nil {
				t.Fatalf("client: %v, hist=%v", err, srv.pathHistory())
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

		if len(gotUp) != totalBytes || len(gotDown) != totalBytes {
			t.Fatalf("up=%d down=%d want %d", len(gotUp), len(gotDown), totalBytes)
		}
		checkPattern(t, gotUp)
		checkPattern(t, gotDown)
		if sha256.Sum256(gotUp) != sha256.Sum256(upWant) || sha256.Sum256(gotDown) != sha256.Sum256(makePattern(totalBytes)) {
			t.Fatal("SHA-256 byte mismatch after repeated kills")
		}

		waitUntil(t, 10*time.Second, func() bool { return srv.sessionCount() == 0 })
		if used := srv.budgetUsed(); used != 0 {
			t.Fatalf("buffer leak: %d", used)
		}
	}

	t.Run("StandaloneKCP", func(t *testing.T) {
		runSoak(t, false)
	})

	t.Run("AllowHA_DualPath", func(t *testing.T) {
		runSoak(t, true)
	})
}

func TestAdaptiveKCPInRelay(t *testing.T) {
	const n = 128 << 10
	upWant := makePattern(n)
	downWant := makePattern(n)

	dest, gotUpCh := startBidiDest(t, n, n)
	srv, relayAddr, _ := startRelayKCP(t, dest)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ccfg := defaultKCPClient(relayAddr, dest)
	ccfg.AdaptiveKCP = true

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()

	waitKind(t, srv, transport.KindKCP, 8*time.Second)

	var gotDown []byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer inW.Close()
		_, _ = inW.Write(upWant)
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

	if sha256.Sum256(gotUp) != sha256.Sum256(upWant) || sha256.Sum256(gotDown) != sha256.Sum256(downWant) {
		t.Fatal("SHA-256 byte mismatch in Adaptive KCP relay transfer")
	}
}
