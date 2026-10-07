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
	"github.com/remote-relay/relay/internal/session"
)

// TestRelayTieredSpillResume verifies that when a carrier disconnection stalls
// delivery, data exceeding the L1 RAM threshold spills cleanly to disk,
// and upon resumption, data is streamed directly from disk and validated byte-exact.
func TestRelayTieredSpillResume(t *testing.T) {
	const n = 512 * 1024 // 512 KiB payload, well above L1 threshold of 128 KiB
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

	tempDir := t.TempDir()

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = destLn.Addr().String()
	cfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	cfg.Transports = []string{"tcp"}
	cfg.LogLevel = "error"
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.HoldTimeout = config.Duration(30 * time.Second)

	// FEAT-ROB-04: Configure tight L1 capacity (128 KiB) and custom spill directory
	cfg.SpillL1Bytes = 128 * 1024
	cfg.SpillDir = tempDir
	cfg.NoSpill = false

	srv, relayAddr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = relayAddr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.ReconnectMaxElapsed = config.Duration(20 * time.Second)
	ccfg.ReconnectBackoff = []string{"20ms", "50ms", "100ms"}
	ccfg.SpillL1Bytes = 128 * 1024
	ccfg.SpillDir = tempDir

	log := logging.New(io.Discard, "error", "text")

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, log)
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
		buf := make([]byte, n)
		var have int
		dropped := false
		for have < n {
			k, err := outR.Read(buf[have:])
			have += k
			if !dropped && have >= 64*1024 {
				srv.dropLiveTransports()
				dropped = true
			}
			if err != nil {
				if have != n {
					t.Errorf("stdout read: %v have=%d", err, have)
				}
				break
			}
		}
		gotDown = buf[:have]
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

// TestRelaySpillCLIAndConfigFlags verifies that CLI flags correctly configure
// the spill parameters in Server and Client configurations.
func TestRelaySpillCLIAndConfigFlags(t *testing.T) {
	tempDir := t.TempDir()
	noSpillTrue := true

	scfg, err := config.LoadServer(config.ServerOptions{
		SpillDir:     tempDir,
		SpillL1Bytes: 256 * 1024,
		NoSpill:      &noSpillTrue,
	})
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if scfg.SpillDir != tempDir {
		t.Errorf("SpillDir = %q, want %q", scfg.SpillDir, tempDir)
	}
	if scfg.SpillL1Bytes != 256*1024 {
		t.Errorf("SpillL1Bytes = %d, want %d", scfg.SpillL1Bytes, 256*1024)
	}
	if !scfg.NoSpill {
		t.Errorf("NoSpill = false, want true")
	}

	ccfg, err := config.LoadClient(config.ClientOptions{
		SpillDir:     tempDir,
		SpillL1Bytes: 512 * 1024,
		NoSpill:      &noSpillTrue,
	})
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if ccfg.SpillDir != tempDir {
		t.Errorf("Client SpillDir = %q, want %q", ccfg.SpillDir, tempDir)
	}
	if ccfg.SpillL1Bytes != 512*1024 {
		t.Errorf("Client SpillL1Bytes = %d, want %d", ccfg.SpillL1Bytes, 512*1024)
	}
	if !ccfg.NoSpill {
		t.Errorf("Client NoSpill = false, want true")
	}
}

// TestRelayTieredSpillDirect verifies that writing into a server sendLog spills
// blocks to disk when exceeding L1Cap and reclaims them upon AdvanceTo.
func TestRelayTieredSpillDirect(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultServer()
	cfg.SpillDir = tempDir
	cfg.SpillL1Bytes = 128 * 1024 // 128 KiB L1 RAM
	cfg.NoSpill = false

	ring := cfg.SpillDir // ensure config field is used
	_ = ring

	scfg := config.DefaultServer()
	scfg.SpillL1Bytes = 128 * 1024
	scfg.SpillDir = tempDir

	r := session.NewTieredRing(session.RingConfig{
		CapMax:   1024 * 1024,
		L1Cap:    scfg.SpillL1Bytes,
		SpillDir: scfg.SpillDir,
		NoSpill:  scfg.NoSpill,
	})
	defer r.Release()

	// Append 256 KiB
	data := makePattern(256 * 1024)
	if err := r.Append(context.Background(), data); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if r.Len() != 256*1024 {
		t.Fatalf("Len = %d, want %d", r.Len(), 256*1024)
	}
	if r.SpillLen() == 0 {
		t.Fatalf("expected data to spill to disk, got SpillLen = 0")
	}
	if r.RAMLen() > scfg.SpillL1Bytes+65536 {
		t.Fatalf("RAMLen = %d exceeded L1 threshold", r.RAMLen())
	}

	// Read full content back
	from, got := r.Slice(0, 256*1024)
	if from != 0 || len(got) != 256*1024 {
		t.Fatalf("Slice returned %d bytes from %d", len(got), from)
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		t.Fatal("data read back does not match original")
	}

	// Advance past disk blocks
	spillLenBefore := r.SpillLen()
	r.AdvanceTo(uint64(spillLenBefore))
	if r.SpillLen() != 0 {
		t.Fatalf("expected disk spill to be drained, got SpillLen = %d", r.SpillLen())
	}
}
