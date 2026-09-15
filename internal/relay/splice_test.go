package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
)

func TestSpliceDirectE2E(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("splice is only supported on linux")
	}

	ResetSplicedStats()

	const n = 2 << 20 // 2 MiB
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

	srvCfg := config.DefaultServer()
	srvCfg.ListenTCP = "127.0.0.1:0"
	srvCfg.DefaultDestination = destLn.Addr().String()
	srvCfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	srvCfg.Transports = []string{"tcp"}
	srvCfg.Splice = true
	srvCfg.LogLevel = "error"

	_, relayAddr, _ := startRelayCfg(t, srvCfg)

	// Use real OS pipes for client IO so getFD returns real file descriptors
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = relayAddr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.Splice = true
	ccfg.LogLevel = "error"
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
			t.Errorf("os.pipe write: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		b, err := io.ReadAll(outR)
		if err != nil {
			t.Errorf("os.pipe read: %v", err)
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

	sIn, sOut, calls := SplicedStats()
	t.Logf("Splice stats: in=%d, out=%d, calls=%d", sIn, sOut, calls)
	if calls == 0 {
		t.Fatalf("expected splice calls > 0, got %d", calls)
	}
	if sIn == 0 {
		t.Fatalf("expected spliced bytes in > 0, got %d", sIn)
	}
}

func TestSpliceDisabledNoCalls(t *testing.T) {
	ResetSplicedStats()

	const n = 256 << 10 // 256 KiB
	upWant := makePattern(n)
	downWant := makePattern(n)

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

	srvCfg := config.DefaultServer()
	srvCfg.ListenTCP = "127.0.0.1:0"
	srvCfg.DefaultDestination = destLn.Addr().String()
	srvCfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	srvCfg.Transports = []string{"tcp"}
	srvCfg.Splice = false
	srvCfg.LogLevel = "error"

	_, relayAddr, _ := startRelayCfg(t, srvCfg)

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = relayAddr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.Splice = false
	ccfg.LogLevel = "error"
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
		_, _ = inW.Write(upWant)
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
		t.Fatal("timeout waiting for client")
	}

	gotUp := <-gotUpCh
	if !bytes.Equal(gotUp, upWant) || !bytes.Equal(gotDown, downWant) {
		t.Fatal("data payload mismatch with splice disabled")
	}

	_, _, calls := SplicedStats()
	if calls != 0 {
		t.Fatalf("expected 0 splice calls when splice is disabled, got %d", calls)
	}
}
