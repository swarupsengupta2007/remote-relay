package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/crypto/kex"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

func TestKillTCPResumeByteExact(t *testing.T) {
	const n = 1 << 20
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

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = destLn.Addr().String()
	cfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	cfg.Transports = []string{"tcp"}
	cfg.LogLevel = "error"
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.HoldTimeout = config.Duration(30 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	ccfg := config.DefaultClient()
	ccfg.Server = relayAddr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.ReconnectMaxElapsed = config.Duration(20 * time.Second)
	ccfg.ReconnectBackoff = []string{"20ms", "50ms", "100ms"}
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

func TestResumeStaleToken(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(10 * time.Second)
	_, addr, _ := startRelayCfg(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, hello, err := rawHello(ctx, addr, dest)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	bad := base64.StdEncoding.EncodeToString(make([]byte, 32))
	fail := rawResumeFail(t, ctx, addr, hello.SessionID, bad, 0)
	if fail.Code != proto.CodeBadToken {
		t.Fatalf("got %s want %s", fail.Code, proto.CodeBadToken)
	}
}

func TestResumeUnknownSession(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	_, addr, _ := startRelayCfg(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tok := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	fail := rawResumeFail(t, ctx, addr, "s-deadbeefdead", tok, 0)
	if fail.Code != proto.CodeUnknownSession {
		t.Fatalf("got %s want %s", fail.Code, proto.CodeUnknownSession)
	}
}

func TestResumeAfterHoldExpiry(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(200 * time.Millisecond)
	cfg.IdleTimeout = config.Duration(5 * time.Second)
	_, addr, _ := startRelayCfg(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, hello, err := rawHello(ctx, addr, dest)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	time.Sleep(500 * time.Millisecond)
	fail := rawResumeFail(t, ctx, addr, hello.SessionID, hello.ResumeToken, 0)
	if fail.Code != proto.CodeExpired {
		t.Fatalf("got %s want %s", fail.Code, proto.CodeExpired)
	}
}

func TestBackpressureFillsBuffer(t *testing.T) {
	const bufSize = 32 * 1024
	const downN = 128 * 1024
	downWant := makePattern(downN)
	downHash := sha256.Sum256(downWant)

	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()

	var destWritten atomic.Int64
	upCh := make(chan []byte, 1)
	go func() {
		c, err := destLn.Accept()
		if err != nil {
			upCh <- nil
			return
		}
		defer c.Close()
		tc := c.(*net.TCPConn)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			n, _ := tc.Write(downWant)
			destWritten.Store(int64(n))
			_ = tc.CloseWrite()
		}()
		go func() {
			defer wg.Done()
			b, _ := io.ReadAll(tc)
			upCh <- b
		}()
		wg.Wait()
	}()

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = destLn.Addr().String()
	cfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	cfg.Transports = []string{"tcp"}
	cfg.BufferBytes = bufSize
	cfg.TotalBufferBytes = 4 * bufSize
	cfg.SendWindow = bufSize
	cfg.DataChunkBytes = 1024
	cfg.HoldTimeout = config.Duration(15 * time.Second)
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ccfg := config.DefaultClient()
	ccfg.Server = relayAddr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.BufferBytes = bufSize
	ccfg.SendWindow = bufSize
	log := logging.New(io.Discard, "error", "text")

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, log)
		_ = outW.Close()
		errc <- err
	}()

	waitUntil(t, 3*time.Second, func() bool {
		for _, n := range srv.sessionBufferLens() {
			if n >= bufSize {
				return true
			}
		}
		return false
	})
	endStable := maxLens(srv.sessionBufferLens())
	time.Sleep(80 * time.Millisecond)
	if got := maxLens(srv.sessionBufferLens()); got != endStable {
		t.Fatalf("downLog kept growing after cap: %d -> %d", endStable, got)
	}

	_ = inW.Close()
	gotDown, err := io.ReadAll(outR)
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("client: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for client")
	}
	if len(gotDown) != downN {
		t.Fatalf("down len=%d want %d", len(gotDown), downN)
	}
	checkPattern(t, gotDown)
	if sha256.Sum256(gotDown) != downHash {
		t.Fatal("down SHA-256 mismatch")
	}
	select {
	case <-upCh:
	case <-ctx.Done():
		t.Fatal("dest did not finish")
	}
}

func TestGlobalBufferBudget(t *testing.T) {
	const bufSize = 8 * 1024
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	go func() {
		for {
			c, err := destLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				chunk := bytes.Repeat([]byte("n"), 1024)
				for {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = destLn.Addr().String()
	cfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	cfg.Transports = []string{"tcp"}
	cfg.BufferBytes = bufSize
	cfg.TotalBufferBytes = bufSize + bufSize/2
	cfg.SendWindow = bufSize
	cfg.DataChunkBytes = 1024
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.HoldTimeout = config.Duration(15 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	type clog struct {
		inW  *io.PipeWriter
		outR *io.PipeReader
		errc chan error
		stop context.CancelFunc
	}
	startBlocked := func() clog {
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		ccfg := config.DefaultClient()
		ccfg.Server = relayAddr
		ccfg.Destination = destLn.Addr().String()
		ccfg.Transport = "tcp"
		ccfg.BufferBytes = bufSize
		ccfg.SendWindow = bufSize
		log := logging.New(io.Discard, "error", "text")
		errc := make(chan error, 1)
		go func() {
			err := RunClient(ctx, ccfg, inR, outW, log)
			_ = outW.Close()
			errc <- err
		}()
		return clog{inW: inW, outR: outR, errc: errc, stop: cancel}
	}

	c1 := startBlocked()
	defer c1.stop()
	waitUntil(t, 3*time.Second, func() bool {
		return srv.budgetUsed() > 0 && maxLens(srv.sessionBufferLens()) > 0
	})
	c2 := startBlocked()
	defer c2.stop()
	waitUntil(t, 3*time.Second, func() bool {
		return srv.budget.Exhausted() || srv.budgetUsed() >= int64(cfg.TotalBufferBytes)
	})
	if !srv.budget.Exhausted() && srv.budgetUsed() < int64(cfg.TotalBufferBytes) {
		t.Fatalf("budget used=%d cap=%d", srv.budgetUsed(), cfg.TotalBufferBytes)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ccfg := config.DefaultClient()
	ccfg.Server = relayAddr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	err = RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	if !errors.Is(err, proto.ErrNoCapacity) {
		t.Fatalf("got %v want ERR_NO_CAPACITY", err)
	}
	if srv.sessionCount() < 2 {
		t.Fatalf("existing sessions died, count=%d", srv.sessionCount())
	}

	go func() { _, _ = io.Copy(io.Discard, c1.outR) }()
	go func() { _, _ = io.Copy(io.Discard, c2.outR) }()
	_ = c1.inW.Close()
	_ = c2.inW.Close()
}

func TestBudgetReleaseWakesExistingSession(t *testing.T) {
	const bufSize = 8 * 1024
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	accepted := make(chan *net.TCPConn, 8)
	go func() {
		for {
			c, err := destLn.Accept()
			if err != nil {
				return
			}
			accepted <- c.(*net.TCPConn)
		}
	}()

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = destLn.Addr().String()
	cfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	cfg.Transports = []string{"tcp"}
	cfg.BufferBytes = bufSize
	cfg.TotalBufferBytes = bufSize + bufSize/2
	cfg.SendWindow = bufSize
	cfg.DataChunkBytes = 1024
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.HoldTimeout = config.Duration(15 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	type clog struct {
		inW  *io.PipeWriter
		outR *io.PipeReader
		stop context.CancelFunc
	}
	startBlocked := func() clog {
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		ccfg := config.DefaultClient()
		ccfg.Server = relayAddr
		ccfg.Destination = destLn.Addr().String()
		ccfg.Transport = "tcp"
		ccfg.BufferBytes = bufSize
		ccfg.SendWindow = bufSize
		go func() {
			_ = RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
			_ = outW.Close()
		}()
		return clog{inW: inW, outR: outR, stop: cancel}
	}

	c3 := startBlocked()
	defer c3.stop()
	var d3 *net.TCPConn
	select {
	case d3 = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("dest 3 did not accept")
	}

	c1 := startBlocked()
	defer c1.stop()
	var d1 *net.TCPConn
	select {
	case d1 = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("dest 1 did not accept")
	}
	c2 := startBlocked()
	defer c2.stop()
	var d2 *net.TCPConn
	select {
	case d2 = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("dest 2 did not accept")
	}

	stopFlood := make(chan struct{})
	flood := func(c *net.TCPConn) {
		chunk := bytes.Repeat([]byte("n"), 1024)
		for {
			select {
			case <-stopFlood:
				return
			default:
			}
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	}
	go flood(d1)
	go flood(d2)

	waitUntil(t, 3*time.Second, func() bool {
		return srv.budget.Exhausted() || srv.budgetUsed() >= int64(cfg.TotalBufferBytes)
	})
	if zeros(srv.sessionBufferLens()) < 1 {
		t.Fatalf("session 3 sendLog should still be empty: %v", srv.sessionBufferLens())
	}

	if _, err := d3.Write(bytes.Repeat([]byte("z"), 4096)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if z := zeros(srv.sessionBufferLens()); z < 1 {
		t.Fatalf("session 3 should still be blocked on budget: %v", srv.sessionBufferLens())
	}
	before := srv.sessionCount()

	close(stopFlood)
	_ = d1.CloseWrite()
	_ = d2.CloseWrite()
	go func() { _, _ = io.Copy(io.Discard, c1.outR) }()
	go func() { _, _ = io.Copy(io.Discard, c2.outR) }()

	waitUntil(t, 3*time.Second, func() bool {
		return zeros(srv.sessionBufferLens()) == 0
	})
	if srv.sessionCount() != before {
		t.Fatalf("link flap: sessions %d -> %d", before, srv.sessionCount())
	}

	_ = c1.inW.Close()
	_ = c2.inW.Close()
	_ = c3.inW.Close()
	_ = d3.Close()
}

func zeros(v []int) int {
	n := 0
	for _, x := range v {
		if x == 0 {
			n++
		}
	}
	return n
}

func TestHalfCloseAcrossResume(t *testing.T) {
	const downN = 128 << 10
	downWant := makePattern(downN)
	upWant := []byte("hello-up")

	upEOF := make(chan []byte, 1)
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
			time.Sleep(150 * time.Millisecond)
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

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = destLn.Addr().String()
	cfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(15 * time.Second)
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ccfg := config.DefaultClient()
	ccfg.Server = relayAddr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.ReconnectBackoff = []string{"20ms", "50ms"}
	ccfg.ReconnectMaxElapsed = config.Duration(10 * time.Second)
	log := logging.New(io.Discard, "error", "text")

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, log)
		_ = outW.Close()
		errc <- err
	}()

	if _, err := inW.Write(upWant); err != nil {
		t.Fatal(err)
	}
	if err := inW.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	srv.dropLiveTransports()

	gotDown, err := io.ReadAll(outR)
	if err != nil {
		t.Fatalf("stdout: %v", err)
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

func TestHalfCloseKillImmediately(t *testing.T) {
	upWant := []byte("hello-up")
	upEOF := make(chan []byte, 1)
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
		b, _ := io.ReadAll(c)
		upEOF <- b
	}()

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = destLn.Addr().String()
	cfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(15 * time.Second)
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ccfg := config.DefaultClient()
	ccfg.Server = relayAddr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.ReconnectBackoff = []string{"10ms", "20ms"}
	ccfg.ReconnectMaxElapsed = config.Duration(8 * time.Second)
	log := logging.New(io.Discard, "error", "text")

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, log)
		_ = outW.Close()
		errc <- err
	}()

	if _, err := inW.Write(upWant); err != nil {
		t.Fatal(err)
	}
	if err := inW.Close(); err != nil {
		t.Fatal(err)
	}
	srv.dropLiveTransports()

	_, _ = io.Copy(io.Discard, outR)
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
}

func TestKillTwiceAfterReconnectBudget(t *testing.T) {
	const n = 256 << 10
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

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = destLn.Addr().String()
	cfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(20 * time.Second)
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ccfg := config.DefaultClient()
	ccfg.Server = relayAddr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.ReconnectMaxElapsed = config.Duration(250 * time.Millisecond)
	ccfg.ReconnectBackoff = []string{"10ms", "20ms"}
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
		kills := 0
		for have < n {
			k, err := outR.Read(buf[have:])
			have += k
			if kills == 0 && have >= 16*1024 {
				srv.dropLiveTransports()
				time.Sleep(400 * time.Millisecond)
				srv.dropLiveTransports()
				kills = 2
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
	if len(gotUp) != n || len(gotDown) != n {
		t.Fatalf("up=%d down=%d want %d", len(gotUp), len(gotDown), n)
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
}

func TestResumeLostOKRetriesOriginalToken(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(10 * time.Second)
	_, addr, _ := startRelayCfg(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, hello, err := rawHello(ctx, addr, dest)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	lost, err := rawResumeWrite(ctx, addr, hello.SessionID, hello.ResumeToken, 0)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	_ = lost.Close()

	okConn, rok, err := rawResumeOK(ctx, addr, hello.SessionID, hello.ResumeToken, 0)
	if err != nil {
		t.Fatalf("original token after lost RESUME_OK: %v", err)
	}
	_ = okConn.Close()
	if rok.SessionID != hello.SessionID {
		t.Fatalf("session %s", rok.SessionID)
	}
	if rok.ResumeToken == "" || rok.ResumeToken == hello.ResumeToken {
		t.Fatal("expected rotated token in RESUME_OK")
	}
}

func TestClientReturnsOnDestDeath(t *testing.T) {
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	go func() {
		c, err := destLn.Accept()
		if err != nil {
			return
		}
		tc := c.(*net.TCPConn)
		_ = tc.SetLinger(0)
		_ = tc.Close()
	}()

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = destLn.Addr().String()
	cfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	cfg.Transports = []string{"tcp"}
	cfg.HoldTimeout = config.Duration(2 * time.Second)
	_, addr, _ := startRelayCfg(t, cfg)

	inR, inW := io.Pipe()
	defer inW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ccfg := config.DefaultClient()
	ccfg.Server = addr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.ReconnectMaxElapsed = config.Duration(500 * time.Millisecond)
	ccfg.ReconnectBackoff = []string{"10ms"}
	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, ccfg, inR, io.Discard, logging.New(io.Discard, "error", "text"))
	}()
	select {
	case <-errc:
	case <-ctx.Done():
		t.Fatal("RunClient hung after dest death")
	}
}

func startHoldDest(t *testing.T) string {
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
				buf := make([]byte, 256)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func rawHello(ctx context.Context, addr, dest string) (transport.Conn, proto.HelloOK, error) {
	cfg := config.DefaultClient()
	cfg.Server = addr
	cfg.Destination = dest
	cfg.Transport = "tcp"
	cfg.StrictHostKeyChecking = "no"
	return clientHello(ctx, cfg)
}

func rawResumeWrite(ctx context.Context, addr, sessionID, token string, downAcked uint64) (transport.Conn, error) {
	conn, err := transport.DialTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	cfg := config.DefaultClient()
	cfg.Server = addr
	cfg.Transport = "tcp"
	cfg.StrictHostKeyChecking = "no"

	kexCli, err := kex.NewClientSession()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.WriteFrame(proto.Frame{Type: proto.TypeKexInit, Payload: kexCli.InitPayload()}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reply, err := conn.ReadFrame()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	verifyHostKey := func(pub ed25519.PublicKey) error {
		return kex.VerifyKnownHosts(cfg.KnownHosts, cfg.Server, pub, cfg.ServerFingerprint, cfg.StrictHostKeyChecking)
	}
	c2sKey, s2cKey, err := kexCli.ProcessReply(reply.Payload, verifyHostKey)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	cipherConn, err := kex.NewCipherConn(conn, c2sKey, s2cKey)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	nonce, err := proto.RandomNonce()
	if err != nil {
		_ = cipherConn.Close()
		return nil, err
	}
	msg := proto.Resume{
		V: 1, SessionID: sessionID, ResumeToken: token,
		Transport: []string{"tcp"}, DownAcked: downAcked, ClientNonce: nonce,
	}
	fr, err := proto.MarshalFrame(proto.TypeResume, msg)
	if err != nil {
		_ = cipherConn.Close()
		return nil, err
	}
	if err := cipherConn.WriteFrame(fr); err != nil {
		_ = cipherConn.Close()
		return nil, err
	}
	return cipherConn.Underlying(), nil
}

func rawResumeOK(ctx context.Context, addr, sessionID, token string, downAcked uint64) (transport.Conn, proto.ResumeOK, error) {
	cfg := config.DefaultClient()
	cfg.Server = addr
	cfg.Transport = "tcp"
	cfg.StrictHostKeyChecking = "no"
	return clientResumeRole(ctx, cfg, sessionID, token, downAcked, "")
}

func rawResumeFail(t *testing.T, ctx context.Context, addr, sessionID, token string, downAcked uint64) proto.Fail {
	t.Helper()
	conn, err := transport.DialTCP(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	kexCli, err := kex.NewClientSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteFrame(proto.Frame{Type: proto.TypeKexInit, Payload: kexCli.InitPayload()}); err != nil {
		t.Fatal(err)
	}
	reply, err := conn.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	c2sKey, s2cKey, err := kexCli.ProcessReply(reply.Payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	cipherConn, err := kex.NewCipherConn(conn, c2sKey, s2cKey)
	if err != nil {
		t.Fatal(err)
	}

	nonce, err := proto.RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	msg := proto.Resume{
		V: 1, SessionID: sessionID, ResumeToken: token,
		Transport: []string{"tcp"}, DownAcked: downAcked, ClientNonce: nonce,
	}
	fr, err := proto.MarshalFrame(proto.TypeResume, msg)
	if err != nil {
		t.Fatal(err)
	}
	_ = cipherConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := cipherConn.WriteFrame(fr); err != nil {
		t.Fatal(err)
	}
	reply, err = cipherConn.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != proto.TypeResumeFail && reply.Type != proto.TypeErr {
		t.Fatalf("got %s want RESUME_FAIL", reply.Type)
	}
	var fail proto.Fail
	if err := proto.UnmarshalPayload(reply, &fail); err != nil {
		t.Fatal(err)
	}
	return fail
}

func waitUntil(t *testing.T, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}

func maxLens(v []int) int {
	m := 0
	for _, n := range v {
		if n > m {
			m = n
		}
	}
	return m
}
