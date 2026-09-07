package relay

import (
	"bytes"
	"context"
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
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()

	var destWritten atomic.Int64
	go func() {
		c, err := destLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		chunk := makePattern(4096)
		for {
			n, err := c.Write(chunk)
			destWritten.Add(int64(n))
			if err != nil {
				return
			}
		}
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
	written := destWritten.Load()
	time.Sleep(80 * time.Millisecond)
	written2 := destWritten.Load()
	if written2-written > 256*1024 {
		t.Fatalf("dest still being read quickly: %d -> %d", written, written2)
	}

	go func() { _, _ = io.Copy(io.Discard, outR) }()
	_ = inW.Close()

	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			t.Logf("client ended: %v", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		<-errc
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
	var none proto.HelloOK
	conn, err := transport.DialTCP(ctx, addr)
	if err != nil {
		return nil, none, err
	}
	nonce, err := proto.RandomNonce()
	if err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	hello := proto.Hello{
		V: 1, Transport: []string{"tcp"}, Destination: dest,
		ClientNonce: nonce, Auth: proto.EmptyAuth(), Window: 65536,
	}
	fr, err := proto.MarshalFrame(proto.TypeHello, hello)
	if err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteFrame(fr); err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	reply, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	if reply.Type != proto.TypeHelloOK {
		_ = conn.Close()
		return nil, none, proto.NewError(proto.CodeProto, reply.Type.String())
	}
	var ok proto.HelloOK
	if err := proto.UnmarshalPayload(reply, &ok); err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	return conn, ok, nil
}

func rawResumeFail(t *testing.T, ctx context.Context, addr, sessionID, token string, downAcked uint64) proto.Fail {
	t.Helper()
	conn, err := transport.DialTCP(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
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
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteFrame(fr); err != nil {
		t.Fatal(err)
	}
	reply, err := conn.ReadFrame()
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
