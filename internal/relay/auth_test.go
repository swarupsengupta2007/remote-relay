package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/crypto/kex"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"os/exec"
)

const authFailDelay = 50 * time.Millisecond

func TestUnauthenticatedClientRejectedBeforeDial(t *testing.T) {
	var accepts atomic.Int64
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
			accepts.Add(1)
			_ = c.Close()
		}
	}()

	dir := t.TempDir()
	_, pubLine := writeEd25519Key(t, dir, "id_ed25519")
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = destLn.Addr().String()
	scfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	scfg.AuthFailDelay = config.Duration(authFailDelay)
	_, addr, _ := startRelayCfg(t, scfg)

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = addr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	if !errors.Is(err, proto.ErrAuth) {
		t.Fatalf("got %v want ERR_AUTH", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepts.Load(); n != 0 {
		t.Fatalf("destination accepted %d connections", n)
	}
}

func TestUnauthorizedKeyERRAuthFixedDelay(t *testing.T) {
	var accepts atomic.Int64
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
			accepts.Add(1)
			_ = c.Close()
		}
	}()

	dir := t.TempDir()
	goodPriv, goodPub := writeEd25519Key(t, dir, "good")
	badPriv, _ := writeEd25519Key(t, dir, "bad")
	_ = goodPriv
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(goodPub+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = destLn.Addr().String()
	scfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	scfg.AuthFailDelay = config.Duration(authFailDelay)
	_, addr, _ := startRelayCfg(t, scfg)

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = addr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.AuthMethod = auth.MethodPublicKey
	ccfg.AuthUser = "alice"
	ccfg.IdentityFiles = []string{badPriv}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	err = RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	elapsed := time.Since(start)
	if !errors.Is(err, proto.ErrAuth) {
		t.Fatalf("got %v want ERR_AUTH", err)
	}
	if elapsed < authFailDelay {
		t.Fatalf("auth failure returned in %s, want >= %s", elapsed, authFailDelay)
	}
	time.Sleep(30 * time.Millisecond)
	if n := accepts.Load(); n != 0 {
		t.Fatalf("destination accepted %d connections", n)
	}
}

func TestAuthOKDestMismatchDoesNotSendAUTH(t *testing.T) {
	rec := &writeRecordConn{}
	ok := proto.AuthOK{
		SessionID:   "s-1",
		ServerNonce: "n",
		Challenge:   base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, sha256.Size)),
		Destination: "10.0.0.1:99",
	}
	fr, err := proto.MarshalFrame(proto.TypeAuthOK, ok)
	if err != nil {
		t.Fatal(err)
	}
	err = completeClientAuth(rec, auth.New(auth.Config{}), auth.Challenge{
		Destination: "127.0.0.1:22",
		Canonical:   []byte(`{"v":1}`),
	}, fr)
	if !errors.Is(err, proto.ErrAuth) {
		t.Fatalf("got %v want ERR_AUTH", err)
	}
	if !strings.Contains(err.Error(), "challenge mismatch") {
		t.Fatalf("err=%v", err)
	}
	for _, w := range rec.writes {
		if w.Type == proto.TypeAuth {
			t.Fatal("client produced AUTH after dest mismatch")
		}
	}

	dir := t.TempDir()
	priv, _ := writeEd25519Key(t, dir, "id")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sawAuth := make(chan bool, 1)
	go func() {
		sent := false
		defer func() { sawAuth <- sent }()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		conn, err := transport.WrapTCP(c)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		initFrame, err := conn.ReadFrame()
		if err != nil {
			return
		}
		_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return
		}
		kexSrv, err := kex.NewServerSession(hostPriv)
		if err != nil {
			return
		}
		replyPayload, c2sKey, s2cKey, err := kexSrv.ProcessInit(initFrame.Payload)
		if err != nil {
			return
		}
		if err := conn.WriteFrame(proto.Frame{Type: proto.TypeKexReply, Payload: replyPayload}); err != nil {
			return
		}
		cipherConn, err := kex.NewCipherConn(conn, s2cKey, c2sKey)
		if err != nil {
			return
		}
		if _, err := cipherConn.ReadFrame(); err != nil {
			return
		}

		nonce, err := proto.RandomNonce()
		if err != nil {
			return
		}
		fr, err := proto.MarshalFrame(proto.TypeAuthOK, proto.AuthOK{
			SessionID:   "s-x",
			ServerNonce: nonce,
			Challenge:   base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)),
			Destination: "10.255.255.1:1",
		})
		if err != nil {
			return
		}
		if err := cipherConn.WriteFrame(fr); err != nil {
			return
		}
		f, err := cipherConn.ReadFrame()
		sent = err == nil && f.Type == proto.TypeAuth
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ccfg := authClient(ln.Addr().String(), "127.0.0.1:22", priv)
	ccfg.StrictHostKeyChecking = "no"
	_, _, err = clientHello(ctx, ccfg)
	if !errors.Is(err, proto.ErrAuth) {
		t.Fatalf("clientHello got %v want ERR_AUTH", err)
	}
	select {
	case sent := <-sawAuth:
		if sent {
			t.Fatal("client sent AUTH on the wire")
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for stub server")
	}
}

func TestAuthorizedHelloRelaysBytes(t *testing.T) {
	upWant := []byte("hello-up-auth")
	downWant := []byte("hello-down-auth")
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

	dir := t.TempDir()
	priv, pubLine := writeEd25519Key(t, dir, "id_ed25519")
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = destLn.Addr().String()
	scfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	scfg.AuthFailDelay = config.Duration(authFailDelay)
	_, addr, _ := startRelayCfg(t, scfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ccfg := authClient(addr, destLn.Addr().String(), priv)
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()
	if _, err := inW.Write(upWant); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()
	gotDown, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
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
	case gotUp = <-gotUpCh:
	case <-ctx.Done():
		t.Fatal("dest timeout")
	}
	if !bytes.Equal(gotUp, upWant) {
		t.Fatalf("up %q", gotUp)
	}
	if !bytes.Equal(gotDown, downWant) {
		t.Fatalf("down %q", gotDown)
	}
}

func TestResumeTokenAloneOrWrongKeyERRAuth(t *testing.T) {
	dest := startHoldDest(t)
	dir := t.TempDir()
	priv, pubLine := writeEd25519Key(t, dir, "good")
	otherPriv, _ := writeEd25519Key(t, dir, "other")
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = dest
	scfg.AllowDestinations = []string{dest, "*"}
	scfg.Transports = []string{"tcp"}
	scfg.HoldTimeout = config.Duration(10 * time.Second)
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	scfg.AuthFailDelay = config.Duration(authFailDelay)
	_, addr, _ := startRelayCfg(t, scfg)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, hello, err := rawHelloAuth(ctx, addr, dest, priv, "alice")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// 1. FEAT-PERF-03 Fast 3-RTT: Token alone with zero client private key material
	// MUST succeed directly with RESUME_OK without triggering challenge.
	rok := rawResumeAuthOK(t, ctx, addr, hello.SessionID, hello.ResumeToken, dest, "")
	if rok.SessionID != hello.SessionID {
		t.Fatalf("token alone resume: got session %s want %s", rok.SessionID, hello.SessionID)
	}
	if rok.ResumeToken == "" || rok.ResumeToken == hello.ResumeToken {
		t.Fatalf("token was not rotated on resume: got %s", rok.ResumeToken)
	}

	// 2. Fallback Path: Invalid token with wrong key triggers fallback and FAILS with ERR_AUTH.
	badToken := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xbb}, 32))
	start := time.Now()
	fail := rawResumeAuthFail(t, ctx, addr, hello.SessionID, badToken, dest, otherPriv)
	if fail.Code != proto.CodeAuth {
		t.Fatalf("wrong key fallback: got %s want %s", fail.Code, proto.CodeAuth)
	}
	if time.Since(start) < authFailDelay {
		t.Fatalf("fallback failure too fast")
	}

	// 3. Fallback Recovery: Invalid token with good key triggers fallback and SUCCEEDS with re-seeded token.
	recovered := rawResumeAuthOK(t, ctx, addr, hello.SessionID, badToken, dest, priv)
	if recovered.ResumeToken == "" || recovered.ResumeToken == badToken {
		t.Fatalf("recovered token invalid: %s", recovered.ResumeToken)
	}

	// 4. Fast-path resume using the freshly recovered token alone.
	rok2 := rawResumeAuthOK(t, ctx, addr, hello.SessionID, recovered.ResumeToken, dest, "")
	if rok2.SessionID != hello.SessionID {
		t.Fatalf("second resume session mismatch: got %s", rok2.SessionID)
	}
}

func TestResumeFastToken3RTTDirect(t *testing.T) {
	dest := startHoldDest(t)
	dir := t.TempDir()
	priv, pubLine := writeEd25519Key(t, dir, "good")
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = dest
	scfg.AllowDestinations = []string{dest, "*"}
	scfg.Transports = []string{"tcp"}
	scfg.HoldTimeout = config.Duration(10 * time.Second)
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	_, addr, _ := startRelayCfg(t, scfg)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, hello, err := rawHelloAuth(ctx, addr, dest, priv, "alice")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// Connect using clientResume directly and verify it completes without error
	cliCfg := config.DefaultClient()
	cliCfg.Server = addr
	cliCfg.Transport = "tcp"
	cliCfg.StrictHostKeyChecking = "no"
	cliCfg.IdentityFiles = []string{priv}

	rconn, rok, err := clientResume(ctx, cliCfg, hello.SessionID, hello.ResumeToken, 0)
	if err != nil {
		t.Fatalf("clientResume failed: %v", err)
	}
	defer rconn.Close()
	if rok.SessionID != hello.SessionID {
		t.Fatalf("session id mismatch: got %s", rok.SessionID)
	}
	if rok.ResumeToken == "" || rok.ResumeToken == hello.ResumeToken {
		t.Fatalf("token rotation expected, got %s", rok.ResumeToken)
	}
}

func TestAuthorizedResumeSameKeyByteExact(t *testing.T) {
	const n = 256 << 10
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

	dir := t.TempDir()
	priv, pubLine := writeEd25519Key(t, dir, "id_ed25519")
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = destLn.Addr().String()
	scfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	scfg.Transports = []string{"tcp"}
	scfg.HoldTimeout = config.Duration(20 * time.Second)
	scfg.IdleTimeout = config.Duration(30 * time.Second)
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	scfg.AuthFailDelay = config.Duration(authFailDelay)
	srv, relayAddr, _ := startRelayCfg(t, scfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ccfg := authClient(relayAddr, destLn.Addr().String(), priv)
	ccfg.ReconnectMaxElapsed = config.Duration(15 * time.Second)
	ccfg.ReconnectBackoff = []string{"20ms", "50ms", "100ms"}

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
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
			if !dropped && have >= 32*1024 {
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
	if len(gotUp) != n || len(gotDown) != n {
		t.Fatalf("up=%d down=%d want %d", len(gotUp), len(gotDown), n)
	}
	checkPattern(t, gotUp)
	checkPattern(t, gotDown)
	if sha256.Sum256(gotUp) != upHash || sha256.Sum256(gotDown) != downHash {
		t.Fatal("SHA-256 mismatch")
	}
}

func authClient(server, dest, identity string) config.Client {
	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = server
	ccfg.Destination = dest
	ccfg.Transport = "tcp"
	ccfg.AuthMethod = auth.MethodPublicKey
	ccfg.AuthUser = "alice"
	ccfg.IdentityFiles = []string{identity}
	return ccfg
}

func writeEd25519Key(t *testing.T, dir, name string) (privPath, pubLine string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return path, pubLine
}

func rawHelloAuth(ctx context.Context, addr, dest, identity, user string) (transport.Conn, proto.HelloOK, error) {
	cfg := config.DefaultClient()
	cfg.Server = addr
	cfg.Destination = dest
	cfg.Transport = "tcp"
	cfg.StrictHostKeyChecking = "no"
	cfg.AuthMethod = auth.MethodPublicKey
	cfg.AuthUser = user
	if identity != "" {
		cfg.IdentityFiles = []string{identity}
	}
	return clientHello(ctx, cfg)
}

func rawResumeAuth(t *testing.T, ctx context.Context, addr, sessionID, token, dest, identity string) (proto.Type, proto.ResumeOK, proto.Fail) {
	t.Helper()
	conn, err := transport.DialTCP(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// 1. KEX
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
	if reply.Type != proto.TypeKexReply {
		t.Fatalf("expected KEX_REPLY, got %v", reply.Type)
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
		Transport: []string{"tcp"}, DownAcked: 0, ClientNonce: nonce,
	}
	var a auth.Authenticator
	if identity != "" {
		a = auth.New(auth.Config{Method: auth.MethodPublicKey, User: "alice", IdentityFiles: []string{identity}})
		offer, err := a.Respond(auth.Challenge{Destination: dest, ClientNonce: nonce})
		if err != nil {
			t.Fatal(err)
		}
		msg.Auth = offer
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
	if reply.Type == proto.TypeAuthOK {
		if identity != "" {
			ch := auth.Challenge{
				SessionID: sessionID, Destination: dest, ClientNonce: nonce,
				Canonical: fr.Payload, Offer: msg.Auth,
			}
			if err := completeClientAuth(cipherConn, a, ch, reply); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := cipherConn.WriteFrame(proto.Frame{Type: proto.TypeAuth, Payload: []byte(`{"sig":""}`)}); err != nil {
				t.Fatal(err)
			}
		}
		reply, err = cipherConn.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
	}
	if reply.Type == proto.TypeResumeOK {
		var ok proto.ResumeOK
		if err := proto.UnmarshalPayload(reply, &ok); err != nil {
			t.Fatal(err)
		}
		return reply.Type, ok, proto.Fail{}
	}
	var fail proto.Fail
	_ = proto.UnmarshalPayload(reply, &fail)
	return reply.Type, proto.ResumeOK{}, fail
}

func rawResumeAuthFail(t *testing.T, ctx context.Context, addr, sessionID, token, dest, identity string) proto.Fail {
	t.Helper()
	typ, _, fail := rawResumeAuth(t, ctx, addr, sessionID, token, dest, identity)
	if typ != proto.TypeResumeFail && typ != proto.TypeErr {
		t.Fatalf("got %s want ERR", typ)
	}
	return fail
}

func rawResumeAuthOK(t *testing.T, ctx context.Context, addr, sessionID, token, dest, identity string) proto.ResumeOK {
	t.Helper()
	typ, ok, fail := rawResumeAuth(t, ctx, addr, sessionID, token, dest, identity)
	if typ != proto.TypeResumeOK {
		t.Fatalf("got %s (code=%s msg=%s) want RESUME_OK", typ, fail.Code, fail.Msg)
	}
	return ok
}

type writeRecordConn struct {
	writes []proto.Frame
}

func (c *writeRecordConn) ReadFrame() (proto.Frame, error) { return proto.Frame{}, io.EOF }
func (c *writeRecordConn) WriteFrame(f proto.Frame) error {
	c.writes = append(c.writes, f)
	return nil
}
func (c *writeRecordConn) SetDeadline(time.Time) error { return nil }
func (c *writeRecordConn) LocalAddr() net.Addr         { return nil }
func (c *writeRecordConn) RemoteAddr() net.Addr        { return nil }
func (c *writeRecordConn) Kind() transport.Kind        { return transport.KindTCP }
func (c *writeRecordConn) Close() error                { return nil }
func (c *writeRecordConn) ResetReader()                {}

func startRelayAgentSocket(t *testing.T, ag agent.Agent) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = agent.ServeAgent(ag, c)
			}(conn)
		}
	}()
	return sock, func() {
		_ = ln.Close()
		<-done
	}
}

func TestClientAuthViaAgentNoDiskFiles(t *testing.T) {
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
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	keyring := agent.NewKeyring()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "agent-only-key"}); err != nil {
		t.Fatal(err)
	}
	sock, cleanup := startRelayAgentSocket(t, keyring)
	defer cleanup()

	signer, _ := ssh.NewSignerFromKey(priv)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	dir := t.TempDir()
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = destLn.Addr().String()
	scfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	_, addr, _ := startRelayCfg(t, scfg)

	t.Setenv("RELAY_TEST_IDENTITY", filepath.Join(dir, "nonexistent"))

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = addr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.AuthSock = sock
	ccfg.IdentityFiles = nil // ZERO files on disk

	payload := bytes.Repeat([]byte("hello-agent-tunnel\n"), 1000)
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = RunClient(ctx, ccfg, bytes.NewReader(payload), &outBuf, logging.New(io.Discard, "error", "text"))
	if err != nil {
		t.Fatalf("RunClient with agent failed: %v", err)
	}

	if !bytes.Equal(outBuf.Bytes(), payload) {
		t.Fatalf("data mismatch: got %d bytes, want %d bytes", outBuf.Len(), len(payload))
	}
}

func TestClientAuthViaAgentPassphraseProtectedKey(t *testing.T) {
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
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	dir := t.TempDir()
	privPath := filepath.Join(dir, "id_enc_relay")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "secretpass123", "-f", privPath, "-C", "enc@relay")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}

	pubBytes, err := os.ReadFile(privPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, pubBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	encBytes, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	rawPriv, err := ssh.ParseRawPrivateKeyWithPassphrase(encBytes, []byte("secretpass123"))
	if err != nil {
		t.Fatal(err)
	}

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: rawPriv, Comment: privPath}); err != nil {
		t.Fatal(err)
	}
	sock, cleanup := startRelayAgentSocket(t, keyring)
	defer cleanup()

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = destLn.Addr().String()
	scfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	_, addr, _ := startRelayCfg(t, scfg)

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = addr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.AuthSock = sock
	ccfg.IdentityFiles = []string{privPath} // Points to encrypted file on disk!

	payload := []byte("encrypted-key-delegated-to-agent-test")
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = RunClient(ctx, ccfg, bytes.NewReader(payload), &outBuf, logging.New(io.Discard, "error", "text"))
	if err != nil {
		t.Fatalf("RunClient with passphrase key delegated to agent failed: %v", err)
	}
	if !bytes.Equal(outBuf.Bytes(), payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestClientAuthAgentStaleSocketFallbackToDisk(t *testing.T) {
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
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	dir := t.TempDir()
	priv, pubLine := writeEd25519Key(t, dir, "id_disk_fallback")
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = destLn.Addr().String()
	scfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	_, addr, _ := startRelayCfg(t, scfg)

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = addr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.AuthSock = "/tmp/nonexistent-stale-agent-sock-" + t.Name() + ".sock"
	ccfg.IdentityFiles = []string{priv}

	payload := []byte("stale-agent-socket-fallback-success")
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = RunClient(ctx, ccfg, bytes.NewReader(payload), &outBuf, logging.New(io.Discard, "error", "text"))
	if err != nil {
		t.Fatalf("RunClient fallback on stale agent socket failed: %v", err)
	}
	if !bytes.Equal(outBuf.Bytes(), payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestClientAuthViaRealSSHAgentProcess(t *testing.T) {
	if _, err := exec.LookPath("ssh-agent"); err != nil {
		t.Skip("ssh-agent binary not found in PATH")
	}
	if _, err := exec.LookPath("ssh-add"); err != nil {
		t.Skip("ssh-add binary not found in PATH")
	}

	dir := t.TempDir()
	privPath := filepath.Join(dir, "id_real_agent")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", privPath, "-C", "real-agent-test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}

	// Start real ssh-agent process
	agentSock := filepath.Join(dir, "real-agent.sock")
	agentCmd := exec.Command("ssh-agent", "-a", agentSock, "-d")
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("failed to start ssh-agent: %v", err)
	}
	defer func() {
		_ = agentCmd.Process.Kill()
		_ = agentCmd.Wait()
	}()

	// Wait for socket to become available
	var conn net.Conn
	var err error
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		conn, err = net.Dial("unix", agentSock)
		if err == nil {
			conn.Close()
			break
		}
	}
	if err != nil {
		t.Fatalf("failed to connect to real ssh-agent socket: %v", err)
	}

	// Add key using ssh-add
	addCmd := exec.Command("ssh-add", privPath)
	addCmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+agentSock)
	if out, err := addCmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add failed: %v: %s", err, out)
	}

	// Now remove private key from disk to ensure client has NO file on disk!
	if err := os.Remove(privPath); err != nil {
		t.Fatal(err)
	}

	// Destination echo server
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
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	pubBytes, err := os.ReadFile(privPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, pubBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = destLn.Addr().String()
	scfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	_, addr, _ := startRelayCfg(t, scfg)

	t.Setenv("RELAY_TEST_IDENTITY", filepath.Join(dir, "nonexistent"))

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = addr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.AuthSock = agentSock
	ccfg.IdentityFiles = nil // No files on disk!

	payload := []byte("real-openssh-agent-process-verification-success")
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = RunClient(ctx, ccfg, bytes.NewReader(payload), &outBuf, logging.New(io.Discard, "error", "text"))
	if err != nil {
		t.Fatalf("RunClient with real ssh-agent failed: %v", err)
	}
	if !bytes.Equal(outBuf.Bytes(), payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestClientAuthViaAgentResumeFastAndFallback(t *testing.T) {
	dest := startHoldDest(t)
	dir := t.TempDir()

	keyring := agent.NewKeyring()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "resume-agent-key"}); err != nil {
		t.Fatal(err)
	}
	sock, cleanup := startRelayAgentSocket(t, keyring)
	defer cleanup()

	signer, _ := ssh.NewSignerFromKey(priv)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.DefaultDestination = dest
	scfg.AllowDestinations = []string{dest, "*"}
	scfg.Transports = []string{"tcp"}
	scfg.HoldTimeout = config.Duration(10 * time.Second)
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = ak
	_, addr, _ := startRelayCfg(t, scfg)

	t.Setenv("RELAY_TEST_IDENTITY", filepath.Join(dir, "nonexistent"))

	cliCfg := config.DefaultClient()
	cliCfg.Server = addr
	cliCfg.Destination = dest
	cliCfg.Transport = "tcp"
	cliCfg.StrictHostKeyChecking = "no"
	cliCfg.AuthSock = sock
	cliCfg.IdentityFiles = nil // Pure agent

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Initial connect via agent
	conn, hello, err := clientHello(ctx, cliCfg)
	if err != nil {
		t.Fatalf("initial clientHello via agent failed: %v", err)
	}
	_ = conn.Close()

	// 1. Fast 3-RTT resume with valid token via agent
	rconn1, rok1, err := clientResume(ctx, cliCfg, hello.SessionID, hello.ResumeToken, 0)
	if err != nil {
		t.Fatalf("fast clientResume via agent failed: %v", err)
	}
	_ = rconn1.Close()
	if rok1.SessionID != hello.SessionID {
		t.Fatalf("session id mismatch: got %s", rok1.SessionID)
	}
	if rok1.ResumeToken == "" || rok1.ResumeToken == hello.ResumeToken {
		t.Fatalf("token rotation expected, got %s", rok1.ResumeToken)
	}

	// 2. Cryptographic fallback resume with stale token via agent
	rconn2, rok2, err := clientResume(ctx, cliCfg, hello.SessionID, "stale-corrupted-token", 0)
	if err != nil {
		t.Fatalf("fallback clientResume via agent failed: %v", err)
	}
	_ = rconn2.Close()
	if rok2.SessionID != hello.SessionID {
		t.Fatalf("fallback session id mismatch: got %s", rok2.SessionID)
	}
}
