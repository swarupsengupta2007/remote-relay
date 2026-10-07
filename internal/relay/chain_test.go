package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
	"golang.org/x/crypto/ssh/knownhosts"
)

func chainServerCfg(dest string) config.Server {
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.UDPListen = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.LogLevel = "error"
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.HoldTimeout = config.Duration(30 * time.Second)
	cfg.MaxConnsPerIP = 256
	cfg.Splice = false
	return cfg
}

// startChain starts nHops relay servers innermost-first so each intermediate
// can name the remaining path in allow_relay_hops. Index 0 is the jumphost
// the originator dials; the last is the terminal (empty allow_relay_hops).
func startChain(t *testing.T, nHops int, dest string) (head string, srvs []*Server) {
	t.Helper()
	if nHops < 1 {
		t.Fatal("nHops must be >= 1")
	}
	srvs = make([]*Server, nHops)
	for i := nHops - 1; i >= 0; i-- {
		cfg := chainServerCfg(dest)
		if i < nHops-1 {
			allow := make([]string, 0, nHops-1-i)
			for j := i + 1; j < nHops; j++ {
				allow = append(allow, srvs[j].Addr())
			}
			cfg.AllowRelayHops = allow
			cfg.MaxChainDepth = nHops
		}
		srv, _, _ := startRelayCfg(t, cfg)
		srvs[i] = srv
	}
	return srvs[0].Addr(), srvs
}

func chainClientCfg(terminal, dest string, jumphosts []string) config.Client {
	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = terminal
	ccfg.Destination = dest
	ccfg.Transport = "tcp"
	ccfg.Jumphost = jumphosts
	ccfg.LogLevel = "error"
	ccfg.ReconnectMaxElapsed = config.Duration(20 * time.Second)
	ccfg.ReconnectBackoff = []string{"20ms", "50ms", "100ms"}
	return ccfg
}

func sendChainRaw(t *testing.T, addr string, ch proto.ChainHello) proto.Fail {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
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
	if reply.Type != proto.TypeKexReply {
		t.Fatalf("expected KEX_REPLY, got %s", reply.Type)
	}
	c2s, s2c, err := kexCli.ProcessReply(reply.Payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := kex.NewCipherConn(conn, c2s, s2c)
	if err != nil {
		t.Fatal(err)
	}
	fr, err := proto.MarshalFrame(proto.TypeChain, ch)
	if err != nil {
		t.Fatal(err)
	}
	if err := cipher.WriteFrame(fr); err != nil {
		t.Fatal(err)
	}
	reply, err = cipher.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != proto.TypeErr {
		t.Fatalf("expected ERR, got %s", reply.Type)
	}
	var fail proto.Fail
	if err := proto.UnmarshalPayload(reply, &fail); err != nil {
		t.Fatal(err)
	}
	return fail
}

func writeKnownHosts(t *testing.T, addr string, pub ed25519.PublicKey) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, sshPub)
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func kexTranscript(t *testing.T) (init, reply []byte, nonce string, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := kex.NewServerSession(priv)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := kex.NewClientSession()
	if err != nil {
		t.Fatal(err)
	}
	init = cli.InitPayload()
	reply, _, _, err = srv.ProcessInit(init)
	if err != nil {
		t.Fatal(err)
	}
	return init, reply, base64.StdEncoding.EncodeToString(reply[32:48]), pub
}

func TestReconnectableChainErrors(t *testing.T) {
	for _, err := range []error{proto.ErrChainTooLong, proto.ErrChainLoop, proto.ErrHopForbidden} {
		if reconnectable(err) {
			t.Errorf("%v is reconnectable, want immediate surface to ssh", err)
		}
	}
}

func TestNonceBindingKexEqualsAuth(t *testing.T) {
	dest := echoDest(t)
	_, addr, _ := startRelay(t, dest)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
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
	if reply.Type != proto.TypeKexReply {
		t.Fatalf("got %s", reply.Type)
	}
	kexReply := append([]byte(nil), reply.Payload...)
	want := base64.StdEncoding.EncodeToString(kexReply[32:48])
	c2s, s2c, err := kexCli.ProcessReply(kexReply, nil)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := kex.NewCipherConn(conn, c2s, s2c)
	if err != nil {
		t.Fatal(err)
	}

	a := clientAuth(config.DefaultClient())
	if c, ok := a.(io.Closer); ok {
		defer c.Close()
	}
	nonce, err := proto.RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	offer, err := a.Respond(auth.Challenge{Destination: dest, ClientNonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	hello := proto.Hello{V: 1, Transport: []string{"tcp"}, Destination: dest, ClientNonce: nonce, Auth: offer}
	fr, err := proto.MarshalFrame(proto.TypeHello, hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := cipher.WriteFrame(fr); err != nil {
		t.Fatal(err)
	}
	reply, err = cipher.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != proto.TypeAuthOK {
		t.Fatalf("HELLO: got %s, want AUTH_OK", reply.Type)
	}
	var aok proto.AuthOK
	if err := proto.UnmarshalPayload(reply, &aok); err != nil {
		t.Fatal(err)
	}
	if aok.ServerNonce != want {
		t.Fatalf("HELLO AUTH_OK.ServerNonce = %s, want KEX_REPLY[32:48] %s", aok.ServerNonce, want)
	}
	if err := completeClientAuth(cipher, a, auth.Challenge{
		Destination: dest, ClientNonce: nonce, Canonical: fr.Payload, Offer: offer,
	}, reply); err != nil {
		t.Fatal(err)
	}
	reply, err = cipher.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != proto.TypeHelloOK {
		t.Fatalf("got %s, want HELLO_OK", reply.Type)
	}
	var hok proto.HelloOK
	if err := proto.UnmarshalPayload(reply, &hok); err != nil {
		t.Fatal(err)
	}
	if hok.ServerNonce != want {
		t.Fatalf("HELLO_OK.ServerNonce = %s, want %s", hok.ServerNonce, want)
	}

	_ = cipher.Close()

	conn2, err := transport.DialTCP(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	kex2, err := kex.NewClientSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := conn2.WriteFrame(proto.Frame{Type: proto.TypeKexInit, Payload: kex2.InitPayload()}); err != nil {
		t.Fatal(err)
	}
	reply, err = conn2.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	resumeKex := append([]byte(nil), reply.Payload...)
	wantResume := base64.StdEncoding.EncodeToString(resumeKex[32:48])
	c2s, s2c, err = kex2.ProcessReply(resumeKex, nil)
	if err != nil {
		t.Fatal(err)
	}
	cipher2, err := kex.NewCipherConn(conn2, c2s, s2c)
	if err != nil {
		t.Fatal(err)
	}
	rnonce, err := proto.RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	roffer, err := a.Respond(auth.Challenge{Destination: dest, ClientNonce: rnonce})
	if err != nil {
		t.Fatal(err)
	}
	rmsg := proto.Resume{
		V: 1, SessionID: hok.SessionID, ResumeToken: "not-the-token",
		Transport: []string{"tcp"}, ClientNonce: rnonce, Auth: roffer,
	}
	rfr, err := proto.MarshalFrame(proto.TypeResume, rmsg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cipher2.WriteFrame(rfr); err != nil {
		t.Fatal(err)
	}
	reply, err = cipher2.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != proto.TypeAuthOK {
		t.Fatalf("RESUME fallback: got %s, want AUTH_OK", reply.Type)
	}
	var raok proto.AuthOK
	if err := proto.UnmarshalPayload(reply, &raok); err != nil {
		t.Fatal(err)
	}
	if raok.ServerNonce != wantResume {
		t.Fatalf("RESUME AUTH_OK.ServerNonce = %s, want KEX_REPLY[32:48] %s", raok.ServerNonce, wantResume)
	}
}

func TestChainE2EByteExactBothDirections(t *testing.T) {
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

	dest := destLn.Addr().String()
	head, srvs := startChain(t, 2, dest)
	ccfg := chainClientCfg(srvs[1].Addr(), dest, []string{head})

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
		t.Fatal("timeout")
	}
	gotUp := <-gotUpCh
	if sha256.Sum256(gotUp) != upHash {
		checkPattern(t, gotUp)
		t.Fatalf("up hash mismatch len=%d", len(gotUp))
	}
	if sha256.Sum256(gotDown) != downHash {
		checkPattern(t, gotDown)
		t.Fatalf("down hash mismatch len=%d", len(gotDown))
	}
}

func TestChainThreeHops(t *testing.T) {
	const n = 256 << 10
	upWant := makePattern(n)
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
		b, _ := io.ReadAll(c)
		gotUpCh <- b
	}()

	dest := destLn.Addr().String()
	head, srvs := startChain(t, 3, dest)
	if len(srvs[2].Config().AllowRelayHops) != 0 {
		t.Fatal("terminal must have empty allow_relay_hops")
	}
	ccfg := chainClientCfg(srvs[2].Addr(), dest, []string{head, srvs[1].Addr()})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = RunClient(ctx, ccfg, bytes.NewReader(upWant), io.Discard, logging.New(io.Discard, "error", "text"))
	if err != nil {
		t.Fatal(err)
	}
	gotUp := <-gotUpCh
	if !bytes.Equal(gotUp, upWant) {
		t.Fatalf("three-hop up mismatch got=%d want=%d", len(gotUp), len(upWant))
	}
}

func TestChainHopNotAllowed(t *testing.T) {
	var accepts atomic.Int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = c.Close()
		}
	}()
	dest := ln.Addr().String()
	srv, addr, _ := startRelayCfg(t, chainServerCfg(dest))
	if len(srv.Config().AllowRelayHops) != 0 {
		t.Fatal("default-deny expected")
	}

	start := time.Now()
	fail := sendChainRaw(t, addr, proto.ChainHello{
		V: 1, Hops: []proto.HopSpec{{Addr: "127.0.0.1:1"}},
		Destination: dest, Transport: []string{"tcp"}, ClientNonce: "AAAAAAAAAAAAAAA=",
	})
	if fail.Code != proto.CodeHopForbidden {
		t.Fatalf("got %+v, want ERR_HOP_FORBIDDEN", fail)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("policy refusal took too long; a dial leaked through")
	}
	time.Sleep(50 * time.Millisecond)
	if accepts.Load() != 0 {
		t.Fatal("destination was dialled on a default-deny CHAIN")
	}
}

func TestChainDepthExceeded(t *testing.T) {
	dest := echoDest(t)
	cfg := chainServerCfg(dest)
	cfg.AllowRelayHops = []string{"127.0.0.1:1", "127.0.0.1:2"}
	cfg.MaxChainDepth = 1
	_, addr, _ := startRelayCfg(t, cfg)
	fail := sendChainRaw(t, addr, proto.ChainHello{
		V: 1, Hops: []proto.HopSpec{{Addr: "127.0.0.1:1"}},
		Destination: dest, Transport: []string{"tcp"}, ClientNonce: "AAAAAAAAAAAAAAA=",
	})
	if fail.Code != proto.CodeChainTooLong {
		t.Fatalf("got %+v, want ERR_CHAIN_TOO_LONG", fail)
	}
}

func TestChainLoopDetected(t *testing.T) {
	dest := echoDest(t)
	cfg := chainServerCfg(dest)
	cfg.AllowRelayHops = []string{"*"}
	cfg.MaxChainDepth = 4
	_, addr, _ := startRelayCfg(t, cfg)

	t.Run("self hop", func(t *testing.T) {
		fail := sendChainRaw(t, addr, proto.ChainHello{
			V: 1, Hops: []proto.HopSpec{{Addr: addr}},
			Destination: dest, Transport: []string{"tcp"}, ClientNonce: "AAAAAAAAAAAAAAA=",
		})
		if fail.Code != proto.CodeChainLoop {
			t.Fatalf("got %+v, want ERR_CHAIN_LOOP", fail)
		}
	})
	t.Run("duplicate hops", func(t *testing.T) {
		fail := sendChainRaw(t, addr, proto.ChainHello{
			V: 1, Hops: []proto.HopSpec{{Addr: "127.0.0.1:9"}, {Addr: "127.0.0.1:9"}},
			Destination: dest, Transport: []string{"tcp"}, ClientNonce: "AAAAAAAAAAAAAAA=",
		})
		if fail.Code != proto.CodeChainLoop {
			t.Fatalf("got %+v, want ERR_CHAIN_LOOP", fail)
		}
	})
	t.Run("visited self", func(t *testing.T) {
		fail := sendChainRaw(t, addr, proto.ChainHello{
			V: 1, Hops: []proto.HopSpec{{Addr: "127.0.0.1:9"}}, Visited: []string{addr},
			Destination: dest, Transport: []string{"tcp"}, ClientNonce: "AAAAAAAAAAAAAAA=",
		})
		if fail.Code != proto.CodeChainLoop {
			t.Fatalf("got %+v, want ERR_CHAIN_LOOP", fail)
		}
	})
}

func TestChainAttestationHostKeyMismatch(t *testing.T) {
	dest := echoDest(t)
	head, srvs := startChain(t, 2, dest)
	kh := writeKnownHosts(t, head, srvs[0].HostPublicKey())
	ccfg := chainClientCfg(srvs[1].Addr(), dest, []string{head})
	ccfg.KnownHosts = kh
	ccfg.StrictHostKeyChecking = "yes"
	ccfg.ServerFingerprint = ""

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	if err == nil {
		t.Fatal("expected attestation failure for an unknown terminal host key")
	}
	if !errors.Is(err, kex.ErrHostKey) && !strings.Contains(err.Error(), "host key") {
		t.Fatalf("got %v, want host key failure", err)
	}
}

func TestChainAttestationReplay(t *testing.T) {
	init, reply, nonce, pub := kexTranscript(t)
	fp := kex.FingerprintSHA256(pub)
	hops := []proto.HopSpec{
		{Addr: "j1.example.com:7443"},
		{Addr: "s.example.com:7443", Fp: fp},
	}
	other, err := proto.RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	if other == nonce {
		t.Fatal("unlucky nonce collision")
	}
	cfg := config.DefaultClient()
	cfg.StrictHostKeyChecking = "yes"
	aok := proto.AuthOK{
		SessionID:   "s-1",
		ServerNonce: other,
		Challenge:   base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)),
		Destination: "127.0.0.1:22",
		Hop:         2,
		HelloJSON:   `{"clientNonce":"n","destination":"127.0.0.1:22"}`,
		Attest: &proto.HopAttestation{
			Addr:     "s.example.com:7443",
			KexInit:  base64.StdEncoding.EncodeToString(init),
			KexReply: base64.StdEncoding.EncodeToString(reply),
		},
	}
	_, err = verifyRelayedChallenge(cfg, hops, "127.0.0.1:22", nil, aok)
	if err == nil {
		t.Fatal("stale attestation + fabricated AUTH_OK must be rejected")
	}
	if !strings.Contains(err.Error(), "attestation nonce") {
		t.Fatalf("got %v, want nonce-binding failure", err)
	}
}

func TestChainDestinationMismatch(t *testing.T) {
	cfg := config.DefaultClient()
	hops := []proto.HopSpec{{Addr: "j1:7443"}, {Addr: "s:7443"}}
	canonical := []byte(`{"clientNonce":"cn","destination":"127.0.0.1:22"}`)
	ch := auth.Challenge{
		SessionID: "s", Destination: "10.0.0.1:22", ClientNonce: "cn",
		ServerNonce: "sn", Canonical: canonical,
	}
	aok := proto.AuthOK{
		SessionID: "s", ServerNonce: "sn",
		Challenge:   base64.StdEncoding.EncodeToString(auth.DeriveChallenge(ch)),
		Destination: "10.0.0.1:22",
		Hop:         1,
		HelloJSON:   string(canonical),
	}
	_, err := verifyRelayedChallenge(cfg, hops, "127.0.0.1:22", nil, aok)
	if err == nil {
		t.Fatal("expected destination mismatch")
	}
	if !errors.Is(err, proto.ErrAuth) {
		t.Fatalf("got %v, want ERR_AUTH", err)
	}
}

func TestChainVersionSkewFailClosed(t *testing.T) {
	var accepts atomic.Int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = c.Close()
		}
	}()
	dest := ln.Addr().String()
	_, addr, _ := startRelayCfg(t, chainServerCfg(dest))
	fail := sendChainRaw(t, addr, proto.ChainHello{
		V: 1, Hops: []proto.HopSpec{{Addr: "127.0.0.1:1"}},
		Destination: dest, Transport: []string{"tcp"}, ClientNonce: "AAAAAAAAAAAAAAA=",
	})
	if fail.Code != proto.CodeHopForbidden && fail.Code != proto.CodeProto {
		t.Fatalf("got %+v, want fail-closed (HOP_FORBIDDEN or PROTO)", fail)
	}
	time.Sleep(50 * time.Millisecond)
	if accepts.Load() != 0 {
		t.Fatal("TypeChain must never silently dial the destination")
	}
}

func TestChainTerminalHasNoChainCode(t *testing.T) {
	dest := echoDest(t)
	head, srvs := startChain(t, 2, dest)
	if len(srvs[1].Config().AllowRelayHops) != 0 {
		t.Fatal("terminal allow_relay_hops must be empty")
	}
	ccfg := chainClientCfg(srvs[1].Addr(), dest, []string{head})
	payload := []byte("terminal-hello")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := RunClient(ctx, ccfg, bytes.NewReader(payload), &out, logging.New(io.Discard, "error", "text")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("got %q", out.Bytes())
	}
	fail := sendChainRaw(t, srvs[1].Addr(), proto.ChainHello{
		V: 1, Hops: []proto.HopSpec{{Addr: "127.0.0.1:1"}},
		Destination: dest, Transport: []string{"tcp"}, ClientNonce: "AAAAAAAAAAAAAAA=",
	})
	if fail.Code != proto.CodeHopForbidden {
		t.Fatalf("terminal accepted CHAIN: %+v", fail)
	}
}

func TestChainHalfClosePropagation(t *testing.T) {
	gotEOF := make(chan struct{}, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := c.(*net.TCPConn)
		_, _ = io.Copy(io.Discard, tc)
		gotEOF <- struct{}{}
		_, _ = tc.Write([]byte("got-eof"))
		_ = tc.CloseWrite()
	}()

	dest := ln.Addr().String()
	head, srvs := startChain(t, 2, dest)
	ccfg := chainClientCfg(srvs[1].Addr(), dest, []string{head})
	inR, inW := io.Pipe()
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, ccfg, inR, &out, logging.New(io.Discard, "error", "text"))
	}()
	if _, err := inW.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()
	select {
	case <-gotEOF:
	case <-ctx.Done():
		t.Fatal("destination never saw CloseWrite")
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("client timeout")
	}
	if out.String() != "got-eof" {
		t.Fatalf("stdout = %q, want got-eof", out.String())
	}
}

func invalidateResumeTokens(s *Server) {
	s.livesMu.Lock()
	ids := make([]string, 0, len(s.lives))
	for id := range s.lives {
		ids = append(ids, id)
	}
	s.livesMu.Unlock()
	for _, id := range ids {
		_, _ = s.store.ForceResumeToken(id)
		s.store.ConfirmToken(id)
		_, _ = s.store.ForceResumeToken(id)
		s.store.ConfirmToken(id)
	}
}

func TestChainResumeInnerHopOnly(t *testing.T) {
	const n = 256 << 10
	upWant := makePattern(n)
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
		b, _ := io.ReadAll(c)
		gotUpCh <- b
	}()

	dest := destLn.Addr().String()
	head, srvs := startChain(t, 2, dest)
	ccfg := chainClientCfg(srvs[1].Addr(), dest, []string{head})

	inR, inW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, ccfg, inR, io.Discard, logging.New(io.Discard, "error", "text"))
	}()

	if _, err := inW.Write(upWant[:len(upWant)/2]); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, func() bool { return srvs[0].sessionCount() == 1 && srvs[1].sessionCount() == 1 })
	relays0 := srvs[0].chainAuthRelays.Load()
	srvs[1].dropLiveTransports()
	if _, err := inW.Write(upWant[len(upWant)/2:]); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("client: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	gotUp := <-gotUpCh
	if !bytes.Equal(gotUp, upWant) {
		t.Fatalf("inner-kill mismatch got=%d want=%d", len(gotUp), len(upWant))
	}
	if srvs[0].chainAuthRelays.Load() != relays0 {
		t.Fatalf("Case B must not relay signatures, relays=%d", srvs[0].chainAuthRelays.Load()-relays0)
	}
}

func TestChainStaleTokenInnerRelaysSignature(t *testing.T) {
	const n = 256 << 10
	upWant := makePattern(n)
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
		b, _ := io.ReadAll(c)
		gotUpCh <- b
	}()

	dest := destLn.Addr().String()
	head, srvs := startChain(t, 2, dest)
	ccfg := chainClientCfg(srvs[1].Addr(), dest, []string{head})

	inR, inW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, ccfg, inR, io.Discard, logging.New(io.Discard, "error", "text"))
	}()

	if _, err := inW.Write(upWant[:len(upWant)/2]); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, func() bool { return srvs[0].sessionCount() == 1 && srvs[1].sessionCount() == 1 })
	relays0 := srvs[0].chainAuthRelays.Load()
	invalidateResumeTokens(srvs[1])
	srvs[1].dropLiveTransports()
	if _, err := inW.Write(upWant[len(upWant)/2:]); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("client: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	gotUp := <-gotUpCh
	if !bytes.Equal(gotUp, upWant) {
		t.Fatalf("Case C mismatch got=%d want=%d", len(gotUp), len(upWant))
	}
	if srvs[0].chainAuthRelays.Load() <= relays0 {
		t.Fatal("expected at least one relayed inner signature")
	}
}

func TestChainCaseCDuringSwitchRejected(t *testing.T) {
	p := &pump{}
	p.quiesce.Store(true)
	if p.holdChainAuth() {
		t.Fatal("must not start Case C while SWITCH is quiescing")
	}
	p.quiesce.Store(false)
	if !p.holdChainAuth() {
		t.Fatal("Case C should start when idle")
	}
	if p.holdChainAuth() {
		t.Fatal("second Case C must not interleave")
	}
	p.releaseChainAuth()
	if !p.holdChainAuth() {
		t.Fatal("Case C should start after release")
	}
}

func TestChainHopTransportPreference(t *testing.T) {
	if got := chainHopTransport(proto.HopSpec{}, nil); got != nil {
		t.Fatalf("empty: %v", got)
	}
	got := chainHopTransport(proto.HopSpec{Transport: []string{"kcp"}}, nil)
	if strings.Join(got, ",") != "kcp" {
		t.Fatalf("kcp: %v", got)
	}
	got = chainHopTransport(proto.HopSpec{Transport: []string{"quic"}}, nil)
	if strings.Join(got, ",") != "quic,kcp" {
		t.Fatalf("quic expands: %v", got)
	}
}

func TestChainPerHopTransport(t *testing.T) {
	// Hop 1 upgrades to KCP (originator SWITCH, not the nested bridge).
	// Hop 2 stays TCP: nested upgrade across io.Pipe is a separate risk.
	dest := echoDest(t)
	termCfg := chainServerCfg(dest)
	_, termAddr, _ := startRelayCfg(t, termCfg)

	jCfg := chainServerCfg(dest)
	jCfg.Transports = []string{"kcp"}
	jCfg.UDPListen = "127.0.0.1:0"
	jCfg.ProbeTimeout = config.Duration(400 * time.Millisecond)
	jCfg.ProbeAttempts = 2
	jCfg.KeepaliveInterval = config.Duration(200 * time.Millisecond)
	jCfg.AllowRelayHops = []string{termAddr}
	jCfg.MaxChainDepth = 2
	j, head, _ := startRelayCfg(t, jCfg)

	ccfg := chainClientCfg(termAddr, dest, []string{head + "?transport=kcp"})
	ccfg.Transport = "kcp"
	ccfg.ProbeTimeout = config.Duration(400 * time.Millisecond)

	payload := makePattern(256 << 10)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inR, inW := io.Pipe()
	var out bytes.Buffer
	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, ccfg, inR, &out, logging.New(io.Discard, "error", "text"))
	}()
	waitUntil(t, 5*time.Second, func() bool { return j.sessionCount() == 1 })
	waitKind(t, j, transport.KindKCP, 8*time.Second)
	if _, err := inW.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("client: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("echo mismatch got=%d want=%d", out.Len(), len(payload))
	}
}

func TestChainResumeBothHops(t *testing.T) {
	const n = 256 << 10
	upWant := makePattern(n)
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
		b, _ := io.ReadAll(c)
		gotUpCh <- b
	}()

	dest := destLn.Addr().String()
	head, srvs := startChain(t, 2, dest)
	ccfg := chainClientCfg(srvs[1].Addr(), dest, []string{head})

	inR, inW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, ccfg, inR, io.Discard, logging.New(io.Discard, "error", "text"))
	}()

	if _, err := inW.Write(upWant[:len(upWant)/2]); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, func() bool { return srvs[0].sessionCount() == 1 && srvs[1].sessionCount() == 1 })
	srvs[1].dropLiveTransports()
	srvs[0].dropLiveTransports()
	if _, err := inW.Write(upWant[len(upWant)/2:]); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("client: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	gotUp := <-gotUpCh
	if !bytes.Equal(gotUp, upWant) {
		t.Fatalf("both-hops mismatch got=%d want=%d", len(gotUp), len(upWant))
	}
}

func TestChainResumeOuterHopOnly(t *testing.T) {
	const n = 256 << 10
	upWant := makePattern(n)
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
		b, _ := io.ReadAll(c)
		gotUpCh <- b
	}()

	dest := destLn.Addr().String()
	head, srvs := startChain(t, 2, dest)
	ccfg := chainClientCfg(srvs[1].Addr(), dest, []string{head})

	inR, inW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, ccfg, inR, io.Discard, logging.New(io.Discard, "error", "text"))
	}()

	if _, err := inW.Write(upWant[:len(upWant)/2]); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, func() bool { return srvs[0].sessionCount() == 1 && srvs[1].sessionCount() == 1 })
	srvs[0].dropLiveTransports()
	if _, err := inW.Write(upWant[len(upWant)/2:]); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("client: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	gotUp := <-gotUpCh
	if !bytes.Equal(gotUp, upWant) {
		t.Fatalf("outer-kill mismatch got=%d want=%d", len(gotUp), len(upWant))
	}
}

func TestChainBackpressureGlobalBudget(t *testing.T) {
	dest := startHoldDest(t)
	termCfg := chainServerCfg(dest)
	_, termAddr, _ := startRelayCfg(t, termCfg)
	jCfg := chainServerCfg(dest)
	jCfg.AllowRelayHops = []string{termAddr}
	jCfg.ChainMaxSessions = 1
	j, head, _ := startRelayCfg(t, jCfg)

	ccfg := chainClientCfg(termAddr, dest, []string{head})
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, logging.New(io.Discard, "error", "text"))
		_ = outW.Close()
		errc <- err
	}()
	go func() { _, _ = io.Copy(io.Discard, outR) }()
	waitUntil(t, 8*time.Second, func() bool { return j.sessionCount() == 1 })

	ctx2, cancel2 := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel2()
	err := RunClient(ctx2, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	if !errors.Is(err, proto.ErrNoCapacity) {
		t.Fatalf("second chain: got %v, want ERR_NO_CAPACITY", err)
	}
	if j.sessionCount() != 1 {
		t.Fatalf("existing chained session died, count=%d", j.sessionCount())
	}
	_ = inW.Close()
	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
	}
}

func TestChainOriginIPAccounting(t *testing.T) {
	cfg := chainServerCfg(echoDest(t))
	cfg.MaxConnsPerIP = 1
	cfg.MaxChainConnsPerPeer = 8
	s := NewServer(cfg, logging.New(io.Discard, "error", "text"))

	rel1, err := s.reserveChain("10.0.0.1", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	rel2, err := s.reserveChain("10.0.0.1", "192.0.2.2")
	if err != nil {
		t.Fatalf("distinct originators sharing an upstream relay must be allowed: %v", err)
	}
	if _, err := s.reserveChain("10.0.0.1", "192.0.2.1"); err == nil {
		t.Fatal("same origin IP must hit max_conns_per_ip")
	}
	rel1()
	rel2()

	cfg.MaxConnsPerIP = 64
	cfg.MaxChainConnsPerPeer = 1
	s = NewServer(cfg, logging.New(io.Discard, "error", "text"))
	rel1, err = s.reserveChain("10.0.0.1", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveChain("10.0.0.1", "192.0.2.2"); err == nil {
		t.Fatal("one upstream relay must be bounded by max_chain_conns_per_peer")
	}
	rel1()
}

func TestChainSpliceDisabled(t *testing.T) {
	ResetSplicedStats()
	dest := echoDest(t)
	head, srvs := startChain(t, 2, dest)
	ccfg := chainClientCfg(srvs[1].Addr(), dest, []string{head})
	ccfg.Splice = false
	payload := makePattern(64 << 10)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := RunClient(ctx, ccfg, bytes.NewReader(payload), &out, logging.New(io.Discard, "error", "text")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("echo mismatch len=%d", out.Len())
	}
	_, _, calls := SplicedStats()
	if calls != 0 {
		t.Fatalf("nested leg must not splice, got %d splice(2) calls", calls)
	}
}

func TestChainConcurrencyLeak(t *testing.T) {
	runtime.GC()
	base := runtime.NumGoroutine()

	dest := startEchoDest(t)
	head, srvs := startChain(t, 2, dest)
	j := srvs[0]
	terminal := srvs[1].Addr()

	const (
		nSessions = 8
		payload   = 8 << 10
	)
	upWant := makePattern(payload)
	var wg sync.WaitGroup
	var fail atomic.Int32
	ready := make(chan *io.PipeWriter, nSessions)

	for i := 0; i < nSessions; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inR, inW := io.Pipe()
			var out bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			ccfg := chainClientCfg(terminal, dest, []string{head})
			errc := make(chan error, 1)
			go func() {
				errc <- RunClient(ctx, ccfg, inR, &out, logging.New(io.Discard, "error", "text"))
			}()
			if _, err := inW.Write(upWant[:len(upWant)/2]); err != nil {
				fail.Add(1)
				t.Errorf("write: %v", err)
				_ = inW.Close()
				return
			}
			ready <- inW
			if err := <-errc; err != nil {
				fail.Add(1)
				t.Errorf("client: %v", err)
				return
			}
			if !bytes.Equal(out.Bytes(), upWant) {
				fail.Add(1)
				t.Errorf("byte mismatch got=%d", out.Len())
			}
		}()
	}

	writers := make([]*io.PipeWriter, 0, nSessions)
	deadline := time.Now().Add(10 * time.Second)
	for len(writers) < nSessions && time.Now().Before(deadline) {
		select {
		case w := <-ready:
			writers = append(writers, w)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if len(writers) != nSessions {
		t.Fatalf("only %d/%d sessions started", len(writers), nSessions)
	}
	waitUntil(t, 5*time.Second, func() bool { return j.sessionCount() >= nSessions })
	j.dropLiveTransports()
	for _, w := range writers {
		if _, err := w.Write(upWant[len(upWant)/2:]); err != nil {
			t.Errorf("write after drop: %v", err)
		}
		_ = w.Close()
	}
	wg.Wait()
	if fail.Load() != 0 {
		t.Fatalf("%d sessions failed", fail.Load())
	}
	waitUntil(t, 8*time.Second, func() bool { return j.sessionCount() == 0 && srvs[1].sessionCount() == 0 })
	if used := j.budgetUsed(); used != 0 {
		t.Fatalf("buffer leak: %d", used)
	}

	leakDeadline := time.Now().Add(4 * time.Second)
	var got int
	for {
		runtime.GC()
		got = runtime.NumGoroutine()
		if got <= base+32 || time.Now().After(leakDeadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got > base+32 {
		t.Fatalf("goroutine leak: baseline=%d now=%d", base, got)
	}
}

func TestAddrEqualWildcard(t *testing.T) {
	orig := localIPs
	localIPs = func() []net.IP { return []net.IP{net.ParseIP("10.9.9.9")} }
	defer func() { localIPs = orig }()

	if addrEqual("0.0.0.0:7443", "10.1.2.3:7443") {
		t.Fatal("wildcard bind must not match another host on the same port")
	}
	if !addrEqual("0.0.0.0:7443", "10.9.9.9:7443") {
		t.Fatal("wildcard bind must match a local address on the same port")
	}
	if !addrEqual("[::]:7443", "127.0.0.1:7443") {
		t.Fatal("wildcard bind must match loopback on the same port")
	}
	if addrEqual("0.0.0.0:7443", "10.9.9.9:8443") {
		t.Fatal("wildcard must still require the same port")
	}
	if !addrEqual("127.0.0.1:9", "127.0.0.1:9") {
		t.Fatal("exact match")
	}
}

func TestVerifyRelayedChallengeHop1(t *testing.T) {
	canonical := []byte(`{"clientNonce":"cn","destination":"127.0.0.1:22"}`)
	ch := auth.Challenge{
		SessionID: "s", Destination: "127.0.0.1:22", ClientNonce: "cn",
		ServerNonce: "sn", Canonical: canonical,
	}
	aok := proto.AuthOK{
		SessionID: "s", ServerNonce: "sn",
		Challenge:   base64.StdEncoding.EncodeToString(auth.DeriveChallenge(ch)),
		Destination: "127.0.0.1:22",
		Hop:         1,
		HelloJSON:   string(canonical),
	}
	got, err := verifyRelayedChallenge(config.DefaultClient(), []proto.HopSpec{{Addr: "j1:1"}, {Addr: "s:1"}}, "127.0.0.1:22", json.RawMessage(`{}`), aok)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "s" || got.ClientNonce != "cn" {
		t.Fatalf("%+v", got)
	}
	aok.Hop = 0
	if _, err := verifyRelayedChallenge(config.DefaultClient(), []proto.HopSpec{{Addr: "j1:1"}}, "127.0.0.1:22", nil, aok); err == nil {
		t.Fatal("hop 0 on a chained path must be refused")
	}
}
