package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/socks5"
)

// Helper to start an echo TCP listener.
func startEchoTarget(t *testing.T) (string, uint16, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32768)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)

	cleanup := func() {
		_ = ln.Close()
	}
	return ln.Addr().String(), uint16(p), cleanup
}

// 1. Happy and Sad Path: Direct connection with permitopen options on keys.
func TestRBAC_DirectPermitOpen_AllowedAndForbidden(t *testing.T) {
	dir := t.TempDir()

	dest1Addr, _, stop1 := startEchoTarget(t)
	defer stop1()
	dest2Addr, _, stop2 := startEchoTarget(t)
	defer stop2()

	// Key A: only allowed dest1
	privA, pubA := writeEd25519Key(t, dir, "id_user_a")
	lineA := fmt.Sprintf("permitopen=%q %s", dest1Addr, pubA)

	// Key B: only allowed dest2
	privB, pubB := writeEd25519Key(t, dir, "id_user_b")
	lineB := fmt.Sprintf("permitopen=%q %s", dest2Addr, pubB)

	// Key Wild: allowed 127.0.0.1:*
	privWild, pubWild := writeEd25519Key(t, dir, "id_user_wild")
	lineWild := fmt.Sprintf("permitopen=%q %s", "127.0.0.1:*", pubWild)

	akPath := filepath.Join(dir, "authorized_keys")
	akContent := strings.Join([]string{lineA, lineB, lineWild}, "\n") + "\n"
	if err := os.WriteFile(akPath, []byte(akContent), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.AllowDestinations = []string{"127.0.0.1:*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = akPath

	srv, srvAddr, cancel := startRelayCfg(t, scfg)
	defer cancel()
	_ = srv

	// Subtest 1: User A connecting to dest1 -> SUCCESS
	t.Run("UserA_Dest1_Success", func(t *testing.T) {
		ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cCancel()
		in := bytes.NewBuffer([]byte("hello dest1 from A"))
		out := &bytes.Buffer{}
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = dest1Addr
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user_a"
		ccfg.IdentityFiles = []string{privA}

		err := RunClient(ctx, ccfg, in, out, logging.New(io.Discard, "error", "text"))
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
		if out.String() != "hello dest1 from A" {
			t.Fatalf("unexpected echo output: %q", out.String())
		}
	})

	// Subtest 2: User A connecting to dest2 -> FORBIDDEN (Sad Path)
	t.Run("UserA_Dest2_Forbidden", func(t *testing.T) {
		ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cCancel()
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = dest2Addr
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user_a"
		ccfg.IdentityFiles = []string{privA}

		err := RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
		if err == nil {
			t.Fatal("expected ERR_DEST_FORBIDDEN, got nil")
		}
		if !errors.Is(err, proto.ErrDestForbidden) {
			t.Fatalf("expected ErrDestForbidden, got %v", err)
		}
	})

	// Subtest 3: User B connecting to dest2 -> SUCCESS
	t.Run("UserB_Dest2_Success", func(t *testing.T) {
		ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cCancel()
		in := bytes.NewBuffer([]byte("hello dest2 from B"))
		out := &bytes.Buffer{}
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = dest2Addr
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user_b"
		ccfg.IdentityFiles = []string{privB}

		err := RunClient(ctx, ccfg, in, out, logging.New(io.Discard, "error", "text"))
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
		if out.String() != "hello dest2 from B" {
			t.Fatalf("unexpected echo output: %q", out.String())
		}
	})

	// Subtest 4: User B connecting to dest1 -> FORBIDDEN (Sad Path)
	t.Run("UserB_Dest1_Forbidden", func(t *testing.T) {
		ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cCancel()
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = dest1Addr
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user_b"
		ccfg.IdentityFiles = []string{privB}

		err := RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
		if err == nil {
			t.Fatal("expected ERR_DEST_FORBIDDEN, got nil")
		}
		if !errors.Is(err, proto.ErrDestForbidden) {
			t.Fatalf("expected ErrDestForbidden, got %v", err)
		}
	})

	// Subtest 5 & 6: User Wild connecting to both -> SUCCESS
	t.Run("UserWild_Both_Success", func(t *testing.T) {
		for _, dest := range []string{dest1Addr, dest2Addr} {
			ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
			in := bytes.NewBuffer([]byte("test wild"))
			out := &bytes.Buffer{}
			ccfg := config.DefaultClient()
			ccfg.StrictHostKeyChecking = "no"
			ccfg.Server = srvAddr
			ccfg.Destination = dest
			ccfg.Transport = "tcp"
			ccfg.AuthMethod = auth.MethodPublicKey
			ccfg.AuthUser = "user_wild"
			ccfg.IdentityFiles = []string{privWild}

			err := RunClient(ctx, ccfg, in, out, logging.New(io.Discard, "error", "text"))
			cCancel()
			if err != nil {
				t.Fatalf("wildcard failed for dest %s: %v", dest, err)
			}
			if out.String() != "test wild" {
				t.Fatalf("unexpected output for dest %s: %q", dest, out.String())
			}
		}
	})
}

// 2. Sad Path: Keys with no-port-forwarding, permitopen="none", restrict.
func TestRBAC_Restrictions_NoPortForwarding_And_PermitOpenNone(t *testing.T) {
	dir := t.TempDir()

	destAddr, _, stop := startEchoTarget(t)
	defer stop()

	privNoFwd, pubNoFwd := writeEd25519Key(t, dir, "id_nofwd")
	lineNoFwd := fmt.Sprintf("no-port-forwarding %s", pubNoFwd)

	privNone, pubNone := writeEd25519Key(t, dir, "id_none")
	lineNone := fmt.Sprintf("permitopen=\"none\" %s", pubNone)

	privRestrict, pubRestrict := writeEd25519Key(t, dir, "id_restrict")
	lineRestrict := fmt.Sprintf("restrict %s", pubRestrict)

	privRestrictWithFwd, pubRestrictWithFwd := writeEd25519Key(t, dir, "id_restrict_fwd")
	lineRestrictWithFwd := fmt.Sprintf("restrict,port-forwarding,permitopen=%q %s", destAddr, pubRestrictWithFwd)

	akPath := filepath.Join(dir, "authorized_keys")
	akContent := strings.Join([]string{lineNoFwd, lineNone, lineRestrict, lineRestrictWithFwd}, "\n") + "\n"
	if err := os.WriteFile(akPath, []byte(akContent), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.AllowDestinations = []string{"*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = akPath

	_, srvAddr, cancel := startRelayCfg(t, scfg)
	defer cancel()

	// Case 1: no-port-forwarding rejected
	t.Run("NoPortForwarding_Rejected", func(t *testing.T) {
		ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cCancel()
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = destAddr
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user_nofwd"
		ccfg.IdentityFiles = []string{privNoFwd}

		err := RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
		if !errors.Is(err, proto.ErrDestForbidden) {
			t.Fatalf("expected ErrDestForbidden, got %v", err)
		}
	})

	// Case 2: permitopen="none" rejected
	t.Run("PermitOpenNone_Rejected", func(t *testing.T) {
		ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cCancel()
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = destAddr
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user_none"
		ccfg.IdentityFiles = []string{privNone}

		err := RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
		if !errors.Is(err, proto.ErrDestForbidden) {
			t.Fatalf("expected ErrDestForbidden, got %v", err)
		}
	})

	// Case 3: restrict rejected
	t.Run("Restrict_Rejected", func(t *testing.T) {
		ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cCancel()
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = destAddr
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user_restrict"
		ccfg.IdentityFiles = []string{privRestrict}

		err := RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
		if !errors.Is(err, proto.ErrDestForbidden) {
			t.Fatalf("expected ErrDestForbidden, got %v", err)
		}
	})

	// Case 4: restrict with port-forwarding and permitopen to destAddr -> SUCCESS
	t.Run("Restrict_PortForwarding_Success", func(t *testing.T) {
		ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cCancel()
		in := bytes.NewBuffer([]byte("allowed through restrict"))
		out := &bytes.Buffer{}
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = destAddr
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user_restrict_fwd"
		ccfg.IdentityFiles = []string{privRestrictWithFwd}

		err := RunClient(ctx, ccfg, in, out, logging.New(io.Discard, "error", "text"))
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
		if out.String() != "allowed through restrict" {
			t.Fatalf("unexpected output: %q", out.String())
		}
	})
}

// 3. SOCKS5 RBAC Enforcement: per-user permitopen and blocked port-forwarding on individual streams.
func TestRBAC_SOCKS5_StreamEnforcement(t *testing.T) {
	dir := t.TempDir()

	dest1Addr, dest1Port, stop1 := startEchoTarget(t)
	defer stop1()
	_, dest2Port, stop2 := startEchoTarget(t)
	defer stop2()

	// Key Restricted: only allowed dest1Addr
	privRestricted, pubRestricted := writeEd25519Key(t, dir, "id_socks_restricted")
	lineRestricted := fmt.Sprintf("permitopen=%q %s", dest1Addr, pubRestricted)

	// Key Blocked: no-port-forwarding
	privBlocked, pubBlocked := writeEd25519Key(t, dir, "id_socks_blocked")
	lineBlocked := fmt.Sprintf("no-port-forwarding %s", pubBlocked)

	akPath := filepath.Join(dir, "authorized_keys")
	akContent := strings.Join([]string{lineRestricted, lineBlocked}, "\n") + "\n"
	if err := os.WriteFile(akPath, []byte(akContent), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.AllowDestinations = []string{"*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = akPath

	_, srvAddr, cancel := startRelayCfg(t, scfg)
	defer cancel()

	// Subtest 1: User with no-port-forwarding attempting SOCKS5 tunnel is rejected during HELLO
	t.Run("SOCKS5_BlockedKey_RejectedAtHello", func(t *testing.T) {
		ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cCancel()
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = proto.DestSOCKS5
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user_blocked"
		ccfg.IdentityFiles = []string{privBlocked}

		socksCfg := SocksConfig{
			Listen: "127.0.0.1:0",
		}
		err := RunSocks(ctx, socksCfg, ccfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	// Subtest 2: User with permitopen="dest1" starts SOCKS5 tunnel;
	// stream to dest1 succeeds; stream to dest2 is rejected with RepConnectionNotAllowed (0x02).
	t.Run("SOCKS5_StreamRBAC_PermittedVsForbidden", func(t *testing.T) {
		ctx, cCancel := context.WithCancel(context.Background())
		defer cCancel()

		socksBoundCh := make(chan string, 1)
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = proto.DestSOCKS5
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user_restricted"
		ccfg.IdentityFiles = []string{privRestricted}

		socksCfg := SocksConfig{
			Listen: "127.0.0.1:0",
			OnBound: func(addr string) {
				socksBoundCh <- addr
			},
		}

		go func() {
			_ = RunSocks(ctx, socksCfg, ccfg)
		}()

		var socksProxyAddr string
		select {
		case socksProxyAddr = <-socksBoundCh:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for socks proxy to bind")
		}

		// Wait briefly for tunnel HELLO to establish
		time.Sleep(100 * time.Millisecond)

		// 1. Dial dest1 (allowed): must succeed and transfer data
		conn1, rep1, err1 := socks5DialTarget(socksProxyAddr, socks5.CmdConnect, "127.0.0.1", dest1Port)
		if err1 != nil {
			t.Fatalf("expected stream to dest1 to succeed, got error: %v (rep 0x%02x)", err1, rep1)
		}
		defer conn1.Close()
		if rep1 != socks5.RepSucceeded {
			t.Fatalf("expected RepSucceeded (0x00), got 0x%02x", rep1)
		}
		testMsg := "socks rbac allowed stream test"
		if _, err := conn1.Write([]byte(testMsg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(testMsg))
		if _, err := io.ReadFull(conn1, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != testMsg {
			t.Fatalf("expected %q, got %q", testMsg, string(buf))
		}

		// 2. Dial dest2 (forbidden by user permitopen): must fail with 0x02 RepConnectionNotAllowed
		_, rep2, err2 := socks5DialTarget(socksProxyAddr, socks5.CmdConnect, "127.0.0.1", dest2Port)
		if err2 == nil {
			t.Fatal("expected stream to dest2 to fail, got success")
		}
		if rep2 != socks5.RepConnectionNotAllowed {
			t.Fatalf("expected RepConnectionNotAllowed (0x02), got 0x%02x", rep2)
		}
	})
}

// 4. Live SIGHUP Configuration Reload: Adding new key and updating allow_destinations.
func TestRBAC_SIGHUP_LiveReload_AddKeyAndAllowDests(t *testing.T) {
	dir := t.TempDir()

	dest1Addr, _, stop1 := startEchoTarget(t)
	defer stop1()
	dest2Addr, _, stop2 := startEchoTarget(t)
	defer stop2()

	// Initial key 1
	priv1, pub1 := writeEd25519Key(t, dir, "id_user1")
	line1 := fmt.Sprintf("permitopen=%q %s", dest1Addr, pub1)

	// Key 2 to be added on reload
	priv2, pub2 := writeEd25519Key(t, dir, "id_user2")
	line2 := fmt.Sprintf("permitopen=%q %s", dest2Addr, pub2)

	akPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte(line1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "server.toml")
	initialToml := fmt.Sprintf(`
listen_tcp = "127.0.0.1:0"
allow_destinations = ["%s"]
transports = ["tcp"]
auth_method = "ssh-publickey"
authorized_keys = %q
`, dest1Addr, akPath)
	if err := os.WriteFile(cfgPath, []byte(initialToml), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg, err := config.LoadServer(config.ServerOptions{ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	srv, srvAddr, cancel := startRelayCfg(t, scfg)
	defer cancel()

	// Step 1: User 1 connects successfully to dest1
	ccfg1 := config.DefaultClient()
	ccfg1.StrictHostKeyChecking = "no"
	ccfg1.Server = srvAddr
	ccfg1.Destination = dest1Addr
	ccfg1.Transport = "tcp"
	ccfg1.AuthMethod = auth.MethodPublicKey
	ccfg1.AuthUser = "user1"
	ccfg1.IdentityFiles = []string{priv1}

	// Keep an active session running across SIGHUP
	activeInR, activeInW := io.Pipe()
	activeOutR, activeOutW := io.Pipe()
	activeDone := make(chan error, 1)

	sessionCtx, sessionCancel := context.WithCancel(context.Background())
	defer sessionCancel()

	go func() {
		activeDone <- RunClient(sessionCtx, ccfg1, activeInR, activeOutW, logging.New(io.Discard, "error", "text"))
	}()

	// Verify active session can transfer data before reload
	go func() {
		_, _ = activeInW.Write([]byte("before-sighup\n"))
	}()
	readBuf := make([]byte, 14)
	if _, err := io.ReadFull(activeOutR, readBuf); err != nil {
		t.Fatalf("failed reading before-sighup: %v", err)
	}
	if string(readBuf) != "before-sighup\n" {
		t.Fatalf("unexpected data: %q", string(readBuf))
	}

	// User 2 before reload:
	// a) Connecting to dest1 (which is in allow_destinations) fails ERR_AUTH because key2 is not yet in authorized_keys
	ccfg2 := config.DefaultClient()
	ccfg2.StrictHostKeyChecking = "no"
	ccfg2.Server = srvAddr
	ccfg2.Destination = dest1Addr
	ccfg2.Transport = "tcp"
	ccfg2.AuthMethod = auth.MethodPublicKey
	ccfg2.AuthUser = "user2"
	ccfg2.IdentityFiles = []string{priv2}

	ctx2Pre, cancel2Pre := context.WithTimeout(context.Background(), 3*time.Second)
	err2Pre := RunClient(ctx2Pre, ccfg2, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	cancel2Pre()
	if !errors.Is(err2Pre, proto.ErrAuth) {
		t.Fatalf("expected ErrAuth for user2 before reload, got: %v", err2Pre)
	}

	// b) Connecting to dest2 fails ERR_DEST_FORBIDDEN because dest2 is not yet in allow_destinations
	ccfg2.Destination = dest2Addr
	ctx2DestPre, cancel2DestPre := context.WithTimeout(context.Background(), 3*time.Second)
	err2DestPre := RunClient(ctx2DestPre, ccfg2, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	cancel2DestPre()
	if !errors.Is(err2DestPre, proto.ErrDestForbidden) {
		t.Fatalf("expected ErrDestForbidden for dest2 before reload, got: %v", err2DestPre)
	}

	// Step 2: Update server.toml and authorized_keys
	updatedToml := fmt.Sprintf(`
listen_tcp = "127.0.0.1:0"
allow_destinations = ["%s", "%s"]
transports = ["tcp"]
auth_method = "ssh-publickey"
authorized_keys = %q
`, dest1Addr, dest2Addr, akPath)
	if err := os.WriteFile(cfgPath, []byte(updatedToml), 0o600); err != nil {
		t.Fatal(err)
	}
	// Append key2
	if err := os.WriteFile(akPath, []byte(line1+"\n"+line2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Trigger SIGHUP reload
	if err := srv.ReloadConfig(); err != nil {
		t.Fatalf("ReloadConfig failed: %v", err)
	}

	// Step 3: Verify User 2 can now connect to dest2!
	ctx2Post, cancel2Post := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2Post()
	in2 := bytes.NewBuffer([]byte("user2 post-sighup"))
	out2 := &bytes.Buffer{}
	if err := RunClient(ctx2Post, ccfg2, in2, out2, logging.New(io.Discard, "error", "text")); err != nil {
		t.Fatalf("user2 failed to connect after SIGHUP: %v", err)
	}
	if out2.String() != "user2 post-sighup" {
		t.Fatalf("unexpected user2 echo: %q", out2.String())
	}

	// Step 4: Verify active session (User 1) was NOT interrupted and continues pumping data!
	go func() {
		_, _ = activeInW.Write([]byte("after-sighup\n"))
	}()
	readBufPost := make([]byte, 13)
	if _, err := io.ReadFull(activeOutR, readBufPost); err != nil {
		t.Fatalf("failed reading after-sighup from active session: %v", err)
	}
	if string(readBufPost) != "after-sighup\n" {
		t.Fatalf("unexpected data from active session after SIGHUP: %q", string(readBufPost))
	}

	// Clean up active session
	_ = activeInW.Close()
	sessionCancel()
}

// 5. Live SIGHUP: Key Revocation immediately rejects new handshakes.
func TestRBAC_SIGHUP_KeyRevocation(t *testing.T) {
	dir := t.TempDir()

	destAddr, _, stop := startEchoTarget(t)
	defer stop()

	priv1, pub1 := writeEd25519Key(t, dir, "id_revoked")
	priv2, pub2 := writeEd25519Key(t, dir, "id_survivor")

	akPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte(pub1+"\n"+pub2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "server.toml")
	cfgToml := fmt.Sprintf(`
listen_tcp = "127.0.0.1:0"
allow_destinations = ["*"]
transports = ["tcp"]
auth_method = "ssh-publickey"
authorized_keys = %q
`, akPath)
	if err := os.WriteFile(cfgPath, []byte(cfgToml), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg, err := config.LoadServer(config.ServerOptions{ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	srv, srvAddr, cancel := startRelayCfg(t, scfg)
	defer cancel()

	// Both connect successfully initially
	for _, priv := range []string{priv1, priv2} {
		ctx, cCancel := context.WithTimeout(context.Background(), 4*time.Second)
		ccfg := config.DefaultClient()
		ccfg.StrictHostKeyChecking = "no"
		ccfg.Server = srvAddr
		ccfg.Destination = destAddr
		ccfg.Transport = "tcp"
		ccfg.AuthMethod = auth.MethodPublicKey
		ccfg.AuthUser = "user"
		ccfg.IdentityFiles = []string{priv}

		err := RunClient(ctx, ccfg, bytes.NewBuffer([]byte("ok")), io.Discard, logging.New(io.Discard, "error", "text"))
		cCancel()
		if err != nil {
			t.Fatalf("initial connect failed for %s: %v", priv, err)
		}
	}

	// Revoke key 1 by rewriting authorized_keys to contain only key 2
	if err := os.WriteFile(akPath, []byte(pub2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Trigger SIGHUP reload
	if err := srv.ReloadConfig(); err != nil {
		t.Fatalf("ReloadConfig failed: %v", err)
	}

	// Key 1 must now be rejected with ERR_AUTH
	ctx1, c1Cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer c1Cancel()
	ccfg1 := config.DefaultClient()
	ccfg1.StrictHostKeyChecking = "no"
	ccfg1.Server = srvAddr
	ccfg1.Destination = destAddr
	ccfg1.Transport = "tcp"
	ccfg1.AuthMethod = auth.MethodPublicKey
	ccfg1.AuthUser = "user1"
	ccfg1.IdentityFiles = []string{priv1}

	err1 := RunClient(ctx1, ccfg1, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	if !errors.Is(err1, proto.ErrAuth) {
		t.Fatalf("expected ErrAuth for revoked key1, got: %v", err1)
	}

	// Key 2 must still succeed
	ctx2, c2Cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer c2Cancel()
	ccfg2 := config.DefaultClient()
	ccfg2.StrictHostKeyChecking = "no"
	ccfg2.Server = srvAddr
	ccfg2.Destination = destAddr
	ccfg2.Transport = "tcp"
	ccfg2.AuthMethod = auth.MethodPublicKey
	ccfg2.AuthUser = "user2"
	ccfg2.IdentityFiles = []string{priv2}

	out2 := &bytes.Buffer{}
	if err := RunClient(ctx2, ccfg2, bytes.NewBuffer([]byte("survivor")), out2, logging.New(io.Discard, "error", "text")); err != nil {
		t.Fatalf("key2 failed after reload: %v", err)
	}
	if out2.String() != "survivor" {
		t.Fatalf("unexpected echo from survivor: %q", out2.String())
	}
}

// 6. Sad Path: SIGHUP with corrupt TOML config or corrupt/empty authorized_keys fails closed and retains old valid config.
func TestRBAC_SIGHUP_SadPath_CorruptConfigOrAuthKeys(t *testing.T) {
	dir := t.TempDir()

	destAddr, _, stop := startEchoTarget(t)
	defer stop()

	priv, pub := writeEd25519Key(t, dir, "id_valid")
	akPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte(pub+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "server.toml")
	validToml := fmt.Sprintf(`
listen_tcp = "127.0.0.1:0"
allow_destinations = ["%s"]
transports = ["tcp"]
auth_method = "ssh-publickey"
authorized_keys = %q
`, destAddr, akPath)
	if err := os.WriteFile(cfgPath, []byte(validToml), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg, err := config.LoadServer(config.ServerOptions{ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	srv, srvAddr, cancel := startRelayCfg(t, scfg)
	defer cancel()

	// 1. Corrupt the TOML file
	if err := os.WriteFile(cfgPath, []byte("invalid toml [[[]== broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadErr := srv.ReloadConfig()
	if reloadErr == nil {
		t.Fatal("expected ReloadConfig to return error on corrupt TOML, got nil")
	}

	// Server must still be running and serving traffic using the previous valid config
	ctx1, cancel1 := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel1()
	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = srvAddr
	ccfg.Destination = destAddr
	ccfg.Transport = "tcp"
	ccfg.AuthMethod = auth.MethodPublicKey
	ccfg.AuthUser = "valid_user"
	ccfg.IdentityFiles = []string{priv}

	out1 := &bytes.Buffer{}
	if err := RunClient(ctx1, ccfg, bytes.NewBuffer([]byte("still working")), out1, logging.New(io.Discard, "error", "text")); err != nil {
		t.Fatalf("client failed to connect after failed corrupt-toml reload: %v", err)
	}
	if out1.String() != "still working" {
		t.Fatalf("unexpected echo output: %q", out1.String())
	}

	// 2. Restore valid TOML but corrupt authorized_keys (empty file)
	if err := os.WriteFile(cfgPath, []byte(validToml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(akPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadErr2 := srv.ReloadConfig()
	if reloadErr2 == nil {
		t.Fatal("expected ReloadConfig to return error on empty authorized_keys, got nil")
	}

	// Server must retain previous valid authorized_keys and allow valid key to connect
	ctx2, cancel2 := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel2()
	out2 := &bytes.Buffer{}
	if err := RunClient(ctx2, ccfg, bytes.NewBuffer([]byte("still authenticated")), out2, logging.New(io.Discard, "error", "text")); err != nil {
		t.Fatalf("client failed to authenticate after failed empty-auth reload: %v", err)
	}
	if out2.String() != "still authenticated" {
		t.Fatalf("unexpected echo output: %q", out2.String())
	}
}

// 7. Sad Path: Jumphost chaining with destination forbidden by key's permitopen.
func TestRBAC_Chain_HopDestinationPolicy(t *testing.T) {
	dir := t.TempDir()

	dest1Addr, _, stop1 := startEchoTarget(t)
	defer stop1()
	dest2Addr, _, stop2 := startEchoTarget(t)
	defer stop2()

	// User key is ONLY permitted dest1Addr
	priv, pub := writeEd25519Key(t, dir, "id_chain_user")
	line := fmt.Sprintf("permitopen=%q %s", dest1Addr, pub)

	akPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg := config.DefaultServer()
	scfg.ListenTCP = "127.0.0.1:0"
	scfg.AllowDestinations = []string{"*"}
	scfg.Transports = []string{"tcp"}
	scfg.AuthMethod = auth.MethodPublicKey
	scfg.AuthorizedKeys = akPath

	srv, srvAddr, cancel := startRelayCfg(t, scfg)
	defer cancel()
	_ = srv

	// Chaining attempt via client chain to dest2Addr (which is forbidden for this user key)
	ctx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cCancel()

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = srvAddr
	ccfg.Destination = dest2Addr
	ccfg.Transport = "tcp"
	ccfg.AuthMethod = auth.MethodPublicKey
	ccfg.AuthUser = "chain_user"
	ccfg.IdentityFiles = []string{priv}

	// Attempt raw HELLO to dest2: must be forbidden
	_, _, err := rawHelloAuth(ctx, srvAddr, dest2Addr, priv, "chain_user")
	if err == nil {
		t.Fatal("expected ErrDestForbidden, got nil")
	}
	if !errors.Is(err, proto.ErrDestForbidden) {
		t.Fatalf("expected ErrDestForbidden, got: %v", err)
	}

	// Raw HELLO to dest1: must succeed
	conn, _, errOK := rawHelloAuth(ctx, srvAddr, dest1Addr, priv, "chain_user")
	if errOK != nil {
		t.Fatalf("expected rawHelloAuth to dest1 to succeed, got: %v", errOK)
	}
	_ = conn.Close()
}

// 8. High concurrency race test: concurrent connections during live SIGHUP reloads.
func TestRBAC_SIGHUP_HighConcurrency_Race(t *testing.T) {
	dir := t.TempDir()

	destAddr, _, stop := startEchoTarget(t)
	defer stop()

	priv, pub := writeEd25519Key(t, dir, "id_race_user")
	akPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte(pub+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "server.toml")
	tomlCfg := fmt.Sprintf(`
listen_tcp = "127.0.0.1:0"
allow_destinations = ["%s"]
transports = ["tcp"]
auth_method = "ssh-publickey"
authorized_keys = %q
max_conns_per_ip = 64
max_sessions = 128
`, destAddr, akPath)
	if err := os.WriteFile(cfgPath, []byte(tomlCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	scfg, err := config.LoadServer(config.ServerOptions{ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	srv, srvAddr, cancel := startRelayCfg(t, scfg)
	defer cancel()

	ctx, runCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer runCancel()

	var wg sync.WaitGroup

	// Background reloader: triggers ReloadConfig 10 times with small sleeps
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
				_ = srv.ReloadConfig()
			}
		}
	}()

	// 10 concurrent clients repeatedly connecting and transferring small packets
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				if ctx.Err() != nil {
					return
				}
				ccfg := config.DefaultClient()
				ccfg.StrictHostKeyChecking = "no"
				ccfg.Server = srvAddr
				ccfg.Destination = destAddr
				ccfg.Transport = "tcp"
				ccfg.AuthMethod = auth.MethodPublicKey
				ccfg.AuthUser = fmt.Sprintf("race_user_%d", workerID)
				ccfg.IdentityFiles = []string{priv}

				msg := fmt.Sprintf("race-msg-%d-%d", workerID, j)
				in := bytes.NewBuffer([]byte(msg))
				out := &bytes.Buffer{}

				clientCtx, clientCancel := context.WithTimeout(ctx, 3*time.Second)
				err := RunClient(clientCtx, ccfg, in, out, logging.New(io.Discard, "error", "text"))
				clientCancel()
				if err != nil {
					t.Errorf("worker %d run %d failed: %v", workerID, j, err)
					return
				}
				if out.String() != msg {
					t.Errorf("worker %d run %d expected %q, got %q", workerID, j, msg, out.String())
					return
				}
			}
		}(i)
	}

	wg.Wait()
}

// 9. Real OS SIGHUP signal test using syscall.Kill on a dedicated server process.
func TestRBAC_OS_SIGHUP_SignalDispatch(t *testing.T) {
	dir := t.TempDir()

	destAddr, _, stop := startEchoTarget(t)
	defer stop()

	priv1, pub1 := writeEd25519Key(t, dir, "id_sig1")
	priv2, pub2 := writeEd25519Key(t, dir, "id_sig2")

	akPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte(pub1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "server.toml")
	cfgToml := fmt.Sprintf(`
listen_tcp = "127.0.0.1:0"
allow_destinations = ["%s"]
transports = ["tcp"]
auth_method = "ssh-publickey"
authorized_keys = %q
`, destAddr, akPath)
	if err := os.WriteFile(cfgPath, []byte(cfgToml), 0o600); err != nil {
		t.Fatal(err)
	}

	// Find an open port for the relay server
	testLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := testLn.Addr().String()
	_ = testLn.Close()

	// Compile relay binary
	binPath := filepath.Join(dir, "relay-test-bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../cmd/relay")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}

	// Launch relay server process
	serverCmd := exec.Command(binPath, "server",
		"--config", cfgPath,
		"--listen", relayAddr,
		"--authorized-keys", akPath,
		"--log-level", "debug",
	)
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(serverCmd.Process.Pid, syscall.SIGKILL)
		_ = serverCmd.Wait()
	})

	// Wait until server is listening
	for i := 0; i < 50; i++ {
		conn, dialErr := net.DialTimeout("tcp", relayAddr, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify key1 connects successfully
	ctx1, c1Cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer c1Cancel()
	ccfg1 := config.DefaultClient()
	ccfg1.StrictHostKeyChecking = "no"
	ccfg1.Server = relayAddr
	ccfg1.Destination = destAddr
	ccfg1.Transport = "tcp"
	ccfg1.AuthMethod = auth.MethodPublicKey
	ccfg1.AuthUser = "sig_user1"
	ccfg1.IdentityFiles = []string{priv1}

	out1 := &bytes.Buffer{}
	if err := RunClient(ctx1, ccfg1, bytes.NewBuffer([]byte("hello key1")), out1, logging.New(io.Discard, "error", "text")); err != nil {
		t.Fatalf("client1 initial connect failed: %v", err)
	}
	if out1.String() != "hello key1" {
		t.Fatalf("unexpected echo from client1: %q", out1.String())
	}

	// Verify key2 is rejected before reload
	ctx2Pre, c2PreCancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer c2PreCancel()
	ccfg2 := config.DefaultClient()
	ccfg2.StrictHostKeyChecking = "no"
	ccfg2.Server = relayAddr
	ccfg2.Destination = destAddr
	ccfg2.Transport = "tcp"
	ccfg2.AuthMethod = auth.MethodPublicKey
	ccfg2.AuthUser = "sig_user2"
	ccfg2.IdentityFiles = []string{priv2}

	err2Pre := RunClient(ctx2Pre, ccfg2, bytes.NewReader(nil), io.Discard, logging.New(io.Discard, "error", "text"))
	if !errors.Is(err2Pre, proto.ErrAuth) {
		t.Fatalf("expected ErrAuth for key2 before reload, got: %v", err2Pre)
	}

	// Append key2 to authorized_keys
	if err := os.WriteFile(akPath, []byte(pub1+"\n"+pub2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Dispatch real SIGHUP to the dedicated server subprocess
	if err := syscall.Kill(serverCmd.Process.Pid, syscall.SIGHUP); err != nil {
		t.Fatalf("syscall.Kill SIGHUP failed: %v", err)
	}

	// Wait briefly for asynchronous signal handler goroutine in server to execute ReloadConfig
	time.Sleep(300 * time.Millisecond)

	// Verify key2 can now connect!
	ctx2Post, c2PostCancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer c2PostCancel()

	out2 := &bytes.Buffer{}
	if err := RunClient(ctx2Post, ccfg2, bytes.NewBuffer([]byte("signal reload ok")), out2, logging.New(io.Discard, "error", "text")); err != nil {
		t.Fatalf("client2 failed after real OS SIGHUP signal: %v", err)
	}
	if out2.String() != "signal reload ok" {
		t.Fatalf("unexpected echo: %q", out2.String())
	}
}
