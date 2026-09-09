package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
	"golang.org/x/crypto/ssh"
)

// echoDest spins up a TCP listener that echoes back everything received until EOF.
func echoDest(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestSecE2EEncryptedHandshakeAndDataTransfer(t *testing.T) {
	dest := echoDest(t)
	srv, srvAddr, cancel := startRelay(t, dest)
	defer cancel()

	fingerprint := srv.HostFingerprint()
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("unexpected host fingerprint format: %s", fingerprint)
	}

	cliCfg := config.DefaultClient()
	cliCfg.Server = srvAddr
	cliCfg.Destination = dest
	cliCfg.Transport = "tcp"
	cliCfg.ServerFingerprint = fingerprint
	cliCfg.StrictHostKeyChecking = "yes"
	cliCfg.LogLevel = "error"

	log := logging.New(io.Discard, "error", "text")

	ctx, cancelCtx := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCtx()

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, cliCfg, inR, outW, log)
	}()

	testPayload := []byte("hello-encrypted-control-plane-e2e-payload-data")
	go func() {
		_, _ = inW.Write(testPayload)
		_ = inW.Close()
	}()

	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(outR, buf); err != nil {
		t.Fatalf("io.ReadFull failed: %v", err)
	}

	if !bytes.Equal(buf, testPayload) {
		t.Fatalf("payload mismatch: got %q, want %q", string(buf), string(testPayload))
	}
}

func TestSecCleartextHelloRejected(t *testing.T) {
	dest := echoDest(t)
	_, srvAddr, cancel := startRelay(t, dest)
	defer cancel()

	ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelCtx()

	conn, err := transport.DialTCP(ctx, srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send raw TypeHello frame without KEX_INIT
	helloMsg := proto.Hello{
		V:           1,
		Destination: dest,
		Transport:   []string{"tcp"},
		ClientNonce: "cleartext-nonce-123",
	}
	fr, err := proto.MarshalFrame(proto.TypeHello, helloMsg)
	if err != nil {
		t.Fatal(err)
	}

	if err := conn.WriteFrame(fr); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	resp, err := conn.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if resp.Type != proto.TypeErr {
		t.Fatalf("expected TypeErr (0x09), got %s (0x%02x)", resp.Type, byte(resp.Type))
	}

	var failMsg proto.Fail
	if err := proto.UnmarshalPayload(resp, &failMsg); err != nil {
		t.Fatalf("UnmarshalPayload failed: %v", err)
	}

	if failMsg.Code != proto.CodeProto {
		t.Fatalf("expected CodeProto (%s), got %s", proto.CodeProto, failMsg.Code)
	}
	if !strings.Contains(failMsg.Msg, "encrypted handshake required") {
		t.Fatalf("expected msg to mention 'encrypted handshake required', got: %s", failMsg.Msg)
	}
}

func TestSecCleartextResumeRejected(t *testing.T) {
	dest := echoDest(t)
	_, srvAddr, cancel := startRelay(t, dest)
	defer cancel()

	ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelCtx()

	conn, err := transport.DialTCP(ctx, srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send raw TypeResume frame without KEX_INIT
	resumeMsg := proto.Resume{
		V:           1,
		SessionID:   "s-fake12345678",
		ResumeToken: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		Transport:   []string{"tcp"},
		ClientNonce: "cleartext-nonce-resume",
	}
	fr, err := proto.MarshalFrame(proto.TypeResume, resumeMsg)
	if err != nil {
		t.Fatal(err)
	}

	if err := conn.WriteFrame(fr); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	resp, err := conn.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if resp.Type != proto.TypeResumeFail && resp.Type != proto.TypeErr {
		t.Fatalf("expected TypeResumeFail or TypeErr, got %s", resp.Type)
	}

	var failMsg proto.Fail
	if err := proto.UnmarshalPayload(resp, &failMsg); err != nil {
		t.Fatalf("UnmarshalPayload failed: %v", err)
	}

	if failMsg.Code != proto.CodeProto {
		t.Fatalf("expected CodeProto (%s), got %s", proto.CodeProto, failMsg.Code)
	}
}

func TestSecHostKeyFingerprintValidation(t *testing.T) {
	dest := echoDest(t)
	srv, srvAddr, cancel := startRelay(t, dest)
	defer cancel()

	fingerprint := srv.HostFingerprint()

	// 1. Correct fingerprint succeeds
	{
		cliCfg := config.DefaultClient()
		cliCfg.Server = srvAddr
		cliCfg.Destination = dest
		cliCfg.Transport = "tcp"
		cliCfg.ServerFingerprint = fingerprint
		cliCfg.StrictHostKeyChecking = "yes"
		cliCfg.LogLevel = "error"

		ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
		conn, _, err := clientHello(ctx, cliCfg)
		cancelCtx()
		if err != nil {
			t.Fatalf("expected success with matching fingerprint, got: %v", err)
		}
		_ = conn.Close()
	}

	// 2. Incorrect fingerprint fails
	{
		cliCfg := config.DefaultClient()
		cliCfg.Server = srvAddr
		cliCfg.Destination = dest
		cliCfg.Transport = "tcp"
		cliCfg.ServerFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		cliCfg.StrictHostKeyChecking = "yes"
		cliCfg.LogLevel = "error"

		ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
		conn, _, err := clientHello(ctx, cliCfg)
		cancelCtx()
		if err == nil {
			if conn != nil {
				_ = conn.Close()
			}
			t.Fatal("expected failure with mismatched fingerprint, but connect succeeded")
		}
		if !strings.Contains(err.Error(), "host key fingerprint mismatch") {
			t.Fatalf("expected error to mention 'host key fingerprint mismatch', got: %v", err)
		}
	}
}

func TestSecStrictHostKeyCheckingModes(t *testing.T) {
	dest := echoDest(t)
	_, srvAddr, cancel := startRelay(t, dest)
	defer cancel()

	tmpDir := t.TempDir()
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")

	// 1. Mode "yes" with empty/missing known_hosts -> must fail
	{
		cliCfg := config.DefaultClient()
		cliCfg.Server = srvAddr
		cliCfg.Destination = dest
		cliCfg.Transport = "tcp"
		cliCfg.KnownHosts = knownHostsPath
		cliCfg.StrictHostKeyChecking = "yes"
		cliCfg.LogLevel = "error"

		ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
		conn, _, err := clientHello(ctx, cliCfg)
		cancelCtx()
		if err == nil {
			if conn != nil {
				_ = conn.Close()
			}
			t.Fatal("expected error with StrictHostKeyChecking=yes on unknown host, got success")
		}
	}

	// 2. Mode "accept-new" with empty known_hosts -> must succeed and record host key
	{
		cliCfg := config.DefaultClient()
		cliCfg.Server = srvAddr
		cliCfg.Destination = dest
		cliCfg.Transport = "tcp"
		cliCfg.KnownHosts = knownHostsPath
		cliCfg.StrictHostKeyChecking = "accept-new"
		cliCfg.LogLevel = "error"

		ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
		conn, _, err := clientHello(ctx, cliCfg)
		cancelCtx()
		if err != nil {
			t.Fatalf("expected success with StrictHostKeyChecking=accept-new, got: %v", err)
		}
		_ = conn.Close()

		// Verify known_hosts file exists and is populated
		data, err := os.ReadFile(knownHostsPath)
		if err != nil || len(data) == 0 {
			t.Fatalf("expected known_hosts to be written, got err=%v len=%d", err, len(data))
		}
	}

	// 3. Mode "yes" with newly populated known_hosts -> must succeed
	{
		cliCfg := config.DefaultClient()
		cliCfg.Server = srvAddr
		cliCfg.Destination = dest
		cliCfg.Transport = "tcp"
		cliCfg.KnownHosts = knownHostsPath
		cliCfg.StrictHostKeyChecking = "yes"
		cliCfg.LogLevel = "error"

		ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
		conn, _, err := clientHello(ctx, cliCfg)
		cancelCtx()
		if err != nil {
			t.Fatalf("expected success with StrictHostKeyChecking=yes on known host, got: %v", err)
		}
		_ = conn.Close()
	}

	// 4. Manually corrupt known_hosts with a different key for this server -> must detect MITM
	{
		_, fakePriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		fakeSSHSigner, err := ssh.NewSignerFromKey(fakePriv)
		if err != nil {
			t.Fatal(err)
		}
		fakeLine := srvAddr + " " + fakeSSHSigner.PublicKey().Type() + " " + base64.StdEncoding.EncodeToString(fakeSSHSigner.PublicKey().Marshal()) + "\n"
		if err := os.WriteFile(knownHostsPath, []byte(fakeLine), 0600); err != nil {
			t.Fatal(err)
		}

		cliCfg := config.DefaultClient()
		cliCfg.Server = srvAddr
		cliCfg.Destination = dest
		cliCfg.Transport = "tcp"
		cliCfg.KnownHosts = knownHostsPath
		cliCfg.StrictHostKeyChecking = "yes"
		cliCfg.LogLevel = "error"

		ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
		conn, _, err := clientHello(ctx, cliCfg)
		cancelCtx()
		if err == nil {
			if conn != nil {
				_ = conn.Close()
			}
			t.Fatal("expected failure on altered host key, got success")
		}
	}

	// 5. Mode "no" succeeds regardless of known_hosts
	{
		cliCfg := config.DefaultClient()
		cliCfg.Server = srvAddr
		cliCfg.Destination = dest
		cliCfg.Transport = "tcp"
		cliCfg.KnownHosts = filepath.Join(tmpDir, "non_existent_file")
		cliCfg.StrictHostKeyChecking = "no"
		cliCfg.LogLevel = "error"

		ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
		conn, _, err := clientHello(ctx, cliCfg)
		cancelCtx()
		if err != nil {
			t.Fatalf("expected success with StrictHostKeyChecking=no, got: %v", err)
		}
		_ = conn.Close()
	}
}

func TestSecWireEncryptionNoCleartextLeak(t *testing.T) {
	dest := echoDest(t)
	_, srvAddr, cancel := startRelay(t, dest)
	defer cancel()

	// Intercepting proxy: captures all bytes exchanged over TCP
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	var clientToServerBytes bytes.Buffer
	var serverToClientBytes bytes.Buffer
	var mu sync.Mutex

	go func() {
		for {
			cConn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			sConn, err := net.Dial("tcp", srvAddr)
			if err != nil {
				cConn.Close()
				return
			}

			// c -> s
			go func() {
				defer cConn.Close()
				defer sConn.Close()
				buf := make([]byte, 4096)
				for {
					n, err := cConn.Read(buf)
					if n > 0 {
						mu.Lock()
						clientToServerBytes.Write(buf[:n])
						mu.Unlock()
						_, _ = sConn.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()

			// s -> c
			go func() {
				defer cConn.Close()
				defer sConn.Close()
				buf := make([]byte, 4096)
				for {
					n, err := sConn.Read(buf)
					if n > 0 {
						mu.Lock()
						serverToClientBytes.Write(buf[:n])
						mu.Unlock()
						_, _ = cConn.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	cliCfg := config.DefaultClient()
	cliCfg.Server = proxyLn.Addr().String()
	cliCfg.Destination = dest
	cliCfg.Transport = "tcp"
	cliCfg.StrictHostKeyChecking = "no"
	cliCfg.LogLevel = "error"

	ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelCtx()

	conn, helloOK, err := clientHello(ctx, cliCfg)
	if err != nil {
		t.Fatalf("clientHello failed: %v", err)
	}
	defer conn.Close()

	// Handshake has completed. Check intercepted bytes:
	mu.Lock()
	c2s := clientToServerBytes.Bytes()
	s2c := serverToClientBytes.Bytes()
	mu.Unlock()

	// Assert that sensitive metadata is NOT present in plaintext in c2s or s2c
	sensitiveStrings := []string{
		"\"destination\":",
		dest,
		"\"resumeToken\":",
		helloOK.ResumeToken,
		"\"sessionId\":",
		helloOK.SessionID,
		"\"serverNonce\":",
		helloOK.ServerNonce,
	}

	for _, s := range sensitiveStrings {
		if bytes.Contains(c2s, []byte(s)) {
			t.Fatalf("LEAK DETECTED: client->server wire traffic contains plaintext %q", s)
		}
		if bytes.Contains(s2c, []byte(s)) {
			t.Fatalf("LEAK DETECTED: server->client wire traffic contains plaintext %q", s)
		}
	}
}

func TestSecOptionACleanPhaseCut(t *testing.T) {
	// Verifies that after handshake, data transfer frames sent on the wire
	// are regular TypeData (0x01) frames and NOT TypeEncrypted (0x0D).
	dest := echoDest(t)
	_, srvAddr, cancel := startRelay(t, dest)
	defer cancel()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	var clientFrames []proto.Frame
	var mu sync.Mutex

	go func() {
		for {
			cConn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			sConn, err := net.Dial("tcp", srvAddr)
			if err != nil {
				cConn.Close()
				return
			}

			// Read frames from client, record frame types, forward to server
			go func() {
				defer cConn.Close()
				defer sConn.Close()
				for {
					fr, err := proto.ReadFrame(cConn)
					if err != nil {
						return
					}
					mu.Lock()
					clientFrames = append(clientFrames, fr)
					mu.Unlock()
					if err := proto.WriteFrame(sConn, fr); err != nil {
						return
					}
				}
			}()

			// Forward server frames to client
			go func() {
				defer cConn.Close()
				defer sConn.Close()
				for {
					fr, err := proto.ReadFrame(sConn)
					if err != nil {
						return
					}
					if err := proto.WriteFrame(cConn, fr); err != nil {
						return
					}
				}
			}()
		}
	}()

	cliCfg := config.DefaultClient()
	cliCfg.Server = proxyLn.Addr().String()
	cliCfg.Destination = dest
	cliCfg.Transport = "tcp"
	cliCfg.StrictHostKeyChecking = "no"
	cliCfg.LogLevel = "error"

	ctx, cancelCtx := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelCtx()

	conn, _, err := clientHello(ctx, cliCfg)
	if err != nil {
		t.Fatalf("clientHello failed: %v", err)
	}
	defer conn.Close()

	// Now send a TypeData frame on conn
	dataFr := proto.Frame{
		Type:    proto.TypeData,
		Payload: []byte("clean-phase-cut-test-data"),
	}
	if err := conn.WriteFrame(dataFr); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	// Give frames a moment to be read by proxy
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	frames := make([]proto.Frame, len(clientFrames))
	copy(frames, clientFrames)
	mu.Unlock()

	var seenKexInit, seenEncryptedHello, seenData bool
	for _, fr := range frames {
		switch fr.Type {
		case proto.TypeKexInit:
			seenKexInit = true
		case proto.TypeEncrypted:
			seenEncryptedHello = true
		case proto.TypeData:
			seenData = true
		}
	}

	if !seenKexInit {
		t.Fatal("expected to see TypeKexInit frame from client")
	}
	if !seenEncryptedHello {
		t.Fatal("expected to see TypeEncrypted frame for HELLO from client")
	}
	if !seenData {
		t.Fatal("expected to see raw TypeData frame from client (Clean Phase Cut)")
	}
}
