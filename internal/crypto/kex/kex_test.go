package kex

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

func TestKexHandshakeSuccess(t *testing.T) {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	serverSess, err := NewServerSession(hostPriv)
	if err != nil {
		t.Fatalf("NewServerSession: %v", err)
	}

	clientSess, err := NewClientSession()
	if err != nil {
		t.Fatalf("NewClientSession: %v", err)
	}

	initPayload := clientSess.InitPayload()
	if len(initPayload) != KexInitLen {
		t.Fatalf("initPayload len = %d, want %d", len(initPayload), KexInitLen)
	}

	replyPayload, serverC2S, serverS2C, err := serverSess.ProcessInit(initPayload)
	if err != nil {
		t.Fatalf("server ProcessInit: %v", err)
	}
	if len(replyPayload) != KexReplyLen {
		t.Fatalf("replyPayload len = %d, want %d", len(replyPayload), KexReplyLen)
	}

	var verifiedHostKey ed25519.PublicKey
	clientC2S, clientS2C, err := clientSess.ProcessReply(replyPayload, func(pub ed25519.PublicKey) error {
		verifiedHostKey = pub
		return nil
	})
	if err != nil {
		t.Fatalf("client ProcessReply: %v", err)
	}

	if !bytes.Equal(verifiedHostKey, serverSess.HostPublicKey()) {
		t.Fatalf("verified host key mismatch")
	}

	if !bytes.Equal(clientC2S, serverC2S) {
		t.Fatalf("c2s key mismatch:\nclient: %x\nserver: %x", clientC2S, serverC2S)
	}
	if !bytes.Equal(clientS2C, serverS2C) {
		t.Fatalf("s2c key mismatch:\nclient: %x\nserver: %x", clientS2C, serverS2C)
	}
}

func TestKexTamperedSignature(t *testing.T) {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	serverSess, err := NewServerSession(hostPriv)
	if err != nil {
		t.Fatalf("NewServerSession: %v", err)
	}
	clientSess, err := NewClientSession()
	if err != nil {
		t.Fatalf("NewClientSession: %v", err)
	}

	replyPayload, _, _, err := serverSess.ProcessInit(clientSess.InitPayload())
	if err != nil {
		t.Fatalf("ProcessInit: %v", err)
	}

	// Corrupt signature byte
	replyPayload[len(replyPayload)-1] ^= 0xFF

	_, _, err = clientSess.ProcessReply(replyPayload, nil)
	if err == nil {
		t.Fatalf("expected error on tampered signature, got nil")
	}
	if !strings.Contains(err.Error(), "invalid server signature") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// mockConn creates an in-memory transport.Conn pair using net.Pipe.
func mockConnPair(t *testing.T) (transport.Conn, transport.Conn) {
	p1, p2 := net.Pipe()
	c1, err := transport.WrapTCP(p1)
	if err != nil {
		// net.Pipe is not *net.TCPConn, so WrapTCP might fail. Let's use pipeConn.
	}
	_ = c1
	_ = p2
	return nil, nil
}

type memoryConn struct {
	net.Conn
	rCh chan proto.Frame
	wCh chan proto.Frame
}

func newMemConnPair() (*memConn, *memConn) {
	c2s := make(chan proto.Frame, 16)
	s2c := make(chan proto.Frame, 16)
	return &memConn{rCh: s2c, wCh: c2s}, &memConn{rCh: c2s, wCh: s2c}
}

type memConn struct {
	rCh    chan proto.Frame
	wCh    chan proto.Frame
	closed bool
	mu     sync.Mutex
}

func (m *memConn) ReadFrame() (proto.Frame, error) {
	f, ok := <-m.rCh
	if !ok {
		return proto.Frame{}, net.ErrClosed
	}
	return f, nil
}

func (m *memConn) WriteFrame(f proto.Frame) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return net.ErrClosed
	}
	m.wCh <- f
	return nil
}

func (m *memConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.wCh)
	}
	return nil
}

func (m *memConn) SetDeadline(t time.Time) error { return nil }
func (m *memConn) LocalAddr() net.Addr           { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234} }
func (m *memConn) RemoteAddr() net.Addr          { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7443} }
func (m *memConn) Kind() transport.Kind          { return transport.KindTCP }
func (m *memConn) ResetReader()                  {}

func TestCipherConnEncryptDecrypt(t *testing.T) {
	c2sKey := make([]byte, KeyLen)
	s2cKey := make([]byte, KeyLen)
	for i := range c2sKey {
		c2sKey[i] = byte(i)
		s2cKey[i] = byte(i + 100)
	}

	cliRaw, srvRaw := newMemConnPair()
	defer cliRaw.Close()
	defer srvRaw.Close()

	cliCipher, err := NewCipherConn(cliRaw, c2sKey, s2cKey)
	if err != nil {
		t.Fatalf("NewCipherConn cli: %v", err)
	}
	srvCipher, err := NewCipherConn(srvRaw, s2cKey, c2sKey)
	if err != nil {
		t.Fatalf("NewCipherConn srv: %v", err)
	}

	// 1. Client writes control frame (HELLO)
	innerHello := proto.Frame{
		Type:    proto.TypeHello,
		Payload: []byte(`{"v":1,"transport":"tcp","destination":"localhost:22"}`),
	}
	if err := cliCipher.WriteControlFrame(innerHello); err != nil {
		t.Fatalf("cli WriteControlFrame: %v", err)
	}

	// 2. Server reads control frame
	recvHello, err := srvCipher.ReadControlFrame()
	if err != nil {
		t.Fatalf("srv ReadControlFrame: %v", err)
	}
	if recvHello.Type != proto.TypeHello {
		t.Fatalf("recvHello type = %v, want %v", recvHello.Type, proto.TypeHello)
	}
	if !bytes.Equal(recvHello.Payload, innerHello.Payload) {
		t.Fatalf("recvHello payload = %s, want %s", recvHello.Payload, innerHello.Payload)
	}

	// 3. Server replies with HELLO_OK
	innerHelloOK := proto.Frame{
		Type:    proto.TypeHelloOK,
		Payload: []byte(`{"v":1,"sessionId":"s-12345","resumeToken":"tok-abcde"}`),
	}
	if err := srvCipher.WriteControlFrame(innerHelloOK); err != nil {
		t.Fatalf("srv WriteControlFrame: %v", err)
	}

	// 4. Client reads HELLO_OK
	recvHelloOK, err := cliCipher.ReadControlFrame()
	if err != nil {
		t.Fatalf("cli ReadControlFrame: %v", err)
	}
	if recvHelloOK.Type != proto.TypeHelloOK {
		t.Fatalf("recvHelloOK type = %v, want %v", recvHelloOK.Type, proto.TypeHelloOK)
	}
	if !bytes.Equal(recvHelloOK.Payload, innerHelloOK.Payload) {
		t.Fatalf("recvHelloOK payload = %s, want %s", recvHelloOK.Payload, innerHelloOK.Payload)
	}

	// 5. Test Unwrap() exposes the underlying transport.Conn
	if cliCipher.Underlying() != cliRaw {
		t.Fatalf("Underlying mismatch")
	}
}

func TestCipherConnSequenceMismatch(t *testing.T) {
	c2sKey := make([]byte, KeyLen)
	s2cKey := make([]byte, KeyLen)
	cliRaw, srvRaw := newMemConnPair()
	defer cliRaw.Close()
	defer srvRaw.Close()

	cliCipher, _ := NewCipherConn(cliRaw, c2sKey, s2cKey)
	srvCipher, _ := NewCipherConn(srvRaw, s2cKey, c2sKey)

	// Simulate client sending frame
	if err := cliCipher.WriteControlFrame(proto.Frame{Type: proto.TypeHello, Payload: []byte("test")}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Intercept wire frame from channel and tamper with sequence number
	wireFrame := <-srvRaw.rCh
	wireFrame.Payload[7] ^= 0x01 // flip last byte of sequence
	srvRaw.rCh <- wireFrame

	_, err := srvCipher.ReadControlFrame()
	if err == nil {
		t.Fatalf("expected sequence mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "sequence mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHostKeyLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "host_key")

	// 1. First run: auto-generation
	key1, err := LoadOrGenerateHostKey(keyPath)
	if err != nil {
		t.Fatalf("first LoadOrGenerateHostKey: %v", err)
	}
	pub1 := key1.Public().(ed25519.PublicKey)
	fp1 := FingerprintSHA256(pub1)
	if !strings.HasPrefix(fp1, "SHA256:") {
		t.Fatalf("invalid fingerprint format: %s", fp1)
	}

	// 2. Second run: load existing
	key2, err := LoadOrGenerateHostKey(keyPath)
	if err != nil {
		t.Fatalf("second LoadOrGenerateHostKey: %v", err)
	}
	pub2 := key2.Public().(ed25519.PublicKey)
	fp2 := FingerprintSHA256(pub2)

	if fp1 != fp2 {
		t.Fatalf("fingerprint changed on reload: %s != %s", fp1, fp2)
	}
}

func TestKnownHostsVerification(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")
	addr := "relay.example.com:7443"

	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	fp1 := FingerprintSHA256(pub1)

	// 1. Pinned fingerprint match
	if err := VerifyKnownHosts(khPath, addr, pub1, fp1, "yes"); err != nil {
		t.Fatalf("pinned match failed: %v", err)
	}
	// Pinned fingerprint mismatch
	if err := VerifyKnownHosts(khPath, addr, pub2, fp1, "yes"); err == nil {
		t.Fatalf("pinned mismatch succeeded unexpectedly")
	}

	// 2. Strict checking with no file -> fail
	if err := VerifyKnownHosts(khPath, addr, pub1, "", "yes"); err == nil {
		t.Fatalf("strict checking with missing file succeeded unexpectedly")
	}

	// 3. TOFU: record pub1
	if err := VerifyKnownHosts(khPath, addr, pub1, "", "ask"); err != nil {
		t.Fatalf("TOFU failed: %v", err)
	}

	// 4. Match pub1 from file
	if err := VerifyKnownHosts(khPath, addr, pub1, "", "yes"); err != nil {
		t.Fatalf("match from file failed: %v", err)
	}

	// 5. MITM check: pub2 presents for same address -> fatal mismatch
	err := VerifyKnownHosts(khPath, addr, pub2, "", "yes")
	if err == nil {
		t.Fatalf("expected MITM error for changed host key, got nil")
	}
	if !strings.Contains(err.Error(), "REMOTE HOST IDENTIFICATION HAS CHANGED") {
		t.Fatalf("unexpected MITM error: %v", err)
	}
}
