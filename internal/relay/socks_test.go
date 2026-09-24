package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/socks5"
)

func testSocksServer(t *testing.T, allowDests []string, disableSOCKS bool) (string, *Server, context.CancelFunc) {
	t.Helper()
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	if len(allowDests) > 0 {
		cfg.AllowDestinations = allowDests
	} else {
		cfg.AllowDestinations = []string{"127.0.0.1:*", "localhost:*"}
	}
	cfg.DisableSOCKS = disableSOCKS
	cfg.Transports = []string{"tcp"}
	cfg.LogLevel = "error"
	cfg.IdleTimeout = config.Duration(30 * time.Second)
	cfg.HoldTimeout = config.Duration(10 * time.Second)
	cfg.DialTimeout = config.Duration(2 * time.Second)

	srv, addr, cancel := startRelayCfg(t, cfg)
	return addr, srv, cancel
}

func startSocksProxyForTest(t *testing.T, serverAddr string, maxStreams int) (string, context.CancelFunc) {
	t.Helper()
	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = serverAddr
	ccfg.Destination = proto.DestSOCKS5
	ccfg.Transport = "tcp"
	ccfg.IdentityFiles = []string{os.Getenv("RELAY_TEST_IDENTITY")}
	ccfg.LogLevel = "error"
	if maxStreams > 0 {
		ccfg.MaxSocksStreams = maxStreams
	}

	boundCh := make(chan string, 1)
	readyCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	log := logging.New(io.Discard, "error", "text")

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunSocks(ctx, SocksConfig{
			Listen:     "127.0.0.1:0",
			MaxStreams: maxStreams,
			Log:        log,
			ReadyCh:    readyCh,
			OnBound: func(addr string) {
				boundCh <- addr
			},
		}, ccfg)
	}()

	var socksAddr string
	select {
	case socksAddr = <-boundCh:
	case err := <-errCh:
		t.Fatalf("RunSocks failed on startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for SOCKS proxy to bind")
	}

	select {
	case <-readyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for SOCKS proxy ready")
	}

	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
		}
	})

	return socksAddr, cancel
}

func socks5DialTarget(proxyAddr string, cmd byte, targetHost string, targetPort uint16) (net.Conn, byte, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		return nil, 0, err
	}

	// 1. Handshake
	if _, err := conn.Write([]byte{socks5.Version5, 1, socks5.MethodNoAuth}); err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	var authResp [2]byte
	if _, err := io.ReadFull(conn, authResp[:]); err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	if authResp[0] != socks5.Version5 || authResp[1] != socks5.MethodNoAuth {
		_ = conn.Close()
		return nil, authResp[1], fmt.Errorf("auth error: %v", authResp)
	}

	// 2. Request
	var req []byte
	ip := net.ParseIP(targetHost)
	if ip4 := ip.To4(); ip4 != nil {
		req = append([]byte{socks5.Version5, cmd, 0x00, socks5.AtypIPv4}, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = append([]byte{socks5.Version5, cmd, 0x00, socks5.AtypIPv6}, ip6...)
	} else {
		req = append([]byte{socks5.Version5, cmd, 0x00, socks5.AtypDomainName, byte(len(targetHost))}, []byte(targetHost)...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], targetPort)
	req = append(req, portBuf[:]...)

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, 0, err
	}

	// 3. Read Reply
	var replyHdr [4]byte
	if _, err := io.ReadFull(conn, replyHdr[:]); err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	rep := replyHdr[1]
	atyp := replyHdr[3]
	switch atyp {
	case socks5.AtypIPv4:
		var dummy [6]byte
		_, _ = io.ReadFull(conn, dummy[:])
	case socks5.AtypDomainName:
		var lenBuf [1]byte
		_, _ = io.ReadFull(conn, lenBuf[:])
		dummy := make([]byte, int(lenBuf[0])+2)
		_, _ = io.ReadFull(conn, dummy)
	case socks5.AtypIPv6:
		var dummy [18]byte
		_, _ = io.ReadFull(conn, dummy[:])
	}

	if rep != socks5.RepSucceeded {
		_ = conn.Close()
		return nil, rep, fmt.Errorf("socks reply error: 0x%02x", rep)
	}

	return conn, rep, nil
}

func startEchoServer(t *testing.T) (string, uint16, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	port := uint16(p)

	closed := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	return host, port, func() {
		_ = ln.Close()
		close(closed)
	}
}

// 1. Happy Path: IPv4 address destination data transfer with SHA256 integrity check.
func TestSOCKS5_HappyPath_IPv4DataTransfer(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)
	echoHost, echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	conn, rep, err := socks5DialTarget(socksAddr, socks5.CmdConnect, echoHost, echoPort)
	if err != nil {
		t.Fatalf("socks5DialTarget failed: %v, rep: 0x%02x", err, rep)
	}
	defer conn.Close()

	payload := make([]byte, 65536)
	_, _ = rand.Read(payload)
	expectedHash := sha256.Sum256(payload)

	go func() {
		_, _ = conn.Write(payload)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("io.ReadAll failed: %v", err)
	}
	gotHash := sha256.Sum256(got)
	if gotHash != expectedHash {
		t.Fatalf("data corrupted: hash mismatch (got %d bytes, expected %d)", len(got), len(payload))
	}
}

// 2. Happy Path: FQDN domain name destination data transfer.
func TestSOCKS5_HappyPath_DomainDataTransfer(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)
	_, echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	// Dial using "localhost" domain name (RFC 1928 ATYP 0x03)
	conn, rep, err := socks5DialTarget(socksAddr, socks5.CmdConnect, "localhost", echoPort)
	if err != nil {
		t.Fatalf("socks5DialTarget with domain failed: %v, rep: 0x%02x", err, rep)
	}
	defer conn.Close()

	payload := []byte("Hello remote-relay SOCKS5 FQDN dynamic forwarding!")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("conn.Write failed: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("io.ReadFull failed: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("payload mismatch: expected %q, got %q", payload, buf)
	}
}

// 3. Happy Path: Multiple concurrent SOCKS streams multiplexed over the same tunnel.
func TestSOCKS5_HappyPath_ConcurrentMultiplexing(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)
	echoHost, echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	const numClients = 8
	const dataPerClient = 16384 // 16 KiB

	var wg sync.WaitGroup
	errCh := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			conn, rep, err := socks5DialTarget(socksAddr, socks5.CmdConnect, echoHost, echoPort)
			if err != nil {
				errCh <- fmt.Errorf("client %d dial failed (rep: 0x%02x): %w", clientID, rep, err)
				return
			}
			defer conn.Close()

			data := make([]byte, dataPerClient)
			// Unique pattern per client
			for j := range data {
				data[j] = byte((clientID + j) % 256)
			}
			dataHash := sha256.Sum256(data)

			go func() {
				_, _ = conn.Write(data)
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}()

			received, err := io.ReadAll(conn)
			if err != nil {
				errCh <- fmt.Errorf("client %d read failed: %w", clientID, err)
				return
			}
			recvHash := sha256.Sum256(received)
			if recvHash != dataHash {
				errCh <- fmt.Errorf("client %d data mismatch (got %d bytes)", clientID, len(received))
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

// 4. Sad Path: Invalid SOCKS version (e.g. SOCKS4 or HTTP GET).
func TestSOCKS5_SadPath_InvalidVersion(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)

	// Send SOCKS4
	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte{0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0})
	buf := make([]byte, 10)
	n, _ := conn.Read(buf)
	if n > 0 && buf[0] == 0x05 && buf[1] == 0x00 {
		t.Fatalf("unexpected success reply for SOCKS4 version")
	}

	// Send HTTP GET
	conn2, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn2.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	n2, _ := conn2.Read(buf)
	if n2 > 0 && buf[0] == 0x05 && buf[1] == 0x00 {
		t.Fatalf("unexpected success reply for HTTP GET")
	}
}

// 5. Sad Path: Client does not offer NoAuth (0x00).
func TestSOCKS5_SadPath_NoSupportedAuth(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)

	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Offer only 0x02 (Username/Password), but proxy requires 0x00 (NoAuth)
	_, _ = conn.Write([]byte{socks5.Version5, 1, socks5.MethodUsernamePassword})
	var resp [2]byte
	_, err = io.ReadFull(conn, resp[:])
	if err != nil {
		t.Fatalf("failed reading auth response: %v", err)
	}
	if resp[1] != socks5.MethodNoAcceptable {
		t.Fatalf("expected MethodNoAcceptable (0xFF), got 0x%02x", resp[1])
	}
}

// 6. Sad Path: Unsupported command (BIND or UDP ASSOCIATE).
func TestSOCKS5_SadPath_UnsupportedCommand(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)

	// CMD = 0x02 (BIND)
	conn, rep, err := socks5DialTarget(socksAddr, socks5.CmdBind, "127.0.0.1", 8080)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatalf("expected error for BIND command, got success")
	}
	if rep != socks5.RepCommandNotSupported {
		t.Fatalf("expected RepCommandNotSupported (0x07), got 0x%02x", rep)
	}

	// CMD = 0x03 (UDP ASSOCIATE)
	conn, rep, err = socks5DialTarget(socksAddr, socks5.CmdUDPAssociate, "127.0.0.1", 8080)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatalf("expected error for UDP ASSOCIATE command, got success")
	}
	if rep != socks5.RepCommandNotSupported {
		t.Fatalf("expected RepCommandNotSupported (0x07), got 0x%02x", rep)
	}
}

// 7. Sad Path: Unsupported address type.
func TestSOCKS5_SadPath_UnsupportedAddressType(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)

	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Handshake
	_, _ = conn.Write([]byte{socks5.Version5, 1, socks5.MethodNoAuth})
	var authResp [2]byte
	_, _ = io.ReadFull(conn, authResp[:])

	// Send request with ATYP = 0x02 (unsupported)
	_, _ = conn.Write([]byte{socks5.Version5, socks5.CmdConnect, 0x00, 0x02, 127, 0, 0, 1, 0, 80})
	var replyHdr [4]byte
	_, err = io.ReadFull(conn, replyHdr[:])
	if err != nil {
		t.Fatalf("failed reading reply: %v", err)
	}
	if replyHdr[1] != socks5.RepAddressNotSupported {
		t.Fatalf("expected RepAddressNotSupported (0x08), got 0x%02x", replyHdr[1])
	}
}

// 8. Sad Path: Destination forbidden by server ruleset (allow_destinations).
func TestSOCKS5_SadPath_DestinationForbidden_Ruleset(t *testing.T) {
	// Server only allows 10.0.0.0/8
	serverAddr, _, _ := testSocksServer(t, []string{"10.0.0.0/8"}, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)

	// Attempt to connect to 127.0.0.1:80 (forbidden by ruleset)
	conn, rep, err := socks5DialTarget(socksAddr, socks5.CmdConnect, "127.0.0.1", 80)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatalf("expected ruleset forbidden error, got success")
	}
	if rep != socks5.RepConnectionNotAllowed {
		t.Fatalf("expected RepConnectionNotAllowed (0x02), got 0x%02x", rep)
	}
}

// 9. Sad Path: Destination host unreachable (DNS resolution failure).
func TestSOCKS5_SadPath_DestinationHostUnreachable_DNS(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, []string{"*"}, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)

	conn, rep, err := socks5DialTarget(socksAddr, socks5.CmdConnect, "nonexistent.domain.invalid.testing", 8080)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatalf("expected host unreachable error, got success")
	}
	if rep != socks5.RepHostUnreachable && rep != socks5.RepGeneralFailure {
		t.Fatalf("expected RepHostUnreachable (0x04) or RepGeneralFailure (0x01), got 0x%02x", rep)
	}
}

// 10. Sad Path: Destination connection refused.
func TestSOCKS5_SadPath_DestinationConnectionRefused(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, []string{"127.0.0.1:*"}, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)

	// Find an unused local port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	unusedPort := uint16(p)
	_ = ln.Close() // closed immediately, nothing listening

	conn, rep, err := socks5DialTarget(socksAddr, socks5.CmdConnect, "127.0.0.1", unusedPort)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatalf("expected connection refused error, got success")
	}
	if rep != socks5.RepConnectionRefused {
		t.Fatalf("expected RepConnectionRefused (0x05), got 0x%02x", rep)
	}
}

// 11. Sad Path: Abrupt client disconnect mid-transfer.
func TestSOCKS5_SadPath_AbruptClientDisconnect(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)
	echoHost, echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	conn, rep, err := socks5DialTarget(socksAddr, socks5.CmdConnect, echoHost, echoPort)
	if err != nil {
		t.Fatalf("dial failed (rep: 0x%02x): %v", rep, err)
	}

	// Send a few bytes and abruptly close the socket without reading
	_, _ = conn.Write([]byte("abrupt-disconnect-payload"))
	_ = conn.Close()

	// Wait briefly to allow teardown to propagate across the multiplexer
	time.Sleep(100 * time.Millisecond)
}

// 12. Sad Path: Abrupt destination server disconnect.
func TestSOCKS5_SadPath_AbruptServerDisconnect(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)

	// Single-connection server that accepts, sends 12 bytes, then closes
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)
	destPort := uint16(p)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("server-close"))
		_ = c.Close()
	}()

	conn, rep, err := socks5DialTarget(socksAddr, socks5.CmdConnect, "127.0.0.1", destPort)
	if err != nil {
		t.Fatalf("dial failed (rep: 0x%02x): %v", rep, err)
	}
	defer conn.Close()

	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if string(buf) != "server-close" {
		t.Fatalf("expected 'server-close', got %q", string(buf))
	}
}

// 13. Sad Path: Max active streams limit exceeded.
func TestSOCKS5_SadPath_MaxStreamsLimit(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	// Cap proxy at 2 active streams
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 2)
	echoHost, echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	conn1, rep1, err1 := socks5DialTarget(socksAddr, socks5.CmdConnect, echoHost, echoPort)
	if err1 != nil {
		t.Fatalf("conn1 failed: %v (rep 0x%02x)", err1, rep1)
	}
	defer conn1.Close()

	conn2, rep2, err2 := socks5DialTarget(socksAddr, socks5.CmdConnect, echoHost, echoPort)
	if err2 != nil {
		t.Fatalf("conn2 failed: %v (rep 0x%02x)", err2, rep2)
	}
	defer conn2.Close()

	// 3rd stream must exceed limit
	conn3, rep3, err3 := socks5DialTarget(socksAddr, socks5.CmdConnect, echoHost, echoPort)
	if conn3 != nil {
		conn3.Close()
	}
	if err3 == nil {
		t.Fatalf("expected 3rd stream to be rejected due to max streams limit, but got success")
	}
	if rep3 != socks5.RepGeneralFailure {
		t.Fatalf("expected RepGeneralFailure (0x01) on capacity exceeded, got 0x%02x", rep3)
	}
}

// 14. Sad Path: Server has DisableSOCKS configured.
func TestSOCKS5_SadPath_ServerDisabledSOCKS(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, true) // disableSOCKS = true

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = serverAddr
	ccfg.Destination = proto.DestSOCKS5
	ccfg.Transport = "tcp"
	ccfg.IdentityFiles = []string{os.Getenv("RELAY_TEST_IDENTITY")}
	ccfg.LogLevel = "error"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	log := logging.New(io.Discard, "error", "text")

	err := RunClient(ctx, ccfg, bytes.NewReader(nil), io.Discard, log)
	if err == nil {
		t.Fatalf("expected error when SOCKS disabled on server, got nil")
	}
}

// 15. Resilience: Active SOCKS5 data transfer survives carrier drops via hold and resume.
func TestSOCKS5_Resilience_HoldAndResumeDuringActiveStreaming(t *testing.T) {
	serverAddr, srv, _ := testSocksServer(t, nil, false)
	socksAddr, _ := startSocksProxyForTest(t, serverAddr, 0)
	echoHost, echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	conn, rep, err := socks5DialTarget(socksAddr, socks5.CmdConnect, echoHost, echoPort)
	if err != nil {
		t.Fatalf("socks5DialTarget failed: %v, rep: 0x%02x", err, rep)
	}
	defer conn.Close()

	const totalBytes = 256 * 1024 // 256 KiB
	payload := make([]byte, totalBytes)
	_, _ = rand.Read(payload)
	expectedHash := sha256.Sum256(payload)

	// Writer writes in 16 KiB chunks with slight spacing
	go func() {
		defer func() {
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
		}()
		chunkSize := 16384
		for written := 0; written < totalBytes; written += chunkSize {
			end := written + chunkSize
			if end > totalBytes {
				end = totalBytes
			}
			_, _ = conn.Write(payload[written:end])
			time.Sleep(5 * time.Millisecond)
		}
	}()

	received := make([]byte, 0, totalBytes)
	buf := make([]byte, 16384)
	dropped := false

	for len(received) < totalBytes {
		n, err := conn.Read(buf)
		if n > 0 {
			received = append(received, buf[:n]...)
			// Abruptly drop the underlying carrier while data is in-flight!
			if !dropped && len(received) >= 64*1024 {
				dropped = true
				srv.dropLiveTransports()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("read failed mid-stream: %v", err)
		}
	}

	if len(received) != totalBytes {
		t.Fatalf("received length mismatch: got %d, want %d", len(received), totalBytes)
	}
	receivedHash := sha256.Sum256(received)
	if receivedHash != expectedHash {
		t.Fatalf("data corrupted across carrier drop: SHA256 mismatch")
	}
}
