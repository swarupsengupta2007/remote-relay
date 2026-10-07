package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/transport"
)

func startWSEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	host, port, cleanup := startEchoServer(t)
	return fmt.Sprintf("%s:%d", host, port), cleanup
}

func startTestRelayServerWS(t *testing.T, isTLS bool) (*Server, string, func()) {
	t.Helper()
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.UDPListen = "127.0.0.1:0"
	cfg.ListenWS = "127.0.0.1:0"
	if isTLS {
		cfg.ListenWS = "wss://127.0.0.1:0"
	}
	cfg.AllowDestinations = []string{"127.0.0.1:*"}
	cfg.AllowRelayHops = []string{"*"}
	cfg.RelayStrictHostKeyChecking = "no"

	log := logging.New(io.Discard, "error", "text")
	srv := NewServer(cfg, log)

	if err := srv.Listen(); err != nil {
		t.Fatalf("server listen failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	// Wait for WSAddr to be ready
	var wsAddr string
	for i := 0; i < 50; i++ {
		wsAddr = srv.WSAddr()
		if wsAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if wsAddr == "" {
		cancel()
		t.Fatalf("server WSAddr was not set")
	}

	cleanup := func() {
		cancel()
		_ = srv.Close()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
		}
	}

	scheme := "ws"
	if isTLS {
		scheme = "wss"
	}
	return srv, fmt.Sprintf("%s://%s/relay-stream", scheme, wsAddr), cleanup
}

func TestRelayWebSocket_DirectE2E(t *testing.T) {
	echoAddr, echoCleanup := startWSEchoServer(t)
	defer echoCleanup()

	_, wsURL, srvCleanup := startTestRelayServerWS(t, false)
	defer srvCleanup()

	cfg := config.DefaultClient()
	cfg.Server = wsURL
	cfg.Transport = "ws"
	cfg.Destination = echoAddr
	cfg.StrictHostKeyChecking = "no"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand read: %v", err)
	}

	stdin := bytes.NewReader(payload)
	var stdout bytes.Buffer

	log := logging.NewClient("error", "text")
	if err := RunClient(ctx, cfg, stdin, &stdout, log); err != nil {
		t.Fatalf("RunClient failed: %v", err)
	}

	if !bytes.Equal(stdout.Bytes(), payload) {
		t.Fatalf("payload mismatch: sent %d bytes, got %d bytes", len(payload), stdout.Len())
	}
}

func TestRelayWebSocket_TLSE2E(t *testing.T) {
	echoAddr, echoCleanup := startWSEchoServer(t)
	defer echoCleanup()

	_, wssURL, srvCleanup := startTestRelayServerWS(t, true)
	defer srvCleanup()

	cfg := config.DefaultClient()
	cfg.Server = wssURL
	cfg.Transport = "ws"
	cfg.TLSInsecure = true
	cfg.Destination = echoAddr
	cfg.StrictHostKeyChecking = "no"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload := make([]byte, 32*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand read: %v", err)
	}

	stdin := bytes.NewReader(payload)
	var stdout bytes.Buffer

	log := logging.NewClient("error", "text")
	if err := RunClient(ctx, cfg, stdin, &stdout, log); err != nil {
		t.Fatalf("RunClient over TLS failed: %v", err)
	}

	if !bytes.Equal(stdout.Bytes(), payload) {
		t.Fatalf("payload mismatch: sent %d bytes, got %d bytes", len(payload), stdout.Len())
	}
}

func TestRelayWebSocket_ReverseProxyMultiplexing(t *testing.T) {
	echoAddr, echoCleanup := startWSEchoServer(t)
	defer echoCleanup()

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.UDPListen = "127.0.0.1:0"
	cfg.AllowDestinations = []string{"127.0.0.1:*"}

	log := logging.New(io.Discard, "error", "text")
	srv := NewServer(cfg, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Mount WebSocketHandler onto a reverse proxy HTTP server
	proxySrv := httptest.NewServer(srv.WebSocketHandler())
	defer proxySrv.Close()

	// 1. Health check endpoint
	resp, err := http.Get(proxySrv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on /health, got %d", resp.StatusCode)
	}

	// 2. Non-websocket HTTP GET on /relay-stream returns 400 Bad Request
	req, _ := http.NewRequest("GET", proxySrv.URL+"/relay-stream", nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /relay-stream failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on non-upgrade request, got %d", resp2.StatusCode)
	}

	// 3. Connect relay client through reverse proxy
	u, _ := url.Parse(proxySrv.URL)
	cliCfg := config.DefaultClient()
	cliCfg.Server = fmt.Sprintf("ws://%s/relay-stream", u.Host)
	cliCfg.Transport = "ws"
	cliCfg.Destination = echoAddr
	cliCfg.StrictHostKeyChecking = "no"

	payload := []byte("testing reverse proxy multiplexed websocket relay tunnel")
	stdin := bytes.NewReader(payload)
	var stdout bytes.Buffer

	clientCtx, clientCancel := context.WithTimeout(ctx, 10*time.Second)
	defer clientCancel()

	if err := RunClient(clientCtx, cliCfg, stdin, &stdout, logging.NewClient("error", "text")); err != nil {
		t.Fatalf("RunClient through reverse proxy failed: %v", err)
	}

	if !bytes.Equal(stdout.Bytes(), payload) {
		t.Fatalf("payload mismatch: sent %q, got %q", payload, stdout.Bytes())
	}
}

func TestRelayWebSocket_HTTPProxyTunneling(t *testing.T) {
	echoAddr, echoCleanup := startWSEchoServer(t)
	defer echoCleanup()

	_, wsURL, srvCleanup := startTestRelayServerWS(t, false)
	defer srvCleanup()

	// Start mock HTTP CONNECT proxy
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer proxyLn.Close()

	proxyDone := make(chan struct{})
	go func() {
		for {
			c, err := proxyLn.Accept()
			if err != nil {
				select {
				case <-proxyDone:
					return
				default:
					return
				}
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != "CONNECT" {
					return
				}
				targetConn, err := net.DialTimeout("tcp", req.URL.Host, 5*time.Second)
				if err != nil {
					_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer targetConn.Close()
				_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				errCh := make(chan error, 2)
				go func() { _, err := io.Copy(targetConn, conn); errCh <- err }()
				go func() { _, err := io.Copy(conn, targetConn); errCh <- err }()
				<-errCh
			}(c)
		}
	}()
	defer close(proxyDone)

	// Set HTTP_PROXY environment for this test run
	t.Setenv("HTTP_PROXY", "http://"+proxyLn.Addr().String())

	cliCfg := config.DefaultClient()
	cliCfg.Server = wsURL
	cliCfg.Transport = "ws"
	cliCfg.Destination = echoAddr
	cliCfg.StrictHostKeyChecking = "no"

	payload := []byte("piped through an enterprise corporate HTTP CONNECT proxy")
	stdin := bytes.NewReader(payload)
	var stdout bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := RunClient(ctx, cliCfg, stdin, &stdout, logging.NewClient("error", "text")); err != nil {
		t.Fatalf("RunClient through HTTP proxy failed: %v", err)
	}

	if !bytes.Equal(stdout.Bytes(), payload) {
		t.Fatalf("mismatch: got %q, want %q", stdout.Bytes(), payload)
	}
}

func TestRelayWebSocket_JumphostChaining(t *testing.T) {
	echoAddr, echoCleanup := startWSEchoServer(t)
	defer echoCleanup()

	// Hop 1: WebSocket server
	_, hop1WSURL, hop1Cleanup := startTestRelayServerWS(t, false)
	defer hop1Cleanup()

	// Hop 2: Standard TCP server
	hop2Cfg := config.DefaultServer()
	hop2Cfg.ListenTCP = "127.0.0.1:0"
	hop2Cfg.UDPListen = "127.0.0.1:0"
	hop2Cfg.AllowRelayHops = []string{"127.0.0.1:*"}
	hop2Cfg.AllowDestinations = []string{"127.0.0.1:*"}
	hop2Srv := NewServer(hop2Cfg, logging.New(io.Discard, "error", "text"))
	if err := hop2Srv.Listen(); err != nil {
		t.Fatalf("hop2 listen failed: %v", err)
	}
	hop2Ctx, hop2Cancel := context.WithCancel(context.Background())
	defer hop2Cancel()
	go func() { _ = hop2Srv.Serve(hop2Ctx) }()
	defer hop2Srv.Close()

	// Hop 1 needs to allow forwarding to Hop 2
	u1, _ := url.Parse(hop1WSURL)
	hop1HostPort := u1.Host

	// Configure client with -J hop1?transport=ws -> hop2 -> echo
	cliCfg := config.DefaultClient()
	cliCfg.Server = hop2Srv.Addr()
	cliCfg.Destination = echoAddr
	cliCfg.Transport = "tcp"
	cliCfg.Jumphost = []string{fmt.Sprintf("%s?transport=ws", hop1HostPort)}
	cliCfg.StrictHostKeyChecking = "no"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload := make([]byte, 16*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	stdin := bytes.NewReader(payload)
	var stdout bytes.Buffer

	if err := RunClient(ctx, cliCfg, stdin, &stdout, logging.NewClient("error", "text")); err != nil {
		t.Fatalf("RunClient over chained WebSocket hop failed: %v", err)
	}

	if !bytes.Equal(stdout.Bytes(), payload) {
		t.Fatalf("payload mismatch across jumphost chain: sent %d bytes, got %d bytes", len(payload), stdout.Len())
	}
}

func TestRelayWebSocket_Resumption(t *testing.T) {
	echoAddr, echoCleanup := startWSEchoServer(t)
	defer echoCleanup()

	_, wsURL, srvCleanup := startTestRelayServerWS(t, false)
	defer srvCleanup()

	cliCfg := config.DefaultClient()
	cliCfg.Server = wsURL
	cliCfg.Transport = "ws"
	cliCfg.Destination = echoAddr
	cliCfg.StrictHostKeyChecking = "no"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Initial connection via clientHello
	conn, helloOK, err := clientHello(ctx, cliCfg)
	if err != nil {
		t.Fatalf("clientHello failed: %v", err)
	}
	defer conn.Close()

	if helloOK.Transport != "ws" {
		t.Fatalf("expected transport 'ws', got %q", helloOK.Transport)
	}

	// 2. Resume the session over WebSocket via clientResume
	resumeConn, resumeOK, err := clientResume(ctx, cliCfg, helloOK.SessionID, helloOK.ResumeToken, 0)
	if err != nil {
		t.Fatalf("clientResume over WebSocket failed: %v", err)
	}
	defer resumeConn.Close()

	if resumeOK.SessionID != helloOK.SessionID {
		t.Fatalf("session ID mismatch: got %q, want %q", resumeOK.SessionID, helloOK.SessionID)
	}
}

func TestRelayWebSocket_SadPaths(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Unreachable server
	_, err := transport.DialWebSocket(ctx, "ws://127.0.0.1:54321/relay-stream", nil)
	if err == nil {
		t.Fatalf("expected dial failure on closed port, got success")
	}

	// 2. Strict TLS failure
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	_, err = transport.DialWebSocket(ctx, fmt.Sprintf("wss://%s/relay-stream", u.Host), &transport.WebSocketDialOptions{
		TLSConfig: &tls.Config{InsecureSkipVerify: false},
	})
	if err == nil {
		t.Fatalf("expected TLS verification failure, got success")
	}
	t.Logf("Got expected TLS error: %v", err)
}

func TestRelayWebSocket_HostKeyVerification(t *testing.T) {
	echoAddr, echoCleanup := startWSEchoServer(t)
	defer echoCleanup()

	srv, wsURL, srvCleanup := startTestRelayServerWS(t, false)
	defer srvCleanup()

	fingerprint := srv.HostFingerprint()

	// 1. Success with correct pinned fingerprint and StrictHostKeyChecking = "yes"
	{
		cfg := config.DefaultClient()
		cfg.Server = wsURL
		cfg.Transport = "ws"
		cfg.Destination = echoAddr
		cfg.ServerFingerprint = fingerprint
		cfg.StrictHostKeyChecking = "yes"

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, helloOK, err := clientHello(ctx, cfg)
		if err != nil {
			t.Fatalf("clientHello with valid pinned fingerprint failed: %v", err)
		}
		_ = conn.Close()
		if helloOK.SessionID == "" {
			t.Fatalf("expected valid session ID, got empty")
		}
	}

	// 2. Failure with wrong pinned fingerprint
	{
		cfg := config.DefaultClient()
		cfg.Server = wsURL
		cfg.Transport = "ws"
		cfg.Destination = echoAddr
		cfg.ServerFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		cfg.StrictHostKeyChecking = "yes"

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, _, err := clientHello(ctx, cfg)
		if err == nil {
			if conn != nil {
				_ = conn.Close()
			}
			t.Fatalf("expected host key verification failure with mismatched fingerprint, got success")
		}
		t.Logf("Got expected host key error: %v", err)
	}
}
