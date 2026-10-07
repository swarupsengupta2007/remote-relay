package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/proto"
	"golang.org/x/net/websocket"
)

func startTestWSServer(t *testing.T, isTLS bool) (string, *tls.Certificate, func()) {
	t.Helper()
	var cert tls.Certificate
	var err error
	if isTLS {
		cert, err = GenerateEphemeralCert()
		if err != nil {
			t.Fatalf("failed to generate ephemeral cert: %v", err)
		}
	}

	wsHandler := &websocket.Server{
		Handshake: func(cfg *websocket.Config, req *http.Request) error {
			return nil
		},
		Handler: func(ws *websocket.Conn) {
			ws.PayloadType = websocket.BinaryFrame
			wsc, err := WrapWebSocket(ws, ws.RemoteAddr())
			if err != nil {
				return
			}
			defer wsc.Close()

			// Echo frames back to client
			for {
				f, err := wsc.ReadFrame()
				if err != nil {
					return
				}
				if err := wsc.WriteFrame(f); err != nil {
					return
				}
			}
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/relay-stream", wsHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	var srv *httptest.Server
	if isTLS {
		srv = httptest.NewUnstartedServer(mux)
		srv.TLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		srv.StartTLS()
	} else {
		srv = httptest.NewServer(mux)
	}

	cleanup := func() {
		srv.Close()
	}
	return srv.URL, &cert, cleanup
}

func TestWebSocketDirect_HappyPath(t *testing.T) {
	srvURL, _, cleanup := startTestWSServer(t, false)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialWebSocket(ctx, srvURL+"/relay-stream", nil)
	if err != nil {
		t.Fatalf("DialWebSocket failed: %v", err)
	}
	defer conn.Close()

	if conn.Kind() != KindWebSocket {
		t.Fatalf("expected KindWebSocket, got %v", conn.Kind())
	}
	if conn.Kind().String() != "ws" {
		t.Fatalf("expected 'ws', got %q", conn.Kind().String())
	}

	// Send test frame
	testPayload := []byte("hello websocket transport world!")
	f := proto.Frame{Type: proto.TypeData, Payload: testPayload}
	if err := conn.WriteFrame(f); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	reply, err := conn.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if reply.Type != proto.TypeData {
		t.Fatalf("expected TypeData, got %v", reply.Type)
	}
	if string(reply.Payload) != string(testPayload) {
		t.Fatalf("payload mismatch: expected %q, got %q", testPayload, reply.Payload)
	}
}

func TestWebSocketTLS_HappyAndSadPaths(t *testing.T) {
	srvURL, cert, cleanup := startTestWSServer(t, true)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Sad Path: TLS verification failure with strict InsecureSkipVerify: false
	strictOpts := &WebSocketDialOptions{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
	_, err := DialWebSocket(ctx, srvURL+"/relay-stream", strictOpts)
	if err == nil {
		t.Fatalf("expected TLS verification failure on self-signed cert, but succeeded")
	}
	t.Logf("Got expected TLS failure: %v", err)

	// 2. Happy Path: InsecureSkipVerify: true
	insecureOpts := &WebSocketDialOptions{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	conn, err := DialWebSocket(ctx, srvURL+"/relay-stream", insecureOpts)
	if err != nil {
		t.Fatalf("DialWebSocket with InsecureSkipVerify failed: %v", err)
	}
	defer conn.Close()

	// Verify byte-exact echo over TLS
	testMsg := []byte("secure websocket frame over TLS 1.3")
	if err := conn.WriteFrame(proto.Frame{Type: proto.TypePing, Payload: testMsg}); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}
	reply, err := conn.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if reply.Type != proto.TypePing || string(reply.Payload) != string(testMsg) {
		t.Fatalf("unexpected reply: %+v", reply)
	}

	_ = cert
}

// startTestHTTPProxy starts a mock HTTP CONNECT proxy.
func startTestHTTPProxy(t *testing.T, requireAuth bool, wantUser, wantPass string, refuseCode int) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					return
				}
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if req.Method != "CONNECT" {
					resp := "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
					_, _ = conn.Write([]byte(resp))
					return
				}

				if refuseCode > 0 {
					resp := fmt.Sprintf("HTTP/1.1 %d Refused\r\nContent-Length: 0\r\n\r\n", refuseCode)
					_, _ = conn.Write([]byte(resp))
					return
				}

				if requireAuth {
					proxyAuth := req.Header.Get("Proxy-Authorization")
					expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(wantUser+":"+wantPass))
					if proxyAuth != expected {
						resp := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n"
						_, _ = conn.Write([]byte(resp))
						return
					}
				}

				// Dial target
				targetConn, err := net.DialTimeout("tcp", req.URL.Host, 5*time.Second)
				if err != nil {
					resp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
					_, _ = conn.Write([]byte(resp))
					return
				}
				defer targetConn.Close()

				// Connection Established
				resp := "HTTP/1.1 200 Connection Established\r\n\r\n"
				if _, err := conn.Write([]byte(resp)); err != nil {
					return
				}

				// Proxy bi-directionally
				errCh := make(chan error, 2)
				go func() {
					_, err := io.Copy(targetConn, conn)
					errCh <- err
				}()
				go func() {
					_, err := io.Copy(conn, targetConn)
					errCh <- err
				}()
				<-errCh
			}(c)
		}
	}()

	cleanup := func() {
		close(stopCh)
		_ = ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), cleanup
}

func TestWebSocketProxy_HappyPath(t *testing.T) {
	wsURL, _, wsCleanup := startTestWSServer(t, false)
	defer wsCleanup()

	proxyAddr, proxyCleanup := startTestHTTPProxy(t, false, "", "", 0)
	defer proxyCleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	opts := &WebSocketDialOptions{
		ProxyFunc: func(r *http.Request) (*url.URL, error) {
			return proxyURL, nil
		},
	}

	conn, err := DialWebSocket(ctx, wsURL+"/relay-stream", opts)
	if err != nil {
		t.Fatalf("DialWebSocket through proxy failed: %v", err)
	}
	defer conn.Close()

	testData := []byte("tunneled through HTTP CONNECT proxy")
	if err := conn.WriteFrame(proto.Frame{Type: proto.TypeData, Payload: testData}); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}
	reply, err := conn.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if string(reply.Payload) != string(testData) {
		t.Fatalf("mismatch: got %q, want %q", reply.Payload, testData)
	}
}

func TestWebSocketProxy_WithBasicAuth(t *testing.T) {
	wsURL, _, wsCleanup := startTestWSServer(t, false)
	defer wsCleanup()

	proxyAddr, proxyCleanup := startTestHTTPProxy(t, true, "proxyuser", "secret123", 0)
	defer proxyCleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Sad path: missing / bad auth
	badProxyURL, _ := url.Parse("http://wrong:credentials@" + proxyAddr)
	badOpts := &WebSocketDialOptions{
		ProxyFunc: func(r *http.Request) (*url.URL, error) {
			return badProxyURL, nil
		},
	}
	_, err := DialWebSocket(ctx, wsURL+"/relay-stream", badOpts)
	if err == nil {
		t.Fatalf("expected 407 proxy authentication failure, got success")
	}
	if !strings.Contains(err.Error(), "407") {
		t.Fatalf("expected 407 error message, got: %v", err)
	}

	// 2. Happy path: valid credentials
	goodProxyURL, _ := url.Parse("http://proxyuser:secret123@" + proxyAddr)
	goodOpts := &WebSocketDialOptions{
		ProxyFunc: func(r *http.Request) (*url.URL, error) {
			return goodProxyURL, nil
		},
	}
	conn, err := DialWebSocket(ctx, wsURL+"/relay-stream", goodOpts)
	if err != nil {
		t.Fatalf("DialWebSocket with valid proxy credentials failed: %v", err)
	}
	defer conn.Close()

	testData := []byte("authenticated proxy tunnel success")
	if err := conn.WriteFrame(proto.Frame{Type: proto.TypeData, Payload: testData}); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}
	reply, err := conn.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if string(reply.Payload) != string(testData) {
		t.Fatalf("mismatch: got %q, want %q", reply.Payload, testData)
	}
}

func TestWebSocketProxy_RefusalAndBadGateway(t *testing.T) {
	wsURL, _, wsCleanup := startTestWSServer(t, false)
	defer wsCleanup()

	proxyAddr, proxyCleanup := startTestHTTPProxy(t, false, "", "", 403)
	defer proxyCleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	opts := &WebSocketDialOptions{
		ProxyFunc: func(r *http.Request) (*url.URL, error) {
			return proxyURL, nil
		},
	}

	_, err := DialWebSocket(ctx, wsURL+"/relay-stream", opts)
	if err == nil {
		t.Fatalf("expected error on proxy refusal, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 status in error, got: %v", err)
	}
}

func TestWebSocket_InvalidUpgradeResponse(t *testing.T) {
	// Start an HTTP server that returns 404 Not Found on the websocket path
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := DialWebSocket(ctx, srv.URL+"/wrong-path", nil)
	if err == nil {
		t.Fatalf("expected error when connecting to non-websocket endpoint, got nil")
	}
	t.Logf("Got expected upgrade error: %v", err)
}

func TestWebSocket_ClientIPExtraction(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/relay-stream", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	// Direct remote addr, no forwarded headers.
	ip := ExtractClientIP(req, nil, nil)
	if ip != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %q", ip)
	}

	// Forged headers from an untrusted peer are ignored.
	req.Header.Set("X-Real-IP", "203.0.113.195")
	req.Header.Set("X-Forwarded-For", "198.51.100.42, 10.0.0.1")
	ip = ExtractClientIP(req, nil, nil)
	if ip != "10.0.0.1" {
		t.Fatalf("untrusted peer: expected 10.0.0.1, got %q", ip)
	}
	addr := ExtractRemoteAddr(req, nil, nil)
	if addr == nil || addr.String() != "10.0.0.1:12345" {
		t.Fatalf("untrusted peer: expected 10.0.0.1:12345, got %v", addr)
	}

	// The same headers are honored when the direct peer is trusted.
	trusted := []string{"10.0.0.1"}
	ip = ExtractClientIP(req, nil, trusted)
	if ip != "198.51.100.42" {
		t.Fatalf("trusted peer: expected 198.51.100.42, got %q", ip)
	}
	addr = ExtractRemoteAddr(req, nil, trusted)
	if addr == nil || addr.String() != "198.51.100.42:12345" {
		t.Fatalf("trusted peer: expected 198.51.100.42:12345, got %v", addr)
	}

	req.Header.Del("X-Forwarded-For")
	ip = ExtractClientIP(req, nil, trusted)
	if ip != "203.0.113.195" {
		t.Fatalf("trusted X-Real-IP: expected 203.0.113.195, got %q", ip)
	}

	// A server websocket.Conn reports the Origin URL as RemoteAddr; the trust
	// decision must still use the TCP peer in req.RemoteAddr.
	req.Header.Set("X-Forwarded-For", "198.51.100.42")
	origin, _ := url.Parse("http://proxy.example")
	originAddr := &websocket.Addr{URL: origin}
	ip = ExtractClientIP(req, originAddr, trusted)
	if ip != "198.51.100.42" {
		t.Fatalf("origin raw addr, trusted peer: expected 198.51.100.42, got %q", ip)
	}
	ip = ExtractClientIP(req, originAddr, nil)
	if ip != "10.0.0.1" {
		t.Fatalf("origin raw addr, untrusted peer: expected 10.0.0.1, got %q", ip)
	}
}

func TestWebSocket_DeadlineAndResetReader(t *testing.T) {
	srvURL, _, cleanup := startTestWSServer(t, false)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialWebSocket(ctx, srvURL+"/relay-stream", nil)
	if err != nil {
		t.Fatalf("DialWebSocket failed: %v", err)
	}
	defer conn.Close()

	conn.ResetReader()

	// Set very short read deadline
	_ = conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = conn.ReadFrame()
	if err == nil {
		t.Fatalf("expected read timeout error, got nil")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Logf("got error on timeout: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
}
