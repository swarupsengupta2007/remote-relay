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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/proto"
	"golang.org/x/net/websocket"
)

const (
	wsBufSize              = 128 * 1024
	defaultWebSocketPath   = "/relay-stream"
	defaultWSDialTimeout   = 10 * time.Second
	defaultMaxWebSocketMsg = 32 * 1024 * 1024
)

// wsConn implements transport.Conn over a WebSocket connection.
type wsConn struct {
	ws         *websocket.Conn
	br         *bufio.Reader
	bw         *bufio.Writer
	localAddr  net.Addr
	remoteAddr net.Addr
	closeOnce  sync.Once
}

// WrapWebSocket wraps an existing server or client websocket.Conn as a transport.Conn.
func WrapWebSocket(ws *websocket.Conn, remoteAddr net.Addr) (Conn, error) {
	if ws == nil {
		return nil, errors.New("websocket: nil connection")
	}
	ws.PayloadType = websocket.BinaryFrame
	ws.MaxPayloadBytes = defaultMaxWebSocketMsg
	var local net.Addr = ws.LocalAddr()
	if c, ok := ws.Config().Location, ws.IsServerConn(); ok && c != nil {
		local = &websocket.Addr{URL: c}
	}
	return &wsConn{
		ws:         ws,
		br:         bufio.NewReaderSize(ws, wsBufSize),
		bw:         bufio.NewWriterSize(ws, wsBufSize),
		localAddr:  local,
		remoteAddr: remoteAddr,
	}, nil
}

// WrapWebSocketWithAddrs wraps a websocket.Conn with explicit local and remote network addresses.
func WrapWebSocketWithAddrs(ws *websocket.Conn, localAddr, remoteAddr net.Addr) Conn {
	ws.PayloadType = websocket.BinaryFrame
	ws.MaxPayloadBytes = defaultMaxWebSocketMsg
	return &wsConn{
		ws:         ws,
		br:         bufio.NewReaderSize(ws, wsBufSize),
		bw:         bufio.NewWriterSize(ws, wsBufSize),
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

func (c *wsConn) ReadFrame() (proto.Frame, error) {
	return proto.ReadFrame(c.br)
}

func (c *wsConn) WriteFrame(f proto.Frame) error {
	if err := proto.WriteFrame(c.bw, f); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *wsConn) SetDeadline(t time.Time) error {
	return c.ws.SetDeadline(t)
}

func (c *wsConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return c.ws.LocalAddr()
}

func (c *wsConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.ws.RemoteAddr()
}

func (c *wsConn) Kind() Kind {
	return KindWebSocket
}

func (c *wsConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		// Do not Flush here: WriteFrame is the only writer, and Close can race with it.
		err = c.ws.Close()
	})
	return err
}

func (c *wsConn) ResetReader() {
	c.br.Reset(c.ws)
}

func (c *wsConn) Underlying() *websocket.Conn {
	return c.ws
}

// WebSocketDialOptions configures client-side WebSocket dial behavior.
type WebSocketDialOptions struct {
	TLSConfig *tls.Config
	Bind      BindConfig
	ProxyFunc func(*http.Request) (*url.URL, error)
	Header    http.Header
	Timeout   time.Duration
}

// ParseWebSocketURL normalizes a target address or URL into an RFC 6455 WebSocket URL string.
func ParseWebSocketURL(serverAddr string) (rawURL string, hostPort string, isWSS bool, err error) {
	addr := strings.TrimSpace(serverAddr)
	if addr == "" {
		return "", "", false, errors.New("empty websocket server address")
	}

	scheme := ""
	if strings.HasPrefix(addr, "ws://") || strings.HasPrefix(addr, "http://") {
		scheme = "ws"
		addr = strings.TrimPrefix(strings.TrimPrefix(addr, "ws://"), "http://")
	} else if strings.HasPrefix(addr, "wss://") || strings.HasPrefix(addr, "https://") {
		scheme = "wss"
		addr = strings.TrimPrefix(strings.TrimPrefix(addr, "wss://"), "https://")
	}

	path := defaultWebSocketPath
	if idx := strings.Index(addr, "/"); idx >= 0 {
		path = addr[idx:]
		addr = addr[:idx]
	}
	if path == "" || path == "/" {
		path = defaultWebSocketPath
	}

	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		host = addr
		if scheme == "wss" {
			port = "443"
		} else if scheme == "ws" {
			port = "80"
		} else {
			// Unspecified scheme and port: default to 443 with wss
			scheme = "wss"
			port = "443"
		}
	} else {
		if scheme == "" {
			if port == "443" || port == "8443" {
				scheme = "wss"
			} else {
				scheme = "ws"
			}
		}
	}

	hostPort = net.JoinHostPort(host, port)
	isWSS = (scheme == "wss")
	rawURL = fmt.Sprintf("%s://%s%s", scheme, hostPort, path)
	return rawURL, hostPort, isWSS, nil
}

// DialWebSocket dials a WebSocket connection to serverAddr over ws:// or wss://,
// supporting Happy Eyeballs TCP racing, HTTP CONNECT proxy tunneling, and TLS validation.
func DialWebSocket(ctx context.Context, serverAddr string, opts *WebSocketDialOptions) (Conn, error) {
	if opts == nil {
		opts = &WebSocketDialOptions{}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultWSDialTimeout
	}
	proxyFunc := opts.ProxyFunc
	if proxyFunc == nil {
		proxyFunc = http.ProxyFromEnvironment
	}

	wsURLStr, hostPort, isWSS, err := ParseWebSocketURL(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("websocket url: %w", err)
	}
	wsURL, err := url.Parse(wsURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid websocket url: %w", err)
	}

	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}

	// 1. Resolve proxy via proxyFunc
	checkScheme := "http"
	if isWSS {
		checkScheme = "https"
	}
	reqURL, _ := url.Parse(fmt.Sprintf("%s://%s%s", checkScheme, hostPort, wsURL.Path))
	dummyReq := &http.Request{URL: reqURL, Header: make(http.Header)}
	proxyURL, err := proxyFunc(dummyReq)
	if err != nil {
		return nil, fmt.Errorf("websocket proxy error: %w", err)
	}

	// 2. Establish underlying carrier connection (either direct or via proxy CONNECT)
	var rawConn net.Conn
	if proxyURL != nil {
		rawConn, err = dialHTTPProxyCONNECT(ctx, proxyURL, hostPort, opts.Bind, timeout)
		if err != nil {
			return nil, err
		}
	} else {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		pconn, dErr := DialHappyEyeballsTCPWithResolverAndBind(dialCtx, hostPort, DefaultConnectionAttemptDelay, nil, nil, opts.Bind)
		if dErr != nil {
			return nil, fmt.Errorf("dial websocket %q: %w", hostPort, dErr)
		}
		if tcpProvider, ok := pconn.(TCPConnProvider); ok {
			rawConn = tcpProvider.RawTCPConn()
		} else {
			// Fallback to standard net.Dialer
			dialer := &net.Dialer{Timeout: timeout}
			rawConn, err = dialer.DialContext(ctx, "tcp", hostPort)
			_ = pconn.Close()
			if err != nil {
				return nil, fmt.Errorf("dial websocket fallback %q: %w", hostPort, err)
			}
		}
	}

	localAddr := rawConn.LocalAddr()
	remoteAddr := rawConn.RemoteAddr()

	// 3. Perform TLS handshake if WSS
	var carrier io.ReadWriteCloser = rawConn
	if isWSS {
		tlsConf := opts.TLSConfig
		if tlsConf == nil {
			tlsConf = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			tlsConf = tlsConf.Clone()
		}
		if tlsConf.ServerName == "" {
			tlsConf.ServerName = host
		}
		tlsConn := tls.Client(rawConn, tlsConf)
		hsCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(hsCtx); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("websocket tls handshake to %s failed: %w", hostPort, err)
		}
		carrier = tlsConn
	}

	// 4. Perform WebSocket upgrade handshake
	originScheme := "http"
	if isWSS {
		originScheme = "https"
	}
	originURL := fmt.Sprintf("%s://%s", originScheme, host)
	wsConfig, err := websocket.NewConfig(wsURLStr, originURL)
	if err != nil {
		_ = carrier.Close()
		return nil, fmt.Errorf("websocket config: %w", err)
	}
	if opts.Header != nil {
		for k, vs := range opts.Header {
			for _, v := range vs {
				wsConfig.Header.Add(k, v)
			}
		}
	}
	if isWSS && opts.TLSConfig != nil {
		wsConfig.TlsConfig = opts.TLSConfig
	}

	ws, err := websocket.NewClient(wsConfig, carrier)
	if err != nil {
		_ = carrier.Close()
		return nil, fmt.Errorf("websocket upgrade handshake failed: %w", err)
	}

	return WrapWebSocketWithAddrs(ws, localAddr, remoteAddr), nil
}

// dialHTTPProxyCONNECT dials proxyURL, sends an HTTP CONNECT request for targetHostPort,
// and validates the 200 Connection Established response.
func dialHTTPProxyCONNECT(ctx context.Context, proxyURL *url.URL, targetHostPort string, bind BindConfig, timeout time.Duration) (net.Conn, error) {
	proxyHostPort := proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyHostPort); err != nil {
		if proxyURL.Scheme == "https" {
			proxyHostPort = net.JoinHostPort(proxyHostPort, "443")
		} else {
			proxyHostPort = net.JoinHostPort(proxyHostPort, "8080")
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pconn, err := DialHappyEyeballsTCPWithResolverAndBind(dialCtx, proxyHostPort, DefaultConnectionAttemptDelay, nil, nil, bind)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %q: %w", proxyHostPort, err)
	}

	var conn net.Conn
	if tcpProvider, ok := pconn.(TCPConnProvider); ok {
		conn = tcpProvider.RawTCPConn()
	} else {
		_ = pconn.Close()
		return nil, errors.New("proxy connection is not tcp")
	}

	// If the proxy itself is reached over TLS
	if proxyURL.Scheme == "https" {
		proxyTLS := tls.Client(conn, &tls.Config{
			ServerName: proxyURL.Hostname(),
			MinVersion: tls.VersionTLS12,
		})
		if err := proxyTLS.HandshakeContext(dialCtx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("proxy tls handshake failed: %w", err)
		}
		conn = proxyTLS
	}

	// Format HTTP CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: remote-relay/1.0\r\nProxy-Connection: Keep-Alive\r\n", targetHostPort, targetHostPort)
	if proxyURL.User != nil {
		userPass := proxyURL.User.String()
		basicAuth := base64.StdEncoding.EncodeToString([]byte(userPass))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", basicAuth)
	}
	connectReq += "\r\n"

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, connectReq); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send proxy CONNECT request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read proxy CONNECT response: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT to %s refused: %s", targetHostPort, resp.Status)
	}

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, br: br}, nil
	}
	return conn, nil
}

// bufferedConn preserves any bytes pre-buffered by bufio.Reader during CONNECT handshakes.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if b.br != nil && b.br.Buffered() > 0 {
		n, err := b.br.Read(p)
		if b.br.Buffered() == 0 {
			b.br = nil
		}
		return n, err
	}
	return b.Conn.Read(p)
}

// ExtractClientIP extracts the real client IP address from an HTTP request,
// checking X-Forwarded-For and X-Real-IP headers for reverse proxy compatibility.
func ExtractClientIP(req *http.Request, rawAddr net.Addr) string {
	if req != nil {
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
		if xri := req.Header.Get("X-Real-IP"); xri != "" {
			ip := strings.TrimSpace(xri)
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
		if req.RemoteAddr != "" {
			if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				if net.ParseIP(host) != nil {
					return host
				}
			}
		}
	}
	if rawAddr != nil {
		if host, _, err := net.SplitHostPort(rawAddr.String()); err == nil {
			return host
		}
		return rawAddr.String()
	}
	return ""
}

// ExtractRemoteAddr returns a net.Addr reflecting the client IP (considering reverse proxy headers).
func ExtractRemoteAddr(req *http.Request, ws *websocket.Conn) net.Addr {
	if req != nil {
		ipStr := ExtractClientIP(req, nil)
		if ip := net.ParseIP(ipStr); ip != nil {
			port := 0
			if req.RemoteAddr != "" {
				if _, pStr, err := net.SplitHostPort(req.RemoteAddr); err == nil {
					port, _ = strconv.Atoi(pStr)
				}
			}
			return &net.TCPAddr{IP: ip, Port: port}
		}
	}
	if ws != nil {
		return ws.RemoteAddr()
	}
	return nil
}
