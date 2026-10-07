package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/transport"
	"golang.org/x/net/websocket"
)

// handleWebSocket handles an upgraded inbound WebSocket connection on the server.
func (s *Server) handleWebSocket(ws *websocket.Conn) {
	defer ws.Close()
	req := ws.Request()
	trusted := s.Config().TrustedProxies
	remoteAddr := transport.ExtractRemoteAddr(req, ws, trusted)
	ip := transport.ExtractClientIP(req, ws.RemoteAddr(), trusted)
	n := s.incIPConn(ip)
	var once sync.Once
	releaseWS := func() { once.Do(func() { s.decIPConn(ip) }) }
	defer releaseWS()

	conn, err := transport.WrapWebSocket(ws, remoteAddr)
	if err != nil {
		s.log.Error("wrap websocket", "err", err)
		return
	}
	defer conn.Close()

	s.handleTransportConn(conn, ip, n, releaseWS)
}

// WebSocketHandler returns an http.Handler serving the WebSocket relay endpoint.
// It can be mounted on an existing http.Server behind Nginx, Caddy, or Go reverse proxies.
func (s *Server) WebSocketHandler() http.Handler {
	path := s.Config().WebSocketPath
	if path == "" {
		path = "/relay-stream"
	}
	wsServer := &websocket.Server{
		Handshake: func(cfg *websocket.Config, req *http.Request) error {
			// Accept all origins for CLI and browser clients
			return nil
		},
		Handler: func(ws *websocket.Conn) {
			ws.PayloadType = websocket.BinaryFrame
			s.handleWebSocket(ws)
		},
	}
	mux := http.NewServeMux()
	mux.Handle(path, wsServer)
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == path {
			wsServer.ServeHTTP(w, req)
			return
		}
		if req.URL.Path == "/" || req.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("remote-relay websocket server\n"))
			return
		}
		http.NotFound(w, req)
	})
	return mux
}

// wsCert retrieves or generates the TLS certificate for WebSocket serving.
func (s *Server) wsCert() (tls.Certificate, error) {
	s.wsCertOnce.Do(func() {
		cfg := s.Config()
		certFile, keyFile := cfg.WSCert, cfg.WSKey
		if certFile == "" && keyFile == "" {
			certFile, keyFile = cfg.QUICCert, cfg.QUICKey
		}
		s.wsCertVal, s.wsCertErr = transport.LoadOrGenerateCert(certFile, keyFile)
	})
	return s.wsCertVal, s.wsCertErr
}

// listenWS initializes the dedicated WebSocket listener if listen_ws is configured.
func (s *Server) listenWS() error {
	s.wsMu.Lock()
	if s.wsLn != nil {
		s.wsMu.Unlock()
		return nil
	}
	s.wsMu.Unlock()

	cfg := s.Config()
	listenAddr := cfg.ListenWS
	if listenAddr == "" {
		return nil
	}

	_, hostPort, isWSS, err := transport.ParseWebSocketURL(listenAddr)
	if err != nil {
		hostPort = listenAddr
	}

	ln, err := net.Listen("tcp", hostPort)
	if err != nil {
		return fmt.Errorf("listen websocket %q: %w", hostPort, err)
	}
	return s.installWSListener(ln, isWSS)
}

// installWSListener wraps raw in TLS when configured and makes it the
// WebSocket listener. raw is kept unwrapped so a hot restart can pass it on.
func (s *Server) installWSListener(raw net.Listener, isWSS bool) error {
	ln := raw
	if isWSS || s.Config().WSCert != "" {
		cert, err := s.wsCert()
		if err != nil {
			_ = raw.Close()
			return fmt.Errorf("websocket tls cert: %w", err)
		}
		tlsConf := transport.ServerTLSConfig(cert)
		ln = tls.NewListener(raw, tlsConf)
	}

	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if s.wsLn != nil {
		_ = raw.Close()
		return nil
	}
	s.wsLn = ln
	s.wsRawLn = raw
	return nil
}

// adoptWSListener installs a WebSocket listener received from a hot restart.
func (s *Server) adoptWSListener(raw net.Listener) error {
	listenAddr := s.Config().ListenWS
	if listenAddr == "" {
		_ = raw.Close()
		return nil
	}
	_, _, isWSS, err := transport.ParseWebSocketURL(listenAddr)
	if err != nil {
		isWSS = false
	}
	return s.installWSListener(raw, isWSS)
}

// startWS starts the HTTP server on the WebSocket listener.
func (s *Server) startWS(ctx context.Context) {
	s.wsMu.Lock()
	ln := s.wsLn
	s.wsMu.Unlock()
	if ln == nil {
		return
	}

	s.wsSrv = &http.Server{
		Handler:      s.WebSocketHandler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	s.log.Info("websocket listening", "addr", ln.Addr().String(), "path", s.Config().WebSocketPath)

	go func() {
		if err := s.wsSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.log.Error("websocket serve error", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		s.closeWS()
	}()
}

// closeWS cleanly terminates the WebSocket HTTP server and listener.
func (s *Server) closeWS() {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if s.wsSrv != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.wsSrv.Shutdown(shutCtx)
		cancel()
		s.wsSrv = nil
	}
	if s.wsLn != nil {
		_ = s.wsLn.Close()
		s.wsLn = nil
		s.wsRawLn = nil
	}
}

// WSAddr returns the listening address of the WebSocket server, or empty string if not listening.
func (s *Server) WSAddr() string {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if s.wsLn == nil {
		return ""
	}
	return s.wsLn.Addr().String()
}
