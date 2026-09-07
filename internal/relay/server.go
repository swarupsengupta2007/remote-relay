package relay

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/session"
	"github.com/remote-relay/relay/internal/transport"
)

type Server struct {
	cfg   config.Server
	log   *slog.Logger
	auth  auth.Authenticator
	store *session.Store

	mu sync.Mutex
	ln net.Listener
}

func NewServer(cfg config.Server, log *slog.Logger) *Server {
	if log == nil {
		log = logging.New(nil, cfg.LogLevel, cfg.LogFormat)
	}
	return &Server{
		cfg:   cfg,
		log:   log,
		auth:  auth.None{},
		store: session.NewStore(cfg.MaxSessions),
	}
}

func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Close()
}

func (s *Server) Listen() error {
	ln, err := transport.ListenTCP(s.cfg.ListenTCP)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.ln != nil {
		s.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	s.ln = ln
	s.mu.Unlock()
	return nil
}

func (s *Server) Serve(ctx context.Context) error {
	for _, t := range s.cfg.Transports {
		if t != "tcp" {
			s.log.Warn("UDP upgrade is not built yet; listening on TCP only")
			break
		}
	}
	if config.AllowAll(s.cfg.AllowDestinations) {
		s.log.Warn("allow_destinations includes \"*\": this process is an open TCP proxy")
	}

	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln == nil {
		if err := s.Listen(); err != nil {
			return err
		}
		s.mu.Lock()
		ln = s.ln
		s.mu.Unlock()
	}
	defer ln.Close()

	s.log.Info("listening", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Error("accept", "err", err)
			continue
		}
		go s.handle(ctx, c)
	}
}

func (s *Server) handle(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	conn, err := transport.WrapTCP(raw)
	if err != nil {
		s.log.Error("wrap tcp", "err", err)
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	f, err := conn.ReadFrame()
	// Dest dial has its own timeout; do not share the HELLO read deadline with it.
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		s.log.Debug("handshake read", "err", err)
		return
	}
	if f.Type == proto.TypeResume {
		writeErr(conn, proto.CodeUnknownSession, "resume not supported")
		return
	}
	if f.Type != proto.TypeHello {
		writeErr(conn, proto.CodeProto, "expected HELLO")
		return
	}
	var hello proto.Hello
	if err := proto.UnmarshalPayload(f, &hello); err != nil {
		writeErr(conn, proto.CodeProto, "bad HELLO")
		return
	}
	if hello.V != 1 {
		writeErr(conn, proto.CodeVersion, "unsupported version")
		return
	}

	dest := hello.Destination
	if dest == "" {
		dest = s.cfg.DefaultDestination
	}
	if _, _, err := net.SplitHostPort(dest); err != nil {
		writeErr(conn, proto.CodeProto, "bad destination")
		return
	}
	if !config.DestinationAllowed(dest, s.cfg.AllowDestinations) {
		writeErr(conn, proto.CodeDestForbidden, "destination not allowed")
		return
	}

	if _, err := s.auth.Verify(auth.Challenge{
		Destination: dest,
		ClientNonce: hello.ClientNonce,
	}, hello.Auth); err != nil {
		writeErr(conn, proto.CodeAuth, "auth failed")
		return
	}

	sess, token, err := session.New()
	if err != nil {
		writeErr(conn, proto.CodeInternal, "session allocate")
		return
	}
	sess.Destination = dest
	if err := s.store.Add(sess); err != nil {
		writeErr(conn, proto.CodeNoCapacity, "too many sessions")
		return
	}
	defer s.store.Remove(sess.ID)

	d := net.Dialer{Timeout: s.cfg.DialTimeout.Duration(), KeepAlive: 15 * time.Second}
	dconn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		writeErr(conn, proto.CodeDestRefused, "dial destination failed")
		return
	}
	defer dconn.Close()
	dtcp, ok := dconn.(*net.TCPConn)
	if !ok {
		writeErr(conn, proto.CodeInternal, "destination is not tcp")
		return
	}
	_ = dtcp.SetNoDelay(true)

	window := s.cfg.SendWindow
	if hello.Window > 0 && hello.Window < window {
		window = hello.Window
	}
	serverNonce, err := proto.RandomNonce()
	if err != nil {
		writeErr(conn, proto.CodeInternal, "nonce")
		return
	}
	okMsg := proto.HelloOK{
		V:           1,
		SessionID:   sess.ID,
		ResumeToken: token,
		Transport:   "tcp",
		UDP:         nil,
		Limits: proto.Limits{
			BufferBytes:    s.cfg.BufferBytes,
			HoldTimeoutMs:  int(s.cfg.HoldTimeout.Duration() / time.Millisecond),
			Window:         window,
			DataChunkBytes: s.cfg.DataChunkBytes,
		},
		ServerNonce: serverNonce,
	}
	fr, err := proto.MarshalFrame(proto.TypeHelloOK, okMsg)
	if err != nil {
		return
	}
	if err := writeFrameDeadline(conn, fr); err != nil {
		return
	}

	log := logging.WithSession(s.log, sess.ID)
	log.Info("session started", "dest", dest, "peer", conn.RemoteAddr().String())

	err = runPump(ctx, sessionIO{
		conn:       conn,
		src:        dtcp,
		sink:       dtcp,
		closeWrite: dtcp.CloseWrite,
		closeSrc:   func() error { return dtcp.Close() },
		outDir:     proto.DirDown,
		inDir:      proto.DirUp,
	}, pumpConfig{
		chunk:     s.cfg.DataChunkBytes,
		window:    window,
		keepalive: s.cfg.KeepaliveInterval.Duration(),
		idle:      s.cfg.IdleTimeout.Duration(),
		log:       log,
	})
	if err != nil {
		log.Info("session ended", "err", err)
		return
	}
	log.Info("session ended")
}
