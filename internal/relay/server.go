package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/session"
	"github.com/remote-relay/relay/internal/transport"
)

const shutdownDrain = 5 * time.Second

type Server struct {
	cfg    config.Server
	log    *slog.Logger
	auth   auth.Authenticator
	store  *session.Store
	budget *session.Budget

	mu      sync.Mutex
	ln      net.Listener
	livesMu sync.Mutex
	lives   map[string]*live

	serveCtx  context.Context
	runCtx    context.Context
	runCancel context.CancelFunc

	shut       atomic.Bool
	finishOnce sync.Once

	ipMu    sync.Mutex
	ipConns map[string]int
	ipSess  map[string]int

	accepts atomic.Int64
	refused atomic.Int64

	debugMu    sync.Mutex
	debug      []*http.Server
	pprofAddr  string
	expvarAddr string

	udpMu    sync.Mutex
	udpStart sync.Mutex
	udp      *udpEndpoint

	probeMu     sync.Mutex
	probes      map[[16]byte]string
	probeBySess map[string][16]byte

	certOnce sync.Once
	cert     tls.Certificate
	certErr  error

	histMu   sync.Mutex
	pathHist []pathInfo
}

func NewServer(cfg config.Server, log *slog.Logger) *Server {
	if log == nil {
		log = logging.New(nil, cfg.LogLevel, cfg.LogFormat)
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	return &Server{
		cfg:         cfg,
		log:         log,
		auth:        auth.None{},
		store:       session.NewStore(cfg.MaxSessions),
		budget:      session.NewBudget(int64(cfg.TotalBufferBytes)),
		lives:       make(map[string]*live),
		probes:      make(map[[16]byte]string),
		probeBySess: make(map[string][16]byte),
		ipConns:     make(map[string]int),
		ipSess:      make(map[string]int),
		runCtx:      runCtx,
		runCancel:   runCancel,
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
	s.shut.Store(true)
	s.closeListener()
	s.finishShutdown()
	return nil
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
	s.mu.Lock()
	s.serveCtx = ctx
	s.mu.Unlock()
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

	if err := s.startDebug(); err != nil {
		_ = ln.Close()
		return err
	}

	s.log.Info("listening", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		s.closeListener()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || s.shutting() {
				shutCtx, cancel := context.WithTimeout(context.Background(), shutdownDrain)
				_ = s.Shutdown(shutCtx)
				cancel()
				return nil
			}
			s.log.Error("accept", "err", err)
			continue
		}
		s.accepts.Add(1)
		if s.shutting() {
			_ = c.Close()
			continue
		}
		go s.handle(c)
	}
}

func (s *Server) handle(raw net.Conn) {
	defer raw.Close()
	ip := clientIP(raw.RemoteAddr())
	n := s.incIPConn(ip)
	var once sync.Once
	releaseTCP := func() { once.Do(func() { s.decIPConn(ip) }) }
	defer releaseTCP()

	conn, err := transport.WrapTCP(raw)
	if err != nil {
		s.log.Error("wrap tcp", "err", err)
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	f, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		s.log.Debug("handshake read", "err", err)
		return
	}
	ctx := s.sessionContext()
	if s.shutting() {
		if f.Type == proto.TypeResume {
			writeResumeFail(conn, proto.CodeShutdown, "shutting down")
		} else {
			writeErr(conn, proto.CodeShutdown, "shutting down")
		}
		return
	}
	// Flood cap counts live TCP sockets (2× max_conns_per_ip). HELLO is
	// refused with ERR_NO_CAPACITY; RESUME of an existing session proceeds.
	if max := s.cfg.MaxConnsPerIP; max > 0 && n > 2*max && f.Type == proto.TypeHello {
		s.refused.Add(1)
		writeErr(conn, proto.CodeNoCapacity, "too many connections from this address")
		return
	}
	switch f.Type {
	case proto.TypeResume:
		s.handleResume(ctx, conn, f)
	case proto.TypeHello:
		s.handleHello(ctx, conn, f, ip, releaseTCP)
	default:
		writeErr(conn, proto.CodeProto, "expected HELLO")
	}
}

func (s *Server) handleHello(ctx context.Context, conn transport.Conn, f proto.Frame, ip string, releaseTCP func()) {
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

	if err := s.tryReserveIPSess(ip); err != nil {
		s.refused.Add(1)
		var pe *proto.Error
		if errors.As(err, &pe) {
			writeErr(conn, pe.Code, pe.Msg)
			return
		}
		writeErr(conn, proto.CodeNoCapacity, "no capacity")
		return
	}
	reserved := true
	defer func() {
		if reserved {
			s.decIPSess(ip)
		}
	}()

	sess, token, err := session.New()
	if err != nil {
		writeErr(conn, proto.CodeInternal, "session allocate")
		return
	}
	sess.Destination = dest
	if err := s.store.Add(sess); err != nil {
		s.refused.Add(1)
		writeErr(conn, proto.CodeNoCapacity, "too many sessions")
		return
	}
	if s.shutting() {
		s.store.Remove(sess.ID)
		writeErr(conn, proto.CodeShutdown, "shutting down")
		return
	}

	d := net.Dialer{Timeout: s.cfg.DialTimeout.Duration(), KeepAlive: 15 * time.Second}
	dconn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		s.store.Remove(sess.ID)
		writeErr(conn, proto.CodeDestRefused, "dial destination failed")
		return
	}
	dtcp, ok := dconn.(*net.TCPConn)
	if !ok {
		_ = dconn.Close()
		s.store.Remove(sess.ID)
		writeErr(conn, proto.CodeInternal, "destination is not tcp")
		return
	}
	_ = dtcp.SetNoDelay(true)

	window := s.cfg.SendWindow
	if hello.Window > 0 && hello.Window < window {
		window = hello.Window
	}
	bufCap := s.cfg.BufferBytes
	if rem := s.budget.Remaining(); rem > 0 && rem < int64(bufCap) {
		bufCap = int(rem)
	}
	if bufCap <= 0 {
		_ = dtcp.Close()
		s.store.Remove(sess.ID)
		s.refused.Add(1)
		writeErr(conn, proto.CodeNoCapacity, "buffer budget exhausted")
		return
	}
	serverNonce, err := proto.RandomNonce()
	if err != nil {
		_ = dtcp.Close()
		s.store.Remove(sess.ID)
		writeErr(conn, proto.CodeInternal, "nonce")
		return
	}
	selected, udp := s.pickTransport(hello.Transport, sess.ID, conn.LocalAddr())
	okMsg := proto.HelloOK{
		V:           1,
		SessionID:   sess.ID,
		ResumeToken: token,
		Transport:   selected,
		UDP:         udp,
		Limits: proto.Limits{
			BufferBytes:     bufCap,
			HoldTimeoutMs:   int(s.cfg.HoldTimeout.Duration() / time.Millisecond),
			Window:          window,
			DataChunkBytes:  s.cfg.DataChunkBytes,
			SwitchTimeoutMs: int(s.cfg.SwitchTimeout.Duration() / time.Millisecond),
		},
		ServerNonce: serverNonce,
	}
	fr, err := proto.MarshalFrame(proto.TypeHelloOK, okMsg)
	if err != nil {
		_ = dtcp.Close()
		s.store.Remove(sess.ID)
		return
	}

	log := logging.WithSession(s.log, sess.ID)
	sendLog := session.NewRing(bufCap, s.budget)
	p := newPump(ctx, sessionIO{
		conn:       conn,
		src:        dtcp,
		sink:       dtcp,
		closeWrite: dtcp.CloseWrite,
		closeSrc:   func() error { return dtcp.Close() },
		outDir:     proto.DirDown,
		inDir:      proto.DirUp,
	}, pumpConfig{
		chunk:         s.cfg.DataChunkBytes,
		window:        window,
		buffer:        bufCap,
		keepalive:     s.cfg.KeepaliveInterval.Duration(),
		idle:          s.cfg.IdleTimeout.Duration(),
		switchTimeout: s.cfg.SwitchTimeout.Duration(),
		log:           log,
	}, sendLog)

	l := &live{
		pump:            p,
		id:              sess.ID,
		srv:             s,
		store:           s.store,
		cfg:             s.cfg,
		window:          window,
		holdTimeout:     s.cfg.HoldTimeout.Duration(),
		dest:            dtcp,
		log:             log,
		clientIP:        ip,
		releaseHelloTCP: releaseTCP,
		attachCh:        make(chan attachReq, 4),
		deadCh:          make(chan struct{}),
	}
	l.onPeerFrame = func() { l.store.ConfirmToken(l.id) }
	s.livesMu.Lock()
	s.lives[sess.ID] = l
	s.livesMu.Unlock()
	reserved = false
	defer func() {
		s.livesMu.Lock()
		delete(s.lives, sess.ID)
		s.livesMu.Unlock()
		l.cleanup(false)
	}()

	if err := writeFrameDeadline(conn, fr); err != nil {
		return
	}
	log.Info("session started", "dest", dest, "peer", conn.RemoteAddr().String(), "transport", selected)
	l.run(ctx, conn)
}

func (s *Server) handleResume(ctx context.Context, conn transport.Conn, f proto.Frame) {
	if s.shutting() {
		writeResumeFail(conn, proto.CodeShutdown, "shutting down")
		return
	}
	var msg proto.Resume
	if err := proto.UnmarshalPayload(f, &msg); err != nil {
		writeResumeFail(conn, proto.CodeProto, "bad RESUME")
		return
	}
	if msg.V != 1 {
		writeResumeFail(conn, proto.CodeVersion, "unsupported version")
		return
	}
	if err := s.store.VerifyToken(msg.SessionID, msg.ResumeToken); err != nil {
		code, m := proto.CodeInternal, err.Error()
		var pe *proto.Error
		if errors.As(err, &pe) {
			code, m = pe.Code, pe.Msg
		}
		writeResumeFail(conn, code, m)
		return
	}
	s.livesMu.Lock()
	l := s.lives[msg.SessionID]
	s.livesMu.Unlock()
	if l == nil {
		if s.store.IsExpired(msg.SessionID) {
			writeResumeFail(conn, proto.CodeExpired, "session expired")
		} else {
			writeResumeFail(conn, proto.CodeUnknownSession, "unknown session")
		}
		return
	}
	req := attachReq{conn: conn, resume: &msg, done: make(chan error, 1)}
	if err := l.Offer(req); err != nil {
		var pe *proto.Error
		if errors.As(err, &pe) {
			writeResumeFail(conn, pe.Code, pe.Msg)
			return
		}
		writeResumeFail(conn, proto.CodeExpired, "session closed")
		return
	}
	select {
	case <-req.done:
	case <-ctx.Done():
	}
}

type attachReq struct {
	conn   transport.Conn
	resume *proto.Resume
	done   chan error
}

type live struct {
	*pump
	id              string
	srv             *Server
	store           *session.Store
	cfg             config.Server
	window          int
	holdTimeout     time.Duration
	dest            *net.TCPConn
	log             *slog.Logger
	clientIP        string
	releaseHelloTCP func()
	attachCh        chan attachReq
	deadCh          chan struct{}

	mu       sync.Mutex
	heldAt   time.Time
	dead     bool
	cleaned  bool
	pathHist []pathInfo
}

func (l *live) notePath(c transport.Conn) {
	info := pathInfo{Kind: transport.KindTCP}
	if c != nil {
		info.Kind = c.Kind()
		if c.RemoteAddr() != nil {
			info.Remote = c.RemoteAddr().String()
		}
	}
	l.mu.Lock()
	l.pathHist = append(l.pathHist, info)
	l.mu.Unlock()
	if l.srv != nil {
		l.srv.histMu.Lock()
		l.srv.pathHist = append(l.srv.pathHist, info)
		l.srv.histMu.Unlock()
	}
}

func (l *live) markDead() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.dead {
		l.dead = true
		close(l.deadCh)
	}
}

func (l *live) rejectAttach(req attachReq, err error) {
	code, msg := proto.CodeExpired, "session expired"
	var pe *proto.Error
	if errors.As(err, &pe) {
		code, msg = pe.Code, pe.Msg
	}
	writeResumeFail(req.conn, code, msg)
	_ = req.conn.Close()
	select {
	case req.done <- err:
	default:
	}
}

func (l *live) drainAttach(err error) {
	for {
		select {
		case req := <-l.attachCh:
			l.rejectAttach(req, err)
		default:
			return
		}
	}
}

func (l *live) failHold() {
	l.markDead()
	l.store.Expire(l.id)
	l.drainAttach(proto.ErrExpired)
}

func (l *live) Offer(req attachReq) error {
	select {
	case <-l.deadCh:
		return proto.ErrExpired
	default:
	}
	select {
	case l.attachCh <- req:
		select {
		case <-l.deadCh:
			l.rejectAttach(req, proto.ErrExpired)
			return proto.ErrExpired
		default:
			l.dropConn()
			return nil
		}
	case <-l.deadCh:
		return proto.ErrExpired
	case <-l.sessCtx.Done():
		return proto.ErrExpired
	}
}

func (l *live) run(ctx context.Context, first transport.Conn) {
	l.startIO()
	l.notePath(first)
	err := l.serveConn(l.sessCtx, first, 0)
	if l.releaseHelloTCP != nil {
		l.releaseHelloTCP()
		l.releaseHelloTCP = nil
	}
	for reconnectable(err) && ctx.Err() == nil && l.sessionErr() == nil {
		req, ok := l.holdWait(ctx)
		if !ok {
			return
		}
		if req.resume == nil {
			_ = req.conn.Close()
			select {
			case req.done <- proto.ErrProto:
			default:
			}
			err = proto.ErrProto
			continue
		}
		heldMs := 0
		l.mu.Lock()
		if !l.heldAt.IsZero() {
			heldMs = int(time.Since(l.heldAt).Milliseconds())
			if heldMs < 0 {
				heldMs = 0
			}
		}
		l.mu.Unlock()
		if werr := l.writeResumeOK(req, heldMs); werr != nil {
			_ = req.conn.Close()
			select {
			case req.done <- werr:
			default:
			}
			err = werr
			if reconnectable(werr) {
				continue
			}
			return
		}
		sendFrom := req.resume.DownAcked
		l.sendLog.AdvanceTo(sendFrom)
		l.notePath(req.conn)
		err = l.serveConn(l.sessCtx, req.conn, sendFrom)
		select {
		case req.done <- err:
		default:
		}
	}
}

func (l *live) holdWait(ctx context.Context) (attachReq, bool) {
	if l.holdTimeout <= 0 {
		l.log.Info("session expired", "heldMs", 0)
		l.failHold()
		return attachReq{}, false
	}
	l.mu.Lock()
	l.heldAt = time.Now()
	l.mu.Unlock()
	l.sendLog.SetSoftLimit(0)
	l.log.Info("session held", "heldMs", 0)

	timer := time.NewTimer(l.holdTimeout)
	defer timer.Stop()
	select {
	case req := <-l.attachCh:
		return req, true
	case <-timer.C:
		select {
		case req := <-l.attachCh:
			return req, true
		default:
		}
		l.log.Info("session expired", "heldMs", l.heldMs())
		l.failHold()
		return attachReq{}, false
	case <-ctx.Done():
		l.failHold()
		return attachReq{}, false
	case <-l.sessCtx.Done():
		l.failHold()
		return attachReq{}, false
	}
}

func (l *live) heldMs() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.heldAt.IsZero() {
		return 0
	}
	ms := int(time.Since(l.heldAt).Milliseconds())
	if ms < 0 {
		return 0
	}
	return ms
}

func (l *live) writeResumeOK(req attachReq, heldMs int) error {
	token, err := l.store.ResumeToken(l.id)
	if err != nil {
		return err
	}
	pref := []string{"quic", "kcp"}
	if req.resume != nil && len(req.resume.Transport) > 0 {
		pref = req.resume.Transport
	}
	selected, udp := "tcp", (*proto.UdpInfo)(nil)
	if l.srv != nil {
		selected, udp = l.srv.pickTransport(pref, l.id, req.conn.LocalAddr())
	}
	if req.conn != nil {
		switch req.conn.Kind() {
		case transport.KindQUIC:
			selected = "quic"
		case transport.KindKCP:
			selected = "kcp"
		}
	}
	ok := proto.ResumeOK{
		V:           1,
		SessionID:   l.id,
		ResumeToken: token,
		UpAcked:     l.delivered.Load(),
		DownNext:    req.resume.DownAcked,
		State: proto.SessionState{
			UpClosed:   l.inGotClose.Load(),
			DownClosed: l.outEOF.Load(),
			HeldMs:     heldMs,
		},
		Transport: selected,
		UDP:       udp,
		Limits: proto.Limits{
			BufferBytes:     l.sendLog.Cap(),
			HoldTimeoutMs:   int(l.holdTimeout / time.Millisecond),
			Window:          l.window,
			DataChunkBytes:  l.cfg.DataChunkBytes,
			SwitchTimeoutMs: int(l.cfg.SwitchTimeout.Duration() / time.Millisecond),
		},
	}
	fr, err := proto.MarshalFrame(proto.TypeResumeOK, ok)
	if err != nil {
		return err
	}
	if err := writeFrameDeadline(req.conn, fr); err != nil {
		return err
	}
	l.log.Info("session resumed", "heldMs", heldMs)
	return nil
}

func (l *live) cleanup(expired bool) {
	l.mu.Lock()
	if l.cleaned {
		l.mu.Unlock()
		return
	}
	l.cleaned = true
	ip := l.clientIP
	l.mu.Unlock()
	l.markDead()
	l.drainAttach(proto.ErrExpired)
	if l.srv != nil {
		l.srv.unregisterProbe(l.id)
		if ip != "" {
			l.srv.decIPSess(ip)
		}
	}
	if l.dest != nil {
		_ = l.dest.Close()
	}
	l.shutdown()
	if expired || l.store.IsExpired(l.id) {
		l.store.Expire(l.id)
	} else {
		l.store.Remove(l.id)
	}
}

func (s *Server) dropLiveTransports() {
	s.livesMu.Lock()
	lives := make([]*live, 0, len(s.lives))
	for _, l := range s.lives {
		lives = append(lives, l)
	}
	s.livesMu.Unlock()
	for _, l := range lives {
		l.dropConn()
	}
}

func (s *Server) sessionBufferLens() []int {
	s.livesMu.Lock()
	defer s.livesMu.Unlock()
	out := make([]int, 0, len(s.lives))
	for _, l := range s.lives {
		out = append(out, l.sendLog.Len())
	}
	return out
}

func (s *Server) budgetUsed() int64 {
	return s.budget.Used()
}

func (s *Server) sessionCount() int {
	s.livesMu.Lock()
	defer s.livesMu.Unlock()
	return len(s.lives)
}

func (s *Server) heldCount() int {
	s.livesMu.Lock()
	defer s.livesMu.Unlock()
	n := 0
	for _, l := range s.lives {
		if l.isHeld() {
			n++
		}
	}
	return n
}
