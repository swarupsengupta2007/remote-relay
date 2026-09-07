package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

type udpEndpoint struct {
	mux *transport.UDPMux
	ln  *transport.QUICListener
}

func (s *Server) closeUDP() {
	s.udpMu.Lock()
	ep := s.udp
	s.udp = nil
	s.udpMu.Unlock()
	if ep == nil {
		return
	}
	if ep.ln != nil {
		_ = ep.ln.Close()
	}
	if ep.mux != nil {
		_ = ep.mux.Close()
	}
}

func (s *Server) ensureUDP() error {
	s.udpMu.Lock()
	if s.udp != nil {
		s.udpMu.Unlock()
		return nil
	}
	s.udpMu.Unlock()

	s.udpStart.Lock()
	defer s.udpStart.Unlock()

	s.udpMu.Lock()
	if s.udp != nil {
		s.udpMu.Unlock()
		return nil
	}
	s.udpMu.Unlock()

	addr := s.cfg.UDPListen
	if addr == "" {
		addr = "0.0.0.0:7443"
	}
	mux, err := transport.ListenUDPMux(addr)
	if err != nil {
		return err
	}
	mux.SetProbeHandler(s.handleProbe)

	cert, err := s.quicCert()
	if err != nil {
		_ = mux.Close()
		return err
	}
	qconf := transport.NewQUICConfig(s.cfg.IdleTimeout.Duration(), s.cfg.KeepaliveInterval.Duration(), s.cfg.SendWindow)
	ln, err := transport.ListenQUIC(mux.QUIC(), transport.ServerTLSConfig(cert), qconf)
	if err != nil {
		_ = mux.Close()
		return err
	}
	ep := &udpEndpoint{mux: mux, ln: ln}
	s.udpMu.Lock()
	s.udp = ep
	s.udpMu.Unlock()

	s.log.Info("udp listening", "addr", mux.LocalAddr().String())
	go s.serveQUIC(ln)
	return nil
}

func (s *Server) quicCert() (tls.Certificate, error) {
	s.certOnce.Do(func() {
		s.cert, s.certErr = transport.LoadOrGenerateCert(s.cfg.QUICCert, s.cfg.QUICKey)
	})
	return s.cert, s.certErr
}

func (s *Server) serveQUIC(ln *transport.QUICListener) {
	ctx := s.serveCtx
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		qconn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		go s.handleQUIC(ctx, qconn)
	}
}

func (s *Server) handleQUIC(ctx context.Context, qconn *quic.Conn) {
	hs, cancel := context.WithTimeout(ctx, handshakeTimeout)
	conn, err := transport.AcceptQUICConn(hs, qconn)
	cancel()
	if err != nil {
		go func() { _ = qconn.CloseWithError(1, "stream") }()
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	f, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return
	}
	switch f.Type {
	case proto.TypeResume:
		s.handleResume(ctx, conn, f)
	default:
		writeErr(conn, proto.CodeProto, "expected RESUME")
	}
}

func (s *Server) handleProbe(token [16]byte, nonce uint64, addr net.Addr) {
	s.probeMu.Lock()
	_, ok := s.probes[token]
	s.probeMu.Unlock()
	if !ok {
		return
	}
	s.udpMu.Lock()
	ep := s.udp
	s.udpMu.Unlock()
	if ep == nil || ep.mux == nil {
		return
	}
	_ = ep.mux.WriteProbeOK(addr, nonce)
}

func (s *Server) registerProbe(sessionID string, tok [16]byte) {
	s.probeMu.Lock()
	if old, ok := s.probeBySess[sessionID]; ok {
		delete(s.probes, old)
	}
	s.probes[tok] = sessionID
	s.probeBySess[sessionID] = tok
	s.probeMu.Unlock()
}

func (s *Server) unregisterProbe(sessionID string) {
	s.probeMu.Lock()
	if old, ok := s.probeBySess[sessionID]; ok {
		delete(s.probes, old)
		delete(s.probeBySess, sessionID)
	}
	s.probeMu.Unlock()
}

func (s *Server) pickTransport(pref []string, sessionID string, tcpLocal net.Addr) (string, *proto.UdpInfo) {
	if !s.cfg.QUICEnabled() {
		return "tcp", nil
	}
	if len(pref) == 0 {
		pref = []string{"quic", "kcp"}
	}
	for _, p := range pref {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "tcp":
			return "tcp", nil
		case "quic":
			if err := s.ensureUDP(); err != nil {
				s.log.Warn("udp listen failed; staying on tcp", "err", err)
				continue
			}
			info := s.newUdpInfo(sessionID, tcpLocal)
			if info == nil {
				continue
			}
			return "quic", info
		case "kcp":
			// M3
			continue
		}
	}
	return "tcp", nil
}

func (s *Server) newUdpInfo(sessionID string, tcpLocal net.Addr) *proto.UdpInfo {
	s.udpMu.Lock()
	ep := s.udp
	s.udpMu.Unlock()
	if ep == nil || ep.mux == nil {
		return nil
	}
	var tok [16]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return nil
	}
	s.registerProbe(sessionID, tok)
	timeout := s.cfg.ProbeTimeout.Duration()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	attempts := s.cfg.ProbeAttempts
	if attempts <= 0 {
		attempts = 2
	}
	return &proto.UdpInfo{
		Addr:           s.announceAddr(tcpLocal),
		ProbeToken:     transport.EncodeProbeToken(tok),
		ProbeTimeoutMs: int(timeout / time.Millisecond),
		ProbeAttempts:  attempts,
	}
}

func (s *Server) announceAddr(tcpLocal net.Addr) string {
	if s.cfg.UDPAnnounce != "" {
		return s.cfg.UDPAnnounce
	}
	s.udpMu.Lock()
	ep := s.udp
	s.udpMu.Unlock()
	if ep == nil || ep.mux == nil || ep.mux.LocalAddr() == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(ep.mux.LocalAddr().String())
	if err != nil {
		return ep.mux.LocalAddr().String()
	}
	if isUnspecified(host) {
		if tcpLocal != nil {
			if h, _, err := net.SplitHostPort(tcpLocal.String()); err == nil && h != "" && !isUnspecified(h) {
				host = h
			}
		}
		if isUnspecified(host) {
			if h, _, err := net.SplitHostPort(s.cfg.ListenTCP); err == nil && h != "" && !isUnspecified(h) {
				host = h
			}
		}
	}
	return net.JoinHostPort(host, port)
}

func isUnspecified(host string) bool {
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

type pathInfo struct {
	Kind   transport.Kind
	Remote string
}

func (s *Server) liveKinds() []transport.Kind {
	s.livesMu.Lock()
	defer s.livesMu.Unlock()
	out := make([]transport.Kind, 0, len(s.lives))
	for _, l := range s.lives {
		out = append(out, l.currentKind())
	}
	return out
}

func (s *Server) pathHistory() []pathInfo {
	s.histMu.Lock()
	defer s.histMu.Unlock()
	out := make([]pathInfo, len(s.pathHist))
	copy(out, s.pathHist)
	return out
}

func (s *Server) dropLiveKind(k transport.Kind) {
	s.livesMu.Lock()
	lives := make([]*live, 0, len(s.lives))
	for _, l := range s.lives {
		lives = append(lives, l)
	}
	s.livesMu.Unlock()
	for _, l := range lives {
		if l.currentKind() == k {
			l.dropConn()
		}
	}
}
