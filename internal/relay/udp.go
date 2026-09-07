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
	kcp *transport.KCPListener
}

func (s *Server) closeUDP() {
	s.udpMu.Lock()
	ep := s.udp
	s.udp = nil
	s.udpMu.Unlock()
	if ep == nil {
		return
	}
	if ep.kcp != nil {
		_ = ep.kcp.Close()
	}
	if ep.ln != nil {
		_ = ep.ln.Close()
	}
	if ep.mux != nil {
		_ = ep.mux.Close()
	}
}

func (s *Server) ensureUDP() error {
	s.udpStart.Lock()
	defer s.udpStart.Unlock()

	if err := s.ensureMuxLocked(); err != nil {
		return err
	}
	s.startQUICLocked()
	s.startKCPLocked()
	return nil
}

func (s *Server) ensureMuxLocked() error {
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
	s.udpMu.Lock()
	s.udp = &udpEndpoint{mux: mux}
	s.udpMu.Unlock()
	s.log.Info("udp listening", "addr", mux.LocalAddr().String())
	return nil
}

func (s *Server) startQUICLocked() {
	if !s.cfg.QUICEnabled() {
		return
	}
	s.udpMu.Lock()
	ep := s.udp
	s.udpMu.Unlock()
	if ep == nil || ep.ln != nil {
		return
	}
	cert, err := s.quicCert()
	if err != nil {
		s.log.Warn("quic cert failed", "err", err)
		return
	}
	qconf := transport.NewQUICConfig(s.cfg.IdleTimeout.Duration(), s.cfg.KeepaliveInterval.Duration(), s.cfg.SendWindow)
	ln, err := transport.ListenQUIC(ep.mux.QUIC(), transport.ServerTLSConfig(cert), qconf)
	if err != nil {
		s.log.Warn("quic listen failed", "err", err)
		return
	}
	s.udpMu.Lock()
	if s.udp != nil && s.udp.ln == nil {
		s.udp.ln = ln
	} else {
		s.udpMu.Unlock()
		_ = ln.Close()
		return
	}
	s.udpMu.Unlock()
	go s.serveQUIC(ln)
}

func (s *Server) startKCPLocked() {
	if !s.cfg.KCPEnabled() {
		return
	}
	s.udpMu.Lock()
	ep := s.udp
	s.udpMu.Unlock()
	if ep == nil || ep.kcp != nil {
		return
	}
	ln, err := transport.ListenKCP(ep.mux.KCP())
	if err != nil {
		s.log.Warn("kcp listen failed", "err", err)
		return
	}
	s.udpMu.Lock()
	if s.udp != nil && s.udp.kcp == nil {
		s.udp.kcp = ln
	} else {
		s.udpMu.Unlock()
		_ = ln.Close()
		return
	}
	s.udpMu.Unlock()
	go s.serveKCP(ln)
}

func (s *Server) udpHasQUIC() bool {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	return s.udp != nil && s.udp.ln != nil
}

func (s *Server) udpHasKCP() bool {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	return s.udp != nil && s.udp.kcp != nil
}

func (s *Server) quicCert() (tls.Certificate, error) {
	s.certOnce.Do(func() {
		s.cert, s.certErr = transport.LoadOrGenerateCert(s.cfg.QUICCert, s.cfg.QUICKey)
	})
	return s.cert, s.certErr
}

func (s *Server) serveQUIC(ln *transport.QUICListener) {
	ctx := s.sessionContext()
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
	if s.shutting() {
		writeResumeFail(conn, proto.CodeShutdown, "shutting down")
		return
	}
	switch f.Type {
	case proto.TypeResume:
		s.handleResume(ctx, conn, f)
	default:
		writeErr(conn, proto.CodeProto, "expected RESUME")
	}
}

func (s *Server) serveKCP(ln *transport.KCPListener) {
	ctx := s.sessionContext()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if s.shutting() {
			_ = conn.Close()
			continue
		}
		go s.handleKCP(ctx, conn)
	}
}

func (s *Server) handleKCP(ctx context.Context, conn transport.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	f, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return
	}
	if s.shutting() {
		writeResumeFail(conn, proto.CodeShutdown, "shutting down")
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
	if !s.cfg.QUICEnabled() && !s.cfg.KCPEnabled() {
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
			if !s.cfg.QUICEnabled() {
				continue
			}
			if err := s.ensureUDP(); err != nil {
				s.log.Warn("udp listen failed; staying on tcp", "err", err)
				continue
			}
			if !s.udpHasQUIC() {
				continue
			}
			info := s.newUdpInfo(sessionID, tcpLocal)
			if info == nil {
				continue
			}
			return "quic", info
		case "kcp":
			if !s.cfg.KCPEnabled() {
				continue
			}
			if err := s.ensureUDP(); err != nil {
				s.log.Warn("udp listen failed; staying on tcp", "err", err)
				continue
			}
			if !s.udpHasKCP() {
				continue
			}
			info := s.newUdpInfo(sessionID, tcpLocal)
			if info == nil {
				continue
			}
			return "kcp", info
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
