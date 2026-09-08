package relay

import (
	"net"

	"github.com/remote-relay/relay/internal/proto"
)

func clientIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (s *Server) incIPConn(ip string) int {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	if s.ipConns == nil {
		s.ipConns = make(map[string]int)
	}
	s.ipConns[ip]++
	return s.ipConns[ip]
}

func (s *Server) decIPConn(ip string) {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	if s.ipConns == nil {
		return
	}
	s.ipConns[ip]--
	if s.ipConns[ip] <= 0 {
		delete(s.ipConns, ip)
	}
}

func (s *Server) decIPSess(ip string) {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	if s.ipSess == nil {
		return
	}
	s.ipSess[ip]--
	if s.ipSess[ip] <= 0 {
		delete(s.ipSess, ip)
	}
}

// tryReserveIPSess checks global and per-IP caps and, on success, accounts a
// new session against ip. The caller must decIPSess unless it transfers the
// reservation to live.cleanup.
func (s *Server) tryReserveIPSess(ip string) error {
	if s.shutting() {
		return proto.ErrShutdown
	}
	if s.cfg.MaxSessions > 0 && s.store.Len() >= s.cfg.MaxSessions {
		return proto.ErrNoCapacity
	}
	if s.budget.Exhausted() {
		return proto.ErrNoCapacity
	}
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	if s.ipSess == nil {
		s.ipSess = make(map[string]int)
	}
	if max := s.cfg.MaxConnsPerIP; max > 0 && s.ipSess[ip] >= max {
		return proto.ErrNoCapacity
	}
	s.ipSess[ip]++
	return nil
}
