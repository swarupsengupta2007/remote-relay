package relay

import (
	"context"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

func (s *Server) shutting() bool {
	return s.shut.Load()
}

func (s *Server) sessionContext() context.Context {
	if s.runCtx != nil {
		return s.runCtx
	}
	if s.serveCtx != nil {
		return s.serveCtx
	}
	return context.Background()
}

func (s *Server) closeListener() {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

func (s *Server) stopRun() {
	if s.runCancel != nil {
		s.runCancel()
	}
}

func (s *Server) snapshotLives() []*live {
	s.livesMu.Lock()
	defer s.livesMu.Unlock()
	out := make([]*live, 0, len(s.lives))
	for _, l := range s.lives {
		out = append(out, l)
	}
	return out
}

func (s *Server) beginShutdown() {
	if s.shut.CompareAndSwap(false, true) {
		s.log.Info("shutting down", "sessions", s.sessionCount())
	}
	s.closeListener()
	for _, l := range s.snapshotLives() {
		l.requestShutdown()
	}
}

func (s *Server) finishShutdown() {
	s.finishOnce.Do(func() {
		s.stopRun()
		s.forceCloseLives()
		s.closeUDP()
		s.stopDebug()
		s.log.Info("shutdown complete")
	})
}

func (s *Server) forceCloseLives() {
	for _, l := range s.snapshotLives() {
		l.fail(proto.ErrShutdown)
		l.dropConn()
		l.cleanup(false)
	}
}

// Shutdown stops accepting, sends BYE{ERR_SHUTDOWN} to live sessions, drains
// until empty or ctx is done, then closes dest sockets, UDP, and debug listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	s.beginShutdown()
	defer s.finishShutdown()
	if ctx == nil {
		ctx = context.Background()
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if s.sessionCount() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			s.forceCloseLives()
			deadline := time.Now().Add(500 * time.Millisecond)
			for time.Now().Before(deadline) && s.sessionCount() > 0 {
				time.Sleep(10 * time.Millisecond)
			}
			return nil
		case <-tick.C:
		}
	}
}

func (l *live) requestShutdown() {
	l.log.Info("session shutdown", "code", proto.CodeShutdown)
	if l.linkUp.Load() {
		fr, err := proto.MarshalFrame(proto.TypeBye, proto.Bye{
			Code: proto.CodeShutdown,
			Msg:  "shutting down",
		})
		if err == nil {
			_ = l.sendCtrl(fr)
		}
		return
	}
	l.fail(proto.ErrShutdown)
}

func (l *live) isHeld() bool {
	if l.linkUp.Load() {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.dead
}
