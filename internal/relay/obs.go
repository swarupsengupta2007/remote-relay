package relay

import (
	"context"
	"expvar"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	expvarOnce    sync.Once
	activeMetrics atomic.Pointer[Server]
)

func publishRelayExpvars() {
	expvarOnce.Do(func() {
		expvar.Publish("sessions", expvar.Func(func() any {
			if s := activeMetrics.Load(); s != nil {
				return s.sessionCount()
			}
			return 0
		}))
		expvar.Publish("held", expvar.Func(func() any {
			if s := activeMetrics.Load(); s != nil {
				return s.heldCount()
			}
			return 0
		}))
		expvar.Publish("buffer_used", expvar.Func(func() any {
			if s := activeMetrics.Load(); s != nil {
				return s.budgetUsed()
			}
			return 0
		}))
		expvar.Publish("accepts", expvar.Func(func() any {
			if s := activeMetrics.Load(); s != nil {
				return s.accepts.Load()
			}
			return 0
		}))
		expvar.Publish("refused", expvar.Func(func() any {
			if s := activeMetrics.Load(); s != nil {
				return s.refused.Load()
			}
			return 0
		}))
	})
}

func registerPprof(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
}

func (s *Server) startDebug() error {
	pprofAddr := strings.TrimSpace(s.cfg.PprofListen)
	expvarAddr := strings.TrimSpace(s.cfg.ExpvarListen)
	if pprofAddr == "" && expvarAddr == "" {
		return nil
	}
	publishRelayExpvars()
	activeMetrics.Store(s)

	if pprofAddr != "" && pprofAddr == expvarAddr {
		mux := http.NewServeMux()
		registerPprof(mux)
		mux.Handle("/debug/vars", expvar.Handler())
		return s.serveDebug("debug", pprofAddr, mux, true, true)
	}
	if pprofAddr != "" {
		mux := http.NewServeMux()
		registerPprof(mux)
		if err := s.serveDebug("pprof", pprofAddr, mux, true, false); err != nil {
			return err
		}
	}
	if expvarAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/debug/vars", expvar.Handler())
		if err := s.serveDebug("expvar", expvarAddr, mux, false, true); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) serveDebug(name, addr string, h http.Handler, pprof, expv bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("%s listen: %w", name, err)
	}
	hs := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.debugMu.Lock()
	s.debug = append(s.debug, hs)
	bound := ln.Addr().String()
	if pprof {
		s.pprofAddr = bound
	}
	if expv {
		s.expvarAddr = bound
	}
	s.debugMu.Unlock()
	s.log.Info(name+" listening", "addr", bound)
	go func() { _ = hs.Serve(ln) }()
	return nil
}

func (s *Server) stopDebug() {
	s.debugMu.Lock()
	srvs := s.debug
	s.debug = nil
	s.debugMu.Unlock()
	if activeMetrics.Load() == s {
		activeMetrics.Store(nil)
	}
	if len(srvs) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, hs := range srvs {
		_ = hs.Shutdown(ctx)
		_ = hs.Close()
	}
}

func (s *Server) PprofAddr() string {
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	return s.pprofAddr
}

func (s *Server) ExpvarAddr() string {
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	return s.expvarAddr
}
