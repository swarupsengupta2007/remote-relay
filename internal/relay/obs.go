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

	"github.com/remote-relay/relay/internal/obs"
	kcp "github.com/xtaci/kcp-go/v5"
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
		expvar.Publish("spliced_bytes_in", expvar.Func(func() any {
			in, _, _ := SplicedStats()
			return in
		}))
		expvar.Publish("spliced_bytes_out", expvar.Func(func() any {
			_, out, _ := SplicedStats()
			return out
		}))
		expvar.Publish("splice_calls_total", expvar.Func(func() any {
			_, _, calls := SplicedStats()
			return calls
		}))
		expvar.Publish("kcp_out_segs", expvar.Func(func() any {
			return atomic.LoadUint64(&kcp.DefaultSnmp.OutSegs)
		}))
		expvar.Publish("kcp_retrans_segs", expvar.Func(func() any {
			return atomic.LoadUint64(&kcp.DefaultSnmp.RetransSegs)
		}))
		expvar.Publish("kcp_lost_segs", expvar.Func(func() any {
			return atomic.LoadUint64(&kcp.DefaultSnmp.LostSegs)
		}))
		expvar.Publish("kcp_snd_queue", expvar.Func(func() any {
			return atomic.LoadUint64(&kcp.DefaultSnmp.RingBufferSndQueue)
		}))
		expvar.Publish("chain_sessions", expvar.Func(func() any {
			if s := activeMetrics.Load(); s != nil {
				return s.chainActive.Load()
			}
			return 0
		}))
		expvar.Publish("chain_hops_total", expvar.Func(func() any {
			if s := activeMetrics.Load(); s != nil {
				return s.chainHops.Load()
			}
			return 0
		}))
		expvar.Publish("chain_auth_relays", expvar.Func(func() any {
			if s := activeMetrics.Load(); s != nil {
				return s.chainAuthRelays.Load()
			}
			return 0
		}))
		expvar.Publish("chain_refused", expvar.Func(func() any {
			if s := activeMetrics.Load(); s != nil {
				return s.chainRefused.Load()
			}
			return 0
		}))
		expvar.Publish("chain_attest_failures", expvar.Func(func() any {
			if s := activeMetrics.Load(); s != nil {
				return s.chainAttestFailures.Load()
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
	defer s.closeAdoptedDebug()
	cfg := s.Config()
	metricsAddr := strings.TrimSpace(cfg.MetricsListen)
	pprofAddr := strings.TrimSpace(cfg.PprofListen)
	expvarAddr := strings.TrimSpace(cfg.ExpvarListen)
	if metricsAddr == "" && pprofAddr == "" && expvarAddr == "" {
		return nil
	}
	publishRelayExpvars()
	activeMetrics.Store(s)

	metricsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.syncMetrics()
		if s.metrics != nil {
			s.metrics.HTTPHandler().ServeHTTP(w, r)
		}
	})

	type addrConfig struct {
		pprof   bool
		expvar  bool
		metrics bool
	}
	addrs := make(map[string]addrConfig)

	if pprofAddr != "" {
		st := addrs[pprofAddr]
		st.pprof = true
		addrs[pprofAddr] = st
	}
	if expvarAddr != "" {
		st := addrs[expvarAddr]
		st.expvar = true
		addrs[expvarAddr] = st
	}
	if metricsAddr != "" {
		st := addrs[metricsAddr]
		st.metrics = true
		addrs[metricsAddr] = st
	}

	for addr, st := range addrs {
		mux := http.NewServeMux()
		// Always expose /metrics on all debug/metrics listeners
		mux.Handle("/metrics", metricsHandler)

		if st.pprof {
			registerPprof(mux)
		}
		if st.expvar {
			mux.Handle("/debug/vars", expvar.Handler())
		}

		name := "debug"
		if st.metrics && !st.pprof && !st.expvar {
			name = "metrics"
		} else if st.pprof && !st.expvar && !st.metrics {
			name = "pprof"
		} else if st.expvar && !st.pprof && !st.metrics {
			name = "expvar"
		}

		if err := s.serveDebug(name, addr, mux, st.pprof, st.expvar, st.metrics); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) serveDebug(name, addr string, h http.Handler, pprof, expv, met bool) error {
	s.debugMu.Lock()
	ln, adopted := s.adoptedDebug[addr]
	delete(s.adoptedDebug, addr)
	s.debugMu.Unlock()
	if !adopted {
		var err error
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%s listen: %w", name, err)
		}
	}
	hs := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.debugMu.Lock()
	s.debug = append(s.debug, hs)
	if s.debugLns == nil {
		s.debugLns = make(map[string]net.Listener)
	}
	s.debugLns[addr] = ln
	bound := ln.Addr().String()
	if pprof {
		s.pprofAddr = bound
	}
	if expv {
		s.expvarAddr = bound
	}
	if met || s.metricsAddr == "" {
		s.metricsAddr = bound
	}
	s.debugMu.Unlock()
	s.log.Info(name+" listening", "addr", bound)
	go func() { _ = hs.Serve(ln) }()
	return nil
}

// closeAdoptedDebug closes hot-restart debug listeners the current config
// no longer binds.
func (s *Server) closeAdoptedDebug() {
	s.debugMu.Lock()
	lns := s.adoptedDebug
	s.adoptedDebug = nil
	s.debugMu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}
}

func (s *Server) stopDebug() {
	s.closeAdoptedDebug()
	s.debugMu.Lock()
	srvs := s.debug
	s.debug = nil
	s.debugLns = nil
	s.pprofAddr = ""
	s.expvarAddr = ""
	s.metricsAddr = ""
	s.debugMu.Unlock()
	if activeMetrics.Load() == s {
		activeMetrics.Store(nil)
	}
	if s.tracer != nil {
		_ = s.tracer.Close()
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

func (s *Server) MetricsAddr() string {
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	return s.metricsAddr
}

func (s *Server) Metrics() *obs.Metrics {
	return s.metrics
}

func (s *Server) Tracer() *obs.Tracer {
	return s.tracer
}

func (s *Server) syncMetrics() {
	if s == nil || s.metrics == nil {
		return
	}

	s.livesMu.Lock()
	var (
		tcpCount, kcpCount, quicCount, wsCount int
		heldCount, standbyCount, socksCount    int
	)
	for _, l := range s.lives {
		if l.isHeld() {
			heldCount++
		} else {
			k := l.currentTransport()
			switch k {
			case "tcp":
				tcpCount++
			case "kcp":
				kcpCount++
			case "quic":
				quicCount++
			case "ws":
				wsCount++
			default:
				if strings.Contains(k, "tcp") {
					tcpCount++
				} else if strings.Contains(k, "kcp") {
					kcpCount++
				} else if strings.Contains(k, "quic") {
					quicCount++
				} else if strings.Contains(k, "ws") {
					wsCount++
				} else {
					tcpCount++
				}
			}
		}
		if l.hasStandby() {
			standbyCount++
		}
		if l.socksMux != nil {
			socksCount += l.socksMux.activeStreams()
		}
	}
	s.livesMu.Unlock()

	s.metrics.ActiveSessions.WithLabelValues("tcp").Set(float64(tcpCount))
	s.metrics.ActiveSessions.WithLabelValues("kcp").Set(float64(kcpCount))
	s.metrics.ActiveSessions.WithLabelValues("quic").Set(float64(quicCount))
	s.metrics.ActiveSessions.WithLabelValues("ws").Set(float64(wsCount))
	s.metrics.HeldSessions.Set(float64(heldCount))
	s.metrics.StandbyConns.Set(float64(standbyCount))
	s.metrics.SocksStreams.Set(float64(socksCount))

	s.metrics.ChainSessions.Set(float64(s.chainActive.Load()))
	s.metrics.ChainHopsTotal.Set(float64(s.chainHops.Load()))
	s.metrics.ChainAuthRelays.Set(float64(s.chainAuthRelays.Load()))
	s.metrics.ChainRefused.Set(float64(s.chainRefused.Load()))
	s.metrics.ChainAttestFails.Set(float64(s.chainAttestFailures.Load()))

	s.metrics.AcceptsTotal.Set(float64(s.accepts.Load()))
	s.metrics.RefusedTotal.Set(float64(s.refused.Load()))

	used := s.budgetUsed()
	total := float64(s.Config().TotalBufferBytes)
	if total > 0 {
		s.metrics.BufferUtilization.Set(float64(used) / total)
	}
	s.metrics.BufferBytesUsed.Set(float64(used))
	s.metrics.BufferBytesTotal.Set(total)

	in, out, calls := SplicedStats()
	s.metrics.SplicedBytes.WithLabelValues("in").Set(float64(in))
	s.metrics.SplicedBytes.WithLabelValues("out").Set(float64(out))
	s.metrics.SpliceCalls.Set(float64(calls))

	s.metrics.KCPSegments.WithLabelValues("out").Set(float64(atomic.LoadUint64(&kcp.DefaultSnmp.OutSegs)))
	s.metrics.KCPSegments.WithLabelValues("retrans").Set(float64(atomic.LoadUint64(&kcp.DefaultSnmp.RetransSegs)))
	s.metrics.KCPSegments.WithLabelValues("lost").Set(float64(atomic.LoadUint64(&kcp.DefaultSnmp.LostSegs)))
	s.metrics.KCPSegments.WithLabelValues("snd_queue").Set(float64(atomic.LoadUint64(&kcp.DefaultSnmp.RingBufferSndQueue)))
}
