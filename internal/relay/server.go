package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/bfd"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/crypto/kex"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/obs"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/session"
	"github.com/remote-relay/relay/internal/transport"
)

const shutdownDrain = 5 * time.Second

type Server struct {
	cfgPtr atomic.Pointer[config.Server]
	optsMu sync.RWMutex
	opts   config.ServerOptions
	logMu  sync.RWMutex
	log    *slog.Logger
	authMu sync.RWMutex
	auth   auth.Authenticator
	store  *session.Store
	budget *session.Budget

	hostKey    ed25519.PrivateKey
	hostKeyErr error

	mu      sync.Mutex
	ln      net.Listener
	livesMu sync.Mutex
	lives   map[string]*live

	serveCtx  context.Context
	runCtx    context.Context
	runCancel context.CancelFunc

	shut       atomic.Bool
	finishOnce sync.Once

	ipMu       sync.Mutex
	ipConns    map[string]int
	ipSess     map[string]int
	chainPeers map[string]int

	agentReg *AgentRegistry

	accepts atomic.Int64
	refused atomic.Int64

	// FEAT-UTL-05 chaining counters (published as expvars in obs.go).
	// chainActive is the live chained-session gauge that chain_sessions reports.
	chainActive         atomic.Int64
	chainHops           atomic.Int64
	chainAuthRelays     atomic.Int64
	chainRefused        atomic.Int64
	chainAttestFailures atomic.Int64
	chainGone           atomic.Int64

	debugMu sync.Mutex
	debug   []*http.Server
	// debugLns holds each bound debug listener by configured address so a
	// hot restart can pass it on; adoptedDebug holds those received from one.
	debugLns     map[string]net.Listener
	adoptedDebug map[string]net.Listener
	pprofAddr    string
	expvarAddr   string
	metricsAddr  string
	metrics      *obs.Metrics
	tracer       *obs.Tracer

	udpMu    sync.Mutex
	udpStart sync.Mutex
	udp      *udpEndpoint

	probeMu     sync.Mutex
	probes      map[[16]byte]string
	probeBySess map[string][16]byte

	certOnce sync.Once
	cert     tls.Certificate
	certErr  error

	wsMu       sync.Mutex
	wsLn       net.Listener
	wsRawLn    net.Listener // wsLn before any TLS wrapping
	wsSrv      *http.Server
	wsCertOnce sync.Once
	wsCertVal  tls.Certificate
	wsCertErr  error

	histMu   sync.Mutex
	pathHist []pathInfo

	restarting      atomic.Bool
	restartingDone  chan struct{}
	noExitOnRestart bool
	reexecPath      string
	reexecArgs      []string
}

func (s *Server) Config() config.Server {
	if p := s.cfgPtr.Load(); p != nil {
		return *p
	}
	return config.DefaultServer()
}

func (s *Server) getAuth() auth.Authenticator {
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	return s.auth
}

func (s *Server) setAuth(a auth.Authenticator) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	s.auth = a
}

func (s *Server) setLogger(l *slog.Logger) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	s.log = l
}

func (s *Server) SetOptions(opts config.ServerOptions) {
	s.optsMu.Lock()
	defer s.optsMu.Unlock()
	s.opts = opts
}

func (s *Server) getOptions() config.ServerOptions {
	s.optsMu.RLock()
	defer s.optsMu.RUnlock()
	return s.opts
}

// ReloadConfig re-reads the server's configuration file (if configured) and
// the authorized_keys file, validates the changes, and atomically updates the
// server's active configuration and authenticator. Active sessions and listener
// sockets continue uninterrupted (FEAT-SEC-03).
func (s *Server) ReloadConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	currentCfg := s.Config()
	opts := s.getOptions()
	if opts.ConfigPath == "" && currentCfg.ConfigPath != "" {
		opts.ConfigPath = currentCfg.ConfigPath
	}
	if opts.AuthorizedKeys == "" && currentCfg.AuthorizedKeys != "" {
		opts.AuthorizedKeys = currentCfg.AuthorizedKeys
	}

	var newCfg config.Server
	if opts.ConfigPath != "" {
		loaded, err := config.LoadServer(opts)
		if err != nil {
			s.log.Error("reload: failed to reload configuration file; keeping existing configuration", "path", opts.ConfigPath, "err", err)
			return fmt.Errorf("reload config file %q: %w", opts.ConfigPath, err)
		}
		newCfg = loaded
		// Sockets cannot be re-bound on live reload without restart
		newCfg.ListenTCP = currentCfg.ListenTCP
		newCfg.UDPListen = currentCfg.UDPListen
		newCfg.ListenWS = currentCfg.ListenWS
		newCfg.WebSocketPath = currentCfg.WebSocketPath
		newCfg.WSCert = currentCfg.WSCert
		newCfg.WSKey = currentCfg.WSKey
	} else {
		newCfg = currentCfg
	}

	var newAuth auth.Authenticator
	entriesCount := 0
	if newCfg.AuthMethod == auth.MethodPublicKey {
		akPath := newCfg.AuthorizedKeys
		if akPath == "" {
			akPath = auth.DefaultAuthorizedKeys()
		}

		entries, err := auth.LoadAuthorizedKeyEntries(akPath)
		if err != nil || len(entries) == 0 {
			s.log.Error("reload: failed to read authorized_keys or no valid keys found; keeping existing authentication", "path", akPath, "err", err)
			return fmt.Errorf("reload authorized_keys %q: %w", akPath, err)
		}
		entriesCount = len(entries)
		newAuth = auth.New(auth.Config{
			Method:         newCfg.AuthMethod,
			AuthorizedKeys: akPath,
			FailDelay:      newCfg.AuthFailDelay.Duration(),
		})
	} else {
		newAuth = auth.New(auth.Config{
			Method:    newCfg.AuthMethod,
			FailDelay: newCfg.AuthFailDelay.Duration(),
		})
	}

	if err := newCfg.Validate(); err != nil {
		s.log.Error("reload: configuration validation failed; keeping existing configuration", "err", err)
		return fmt.Errorf("validate reloaded configuration: %w", err)
	}

	s.cfgPtr.Store(&newCfg)
	s.setAuth(newAuth)

	if newCfg.LogLevel != currentCfg.LogLevel || newCfg.LogFormat != currentCfg.LogFormat {
		s.setLogger(logging.New(nil, newCfg.LogLevel, newCfg.LogFormat))
	}

	s.log.Info("configuration reloaded successfully via SIGHUP",
		"config_path", newCfg.ConfigPath,
		"authorized_keys", newCfg.AuthorizedKeys,
		"authorized_keys_count", entriesCount,
		"allow_destinations", newCfg.AllowDestinations,
	)
	return nil
}

func NewServer(cfg config.Server, log *slog.Logger) *Server {
	if log == nil {
		log = logging.New(nil, cfg.LogLevel, cfg.LogFormat)
	}
	runCtx, runCancel := context.WithCancel(context.Background())

	hostKeyPath := cfg.HostKey
	if hostKeyPath == "" {
		hostKeyPath = "/etc/relay/ssh_host_ed25519_key"
	}
	hostKey, hostErr := kex.LoadOrGenerateHostKey(hostKeyPath)
	if hostErr != nil {
		home, herr := os.UserHomeDir()
		fallback := filepath.Join(os.TempDir(), "relay_ssh_host_ed25519_key")
		if herr == nil && home != "" {
			fallback = filepath.Join(home, ".config", "relay", "host_key")
		}
		hostKey, hostErr = kex.LoadOrGenerateHostKey(fallback)
	}
	if hostKey != nil {
		pub := hostKey.Public().(ed25519.PublicKey)
		fp := kex.FingerprintSHA256(pub)
		log.Info("host key active", "fingerprint", fp)
	} else if hostErr != nil {
		log.Error("failed to load host key", "err", hostErr)
	}

	akPath := cfg.AuthorizedKeys
	if akPath == "" {
		akPath = auth.DefaultAuthorizedKeys()
	}

	s := &Server{
		log:            log,
		auth:           auth.New(auth.Config{Method: cfg.AuthMethod, AuthorizedKeys: akPath, FailDelay: cfg.AuthFailDelay.Duration()}),
		store:          session.NewStore(cfg.MaxSessions),
		budget:         session.NewBudget(int64(cfg.TotalBufferBytes)),
		hostKey:        hostKey,
		hostKeyErr:     hostErr,
		lives:          make(map[string]*live),
		probes:         make(map[[16]byte]string),
		probeBySess:    make(map[string][16]byte),
		ipConns:        make(map[string]int),
		ipSess:         make(map[string]int),
		chainPeers:     make(map[string]int),
		runCtx:         runCtx,
		runCancel:      runCancel,
		restartingDone: make(chan struct{}),
		opts:           config.ServerOptions{ConfigPath: cfg.ConfigPath, AuthorizedKeys: cfg.AuthorizedKeys},
		metrics:        obs.NewMetrics(),
		tracer:         obs.NewTracer("remote-relay", cfg.OTELEndpoint),
		agentReg:       NewAgentRegistry(),
	}
	s.cfgPtr.Store(&cfg)
	return s
}

func (s *Server) AgentRegistry() *AgentRegistry {
	return s.agentReg
}

func (s *Server) HostPublicKey() ed25519.PublicKey {
	if s.hostKey == nil {
		return nil
	}
	return s.hostKey.Public().(ed25519.PublicKey)
}

func (s *Server) HostFingerprint() string {
	pub := s.HostPublicKey()
	if pub == nil {
		return ""
	}
	return kex.FingerprintSHA256(pub)
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

func (s *Server) SetNoExitOnRestart(v bool) {
	s.noExitOnRestart = v
}

func (s *Server) SetReexec(path string, args []string) {
	s.reexecPath = path
	s.reexecArgs = args
}

func (s *Server) HotRestart() error {
	return s.hotRestartPlatform()
}

func systemdListeners() (net.Listener, net.PacketConn, error) {
	pidStr := os.Getenv("LISTEN_PID")
	if pidStr == "" || pidStr != strconv.Itoa(os.Getpid()) {
		return nil, nil, nil
	}
	fdsStr := os.Getenv("LISTEN_FDS")
	if fdsStr == "" {
		return nil, nil, nil
	}
	nfds, err := strconv.Atoi(fdsStr)
	if err != nil || nfds < 1 {
		return nil, nil, nil
	}

	f3 := os.NewFile(3, "systemd-listen-tcp")
	ln, err := net.FileListener(f3)
	_ = f3.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("systemd listen tcp (fd 3): %w", err)
	}

	var pc net.PacketConn
	if nfds >= 2 {
		f4 := os.NewFile(4, "systemd-listen-udp")
		pc, err = net.FilePacketConn(f4)
		_ = f4.Close()
		if err != nil {
			_ = ln.Close()
			return nil, nil, fmt.Errorf("systemd listen udp (fd 4): %w", err)
		}
	}

	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")

	return ln, pc, nil
}

func (s *Server) adoptSystemd() (bool, error) {
	ln, pc, err := systemdListeners()
	if err != nil {
		return false, err
	}
	if ln == nil && pc == nil {
		return false, nil
	}
	if ln != nil {
		s.mu.Lock()
		s.ln = ln
		s.mu.Unlock()
		s.log.Info("systemd socket activation: adopted tcp listener", "addr", ln.Addr().String())
	}
	if pc != nil {
		mux := transport.NewUDPMux(pc)
		mux.SetProbeHandler(s.handleProbe)
		s.udpMu.Lock()
		s.udp = &udpEndpoint{mux: mux}
		s.udpMu.Unlock()
		s.log.Info("systemd socket activation: adopted udp packetconn", "addr", pc.LocalAddr().String())
		s.startQUICLocked()
		s.startKCPLocked()
	}
	return true, nil
}

func (s *Server) adoptHandover() (bool, error) {
	handoverEnv := os.Getenv("RELAY_HANDOVER_FD")
	if handoverEnv == "" {
		return false, nil
	}
	fd, err := strconv.Atoi(handoverEnv)
	if err != nil {
		return false, fmt.Errorf("invalid RELAY_HANDOVER_FD %q: %w", handoverEnv, err)
	}

	f := os.NewFile(uintptr(fd), "relay-handover")
	fc, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return false, fmt.Errorf("wrap handover fd %d: %w", fd, err)
	}
	unixConn, ok := fc.(*net.UnixConn)
	if !ok {
		_ = fc.Close()
		return false, fmt.Errorf("handover fd %d is not a unix domain socket", fd)
	}
	defer unixConn.Close()

	state, files, err := ReceiveHandover(unixConn)
	if err != nil {
		return false, fmt.Errorf("receive handover state: %w", err)
	}

	nextFD := 0
	if state.HasListenTCP {
		if nextFD >= len(files) {
			return false, errors.New("missing TCP listener FD in handover")
		}
		lnFile := files[nextFD]
		nextFD++
		ln, err := net.FileListener(lnFile)
		_ = lnFile.Close()
		if err != nil {
			return false, fmt.Errorf("adopt TCP listener from handover: %w", err)
		}
		s.mu.Lock()
		s.ln = ln
		s.mu.Unlock()
		s.log.Info("handover: adopted tcp listener", "addr", ln.Addr().String())
	}

	if state.HasListenUDP {
		if nextFD >= len(files) {
			return false, errors.New("missing UDP listener FD in handover")
		}
		udpFile := files[nextFD]
		nextFD++
		pc, err := net.FilePacketConn(udpFile)
		_ = udpFile.Close()
		if err != nil {
			return false, fmt.Errorf("adopt UDP listener from handover: %w", err)
		}
		mux := transport.NewUDPMux(pc)
		mux.SetProbeHandler(s.handleProbe)
		s.udpMu.Lock()
		s.udp = &udpEndpoint{mux: mux}
		s.udpMu.Unlock()
		s.log.Info("handover: adopted udp listener", "addr", pc.LocalAddr().String())
		s.startQUICLocked()
		s.startKCPLocked()
	}

	if state.HasListenWS {
		if nextFD >= len(files) {
			return false, errors.New("missing WebSocket listener FD in handover")
		}
		wsFile := files[nextFD]
		nextFD++
		ln, err := net.FileListener(wsFile)
		_ = wsFile.Close()
		if err != nil {
			return false, fmt.Errorf("adopt WebSocket listener from handover: %w", err)
		}
		if err := s.adoptWSListener(ln); err != nil {
			s.log.Error("handover: adopt websocket listener", "err", err)
		} else {
			s.log.Info("handover: adopted websocket listener", "addr", ln.Addr().String())
		}
	}

	for _, addr := range state.DebugListen {
		if nextFD >= len(files) {
			return false, errors.New("missing debug listener FD in handover")
		}
		dbgFile := files[nextFD]
		nextFD++
		ln, err := net.FileListener(dbgFile)
		_ = dbgFile.Close()
		if err != nil {
			return false, fmt.Errorf("adopt debug listener %s from handover: %w", addr, err)
		}
		s.debugMu.Lock()
		if s.adoptedDebug == nil {
			s.adoptedDebug = make(map[string]net.Listener)
		}
		s.adoptedDebug[addr] = ln
		s.debugMu.Unlock()
		s.log.Info("handover: adopted debug listener", "addr", ln.Addr().String())
	}

	for _, hSess := range state.Sessions {
		sess, err := session.RestoreSession(hSess.Session)
		if err != nil {
			s.log.Error("failed to restore session metadata", "sessionId", hSess.Session.ID, "err", err)
			continue
		}
		s.store.Restore(sess)

		var dtcp *net.TCPConn
		if hSess.HasDestFD {
			if nextFD >= len(files) {
				s.log.Error("missing dest FD for session", "sessionId", hSess.Session.ID)
				continue
			}
			destFile := files[nextFD]
			nextFD++
			conn, err := net.FileConn(destFile)
			_ = destFile.Close()
			if err != nil {
				s.log.Error("failed to restore dest TCP socket", "sessionId", hSess.Session.ID, "err", err)
				continue
			}
			var ok bool
			dtcp, ok = conn.(*net.TCPConn)
			if !ok {
				_ = conn.Close()
				s.log.Error("restored dest socket is not TCP", "sessionId", hSess.Session.ID)
				continue
			}
		}
		cfg := s.Config()
		sendLog := session.RestoreTieredRing(hSess.SendLogBase, hSess.SendLogData, hSess.SendLogCap, s.budget, session.RingConfig{
			L1Cap:    cfg.SpillL1Bytes,
			SpillDir: cfg.SpillDir,
			NoSpill:  cfg.NoSpill,
		})
		window := cfg.SendWindow
		if window <= 0 {
			window = 64
		}
		log := logging.WithSession(s.log, hSess.Session.ID)
		var closeWrite func() error
		var closeSrc func() error
		var src io.Reader
		var sink io.Writer
		var rawSrc, rawSink any
		if dtcp != nil {
			closeWrite = dtcp.CloseWrite
			closeSrc = func() error { return dtcp.Close() }
			src = dtcp
			sink = dtcp
			rawSrc = dtcp
			rawSink = dtcp
		}
		p := newPump(s.sessionContext(), sessionIO{
			src:        src,
			sink:       sink,
			rawSrc:     rawSrc,
			rawSink:    rawSink,
			closeWrite: closeWrite,
			closeSrc:   closeSrc,
			outDir:     proto.DirDown,
			inDir:      proto.DirUp,
		}, pumpConfig{
			chunk:         cfg.DataChunkBytes,
			window:        window,
			buffer:        hSess.SendLogCap,
			keepalive:     cfg.KeepaliveInterval.Duration(),
			idle:          cfg.IdleTimeout.Duration(),
			switchTimeout: cfg.SwitchTimeout.Duration(),
			heartbeat:     cfg.HeartbeatInterval.Duration(),
			deadThreshold: cfg.DeadPeerThreshold,
			log:           log,
			splice:        cfg.Splice,
			metrics:       s.metrics,
		}, sendLog)

		p.delivered.Store(hSess.UpAcked)
		p.expected.Store(hSess.UpAcked)
		if hSess.UpClosed {
			p.inGotClose.Store(true)
			p.inFinal.Store(hSess.UpAcked)
		}
		if hSess.DownClosed {
			p.outEOF.Store(true)
			p.outFinal.Store(hSess.DownNext)
		}

		holdDuration := cfg.HoldTimeout.Duration()
		if hSess.RemainingHoldMs > 0 {
			holdDuration = time.Duration(hSess.RemainingHoldMs) * time.Millisecond
		}

		l := &live{
			pump:           p,
			id:             hSess.Session.ID,
			srv:            s,
			store:          s.store,
			cfg:            cfg,
			window:         window,
			holdTimeout:    holdDuration,
			dest:           dtcp,
			log:            log,
			clientIP:       hSess.ClientIP,
			heldAt:         time.Now(),
			deadCh:         make(chan struct{}),
			attachCh:       make(chan attachReq, 4),
			standbyPromote: make(chan struct{}, 1),
		}
		l.onPeerFrame = func() { l.store.ConfirmToken(l.id) }

		if hSess.ClientIP != "" {
			s.incIPSess(hSess.ClientIP)
		}

		s.livesMu.Lock()
		s.lives[l.id] = l
		s.livesMu.Unlock()

		go func(sessID string, liveSession *live) {
			defer func() {
				s.livesMu.Lock()
				delete(s.lives, sessID)
				s.livesMu.Unlock()
				liveSession.cleanup(false)
			}()
			liveSession.run(s.sessionContext(), nil)
		}(hSess.Session.ID, l)

		s.log.Info("handover: restored active session", "sessionId", hSess.Session.ID)
	}

	for i := nextFD; i < len(files); i++ {
		_ = files[i].Close()
	}

	if _, err := unixConn.Write([]byte("OK\n")); err != nil {
		s.log.Error("failed to write handover ack to parent", "err", err)
	}
	_ = os.Unsetenv("RELAY_HANDOVER_FD")
	return true, nil
}

func (s *Server) tryAdoptSockets() bool {
	if ok, err := s.adoptHandover(); ok {
		return true
	} else if err != nil {
		s.log.Error("handover adoption failed", "err", err)
	}

	if ok, err := s.adoptSystemd(); ok {
		return true
	} else if err != nil {
		s.log.Error("systemd adoption failed", "err", err)
	}

	return false
}

func (s *Server) Listen() error {
	s.mu.Lock()
	if s.ln != nil {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if s.tryAdoptSockets() {
		// Adoption may not have supplied a WebSocket listener (systemd, or a
		// parent that predates passing it); bind it here in that case.
		if s.Config().ListenWS != "" {
			if err := s.listenWS(); err != nil {
				s.log.Error("websocket listen after socket adoption", "err", err)
			}
		}
		return nil
	}

	ln, err := transport.ListenTCP(s.Config().ListenTCP)
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
	if s.Config().ListenWS != "" {
		if err := s.listenWS(); err != nil {
			_ = ln.Close()
			return err
		}
	}
	return nil
}

func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	s.serveCtx = ctx
	s.mu.Unlock()
	s.setupHotRestartSignal(ctx)
	s.setupSIGHUPSignal(ctx)
	cfg := s.Config()
	if config.AllowAll(cfg.AllowDestinations) {
		s.log.Warn("allow_destinations includes \"*\": this process is an open TCP proxy")
	}
	if config.AllowAll(cfg.AllowRelayHops) {
		s.log.Warn("allow_relay_hops includes \"*\": this process will chain to any next hop (max_chain_depth must be 1)")
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
	s.startWS(ctx)

	go func() {
		<-ctx.Done()
		s.closeListener()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if s.restarting.Load() {
				<-s.restartingDone
				return nil
			}
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

func unwrapConn(c transport.Conn) transport.Conn {
	if cc, ok := c.(*kex.CipherConn); ok {
		return cc.Underlying()
	}
	return c
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

	s.handleTransportConn(conn, ip, n, releaseTCP)
}

func (s *Server) handleTransportConn(conn transport.Conn, ip string, n int, releaseConn func()) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	f, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		s.log.Debug("handshake read", "err", err)
		return
	}

	// Strict encrypted-only enforcement (FEAT-SEC-01)
	if f.Type != proto.TypeKexInit {
		s.log.Warn("rejecting unencrypted handshake: expected KEX_INIT", "type", f.Type.String(), "from", conn.RemoteAddr().String())
		writeErr(conn, proto.CodeProto, "encrypted handshake required (expected KEX_INIT)")
		return
	}

	if s.hostKey == nil {
		s.log.Error("server host key unavailable", "err", s.hostKeyErr)
		writeErr(conn, proto.CodeInternal, "server host key unavailable")
		return
	}

	kexSrv, err := kex.NewServerSession(s.hostKey)
	if err != nil {
		s.log.Error("kex new server session", "err", err)
		writeErr(conn, proto.CodeInternal, "kex init failed")
		return
	}

	replyPayload, c2sKey, s2cKey, err := kexSrv.ProcessInit(f.Payload)
	if err != nil {
		s.log.Debug("kex process init", "err", err)
		writeErr(conn, proto.CodeProto, "kex init failed: "+err.Error())
		return
	}
	// J-D16: the KEX serverNonce doubles as the auth serverNonce. ExchangeHash
	// (signed by the host key) and DeriveChallenge both cover it, which is what
	// binds a relayed attestation to the challenge an originator signs.
	kexNonce := kexSrv.AttestationNonce()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := conn.WriteFrame(proto.Frame{Type: proto.TypeKexReply, Payload: replyPayload}); err != nil {
		_ = conn.SetDeadline(time.Time{})
		s.log.Debug("write kex reply", "err", err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	// Wrap in CipherConn (server sends s2cKey, receives c2sKey)
	cipherConn, err := kex.NewCipherConn(conn, s2cKey, c2sKey)
	if err != nil {
		s.log.Error("new cipher conn", "err", err)
		return
	}

	// Read encrypted control frame
	_ = cipherConn.SetDeadline(time.Now().Add(handshakeTimeout))
	f, err = cipherConn.ReadFrame()
	_ = cipherConn.SetDeadline(time.Time{})
	if err != nil {
		s.log.Debug("encrypted handshake read", "err", err)
		return
	}

	ctx := s.sessionContext()
	if s.shutting() {
		if f.Type == proto.TypeResume {
			writeResumeFail(cipherConn, proto.CodeShutdown, "shutting down")
		} else {
			writeErr(cipherConn, proto.CodeShutdown, "shutting down")
		}
		return
	}
	// Flood cap counts live carrier sockets (2× max_conns_per_ip). HELLO is
	// refused with ERR_NO_CAPACITY; RESUME of an existing session proceeds.
	if max := s.Config().MaxConnsPerIP; max > 0 && n > 2*max && (f.Type == proto.TypeHello || f.Type == proto.TypeChain) {
		s.refused.Add(1)
		writeErr(cipherConn, proto.CodeNoCapacity, "too many connections from this address")
		return
	}
	switch f.Type {
	case proto.TypeResume:
		s.handleResume(ctx, cipherConn, f, kexNonce)
	case proto.TypeHello:
		s.handleHello(ctx, cipherConn, f, ip, releaseConn, kexNonce)
	case proto.TypeChain:
		s.handleChain(ctx, cipherConn, f, ip, releaseConn, kexNonce)
	case proto.TypeAgentRegister:
		s.handleAgentRegister(ctx, cipherConn, f, ip, releaseConn, kexNonce)
	default:
		writeErr(cipherConn, proto.CodeProto, "expected HELLO")
	}
}

// dialDestination opens the terminal TCP connection a session pumps against.
// It is the seam a chained leg substitutes: an intermediate presents a nested
// relay session in place of a real destination socket (FEAT-UTL-05 §2.1).
func (s *Server) dialDestination(ctx context.Context, dest string) (*net.TCPConn, *proto.Error) {
	d := net.Dialer{Timeout: s.Config().DialTimeout.Duration(), KeepAlive: 15 * time.Second}
	dconn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		return nil, proto.NewError(proto.CodeDestRefused, "dial destination failed")
	}
	dtcp, ok := dconn.(*net.TCPConn)
	if !ok {
		_ = dconn.Close()
		return nil, proto.NewError(proto.CodeInternal, "destination is not tcp")
	}
	_ = dtcp.SetNoDelay(true)
	return dtcp, nil
}

func (s *Server) handleHello(ctx context.Context, conn transport.Conn, f proto.Frame, ip string, releaseTCP func(), kexNonce string) {
	cfg := s.Config()
	var hello proto.Hello
	if err := proto.UnmarshalPayload(f, &hello); err != nil {
		writeErr(conn, proto.CodeProto, "bad HELLO")
		return
	}
	if hello.V != 1 {
		writeErr(conn, proto.CodeVersion, "unsupported version")
		return
	}

	var span *obs.Span
	if s.tracer != nil {
		ctx, span = s.tracer.Start(ctx, "Handshake", obs.WithParentTraceparent(hello.Traceparent), obs.WithAttribute("ip", ip))
		defer span.End()
	}

	dest := hello.Destination
	isSocks := dest == proto.DestSOCKS5
	isAgentData := hello.Role == proto.RoleAgentData || strings.HasPrefix(dest, "bind:")
	isTarget := hello.Target != "" || strings.HasPrefix(dest, proto.DestTargetPrefix)
	var targetName string
	var targetDestOverride string
	if isTarget {
		if hello.Target != "" {
			targetName = hello.Target
			targetDestOverride = dest
		} else {
			val := strings.TrimPrefix(dest, proto.DestTargetPrefix)
			if idx := strings.Index(val, "/"); idx != -1 {
				targetName = val[:idx]
				targetDestOverride = val[idx+1:]
			} else {
				targetName = val
			}
		}
		if dest == "" {
			dest = proto.DestTargetPrefix + targetName
		}
	}

	if isSocks {
		if cfg.DisableSOCKS {
			if s.metrics != nil {
				s.metrics.RBACRejections.WithLabelValues("socks_disabled").Inc()
			}
			if span != nil {
				span.SetStatus("ERROR", "socks proxy mode disabled")
			}
			writeErr(conn, proto.CodeDestForbidden, "socks proxy mode disabled")
			return
		}
	} else if isAgentData {
		// Agent data session rendezvous
	} else if isTarget {
		if targetName == "" {
			if span != nil {
				span.SetStatus("ERROR", "empty target name")
			}
			writeErr(conn, proto.CodeProto, "empty target name")
			return
		}
		if _, ok := s.agentReg.GetTarget(targetName); !ok {
			s.refused.Add(1)
			if span != nil {
				span.SetStatus("ERROR", "target not found or agent offline")
			}
			writeErr(conn, proto.CodeDestRefused, fmt.Sprintf("target %q not found or agent offline", targetName))
			return
		}
		if targetDestOverride != "" {
			if _, _, err := net.SplitHostPort(targetDestOverride); err != nil {
				if span != nil {
					span.SetStatus("ERROR", "bad destination override")
				}
				writeErr(conn, proto.CodeProto, "bad destination override")
				return
			}
		}
	} else {
		if dest == "" {
			dest = cfg.DefaultDestination
		}
		if _, _, err := net.SplitHostPort(dest); err != nil {
			if span != nil {
				span.SetStatus("ERROR", "bad destination")
			}
			writeErr(conn, proto.CodeProto, "bad destination")
			return
		}
		if !config.DestinationAllowed(dest, cfg.AllowDestinations) {
			s.refused.Add(1)
			if s.metrics != nil {
				s.metrics.RBACRejections.WithLabelValues("dest_forbidden").Inc()
			}
			if span != nil {
				span.SetStatus("ERROR", "destination not allowed")
			}
			writeErr(conn, proto.CodeDestForbidden, "destination not allowed")
			return
		}
	}

	id, sess, token, serverNonce, ok := s.helloAuth(conn, hello, f.Payload, dest, kexNonce)
	if !ok {
		if s.metrics != nil {
			s.metrics.RBACRejections.WithLabelValues("auth_failed").Inc()
		}
		if span != nil {
			span.SetStatus("ERROR", "auth failed")
		}
		return
	}
	sess.Destination = dest
	sess.AuthMethod = id.Method
	sess.AuthUser = id.Name
	sess.Fingerprint = id.Fingerprint
	sess.PublicKey = id.RawPubKey
	sess.PortForwardingBlocked = id.PortForwardingBlocked
	sess.PermittedDestinations = id.PermittedDestinations

	// Check per-user RBAC restrictions from authorized_keys
	if id.PortForwardingBlocked {
		s.refused.Add(1)
		if s.metrics != nil {
			s.metrics.RBACRejections.WithLabelValues("port_forwarding_blocked").Inc()
		}
		if span != nil {
			span.SetStatus("ERROR", "port forwarding blocked")
		}
		if isSocks {
			writeErr(conn, proto.CodeDestForbidden, "socks proxy mode disabled for this key")
		} else {
			writeErr(conn, proto.CodeDestForbidden, "port forwarding is disabled for this key")
		}
		return
	}
	if !isSocks && !isAgentData && !isTarget && len(id.PermittedDestinations) > 0 {
		if !config.DestinationAllowed(dest, id.PermittedDestinations) {
			s.refused.Add(1)
			if s.metrics != nil {
				s.metrics.RBACRejections.WithLabelValues("user_policy_forbidden").Inc()
			}
			if span != nil {
				span.SetStatus("ERROR", "destination not allowed by user policy")
			}
			writeErr(conn, proto.CodeDestForbidden, "destination not allowed by user policy")
			return
		}
	}
	if isTarget && id.PermittedTargets != nil {
		allowed := false
		for _, t := range id.PermittedTargets {
			if t == "*" || t == targetName {
				allowed = true
				break
			}
		}
		if !allowed {
			s.refused.Add(1)
			if s.metrics != nil {
				s.metrics.RBACRejections.WithLabelValues("user_target_forbidden").Inc()
			}
			if span != nil {
				span.SetStatus("ERROR", "target not allowed by user policy")
			}
			writeErr(conn, proto.CodeDestForbidden, fmt.Sprintf("target %q not allowed by user policy", targetName))
			return
		}
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

	var (
		dtcp     *net.TCPConn
		smux     *socksServerMux
		sIO      sessionIO
		doSplice = cfg.Splice
	)
	if isSocks {
		toMuxR, toMuxW := io.Pipe()
		fromMuxR, fromMuxW := io.Pipe()
		smux = newSocksServerMux(s, sess.ID, toMuxR, toMuxW, fromMuxR, fromMuxW, sess.PortForwardingBlocked, sess.PermittedDestinations)
		sIO = sessionIO{
			src:        fromMuxR,
			sink:       toMuxW,
			closeWrite: toMuxW.Close,
			closeSrc:   smux.Close,
			outDir:     proto.DirDown,
			inDir:      proto.DirUp,
		}
		doSplice = false
	} else if isAgentData {
		bindID := hello.ResumeToken
		if bindID == "" {
			bindID = strings.TrimPrefix(hello.Destination, "bind:")
		}
		agentPipe, err := s.agentReg.CompleteBind(bindID)
		if err != nil {
			s.store.Remove(sess.ID)
			writeErr(conn, proto.CodeDestRefused, "invalid or expired bind id: "+err.Error())
			return
		}
		sIO = sessionIO{
			src:        agentPipe,
			sink:       agentPipe,
			rawSrc:     agentPipe,
			rawSink:    agentPipe,
			closeWrite: agentPipe.CloseWrite,
			closeSrc:   agentPipe.Close,
			outDir:     proto.DirDown,
			inDir:      proto.DirUp,
		}
		doSplice = false
	} else if isTarget {
		pb, clientPipe, err := s.agentReg.CreateBind(targetName, targetDestOverride, ip, conn.RemoteAddr())
		if err != nil {
			s.store.Remove(sess.ID)
			writeErr(conn, proto.CodeDestRefused, err.Error())
			return
		}
		dialTimeout := cfg.DialTimeout.Duration()
		if dialTimeout <= 0 {
			dialTimeout = 10 * time.Second
		}
		select {
		case <-pb.ReadyCh:
			if pb.Err != nil {
				s.store.Remove(sess.ID)
				_ = clientPipe.Close()
				writeErr(conn, proto.CodeDestRefused, pb.Err.Error())
				return
			}
		case <-time.After(dialTimeout):
			s.agentReg.RemoveBind(pb.BindID)
			s.store.Remove(sess.ID)
			_ = clientPipe.Close()
			writeErr(conn, proto.CodeDestRefused, "agent dial timeout")
			return
		case <-ctx.Done():
			s.agentReg.RemoveBind(pb.BindID)
			s.store.Remove(sess.ID)
			_ = clientPipe.Close()
			return
		}
		sIO = sessionIO{
			src:        clientPipe,
			sink:       clientPipe,
			rawSrc:     clientPipe,
			rawSink:    clientPipe,
			closeWrite: clientPipe.CloseWrite,
			closeSrc:   clientPipe.Close,
			outDir:     proto.DirDown,
			inDir:      proto.DirUp,
		}
		doSplice = false
	} else {
		var derr *proto.Error
		dtcp, derr = s.dialDestination(ctx, dest)
		if derr != nil {
			s.store.Remove(sess.ID)
			writeErr(conn, derr.Code, derr.Msg)
			return
		}
		var closeWrite func() error
		var closeSrc func() error
		if dtcp != nil {
			closeWrite = dtcp.CloseWrite
			closeSrc = func() error { return dtcp.Close() }
		}
		sIO = sessionIO{
			src:        dtcp,
			sink:       dtcp,
			rawSrc:     dtcp,
			rawSink:    dtcp,
			closeWrite: closeWrite,
			closeSrc:   closeSrc,
			outDir:     proto.DirDown,
			inDir:      proto.DirUp,
		}
	}

	window := cfg.SendWindow
	if hello.Window > 0 && hello.Window < window {
		window = hello.Window
	}
	bufCap := cfg.BufferBytes
	if rem := s.budget.Remaining(); rem > 0 && rem < int64(bufCap) {
		bufCap = int(rem)
	}
	if bufCap <= 0 {
		if dtcp != nil {
			_ = dtcp.Close()
		}
		if smux != nil {
			_ = smux.Close()
		}
		if sIO.closeSrc != nil {
			_ = sIO.closeSrc()
		}
		s.store.Remove(sess.ID)
		s.refused.Add(1)
		writeErr(conn, proto.CodeNoCapacity, "buffer budget exhausted")
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
			HoldTimeoutMs:   int(cfg.HoldTimeout.Duration() / time.Millisecond),
			Window:          window,
			DataChunkBytes:  cfg.DataChunkBytes,
			SwitchTimeoutMs: int(cfg.SwitchTimeout.Duration() / time.Millisecond),
		},
		ServerNonce: serverNonce,
	}
	fr, err := proto.MarshalFrame(proto.TypeHelloOK, okMsg)
	if err != nil {
		if dtcp != nil {
			_ = dtcp.Close()
		}
		if smux != nil {
			_ = smux.Close()
		}
		if sIO.closeSrc != nil {
			_ = sIO.closeSrc()
		}
		s.store.Remove(sess.ID)
		return
	}

	rawConn := unwrapConn(conn)
	log := logging.WithSession(s.log, sess.ID)
	sendLog := session.NewTieredRing(session.RingConfig{
		CapMax:   bufCap,
		Budget:   s.budget,
		L1Cap:    cfg.SpillL1Bytes,
		SpillDir: cfg.SpillDir,
		NoSpill:  cfg.NoSpill,
	})
	sIO.conn = rawConn
	p := newPump(ctx, sIO, pumpConfig{
		chunk:         cfg.DataChunkBytes,
		window:        window,
		buffer:        bufCap,
		keepalive:     cfg.KeepaliveInterval.Duration(),
		idle:          cfg.IdleTimeout.Duration(),
		switchTimeout: cfg.SwitchTimeout.Duration(),
		heartbeat:     cfg.HeartbeatInterval.Duration(),
		deadThreshold: cfg.DeadPeerThreshold,
		log:           log,
		splice:        doSplice,
		metrics:       s.metrics,
	}, sendLog)

	l := &live{
		pump:            p,
		id:              sess.ID,
		srv:             s,
		store:           s.store,
		cfg:             cfg,
		window:          window,
		holdTimeout:     cfg.HoldTimeout.Duration(),
		dest:            dtcp,
		socksMux:        smux,
		log:             log,
		clientIP:        ip,
		releaseHelloTCP: releaseTCP,
		attachCh:        make(chan attachReq, 4),
		deadCh:          make(chan struct{}),
	}
	if isSocks && smux != nil {
		go smux.Run(ctx)
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
	log.Info("session started", "dest", dest, "peer", rawConn.RemoteAddr().String(), "transport", selected)
	l.run(ctx, rawConn)
}

func (s *Server) handleResume(ctx context.Context, conn transport.Conn, f proto.Frame, kexNonce string) {
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

	resumeStart := time.Now()
	var span *obs.Span
	if s.tracer != nil {
		ctx, span = s.tracer.Start(ctx, "Resume", obs.WithParentTraceparent(msg.Traceparent), obs.WithAttribute("sessionId", msg.SessionID))
		defer span.End()
	}

	failResume := func(code, reason string) {
		if s.metrics != nil {
			s.metrics.ReconnectTotal.WithLabelValues("failure").Inc()
		}
		if span != nil {
			span.SetStatus("ERROR", reason)
		}
		writeResumeFail(conn, code, reason)
	}

	s.livesMu.Lock()
	l := s.lives[msg.SessionID]
	s.livesMu.Unlock()
	if l == nil {
		if s.store.IsExpired(msg.SessionID) {
			failResume(proto.CodeExpired, "session expired")
		} else {
			failResume(proto.CodeUnknownSession, "unknown session")
		}
		return
	}

	fallback := false
	if err := s.store.VerifyToken(msg.SessionID, msg.ResumeToken); err != nil {
		sess := s.store.Get(msg.SessionID)
		if s.getAuth().RequiresChallenge() && sess != nil && (sess.Fingerprint != "" || len(sess.PublicKey) > 0) {
			fallback = true
		} else {
			code, m := proto.CodeBadToken, "bad resume token"
			var pe *proto.Error
			if errors.As(err, &pe) {
				code, m = pe.Code, pe.Msg
			}
			failResume(code, m)
			return
		}
	}

	if fallback {
		l.log.Info("resume token invalid or missing; initiating cryptographic fallback", "sessionId", msg.SessionID)
		if !s.resumeAuth(conn, msg, f.Payload, kexNonce) {
			if s.metrics != nil {
				s.metrics.ReconnectTotal.WithLabelValues("failure").Inc()
			}
			if span != nil {
				span.SetStatus("ERROR", "fallback auth failed")
			}
			return
		}
	}

	if l.nested != nil {
		if err := l.ensureNestedLive(ctx, conn); err != nil {
			code, m := proto.CodeExpired, "onward hop lost"
			var pe *proto.Error
			if errors.As(err, &pe) {
				code, m = pe.Code, pe.Msg
			}
			failResume(code, m)
			return
		}
	}

	isStandby := msg.Role == "standby"
	req := attachReq{conn: conn, resume: &msg, standby: isStandby, fallback: fallback, done: make(chan error, 1)}
	if isStandby {
		if err := l.AttachStandby(req); err != nil {
			var pe *proto.Error
			if errors.As(err, &pe) {
				failResume(pe.Code, pe.Msg)
				return
			}
			failResume(proto.CodeExpired, "session closed")
			return
		}
		select {
		case err := <-req.done:
			if err == nil {
				if s.metrics != nil {
					s.metrics.ReconnectTotal.WithLabelValues("success").Inc()
					s.metrics.ReconnectDuration.Observe(time.Since(resumeStart).Seconds())
				}
				if span != nil {
					span.SetStatus("OK", "")
				}
			} else {
				if s.metrics != nil {
					s.metrics.ReconnectTotal.WithLabelValues("failure").Inc()
				}
				if span != nil {
					span.SetStatus("ERROR", err.Error())
				}
			}
		case <-ctx.Done():
		}
		return
	}

	if err := l.Offer(req); err != nil {
		var pe *proto.Error
		if errors.As(err, &pe) {
			failResume(pe.Code, pe.Msg)
			return
		}
		failResume(proto.CodeExpired, "session closed")
		return
	}
	select {
	case err := <-req.done:
		if err == nil {
			if s.metrics != nil {
				s.metrics.ReconnectTotal.WithLabelValues("success").Inc()
				s.metrics.ReconnectDuration.Observe(time.Since(resumeStart).Seconds())
			}
			if span != nil {
				span.SetStatus("OK", "")
			}
		} else {
			if s.metrics != nil {
				s.metrics.ReconnectTotal.WithLabelValues("failure").Inc()
			}
			if span != nil {
				span.SetStatus("ERROR", err.Error())
			}
		}
	case <-ctx.Done():
	}
}

type attachReq struct {
	conn     transport.Conn
	resume   *proto.Resume
	standby  bool
	fallback bool
	done     chan error
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
	nested          *nestedHop
	socksMux        *socksServerMux
	releaseChain    func()
	log             *slog.Logger
	clientIP        string
	releaseHelloTCP func()
	attachCh        chan attachReq
	deadCh          chan struct{}

	standbyMu           sync.Mutex
	standbyConn         transport.Conn
	standbyBFD          *bfd.Session
	standbyStop         context.CancelFunc
	standbyPromote      chan struct{}
	standbyPromotedDone chan struct{}
	standbyDone         chan error
	standbyPrefetched   []proto.Frame

	mu           sync.Mutex
	heldAt       time.Time
	dead         bool
	cleaned      bool
	pathHist     []pathInfo
	chainAuthCh  chan proto.Auth
	chainAuthHop int
	chainAuthN   atomic.Int64
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

func (l *live) currentTransport() string {
	if l == nil || l.pump == nil {
		return ""
	}
	return l.pump.currentTransport()
}

func (l *live) hasStandby() bool {
	if l == nil {
		return false
	}
	l.standbyMu.Lock()
	defer l.standbyMu.Unlock()
	return l.standbyConn != nil && l.standbyBFD != nil && l.standbyBFD.IsUp()
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

func (l *live) AttachStandby(req attachReq) error {
	select {
	case <-l.deadCh:
		return proto.ErrExpired
	case <-l.sessCtx.Done():
		return proto.ErrExpired
	default:
	}

	l.standbyMu.Lock()
	defer l.standbyMu.Unlock()

	if l.standbyStop != nil {
		l.standbyStop()
		if l.standbyConn != nil {
			_ = l.standbyConn.Close()
		}
		l.standbyConn = nil
		l.standbyBFD = nil
		l.standbyStop = nil
		l.standbyPromote = nil
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

	if err := l.writeResumeOK(req, heldMs); err != nil {
		_ = req.conn.Close()
		select {
		case req.done <- err:
		default:
		}
		return err
	}

	bfdCfg := bfd.Config{
		DesiredMinTxInterval:  l.cfg.HeartbeatInterval.Duration(),
		RequiredMinRxInterval: l.cfg.HeartbeatInterval.Duration(),
		DetectMultiplier:      uint8(l.cfg.DeadPeerThreshold),
	}
	bfdSess, err := bfd.NewSession(bfdCfg)
	if err != nil {
		_ = req.conn.Close()
		select {
		case req.done <- err:
		default:
		}
		return err
	}

	standbyCtx, standbyCancel := context.WithCancel(l.sessCtx)
	promoteCh := make(chan struct{})
	promotedDone := make(chan struct{})

	rawStandbyConn := unwrapConn(req.conn)
	l.standbyConn = rawStandbyConn
	l.standbyBFD = bfdSess
	l.standbyStop = standbyCancel
	l.standbyPromote = promoteCh
	l.standbyPromotedDone = promotedDone
	l.standbyDone = req.done

	l.notePath(rawStandbyConn)
	l.log.Info("standby connection attached", "transport", rawStandbyConn.Kind().String(), "peer", rawStandbyConn.RemoteAddr().String())

	go l.runStandby(standbyCtx, rawStandbyConn, bfdSess, promoteCh, promotedDone, req.done)
	return nil
}

func (l *live) runStandby(ctx context.Context, conn transport.Conn, sess *bfd.Session, promoteCh, promotedDone chan struct{}, done chan error) {
	errc := make(chan error, 2)
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	gate := newStandbyGate(conn)
	var wg sync.WaitGroup
	var prefetchedMu sync.Mutex
	var prefetched []proto.Frame

	wg.Add(2)
	// Standby BFD reader
	go func() {
		defer wg.Done()
		for {
			f, err := gate.readFrame()
			if err != nil {
				if runCtx.Err() != nil {
					return
				}
				select {
				case errc <- err:
				default:
				}
				runCancel()
				return
			}
			if f.Type == proto.TypePing {
				pkt, perr := bfd.DecodePacket(f.Payload)
				if perr == nil {
					_, _ = sess.Receive(pkt)
				}
				continue
			}

			// Non-ping frame received on standby connection: the peer has switched to this carrier!
			prefetchedMu.Lock()
			prefetched = append(prefetched, f)
			prefetchedMu.Unlock()

			l.dropConn()
			runCancel()
			return
		}
	}()

	// Standby BFD timer
	go func() {
		defer wg.Done()
		cadence := sess.TxInterval()
		if cadence <= 0 {
			cadence = 750 * time.Millisecond
		}
		t := time.NewTicker(cadence)
		defer t.Stop()

		for {
			select {
			case <-runCtx.Done():
				return
			case now := <-t.C:
				if sess.CheckTimeout(now) {
					noteDeadPeer(l.log, l.srv.metrics, "standby", sess, now)
					select {
					case errc <- ErrDeadPeer:
					default:
					}
					runCancel()
					return
				}
				newCadence := sess.TxInterval()
				if newCadence > 0 && newCadence != cadence {
					cadence = newCadence
					t.Reset(cadence)
				}
				pkt := sess.FormatTxPacket()
				payload := bfd.EncodePacket(pkt)
				if err := conn.WriteFrame(proto.Frame{Type: proto.TypePing, Payload: payload}); err != nil {
					if runCtx.Err() != nil {
						return
					}
					select {
					case errc <- err:
					default:
					}
					runCancel()
					return
				}
			}
		}
	}()

	select {
	case <-promoteCh:
		runCancel()
		gate.stop()
		wg.Wait()
		gate.release()
		l.standbyMu.Lock()
		prefetchedMu.Lock()
		l.standbyPrefetched = append(l.standbyPrefetched, prefetched...)
		prefetchedMu.Unlock()
		l.standbyMu.Unlock()
		close(promotedDone)
		l.log.Info("standby connection promoted; yielding to active runner")
		return
	case <-ctx.Done():
		_ = conn.Close()
		select {
		case done <- ctx.Err():
		default:
		}
	case err := <-errc:
		_ = conn.Close()
		l.log.Info("standby connection dropped", "err", err)
		select {
		case done <- err:
		default:
		}
	}

	l.standbyMu.Lock()
	if l.standbyConn == conn {
		l.standbyConn = nil
		l.standbyBFD = nil
		l.standbyStop = nil
		l.standbyPromote = nil
		l.standbyPromotedDone = nil
		l.standbyDone = nil
	}
	l.standbyMu.Unlock()
}

func (l *live) takeStandbyForPromotion() (transport.Conn, *bfd.Session, []proto.Frame, chan error, bool) {
	l.standbyMu.Lock()
	if l.standbyConn == nil || l.standbyBFD == nil || !l.standbyBFD.IsUp() {
		l.standbyMu.Unlock()
		return nil, nil, nil, nil, false
	}

	conn := l.standbyConn
	sess := l.standbyBFD
	doneCh := l.standbyDone
	promoteCh := l.standbyPromote
	promotedDone := l.standbyPromotedDone
	l.standbyConn = nil
	l.standbyDone = nil
	l.standbyBFD = nil
	l.standbyStop = nil
	l.standbyPromote = nil
	l.standbyPromotedDone = nil
	l.standbyMu.Unlock()

	if promoteCh != nil {
		close(promoteCh)
		<-promotedDone
	}

	l.standbyMu.Lock()
	prefetched := l.standbyPrefetched
	l.standbyPrefetched = nil
	l.standbyMu.Unlock()

	return conn, sess, prefetched, doneCh, true
}

func (l *live) disarmDest() {
	l.mu.Lock()
	dest := l.dest
	l.dest = nil
	l.mu.Unlock()
	if dest != nil {
		_ = dest.Close()
	}
	if l.pump != nil {
		l.pump.sessCancel()
	}
}

func (l *live) run(ctx context.Context, first transport.Conn) {
	var err error
	if first != nil {
		first = unwrapConn(first)
		l.startIO()
		l.notePath(first)
		err = l.serveConn(l.sessCtx, first, 0)
		if l.releaseHelloTCP != nil {
			l.releaseHelloTCP()
			l.releaseHelloTCP = nil
		}
	} else if endpointReady(l.io.src) && endpointReady(l.io.sink) {
		l.startIO()
		err = errors.New("carrier dropped for handover")
	} else {
		// SOCKS, reverse-agent, and jumphost sessions have no destination FD.
		// Hold them for reconnect; do not start a pump Read on a nil endpoint.
		err = errors.New("carrier dropped for handover")
	}
	for reconnectable(err) && ctx.Err() == nil && l.sessionErr() == nil {
		if promotedConn, bfdSess, prefetched, doneCh, ok := l.takeStandbyForPromotion(); ok {
			l.log.Info("standby connection promoted to active carrier", "transport", promotedConn.Kind().String())
			l.notePath(promotedConn)
			err = l.serveConnWithBFD(l.sessCtx, promotedConn, l.ack.Get(), bfdSess, prefetched)
			if doneCh != nil {
				select {
				case doneCh <- err:
				default:
				}
			}
			continue
		}

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
		rawReqConn := unwrapConn(req.conn)
		l.notePath(rawReqConn)
		err = l.serveConn(l.sessCtx, rawReqConn, sendFrom)
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
	if l.heldAt.IsZero() {
		l.heldAt = time.Now()
	}
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
	if l.srv != nil && l.srv.metrics != nil && heldMs > 0 {
		l.srv.metrics.HeldDuration.Observe(float64(heldMs) / 1000.0)
	}
	var token string
	if req.fallback {
		var err error
		token, err = l.store.ForceResumeToken(l.id)
		if err != nil {
			return err
		}
	} else if req.resume != nil && req.resume.Role == "standby" {
		token = req.resume.ResumeToken
	} else {
		var err error
		token, err = l.store.ResumeToken(l.id)
		if err != nil {
			return err
		}
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
		Role:      req.resume.Role,
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
	l.standbyMu.Lock()
	if l.standbyStop != nil {
		l.standbyStop()
	}
	if l.standbyConn != nil {
		_ = l.standbyConn.Close()
		l.standbyConn = nil
	}
	l.standbyBFD = nil
	l.standbyStop = nil
	l.standbyPromote = nil
	l.standbyMu.Unlock()
	if l.dest != nil {
		_ = l.dest.Close()
	}
	if l.nested != nil {
		l.nested.close()
	}
	if l.socksMux != nil {
		_ = l.socksMux.Close()
	}
	if l.releaseChain != nil {
		l.releaseChain()
		l.releaseChain = nil
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

func (s *Server) authFail(conn transport.Conn, started time.Time) {
	if d := s.getAuth().FailDelay(); d > 0 {
		if started.IsZero() {
			time.Sleep(d)
		} else if rem := d - time.Since(started); rem > 0 {
			time.Sleep(rem)
		}
	}
	writeErr(conn, proto.CodeAuth, "auth failed")
}

func (s *Server) helloAuth(conn transport.Conn, hello proto.Hello, canonical []byte, dest, kexNonce string) (auth.Identity, *session.Session, string, string, bool) {
	a := s.getAuth()
	if !a.RequiresChallenge() {
		id, err := a.Verify(auth.Challenge{
			Destination: dest,
			ClientNonce: hello.ClientNonce,
		}, hello.Auth)
		if err != nil {
			writeErr(conn, proto.CodeAuth, "auth failed")
			return auth.Identity{}, nil, "", "", false
		}
		sess, token, err := session.New()
		if err != nil {
			writeErr(conn, proto.CodeInternal, "session allocate")
			return auth.Identity{}, nil, "", "", false
		}
		return id, sess, token, kexNonce, true
	}

	var offer auth.Offer
	if err := json.Unmarshal(bytesOrEmpty(hello.Auth), &offer); err != nil || offer.Method != auth.MethodPublicKey {
		s.authFail(conn, time.Time{})
		return auth.Identity{}, nil, "", "", false
	}
	sess, token, err := session.New()
	if err != nil {
		writeErr(conn, proto.CodeInternal, "session allocate")
		return auth.Identity{}, nil, "", "", false
	}
	serverNonce, err := authServerNonce(kexNonce)
	if err != nil {
		writeErr(conn, proto.CodeInternal, "nonce")
		return auth.Identity{}, nil, "", "", false
	}
	ch := auth.Challenge{
		SessionID:   sess.ID,
		Destination: dest,
		ClientNonce: hello.ClientNonce,
		ServerNonce: serverNonce,
		Canonical:   canonical,
		Offer:       hello.Auth,
	}
	if !s.issueChallenge(conn, ch) {
		return auth.Identity{}, nil, "", "", false
	}
	raw, ok := s.readAuth(conn)
	if !ok {
		s.authFail(conn, time.Time{})
		return auth.Identity{}, nil, "", "", false
	}
	started := time.Now()
	id, err := a.Verify(ch, raw)
	if err != nil {
		s.authFail(conn, started)
		return auth.Identity{}, nil, "", "", false
	}
	return id, sess, token, serverNonce, true
}

// authServerNonce returns the nonce a challenge is built with. J-D16 pins it to
// the KEX serverNonce so a relayed attestation and the challenge it vouches for
// share a value the server's host key signed. The random fallback only applies
// to carriers that never ran a KEX (QUIC/KCP RESUME).
func authServerNonce(kexNonce string) (string, error) {
	if kexNonce != "" {
		return kexNonce, nil
	}
	return proto.RandomNonce()
}

func (s *Server) resumeAuth(conn transport.Conn, msg proto.Resume, canonical []byte, kexNonce string) bool {
	a := s.getAuth()
	if !a.RequiresChallenge() {
		return true
	}
	sess := s.store.Get(msg.SessionID)
	if sess == nil || sess.Fingerprint == "" {
		s.authFail(conn, time.Time{})
		return false
	}
	serverNonce, err := authServerNonce(kexNonce)
	if err != nil {
		s.authFail(conn, time.Time{})
		return false
	}
	ch := auth.Challenge{
		SessionID:   msg.SessionID,
		Destination: sess.Destination,
		ClientNonce: msg.ClientNonce,
		ServerNonce: serverNonce,
		Canonical:   canonical,
		Offer:       msg.Auth,
		BoundFP:     sess.Fingerprint,
		RawPubKey:   sess.PublicKey,
	}
	if !s.issueChallenge(conn, ch) {
		return false
	}
	raw, ok := s.readAuth(conn)
	if !ok {
		s.authFail(conn, time.Time{})
		return false
	}
	started := time.Now()
	if _, err := a.Verify(ch, raw); err != nil {
		s.authFail(conn, started)
		return false
	}
	return true
}

func (s *Server) issueChallenge(conn transport.Conn, ch auth.Challenge) bool {
	return s.issueAuthOK(conn, proto.AuthOK{
		SessionID:   ch.SessionID,
		ServerNonce: ch.ServerNonce,
		Challenge:   base64.StdEncoding.EncodeToString(auth.DeriveChallenge(ch)),
		Destination: ch.Destination,
	})
}

// challengeAndVerify is issueChallenge + readAuth + Verify, with the chain
// fields (Hop, HelloJSON, Attest) populated on AUTH_OK. hop 1 of a CHAIN uses
// this so the originator sees Hop=1 rather than the direct-session default 0.
func (s *Server) challengeAndVerify(conn transport.Conn, ch auth.Challenge, hop int, helloJSON string, attest *proto.HopAttestation) (auth.Identity, bool) {
	if !s.issueAuthOK(conn, proto.AuthOK{
		SessionID:   ch.SessionID,
		ServerNonce: ch.ServerNonce,
		Challenge:   base64.StdEncoding.EncodeToString(auth.DeriveChallenge(ch)),
		Destination: ch.Destination,
		Hop:         hop,
		HelloJSON:   helloJSON,
		Attest:      attest,
	}) {
		return auth.Identity{}, false
	}
	raw, ok := s.readAuth(conn)
	if !ok {
		s.authFail(conn, time.Time{})
		return auth.Identity{}, false
	}
	started := time.Now()
	id, err := s.getAuth().Verify(ch, raw)
	if err != nil {
		s.authFail(conn, started)
		return auth.Identity{}, false
	}
	return id, true
}

func (s *Server) issueAuthOK(conn transport.Conn, ok proto.AuthOK) bool {
	fr, err := proto.MarshalFrame(proto.TypeAuthOK, ok)
	if err != nil {
		return false
	}
	return writeFrameDeadline(conn, fr) == nil
}

func (s *Server) readAuth(conn transport.Conn) (json.RawMessage, bool) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	af, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil || af.Type != proto.TypeAuth {
		return nil, false
	}
	return json.RawMessage(af.Payload), true
}

func bytesOrEmpty(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	return raw
}

func (s *Server) dropStandbyConns() {
	s.livesMu.Lock()
	lives := make([]*live, 0, len(s.lives))
	for _, l := range s.lives {
		lives = append(lives, l)
	}
	s.livesMu.Unlock()
	for _, l := range lives {
		l.standbyMu.Lock()
		if l.standbyStop != nil {
			l.standbyStop()
		}
		if l.standbyConn != nil {
			_ = l.standbyConn.Close()
		}
		l.standbyMu.Unlock()
	}
}

func (s *Server) hasStandby() bool {
	s.livesMu.Lock()
	defer s.livesMu.Unlock()
	for _, l := range s.lives {
		l.standbyMu.Lock()
		has := l.standbyConn != nil && l.standbyBFD != nil && l.standbyBFD.IsUp()
		l.standbyMu.Unlock()
		if has {
			return true
		}
	}
	return false
}

func (s *Server) handleAgentRegister(ctx context.Context, conn transport.Conn, f proto.Frame, ip string, releaseConn func(), kexNonce string) {
	if releaseConn != nil {
		defer releaseConn()
	}
	conn = newSafeConn(conn)
	var reg proto.AgentRegister
	if err := json.Unmarshal(f.Payload, &reg); err != nil {
		writeErr(conn, proto.CodeProto, "malformed AGENT_REGISTER")
		return
	}
	if reg.Name == "" {
		writeErr(conn, proto.CodeProto, "empty agent name")
		return
	}
	if !s.Config().TargetAllowed(reg.Name) {
		writeErr(conn, proto.CodeDestForbidden, fmt.Sprintf("target %q forbidden by server policy", reg.Name))
		return
	}

	a := s.getAuth()
	targetDest := proto.DestTargetPrefix + reg.Name
	serverNonce, err := authServerNonce(kexNonce)
	if err != nil {
		writeErr(conn, proto.CodeInternal, "nonce error")
		return
	}

	ch := auth.Challenge{
		SessionID:   "agent:" + reg.Name,
		Destination: targetDest,
		ClientNonce: reg.ClientNonce,
		ServerNonce: serverNonce,
		Canonical:   f.Payload,
		Offer:       reg.Auth,
	}

	var id auth.Identity
	if a.RequiresChallenge() {
		var offer auth.Offer
		if err := json.Unmarshal(bytesOrEmpty(reg.Auth), &offer); err != nil || offer.Method != auth.MethodPublicKey {
			s.authFail(conn, time.Time{})
			return
		}
		if !s.issueChallenge(conn, ch) {
			return
		}
		raw, ok := s.readAuth(conn)
		if !ok {
			s.authFail(conn, time.Time{})
			return
		}
		started := time.Now()
		var vErr error
		id, vErr = a.Verify(ch, raw)
		if vErr != nil {
			s.authFail(conn, started)
			return
		}
	} else {
		var vErr error
		id, vErr = a.Verify(ch, reg.Auth)
		if vErr != nil {
			writeErr(conn, proto.CodeAuth, "auth failed")
			return
		}
	}

	// Verify RBAC permitlisten
	if id.PermittedTargets != nil {
		allowed := false
		for _, t := range id.PermittedTargets {
			if t == "*" || t == reg.Name {
				allowed = true
				break
			}
		}
		if !allowed {
			writeErr(conn, proto.CodeDestForbidden, fmt.Sprintf("key not permitted to register target %q", reg.Name))
			return
		}
	}

	dest := reg.Dest
	if dest == "" {
		dest = "127.0.0.1:22"
	}
	_, err = s.agentReg.Register(reg.Name, id.Fingerprint, id.RawPubKey, dest, reg.AllowDest, id.PermittedTargets, conn)
	if err != nil {
		writeErr(conn, proto.CodeDestForbidden, err.Error())
		return
	}

	okPayload, err := proto.MarshalFrame(proto.TypeAgentRegisterOK, proto.AgentRegisterOK{
		V:            1,
		Target:       reg.Name,
		ServerNonce:  serverNonce,
		ExpiresInSec: 0,
	})
	if err != nil {
		writeErr(conn, proto.CodeInternal, "marshal register ok")
		return
	}
	if err := conn.WriteFrame(okPayload); err != nil {
		s.agentReg.OnControlDisconnect(reg.Name, s.Config().AgentHoldTimeout.Duration(), conn)
		return
	}

	s.runAgentControlLoop(ctx, conn, reg.Name)
}

func (s *Server) runAgentControlLoop(ctx context.Context, conn transport.Conn, targetName string) {
	defer func() {
		_ = conn.Close()
		s.agentReg.OnControlDisconnect(targetName, s.Config().AgentHoldTimeout.Duration(), conn)
	}()

	hb := s.Config().HeartbeatInterval.Duration()
	if hb <= 0 {
		hb = 750 * time.Millisecond
	}
	// A silent control connection is not healthy past two heartbeat intervals.
	idleLimit := hb * 2

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if ag, ok := s.agentReg.GetTarget(targetName); ok {
			ag.noteControlRead(conn, true)
		}
		_ = conn.SetDeadline(time.Now().Add(idleLimit))
		f, err := conn.ReadFrame()
		if ag, ok := s.agentReg.GetTarget(targetName); ok {
			ag.noteControlRead(conn, false)
		}
		_ = conn.SetDeadline(time.Time{})
		if err != nil {
			s.log.Debug("agent control conn read closed", "target", targetName, "err", err)
			return
		}

		switch f.Type {
		case proto.TypeAgentBindOK:
			var okMsg proto.AgentBindOK
			if err := json.Unmarshal(f.Payload, &okMsg); err == nil {
				if okMsg.Status != "ok" {
					s.agentReg.FailBind(okMsg.BindID, fmt.Errorf("agent bind failed: %s", okMsg.Msg))
				}
			}
		case proto.TypePing:
			_ = conn.WriteFrame(proto.Frame{Type: proto.TypePong, Payload: f.Payload})
		case proto.TypePong:
			// Pong acknowledgment
		case proto.TypeBye:
			return
		}
	}
}
