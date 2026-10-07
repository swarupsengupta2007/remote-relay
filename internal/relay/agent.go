package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/crypto/kex"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/session"
	"github.com/remote-relay/relay/internal/transport"
)

func agentAuth(cfg config.Agent) auth.Authenticator {
	return auth.New(auth.Config{
		Method:        cfg.AuthMethod,
		User:          cfg.AuthUser,
		IdentityFiles: cfg.IdentityFiles,
		AuthSock:      cfg.AuthSock,
	})
}

func dialAgent(ctx context.Context, cfg config.Agent) (transport.Conn, error) {
	var conn transport.Conn
	var err error
	if cfg.IsWS() {
		wsOpts := &transport.WebSocketDialOptions{
			Timeout:   handshakeTimeout,
			TLSConfig: &tls.Config{InsecureSkipVerify: cfg.TLSInsecure},
		}
		conn, err = transport.DialWebSocket(ctx, cfg.Server, wsOpts)
		if err != nil {
			return nil, fmt.Errorf("dial websocket server: %w", err)
		}
	} else {
		conn, err = transport.DialTCPWithDelay(ctx, cfg.Server, 250*time.Millisecond)
		if err != nil {
			return nil, fmt.Errorf("dial server: %w", err)
		}
	}

	kexCli, err := kex.NewClientSession()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("kex new client session: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := conn.WriteFrame(proto.Frame{Type: proto.TypeKexInit, Payload: kexCli.InitPayload()}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send KEX_INIT: %w", err)
	}
	reply, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read KEX_REPLY: %w", err)
	}
	if reply.Type != proto.TypeKexReply {
		_ = conn.Close()
		return nil, proto.NewError(proto.CodeProto, "expected KEX_REPLY, got "+reply.Type.String())
	}
	verifyHostKey := func(pub ed25519.PublicKey) error {
		return kex.VerifyKnownHosts(cfg.KnownHosts, cfg.Server, pub, cfg.ServerFingerprint, cfg.StrictHostKeyChecking)
	}
	c2sKey, s2cKey, err := kexCli.ProcessReply(reply.Payload, verifyHostKey)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("kex verify reply: %w", err)
	}
	cipherConn, err := kex.NewCipherConn(conn, c2sKey, s2cKey)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create cipher conn: %w", err)
	}
	return cipherConn, nil
}

func registerAgent(ctx context.Context, conn transport.Conn, cfg config.Agent, a auth.Authenticator) error {
	nonce, err := proto.RandomNonce()
	if err != nil {
		return err
	}
	targetDest := proto.DestTargetPrefix + cfg.Name
	authMsg, err := a.Respond(auth.Challenge{Destination: targetDest, ClientNonce: nonce})
	if err != nil {
		return err
	}
	reg := proto.AgentRegister{
		V:           1,
		Name:        cfg.Name,
		Dest:        cfg.Destination,
		AllowDest:   cfg.AllowDestinations,
		ClientNonce: nonce,
		Auth:        authMsg,
	}
	frame, err := proto.MarshalFrame(proto.TypeAgentRegister, reg)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := conn.WriteFrame(frame); err != nil {
		return fmt.Errorf("send AGENT_REGISTER: %w", err)
	}
	reply, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("read AGENT_REGISTER response: %w", err)
	}
	if reply.Type == proto.TypeAuthOK {
		ch := auth.Challenge{
			Destination: targetDest,
			ClientNonce: nonce,
			Canonical:   frame.Payload,
			Offer:       authMsg,
		}
		if err := completeClientAuth(conn, a, ch, reply); err != nil {
			return err
		}
		_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
		reply, err = conn.ReadFrame()
		_ = conn.SetDeadline(time.Time{})
		if err != nil {
			return fmt.Errorf("read AGENT_REGISTER_OK: %w", err)
		}
	}
	if reply.Type == proto.TypeErr {
		var pe proto.Error
		_ = proto.UnmarshalPayload(reply, &pe)
		return &pe
	}
	if reply.Type != proto.TypeAgentRegisterOK {
		return fmt.Errorf("unexpected frame %s, want AGENT_REGISTER_OK", reply.Type.String())
	}
	return nil
}

func sendAgentBindOK(conn transport.Conn, bindID, status, msg string) error {
	frame, err := proto.MarshalFrame(proto.TypeAgentBindOK, proto.AgentBindOK{
		V:      1,
		BindID: bindID,
		Status: status,
		Msg:    msg,
	})
	if err != nil {
		return err
	}
	return conn.WriteFrame(frame)
}

func handleAgentBind(ctx context.Context, cfg config.Agent, bind proto.AgentBind, controlConn transport.Conn, a auth.Authenticator, log *slog.Logger) {
	dest := bind.Destination
	if dest == "" {
		dest = cfg.Destination
	}
	if !cfg.DestinationAllowed(dest) {
		log.Warn("agent rejected bind destination not allowed", "target", bind.Target, "dest", dest)
		_ = sendAgentBindOK(controlConn, bind.BindID, "error", "destination not allowed by agent policy")
		return
	}

	d := net.Dialer{Timeout: 5 * time.Second}
	localConn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		log.Warn("agent failed to connect local destination", "dest", dest, "err", err)
		_ = sendAgentBindOK(controlConn, bind.BindID, "error", err.Error())
		return
	}
	defer localConn.Close()

	dataConn, err := dialAgent(ctx, cfg)
	if err != nil {
		log.Warn("agent failed to dial relay server for data session", "err", err)
		_ = sendAgentBindOK(controlConn, bind.BindID, "error", "failed to dial relay server: "+err.Error())
		return
	}
	defer dataConn.Close()

	nonce, err := proto.RandomNonce()
	if err != nil {
		_ = sendAgentBindOK(controlConn, bind.BindID, "error", err.Error())
		return
	}
	bindDest := "bind:" + bind.BindID
	authMsg, err := a.Respond(auth.Challenge{Destination: bindDest, ClientNonce: nonce})
	if err != nil {
		_ = sendAgentBindOK(controlConn, bind.BindID, "error", err.Error())
		return
	}
	hello := proto.Hello{
		V:           1,
		Role:        proto.RoleAgentData,
		ResumeToken: bind.BindID,
		Destination: bindDest,
		Transport:   cfg.TransportPreference(),
		ClientNonce: nonce,
		Auth:        authMsg,
		Window:      cfg.SendWindow,
	}
	fr, err := proto.MarshalFrame(proto.TypeHello, hello)
	if err != nil {
		return
	}
	_ = dataConn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := dataConn.WriteFrame(fr); err != nil {
		return
	}
	reply, err := dataConn.ReadFrame()
	_ = dataConn.SetDeadline(time.Time{})
	if err != nil {
		return
	}
	if reply.Type == proto.TypeAuthOK {
		ch := auth.Challenge{
			Destination: bindDest,
			ClientNonce: nonce,
			Canonical:   fr.Payload,
			Offer:       authMsg,
		}
		if err := completeClientAuth(dataConn, a, ch, reply); err != nil {
			return
		}
		_ = dataConn.SetDeadline(time.Now().Add(handshakeTimeout))
		reply, err = dataConn.ReadFrame()
		_ = dataConn.SetDeadline(time.Time{})
		if err != nil {
			return
		}
	}
	if reply.Type != proto.TypeHelloOK {
		var pe proto.Error
		_ = proto.UnmarshalPayload(reply, &pe)
		log.Warn("agent data session HELLO rejected", "err", pe.Error())
		return
	}
	var helloOK proto.HelloOK
	_ = proto.UnmarshalPayload(reply, &helloOK)

	// Send successful bind confirmation over control channel
	_ = sendAgentBindOK(controlConn, bind.BindID, "ok", "")

	rawDataConn := unwrapConn(dataConn)

	// Set up pump bridging local destination and server data connection
	var closeWrite func() error
	if tcpConn, ok := localConn.(*net.TCPConn); ok {
		closeWrite = tcpConn.CloseWrite
		_ = tcpConn.SetNoDelay(true)
	}
	sIO := sessionIO{
		conn:       rawDataConn,
		src:        localConn,
		sink:       localConn,
		rawSrc:     localConn,
		rawSink:    localConn,
		closeWrite: closeWrite,
		closeSrc:   localConn.Close,
		outDir:     proto.DirUp,
		inDir:      proto.DirDown,
	}

	bufCap := cfg.BufferBytes
	if helloOK.Limits.BufferBytes > 0 && helloOK.Limits.BufferBytes < bufCap {
		bufCap = helloOK.Limits.BufferBytes
	}
	sendLog := session.NewTieredRing(session.RingConfig{
		CapMax:   bufCap,
		L1Cap:    cfg.SpillL1Bytes,
		SpillDir: cfg.SpillDir,
		NoSpill:  cfg.NoSpill,
	})
	window := cfg.SendWindow
	if helloOK.Limits.Window > 0 && helloOK.Limits.Window < window {
		window = helloOK.Limits.Window
	}
	chunk := 65536
	if helloOK.Limits.DataChunkBytes > 0 {
		chunk = helloOK.Limits.DataChunkBytes
	}

	p := newPump(ctx, sIO, pumpConfig{
		chunk:         chunk,
		window:        window,
		buffer:        bufCap,
		keepalive:     cfg.KeepaliveInterval.Duration(),
		idle:          cfg.IdleTimeout.Duration(),
		heartbeat:     cfg.HeartbeatInterval.Duration(),
		deadThreshold: cfg.DeadPeerThreshold,
		log:           logging.WithSession(log, helloOK.SessionID),
		splice:        cfg.Splice,
	}, sendLog)

	p.startIO()
	defer p.shutdown()

	token := helloOK.ResumeToken
	pErr := p.serveConn(ctx, rawDataConn, 0)
	clientCfg := config.Client{
		Server:                cfg.Server,
		Transport:             cfg.Transport,
		AuthMethod:            cfg.AuthMethod,
		AuthUser:              cfg.AuthUser,
		AuthSock:              cfg.AuthSock,
		IdentityFiles:         cfg.IdentityFiles,
		KnownHosts:            cfg.KnownHosts,
		ServerFingerprint:     cfg.ServerFingerprint,
		StrictHostKeyChecking: cfg.StrictHostKeyChecking,
		WS:                    cfg.WS,
		WebSocketPath:         cfg.WebSocketPath,
		TLSInsecure:           cfg.TLSInsecure,
		ReconnectBackoff:      cfg.ReconnectBackoff,
		ReconnectMaxElapsed:   cfg.ReconnectMaxElapsed,
	}
	schedule := parseBackoff(cfg.ReconnectBackoff)
	maxElapsed := cfg.ReconnectMaxElapsed.Duration()
	if maxElapsed <= 0 {
		maxElapsed = 5 * time.Minute
	}
	deadline := time.Now().Add(maxElapsed)
	attempt := 0

	for reconnectable(pErr) && time.Now().Before(deadline) && ctx.Err() == nil {
		if serr := sleepBackoff(ctx, schedule, attempt, deadline); serr != nil {
			break
		}
		attempt++
		dialCtx, dialCancel := context.WithDeadline(ctx, deadline)
		nconn, rok, rerr := clientResumeRole(dialCtx, clientCfg, helloOK.SessionID, token, p.delivered.Load(), proto.RoleAgentData)
		dialCancel()
		if rerr != nil {
			pErr = rerr
			continue
		}
		token = rok.ResumeToken
		p.sendLog.AdvanceTo(rok.UpAcked)
		pErr = p.serveConn(ctx, nconn, rok.UpAcked)
	}
}

// RunAgent connects to the remote relay server, registers the target name,
// and handles incoming bind requests by bridging local destination connections.
func RunAgent(ctx context.Context, cfg config.Agent, log *slog.Logger) error {
	if log == nil {
		log = logging.NewClient(cfg.LogLevel, cfg.LogFormat)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	a := agentAuth(cfg)
	if c, ok := a.(io.Closer); ok {
		defer c.Close()
	}

	schedule := parseBackoff(cfg.ReconnectBackoff)
	maxElapsed := cfg.ReconnectMaxElapsed.Duration()
	if maxElapsed <= 0 {
		maxElapsed = 5 * time.Minute
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		rawConn, err := dialAgent(ctx, cfg)
		if err != nil {
			log.Warn("agent failed to connect to server", "err", err)
			if serr := sleepBackoff(ctx, schedule, 0, time.Now().Add(maxElapsed)); serr != nil {
				return serr
			}
			continue
		}
		conn := newSafeConn(rawConn)

		err = registerAgent(ctx, conn, cfg, a)
		if err != nil {
			_ = conn.Close()
			var pe *proto.Error
			if errors.As(err, &pe) && (pe.Code == proto.CodeDestForbidden || pe.Code == proto.CodeAuth) {
				log.Error("agent registration forbidden", "err", err)
				return err
			}
			log.Warn("agent registration failed, retrying", "err", err)
			if serr := sleepBackoff(ctx, schedule, 0, time.Now().Add(maxElapsed)); serr != nil {
				return serr
			}
			continue
		}

		log.Info("agent registered target successfully", "target", cfg.Name, "dest", cfg.Destination)

		// Start heartbeat pinger
		pingCtx, pingCancel := context.WithCancel(ctx)
		var pingWg sync.WaitGroup
		pingWg.Add(1)
		hbInterval := cfg.HeartbeatInterval.Duration()
		if hbInterval <= 0 {
			hbInterval = 750 * time.Millisecond
		}
		go func() {
			defer pingWg.Done()
			ticker := time.NewTicker(hbInterval)
			defer ticker.Stop()
			for {
				select {
				case <-pingCtx.Done():
					return
				case <-ticker.C:
					_ = conn.WriteFrame(proto.Frame{Type: proto.TypePing})
				}
			}
		}()

		// Read loop on control connection
		for {
			f, rerr := conn.ReadFrame()
			if rerr != nil {
				log.Warn("agent control connection lost", "err", rerr)
				break
			}
			switch f.Type {
			case proto.TypeAgentBind:
				var bind proto.AgentBind
				if berr := json.Unmarshal(f.Payload, &bind); berr == nil {
					log.Info("received agent bind request", "bindId", bind.BindID, "target", bind.Target)
					go handleAgentBind(ctx, cfg, bind, conn, a, log)
				}
			case proto.TypePong:
				// Heartbeat ack
			case proto.TypePing:
				_ = conn.WriteFrame(proto.Frame{Type: proto.TypePong, Payload: f.Payload})
			case proto.TypeBye:
				log.Info("server sent bye to agent")
				goto reconnect
			}
		}

	reconnect:
		pingCancel()
		_ = conn.Close()
		pingWg.Wait()

		if ctx.Err() != nil {
			return ctx.Err()
		}

		log.Info("agent reconnecting to server...")
		if serr := sleepBackoff(ctx, schedule, 0, time.Now().Add(maxElapsed)); serr != nil {
			return serr
		}
	}
}
