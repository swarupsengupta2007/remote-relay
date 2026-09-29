package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/bfd"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/crypto/kex"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/session"
	"github.com/remote-relay/relay/internal/transport"
)

const handshakeTimeout = 10 * time.Second

func RunClient(ctx context.Context, cfg config.Client, stdin io.Reader, stdout io.Writer, log *slog.Logger) error {
	if log == nil {
		log = logging.NewClient(cfg.LogLevel, cfg.LogFormat)
	}
	// pathCfg is the config used after HELLO for resume/upgrade. On a chained
	// path the originator only ever reconnects to hop 1; cfg.Server stays the
	// terminal so TypeChain can name it.
	pathCfg := cfg
	if len(cfg.Jumphost) > 0 {
		hops, err := config.ParseJumphost(cfg.Jumphost)
		if err != nil {
			return err
		}
		if len(hops) == 0 {
			return proto.NewError(proto.CodeProto, "jumphost list is empty")
		}
		pathCfg = cfg
		if len(hops[0].Transport) > 0 {
			pathCfg.Transport = hops[0].Transport[0]
		}
		if hops[0].AllowHA {
			pathCfg.AllowHA = true
		}
		// Server stays the terminal so Case D can name hops 2…N. Hop-1 dials
		// use resumeDialAddr.
	}

	hud := NewHUD(HUDConfig{
		Enabled:             cfg.HUD,
		Out:                 cfg.HUDWriter,
		IsTerminal:          cfg.HUDIsTerminal,
		NotificationTimeout: cfg.NotificationTimeout.Duration(),
	})
	defer hud.Clear()

	schedule := parseBackoff(cfg.ReconnectBackoff)
	maxElapsed := cfg.ReconnectMaxElapsed.Duration()
	if maxElapsed <= 0 {
		maxElapsed = 5 * time.Minute
	}

	var conn transport.Conn
	var helloOK proto.HelloOK
	var err error
	attempt := 0
	helloDeadline := time.Now().Add(maxElapsed)
	for {
		helloCtx, helloCancel := context.WithDeadline(ctx, helloDeadline)
		conn, helloOK, err = clientHello(helloCtx, cfg)
		helloCancel()
		if err == nil {
			if attempt > 0 {
				hud.OnRestored(helloOK.Transport, 0)
			}
			break
		}
		if attempt == 0 {
			hud.OnDisrupted(cfg.Transport)
		}
		hud.OnAttempt(attempt+1, len(schedule)+1, cfg.Transport, err)
		if (!reconnectable(err) && !errors.Is(err, context.DeadlineExceeded)) || time.Now().After(helloDeadline) || ctx.Err() != nil {
			hud.OnFailed(err.Error(), err)
			return err
		}
		log.Debug("handshake failed, retrying", "attempt", attempt, "err", err)
		if serr := sleepBackoff(ctx, schedule, attempt, helloDeadline); serr != nil {
			hud.OnAborted("canceled by user")
			return err
		}
		attempt++
	}
	log = logging.WithSession(log, helloOK.SessionID)
	if !cfg.AllowHA && !cfg.IsTCP() && !cfg.IsWS() && (helloOK.Transport == "tcp" || helloOK.UDP == nil) {
		_ = conn.Close()
		return fmt.Errorf("udp route unavailable and --allow-ha not specified: server does not provide udp transport")
	}
	if err := checkStrictUDPProbe(ctx, pathCfg, conn, helloOK.UDP); err != nil {
		_ = conn.Close()
		return err
	}
	log.Info("session established", "transport", helloOK.Transport)

	chunk := clampChunk(helloOK.Limits.DataChunkBytes)
	window := cfg.SendWindow
	if helloOK.Limits.Window > 0 && (window <= 0 || helloOK.Limits.Window < window) {
		window = helloOK.Limits.Window
	}
	bufCap := cfg.BufferBytes
	if helloOK.Limits.BufferBytes > 0 && helloOK.Limits.BufferBytes < bufCap {
		bufCap = helloOK.Limits.BufferBytes
	}

	bw := bufio.NewWriterSize(stdout, 128*1024)
	src, stopSrc := interruptibleReader(stdin)
	sendLog := session.NewRing(bufCap, nil)
	st := 5 * time.Second
	if helloOK.Limits.SwitchTimeoutMs > 0 {
		st = time.Duration(helloOK.Limits.SwitchTimeoutMs) * time.Millisecond
	}
	keepalive := cfg.KeepaliveInterval.Duration()
	if keepalive <= 0 {
		keepalive = 5 * time.Second
	}
	idle := cfg.IdleTimeout.Duration()
	if idle <= 0 {
		idle = 30 * time.Second
	}
	p := newPump(ctx, sessionIO{
		conn:      conn,
		src:       src,
		sink:      bw,
		rawSrc:    stdin,
		rawSink:   stdout,
		flushSink: bw.Flush,
		closeSrc:  func() error { stopSrc(); return nil },
		outDir:    proto.DirUp,
		inDir:     proto.DirDown,
	}, pumpConfig{
		chunk:         chunk,
		window:        window,
		buffer:        bufCap,
		keepalive:     keepalive,
		idle:          idle,
		switchTimeout: st,
		heartbeat:     cfg.HeartbeatInterval.Duration(),
		deadThreshold: cfg.DeadPeerThreshold,
		log:           log,
		splice:        cfg.Splice,
	}, sendLog)
	if len(cfg.Jumphost) > 0 {
		chainHops, herr := config.ParseJumphost(cfg.Jumphost)
		if herr == nil && len(chainHops) > 0 {
			chainHops = append(chainHops, proto.HopSpec{
				Addr: cfg.Server, Fp: cfg.ServerFingerprint, User: cfg.AuthUser,
			})
			signer := clientAuth(cfg)
			if c, ok := signer.(io.Closer); ok {
				defer c.Close()
			}
			p.cfg.onAuthOK = func(aok proto.AuthOK) error {
				return signRelayedDataPlane(p, cfg, chainHops, cfg.Destination, signer, aok)
			}
		}
	}
	p.startIO()
	defer p.shutdown()

	token := helloOK.ResumeToken
	sessionID := helloOK.SessionID
	udp := helloOK.UDP
	target := helloOK.Transport
	current := conn
	sendFrom := uint64(0)
	var udpHold io.Closer
	defer func() {
		if udpHold != nil {
			_ = udpHold.Close()
		}
	}()

	schedule = parseBackoff(cfg.ReconnectBackoff)
	maxElapsed = cfg.ReconnectMaxElapsed.Duration()
	if maxElapsed <= 0 {
		maxElapsed = 5 * time.Minute
	}
	if helloOK.Limits.HoldTimeoutMs > 0 {
		hold := time.Duration(helloOK.Limits.HoldTimeoutMs) * time.Millisecond
		if hold > 0 && hold < maxElapsed {
			maxElapsed = hold
		}
	}

	var standbyMgr *standbyManager
	if cfg.AllowHA {
		standbyMgr = newStandbyManager(ctx, pathCfg, log, sessionID, token, p)
		defer standbyMgr.stop()
	}

	var currentBFD *bfd.Session

	for {
		upgCh, upgCancel := startUpgrade(ctx, p, pathCfg, current, sessionID, token, target, udp, log)
		bfdToUse := currentBFD
		currentBFD = nil
		err = p.serveConnWithBFD(p.sessCtx, current, sendFrom, bfdToUse, nil)
		upg := takeUpgrade(upgCh, upgCancel, p)
		if upg.conn != nil {
			if udpHold != nil {
				_ = udpHold.Close()
			}
			udpHold = upg.hold
			current = upg.conn
			sendFrom = upg.rok.UpAcked
			token = upg.rok.ResumeToken
			if upg.rok.UDP != nil {
				udp = upg.rok.UDP
			}
			if upg.rok.Transport != "" {
				target = upg.rok.Transport
			}
			if upg.rok.Limits.SwitchTimeoutMs > 0 {
				p.cfg.switchTimeout = time.Duration(upg.rok.Limits.SwitchTimeoutMs) * time.Millisecond
			}
			p.sendLog.AdvanceTo(sendFrom)
			log.Info("path upgraded", "transport", current.Kind().String())
			if standbyMgr != nil {
				standbyMgr.updateToken(token)
				standbyMgr.start()
			}
			continue
		}
		if upg.hold != nil {
			_ = upg.hold.Close()
		}

		if se := p.sessionErr(); se != nil {
			hud.OnFailed(se.Error(), se)
			return se
		}
		if !reconnectable(err) {
			classifiedErr := p.classify(err)
			if classifiedErr != nil {
				hud.OnFailed(classifiedErr.Error(), classifiedErr)
			}
			return classifiedErr
		}

		// In HA mode, check if warm standby channel is ready for instant zero-latency promotion
		if standbyMgr != nil {
			if promotedConn, bfdSess, ok := standbyMgr.takeForPromotion(); ok {
				log.Info("standby connection promoted to active carrier", "transport", promotedConn.Kind().String())
				current = promotedConn
				currentBFD = bfdSess
				token = standbyMgr.getToken()
				sendFrom = p.ack.Get()
				continue
			}
		}

		deadline := time.Now().Add(maxElapsed)
		attempt := 0
		resumed := false
		maxAttempts := len(schedule) + 1
		disruptedTransport := current.Kind().String()
		hud.OnDisrupted(disruptedTransport)
		for reconnectable(err) && time.Now().Before(deadline) {
			hud.OnAttempt(attempt+1, maxAttempts, disruptedTransport, err)
			dialCtx, dialCancel := context.WithDeadline(ctx, deadline)
			nconn, rok, rerr := clientResume(dialCtx, pathCfg, sessionID, token, p.delivered.Load())
			dialCancel()
			if rerr != nil {
				if !reconnectable(rerr) && !errors.Is(rerr, context.DeadlineExceeded) {
					hud.OnFailed(rerr.Error(), rerr)
					return rerr
				}
				err = rerr
				if serr := sleepBackoff(ctx, schedule, attempt, deadline); serr != nil {
					hud.OnAborted("canceled by user")
					break
				}
				attempt++
				continue
			}
			token = rok.ResumeToken
			if standbyMgr != nil {
				standbyMgr.updateToken(token)
			}
			udp = rok.UDP
			if rok.Transport != "" {
				target = rok.Transport
			}
			if rok.Limits.SwitchTimeoutMs > 0 {
				p.cfg.switchTimeout = time.Duration(rok.Limits.SwitchTimeoutMs) * time.Millisecond
			}
			if rok.State.UpClosed && !p.outEOF.Load() {
				p.outFinal.Store(p.sendLog.End())
				p.outEOF.Store(true)
				p.sendLog.Close()
			}
			p.sendLog.AdvanceTo(rok.UpAcked)
			if udpHold != nil {
				_ = udpHold.Close()
				udpHold = nil
			}
			if !pathCfg.AllowHA && !pathCfg.IsTCP() && !pathCfg.IsWS() && (target == "tcp" || udp == nil) {
				_ = nconn.Close()
				failErr := fmt.Errorf("udp route unavailable and --allow-ha not specified: server does not provide udp transport")
				hud.OnFailed(failErr.Error(), failErr)
				return failErr
			}
			if perr := checkStrictUDPProbe(ctx, pathCfg, nconn, udp); perr != nil {
				_ = nconn.Close()
				if ctx.Err() != nil {
					hud.OnAborted("canceled by user")
					return ctx.Err()
				}
				err = perr
				if serr := sleepBackoff(ctx, schedule, attempt, deadline); serr != nil {
					hud.OnAborted("canceled by user")
					break
				}
				attempt++
				continue
			}
			current = nconn
			sendFrom = rok.UpAcked
			resumed = true
			hud.OnRestored(current.Kind().String(), p.sendLog.Len())
			log.Info("session resumed", "transport", current.Kind().String())
			break
		}
		if resumed {
			continue
		}
		if reconnectable(err) || errors.Is(err, context.DeadlineExceeded) {
			budgetErr := fmt.Errorf("reconnect budget exhausted: %w", err)
			hud.OnFailed("budget exhausted", budgetErr)
			return budgetErr
		}
		classifiedErr := p.classify(err)
		if classifiedErr != nil {
			hud.OnFailed(classifiedErr.Error(), classifiedErr)
		}
		return classifiedErr
	}
}

func interruptibleReader(r io.Reader) (io.Reader, func()) {
	pr, pw := io.Pipe()
	go func() {
		_, err := io.Copy(pw, r)
		_ = pw.CloseWithError(err)
	}()
	return pr, sync.OnceFunc(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
}

func clientAuth(cfg config.Client) auth.Authenticator {
	return auth.New(auth.Config{
		Method:        cfg.AuthMethod,
		User:          cfg.AuthUser,
		IdentityFiles: cfg.IdentityFiles,
		AuthSock:      cfg.AuthSock,
	})
}

func clientHello(ctx context.Context, cfg config.Client) (transport.Conn, proto.HelloOK, error) {
	var none proto.HelloOK
	hops, err := config.ParseJumphost(cfg.Jumphost)
	if err != nil {
		return nil, none, err
	}
	if len(hops) > 0 {
		return clientChainHello(ctx, cfg, hops)
	}
	tcpBind := transport.BindConfig{
		Interface: cfg.TCPInterface,
		SourceIP:  net.ParseIP(cfg.TCPSourceIP),
	}
	var conn transport.Conn
	if cfg.IsWS() {
		wsOpts := &transport.WebSocketDialOptions{
			Bind:      tcpBind,
			Timeout:   handshakeTimeout,
			TLSConfig: &tls.Config{InsecureSkipVerify: cfg.TLSInsecure},
		}
		conn, err = transport.DialWebSocket(ctx, cfg.Server, wsOpts)
		if err != nil {
			return nil, none, fmt.Errorf("dial websocket server: %w", err)
		}
	} else {
		conn, err = transport.DialTCPWithDelayAndBind(ctx, cfg.Server, cfg.HappyEyeballsDelay.Duration(), tcpBind)
		if err != nil {
			return nil, none, fmt.Errorf("dial server: %w", err)
		}
	}

	// 1. KEX Handshake
	kexCli, err := kex.NewClientSession()
	if err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("kex new client session: %w", err)
	}
	if err := conn.SetDeadline(deadlineOr(ctx, handshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	if err := conn.WriteFrame(proto.Frame{Type: proto.TypeKexInit, Payload: kexCli.InitPayload()}); err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("send KEX_INIT: %w", err)
	}
	reply, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("read KEX_REPLY: %w", err)
	}
	if reply.Type != proto.TypeKexReply {
		_ = conn.Close()
		return nil, none, proto.NewError(proto.CodeProto, "expected KEX_REPLY, got "+reply.Type.String())
	}

	verifyHostKey := func(pub ed25519.PublicKey) error {
		return kex.VerifyKnownHosts(cfg.KnownHosts, cfg.Server, pub, cfg.ServerFingerprint, cfg.StrictHostKeyChecking)
	}
	c2sKey, s2cKey, err := kexCli.ProcessReply(reply.Payload, verifyHostKey)
	if err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("kex verify reply: %w", err)
	}

	// 2. Wrap in CipherConn (client: send c2sKey, recv s2cKey)
	cipherConn, err := kex.NewCipherConn(conn, c2sKey, s2cKey)
	if err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("create cipher conn: %w", err)
	}

	// 3. Send encrypted HELLO, complete auth, read encrypted HELLO_OK
	a := clientAuth(cfg)
	if c, ok := a.(io.Closer); ok {
		defer c.Close()
	}
	nonce, err := proto.RandomNonce()
	if err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}
	authMsg, err := a.Respond(auth.Challenge{Destination: cfg.Destination, ClientNonce: nonce})
	if err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}
	hello := proto.Hello{
		V:           1,
		SessionID:   "",
		ResumeToken: "",
		Transport:   cfg.TransportPreference(),
		Destination: cfg.Destination,
		ClientNonce: nonce,
		Auth:        authMsg,
		Window:      cfg.SendWindow,
	}
	fr, err := proto.MarshalFrame(proto.TypeHello, hello)
	if err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}
	if err := cipherConn.SetDeadline(deadlineOr(ctx, handshakeTimeout)); err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}
	if err := cipherConn.WriteFrame(fr); err != nil {
		_ = cipherConn.Close()
		return nil, none, fmt.Errorf("send HELLO: %w", err)
	}
	if err := cipherConn.SetDeadline(deadlineOr(ctx, handshakeTimeout+config.DefaultServer().DialTimeout.Duration())); err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}
	reply, err = cipherConn.ReadFrame()
	if err != nil {
		_ = cipherConn.Close()
		return nil, none, fmt.Errorf("read HELLO_OK: %w", err)
	}
	if reply.Type == proto.TypeAuthOK {
		ch := auth.Challenge{
			Destination: cfg.Destination,
			ClientNonce: nonce,
			Canonical:   fr.Payload,
			Offer:       authMsg,
		}
		if err := completeClientAuth(cipherConn, a, ch, reply); err != nil {
			_ = cipherConn.Close()
			return nil, none, err
		}
		reply, err = cipherConn.ReadFrame()
		if err != nil {
			_ = cipherConn.Close()
			return nil, none, fmt.Errorf("read HELLO_OK: %w", err)
		}
	}
	_ = cipherConn.SetDeadline(time.Time{})
	if reply.Type == proto.TypeErr {
		_ = cipherConn.Close()
		var fail proto.Fail
		_ = proto.UnmarshalPayload(reply, &fail)
		return nil, none, proto.NewError(fail.Code, fail.Msg)
	}
	if reply.Type != proto.TypeHelloOK {
		_ = cipherConn.Close()
		return nil, none, proto.NewError(proto.CodeProto, "expected HELLO_OK, got "+reply.Type.String())
	}
	var ok proto.HelloOK
	if err := proto.UnmarshalPayload(reply, &ok); err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}
	if ok.V != 1 {
		_ = cipherConn.Close()
		return nil, none, proto.ErrVersion
	}
	// Option A Clean Phase Cut: return the unencrypted underlying conn
	return cipherConn.Underlying(), ok, nil
}

func completeClientAuth(conn transport.Conn, a auth.Authenticator, ch auth.Challenge, reply proto.Frame) error {
	var ok proto.AuthOK
	if err := proto.UnmarshalPayload(reply, &ok); err != nil {
		return err
	}
	// AUTH_OK.destination is a check, not an input. Adopt it only when the
	// client omitted dest (server default). A non-empty client dest must match
	// so a MITM cannot make us sign a host we did not request.
	if ch.Destination != "" {
		if ok.Destination != ch.Destination {
			return proto.NewError(proto.CodeAuth, "challenge mismatch")
		}
	} else {
		ch.Destination = ok.Destination
	}
	ch.SessionID = ok.SessionID
	ch.ServerNonce = ok.ServerNonce
	digest := auth.DeriveChallenge(ch)
	want, err := base64.StdEncoding.DecodeString(ok.Challenge)
	if err != nil || len(want) != sha256.Size || !bytes.Equal(digest, want) {
		return proto.NewError(proto.CodeAuth, "challenge mismatch")
	}
	ch.Digest = digest
	resp, err := a.Sign(ch)
	if err != nil {
		return err
	}
	return conn.WriteFrame(proto.Frame{Type: proto.TypeAuth, Payload: []byte(resp)})
}

func clientResume(ctx context.Context, cfg config.Client, sessionID, token string, downAcked uint64) (transport.Conn, proto.ResumeOK, error) {
	return clientResumeRole(ctx, cfg, sessionID, token, downAcked, "")
}

func clientResumeRole(ctx context.Context, cfg config.Client, sessionID, token string, downAcked uint64, role string) (transport.Conn, proto.ResumeOK, error) {
	return clientResumeHook(ctx, cfg, sessionID, token, downAcked, role, nil)
}

func resumeDialAddr(cfg config.Client) (addr, fp string) {
	addr, fp = cfg.Server, cfg.ServerFingerprint
	if hops, err := config.ParseJumphost(cfg.Jumphost); err == nil && len(hops) > 0 {
		addr = hops[0].Addr
		if hops[0].Fp != "" {
			fp = hops[0].Fp
		}
	}
	return addr, fp
}

func clientResumeHook(ctx context.Context, cfg config.Client, sessionID, token string, downAcked uint64, role string, onChallenge resumeChallengeFn) (transport.Conn, proto.ResumeOK, error) {
	var none proto.ResumeOK
	tcpBind := transport.BindConfig{
		Interface: cfg.TCPInterface,
		SourceIP:  net.ParseIP(cfg.TCPSourceIP),
	}
	addr, _ := resumeDialAddr(cfg)
	var conn transport.Conn
	var err error
	if cfg.IsWS() {
		wsOpts := &transport.WebSocketDialOptions{
			Bind:      tcpBind,
			Timeout:   handshakeTimeout,
			TLSConfig: &tls.Config{InsecureSkipVerify: cfg.TLSInsecure},
		}
		conn, err = transport.DialWebSocket(ctx, addr, wsOpts)
	} else {
		conn, err = transport.DialTCPWithDelayAndBind(ctx, addr, cfg.HappyEyeballsDelay.Duration(), tcpBind)
	}
	if err != nil {
		return nil, none, err
	}
	ok, err := writeResumeRoleHook(ctx, conn, cfg, sessionID, token, downAcked, role, onChallenge)
	if err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	return conn, ok, nil
}

func parseBackoff(ss []string) []time.Duration {
	out := make([]time.Duration, 0, len(ss))
	for _, s := range ss {
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 {
			continue
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return []time.Duration{100 * time.Millisecond}
	}
	return out
}

func sleepBackoff(ctx context.Context, schedule []time.Duration, attempt int, deadline time.Time) error {
	if time.Now().After(deadline) {
		return context.DeadlineExceeded
	}
	var d time.Duration
	if len(schedule) == 0 {
		d = 100 * time.Millisecond
	} else if attempt >= len(schedule) {
		d = schedule[len(schedule)-1]
	} else if attempt >= 0 {
		d = schedule[attempt]
	}
	if d > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(d)+1))
		if err == nil {
			d = time.Duration(n.Int64())
		}
	}
	remain := time.Until(deadline)
	if remain <= 0 {
		return context.DeadlineExceeded
	}
	if d > remain {
		d = remain
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func deadlineOr(ctx context.Context, d time.Duration) time.Time {
	t := time.Now().Add(d)
	if abs, ok := ctx.Deadline(); ok && abs.Before(t) {
		return abs
	}
	return t
}

func checkStrictUDPProbe(ctx context.Context, cfg config.Client, conn transport.Conn, udp *proto.UdpInfo) error {
	if cfg.AllowHA || cfg.IsTCP() || cfg.IsWS() || testGateUpgrade.Load() != nil || conn == nil || conn.Kind() != transport.KindTCP || udp == nil {
		return nil
	}
	attempts := udp.ProbeAttempts
	timeout := time.Duration(udp.ProbeTimeoutMs) * time.Millisecond
	if cfg.ProbeTimeout.Duration() > 0 && (timeout <= 0 || cfg.ProbeTimeout.Duration() < timeout) {
		timeout = cfg.ProbeTimeout.Duration()
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	tok, ok := transport.ParseProbeToken(udp.ProbeToken)
	if !ok {
		return proto.NewError(proto.CodeProto, "bad probe token")
	}
	happyDelay := cfg.HappyEyeballsDelay.Duration()
	if happyDelay <= 0 {
		happyDelay = transport.DefaultConnectionAttemptDelay
	}
	udpBind := transport.BindConfig{
		Interface: cfg.UDPInterface,
		SourceIP:  net.ParseIP(cfg.UDPSourceIP),
	}
	mux, _, err := probeUDPDualStack(ctx, udp.Addr, tok, attempts, timeout, happyDelay, udpBind)
	if mux != nil {
		_ = mux.Close()
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("udp route unavailable and --allow-ha not specified: %w", err)
	}
	return nil
}
