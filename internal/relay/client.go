package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/remote-relay/relay/internal/config"
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
			break
		}
		if (!reconnectable(err) && !errors.Is(err, context.DeadlineExceeded)) || time.Now().After(helloDeadline) || ctx.Err() != nil {
			return err
		}
		log.Debug("handshake failed, retrying", "attempt", attempt, "err", err)
		if serr := sleepBackoff(ctx, schedule, attempt, helloDeadline); serr != nil {
			return err
		}
		attempt++
	}
	log = logging.WithSession(log, helloOK.SessionID)
	if !cfg.AllowHA && !cfg.IsTCP() && (helloOK.Transport == "tcp" || helloOK.UDP == nil) {
		_ = conn.Close()
		return fmt.Errorf("udp route unavailable and --allow-ha not specified: server does not provide udp transport")
	}
	if err := checkStrictUDPProbe(ctx, cfg, conn, helloOK.UDP); err != nil {
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
		log:           log,
	}, sendLog)
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

	for {
		upgCh, upgCancel := startUpgrade(ctx, p, cfg, current, sessionID, token, target, udp, log)
		err = p.serveConn(p.sessCtx, current, sendFrom)
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
			continue
		}
		if upg.hold != nil {
			_ = upg.hold.Close()
		}

		if se := p.sessionErr(); se != nil {
			return se
		}
		if !reconnectable(err) {
			return p.classify(err)
		}

		deadline := time.Now().Add(maxElapsed)
		attempt := 0
		resumed := false
		for reconnectable(err) && time.Now().Before(deadline) {
			dialCtx, dialCancel := context.WithDeadline(ctx, deadline)
			nconn, rok, rerr := clientResume(dialCtx, cfg, sessionID, token, p.delivered.Load())
			dialCancel()
			if rerr != nil {
				if !reconnectable(rerr) && !errors.Is(rerr, context.DeadlineExceeded) {
					return rerr
				}
				err = rerr
				if serr := sleepBackoff(ctx, schedule, attempt, deadline); serr != nil {
					break
				}
				attempt++
				continue
			}
			token = rok.ResumeToken
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
			if !cfg.AllowHA && !cfg.IsTCP() && (target == "tcp" || udp == nil) {
				_ = nconn.Close()
				return fmt.Errorf("udp route unavailable and --allow-ha not specified: server does not provide udp transport")
			}
			if err := checkStrictUDPProbe(ctx, cfg, nconn, udp); err != nil {
				_ = nconn.Close()
				return err
			}
			current = nconn
			sendFrom = rok.UpAcked
			resumed = true
			log.Info("session resumed", "transport", current.Kind().String())
			break
		}
		if resumed {
			continue
		}
		if reconnectable(err) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("reconnect budget exhausted: %w", err)
		}
		return p.classify(err)
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
	})
}

func clientHello(ctx context.Context, cfg config.Client) (transport.Conn, proto.HelloOK, error) {
	var none proto.HelloOK
	conn, err := transport.DialTCP(ctx, cfg.Server)
	if err != nil {
		return nil, none, fmt.Errorf("dial server: %w", err)
	}
	a := clientAuth(cfg)
	nonce, err := proto.RandomNonce()
	if err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	authMsg, err := a.Respond(auth.Challenge{Destination: cfg.Destination, ClientNonce: nonce})
	if err != nil {
		_ = conn.Close()
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
		_ = conn.Close()
		return nil, none, err
	}
	if err := conn.SetDeadline(deadlineOr(ctx, handshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	if err := conn.WriteFrame(fr); err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("send HELLO: %w", err)
	}
	if err := conn.SetDeadline(deadlineOr(ctx, handshakeTimeout+config.DefaultServer().DialTimeout.Duration())); err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	reply, err := conn.ReadFrame()
	if err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("read HELLO_OK: %w", err)
	}
	if reply.Type == proto.TypeAuthOK {
		ch := auth.Challenge{
			Destination: cfg.Destination,
			ClientNonce: nonce,
			Canonical:   fr.Payload,
			Offer:       authMsg,
		}
		if err := completeClientAuth(conn, a, ch, reply); err != nil {
			_ = conn.Close()
			return nil, none, err
		}
		reply, err = conn.ReadFrame()
		if err != nil {
			_ = conn.Close()
			return nil, none, fmt.Errorf("read HELLO_OK: %w", err)
		}
	}
	_ = conn.SetDeadline(time.Time{})
	if reply.Type == proto.TypeErr {
		_ = conn.Close()
		var fail proto.Fail
		_ = proto.UnmarshalPayload(reply, &fail)
		return nil, none, proto.NewError(fail.Code, fail.Msg)
	}
	if reply.Type != proto.TypeHelloOK {
		_ = conn.Close()
		return nil, none, proto.NewError(proto.CodeProto, "expected HELLO_OK, got "+reply.Type.String())
	}
	var ok proto.HelloOK
	if err := proto.UnmarshalPayload(reply, &ok); err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	if ok.V != 1 {
		_ = conn.Close()
		return nil, none, proto.ErrVersion
	}
	return conn, ok, nil
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
	var none proto.ResumeOK
	conn, err := transport.DialTCP(ctx, cfg.Server)
	if err != nil {
		return nil, none, err
	}
	ok, err := writeResumeOn(ctx, conn, cfg, sessionID, token, downAcked)
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
	if cfg.AllowHA || cfg.IsTCP() || testGateUpgrade.Load() != nil || conn == nil || conn.Kind() != transport.KindTCP || udp == nil {
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
	addr, err := net.ResolveUDPAddr("udp", udp.Addr)
	if err != nil {
		return err
	}
	mux, err := transport.ListenUDPMux(transport.UDPBindAll(addr))
	if err != nil {
		return err
	}
	defer func() { _ = mux.Close() }()
	if err := probeUDP(ctx, mux, addr, tok, attempts, timeout); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			return err
		}
		return fmt.Errorf("udp route unavailable and --allow-ha not specified: %w", err)
	}
	return nil
}
