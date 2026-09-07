package relay

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
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
	if cfg.Transport != "tcp" {
		log.Warn("UDP upgrade is not built yet; staying on TCP", "requested", cfg.Transport)
	}

	conn, helloOK, err := clientHello(ctx, cfg)
	if err != nil {
		return err
	}
	log = logging.WithSession(log, helloOK.SessionID)
	log.Info("session established", "transport", "tcp")

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
	p := newPump(ctx, sessionIO{
		conn:      conn,
		src:       src,
		sink:      bw,
		flushSink: bw.Flush,
		closeSrc:  func() error { stopSrc(); return nil },
		outDir:    proto.DirUp,
		inDir:     proto.DirDown,
	}, pumpConfig{
		chunk:     chunk,
		window:    window,
		buffer:    bufCap,
		keepalive: 5 * time.Second,
		idle:      30 * time.Second,
		log:       log,
	}, sendLog)
	p.startIO()
	defer p.shutdown()

	err = p.serveConn(p.sessCtx, conn, 0)
	if se := p.sessionErr(); se != nil {
		return se
	}
	if !reconnectable(err) {
		return p.classify(err)
	}

	token := helloOK.ResumeToken
	sessionID := helloOK.SessionID
	schedule := parseBackoff(cfg.ReconnectBackoff)
	maxElapsed := cfg.ReconnectMaxElapsed.Duration()
	if maxElapsed <= 0 {
		maxElapsed = 5 * time.Minute
	}
	if helloOK.Limits.HoldTimeoutMs > 0 {
		hold := time.Duration(helloOK.Limits.HoldTimeoutMs) * time.Millisecond
		if hold > 0 && hold < maxElapsed {
			maxElapsed = hold
		}
	}

	for reconnectable(err) {
		deadline := time.Now().Add(maxElapsed)
		attempt := 0
		resumed := false
		for reconnectable(err) && time.Now().Before(deadline) {
			nconn, rok, rerr := clientResume(ctx, cfg, sessionID, token, p.delivered.Load())
			if rerr != nil {
				if !reconnectable(rerr) {
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
			if rok.State.UpClosed && !p.outEOF.Load() {
				p.outFinal.Store(p.sendLog.End())
				p.outEOF.Store(true)
				p.sendLog.Close()
			}
			p.sendLog.AdvanceTo(rok.UpAcked)
			err = p.serveConn(p.sessCtx, nconn, rok.UpAcked)
			if se := p.sessionErr(); se != nil {
				return se
			}
			resumed = true
			break
		}
		if resumed && reconnectable(err) {
			continue
		}
		if reconnectable(err) {
			return fmt.Errorf("reconnect budget exhausted: %w", err)
		}
		return p.classify(err)
	}
	return p.classify(err)
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

func clientHello(ctx context.Context, cfg config.Client) (transport.Conn, proto.HelloOK, error) {
	var none proto.HelloOK
	conn, err := transport.DialTCP(ctx, cfg.Server)
	if err != nil {
		return nil, none, fmt.Errorf("dial server: %w", err)
	}
	authMsg, err := auth.None{}.Respond(auth.Challenge{Destination: cfg.Destination})
	if err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	nonce, err := proto.RandomNonce()
	if err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	hello := proto.Hello{
		V:           1,
		SessionID:   "",
		ResumeToken: "",
		Transport:   []string{"tcp"},
		Destination: cfg.Destination,
		ClientNonce: nonce,
		Auth:        authMsg,
		Window:      cfg.SendWindow,
	}
	if cfg.Transport != "" && cfg.Transport != "tcp" {
		hello.Transport = []string{cfg.Transport, "tcp"}
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

func clientResume(ctx context.Context, cfg config.Client, sessionID, token string, downAcked uint64) (transport.Conn, proto.ResumeOK, error) {
	var none proto.ResumeOK
	conn, err := transport.DialTCP(ctx, cfg.Server)
	if err != nil {
		return nil, none, err
	}
	nonce, err := proto.RandomNonce()
	if err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	msg := proto.Resume{
		V:           1,
		SessionID:   sessionID,
		ResumeToken: token,
		Transport:   []string{"tcp"},
		DownAcked:   downAcked,
		ClientNonce: nonce,
	}
	fr, err := proto.MarshalFrame(proto.TypeResume, msg)
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
		return nil, none, err
	}
	reply, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	switch reply.Type {
	case proto.TypeResumeFail, proto.TypeErr:
		_ = conn.Close()
		var fail proto.Fail
		_ = proto.UnmarshalPayload(reply, &fail)
		if fail.Code == "" {
			fail.Code = proto.CodeInternal
		}
		return nil, none, proto.NewError(fail.Code, fail.Msg)
	case proto.TypeResumeOK:
	default:
		_ = conn.Close()
		return nil, none, proto.NewError(proto.CodeProto, "expected RESUME_OK, got "+reply.Type.String())
	}
	var ok proto.ResumeOK
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
