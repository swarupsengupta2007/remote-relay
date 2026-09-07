package relay

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

const switchTimeout = 5 * time.Second

type upgradeResult struct {
	conn transport.Conn
	rok  proto.ResumeOK
	hold io.Closer
	err  error
}

func startUpgrade(ctx context.Context, p *pump, cfg config.Client, tcpConn transport.Conn, sessionID, token, target string, udp *proto.UdpInfo, log *slog.Logger) (<-chan upgradeResult, context.CancelFunc) {
	nop := func() {}
	if udp == nil || tcpConn == nil || tcpConn.Kind() != transport.KindTCP {
		return nil, nop
	}
	if target != "quic" {
		return nil, nop
	}
	upgCtx, cancel := context.WithCancel(ctx)
	ch := make(chan upgradeResult, 1)
	go func() {
		ch <- tryUpgrade(upgCtx, p, cfg, tcpConn, sessionID, token, udp, log)
	}()
	return ch, cancel
}

func takeUpgrade(ch <-chan upgradeResult, cancel context.CancelFunc, p *pump) upgradeResult {
	if ch == nil {
		return upgradeResult{}
	}
	if p.upgrading.Load() {
		return <-ch
	}
	select {
	case res := <-ch:
		return res
	default:
		cancel()
		return <-ch
	}
}

func tryUpgrade(ctx context.Context, p *pump, cfg config.Client, tcpConn transport.Conn, sessionID, token string, udp *proto.UdpInfo, log *slog.Logger) (res upgradeResult) {
	tok, ok := transport.ParseProbeToken(udp.ProbeToken)
	if !ok {
		res.err = proto.NewError(proto.CodeProto, "bad probe token")
		return res
	}
	addr, err := net.ResolveUDPAddr("udp", udp.Addr)
	if err != nil {
		res.err = err
		return res
	}
	mux, err := transport.ListenUDPMux(clientUDPBind(cfg.Server))
	if err != nil {
		res.err = err
		return res
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = mux.Close()
		}
	}()

	attempts := udp.ProbeAttempts
	timeout := time.Duration(udp.ProbeTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = cfg.ProbeTimeout.Duration()
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if err := transport.Probe(ctx, mux, addr, tok, attempts, timeout); err != nil {
		if log != nil {
			log.Info("udp probe failed; staying on tcp")
		}
		res.err = err
		return res
	}

	st := switchTimeout
	if st <= 0 {
		st = 5 * time.Second
	}
	up, down, err := p.waitQuiesced(ctx, st)
	if err != nil {
		if log != nil {
			log.Info("path switch aborted; staying on tcp")
		}
		res.err = err
		return res
	}
	fr, err := proto.MarshalFrame(proto.TypeSwitch, proto.Switch{
		Dir:    proto.DirBoth,
		From:   "tcp",
		Offset: proto.SwitchOffset{Up: up, Down: down},
	})
	if err != nil {
		p.abortQuiesce()
		res.err = err
		return res
	}
	if err := p.sendCtrl(fr); err != nil {
		p.abortQuiesce()
		res.err = err
		return res
	}

	p.upgrading.Store(true)
	defer p.upgrading.Store(false)

	qconf := transport.NewQUICConfig(p.cfg.idle, p.cfg.keepalive, p.cfg.window)
	qconn, err := transport.DialQUIC(ctx, mux.QUIC(), addr, qconf)
	if err != nil {
		p.abortQuiesce()
		res.err = err
		return res
	}
	rok, err := writeResumeOn(ctx, qconn, cfg, sessionID, token, p.delivered.Load())
	if err != nil {
		_ = qconn.Close()
		p.abortQuiesce()
		res.err = err
		return res
	}
	cleanup = false
	_ = tcpConn.Close()
	res.conn = qconn
	res.rok = rok
	res.hold = mux
	return res
}

func clientUDPBind(server string) string {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return "0.0.0.0:0"
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		return "0.0.0.0:0"
	}
	return "[::]:0"
}

func writeResumeOn(ctx context.Context, conn transport.Conn, cfg config.Client, sessionID, token string, downAcked uint64) (proto.ResumeOK, error) {
	var none proto.ResumeOK
	nonce, err := proto.RandomNonce()
	if err != nil {
		return none, err
	}
	msg := proto.Resume{
		V:           1,
		SessionID:   sessionID,
		ResumeToken: token,
		Transport:   cfg.TransportPreference(),
		DownAcked:   downAcked,
		ClientNonce: nonce,
	}
	fr, err := proto.MarshalFrame(proto.TypeResume, msg)
	if err != nil {
		return none, err
	}
	if err := conn.SetDeadline(deadlineOr(ctx, handshakeTimeout)); err != nil {
		return none, err
	}
	if err := conn.WriteFrame(fr); err != nil {
		_ = conn.SetDeadline(time.Time{})
		return none, err
	}
	reply, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return none, err
	}
	switch reply.Type {
	case proto.TypeResumeFail, proto.TypeErr:
		var fail proto.Fail
		_ = proto.UnmarshalPayload(reply, &fail)
		if fail.Code == "" {
			fail.Code = proto.CodeInternal
		}
		return none, proto.NewError(fail.Code, fail.Msg)
	case proto.TypeResumeOK:
	default:
		return none, proto.NewError(proto.CodeProto, "expected RESUME_OK, got "+reply.Type.String())
	}
	var ok proto.ResumeOK
	if err := proto.UnmarshalPayload(reply, &ok); err != nil {
		return none, err
	}
	if ok.V != 1 {
		return none, proto.ErrVersion
	}
	return ok, nil
}
