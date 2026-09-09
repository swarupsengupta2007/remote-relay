package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

var testFailQUICDial atomic.Bool
var testGateUpgrade atomic.Pointer[chan struct{}]
var testDropUDPProbe atomic.Bool

func probeUDP(ctx context.Context, mux *transport.UDPMux, addr net.Addr, tok [16]byte, attempts int, timeout time.Duration) error {
	if testDropUDPProbe.Load() {
		return errors.New("udp probe timeout")
	}
	return transport.Probe(ctx, mux, addr, tok, attempts, timeout)
}

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
	if target != "quic" && target != "kcp" {
		return nil, nop
	}
	upgCtx, cancel := context.WithCancel(ctx)
	ch := make(chan upgradeResult, 1)
	go func() {
		if g := testGateUpgrade.Load(); g != nil {
			select {
			case <-*g:
			case <-upgCtx.Done():
				ch <- upgradeResult{err: upgCtx.Err()}
				return
			}
		}
		ch <- tryUpgrade(upgCtx, p, cfg, tcpConn, sessionID, token, target, udp, log)
	}()
	return ch, cancel
}

func takeUpgrade(ch <-chan upgradeResult, cancel context.CancelFunc, p *pump) upgradeResult {
	if ch == nil {
		return upgradeResult{}
	}
	if p.upgrading.Load() {
		defer p.upgrading.Store(false)
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

func tryUpgrade(ctx context.Context, p *pump, cfg config.Client, tcpConn transport.Conn, sessionID, token, target string, udp *proto.UdpInfo, log *slog.Logger) (res upgradeResult) {
	tok, ok := transport.ParseProbeToken(udp.ProbeToken)
	if !ok {
		res.err = proto.NewError(proto.CodeProto, "bad probe token")
		if !cfg.AllowHA {
			p.fail(res.err)
			_ = tcpConn.Close()
		}
		return res
	}
	addr, err := net.ResolveUDPAddr("udp", udp.Addr)
	if err != nil {
		res.err = err
		if !cfg.AllowHA {
			p.fail(err)
			_ = tcpConn.Close()
		}
		return res
	}
	mux, err := transport.ListenUDPMux(transport.UDPBindAll(addr))
	if err != nil {
		res.err = err
		if !cfg.AllowHA {
			p.fail(err)
			_ = tcpConn.Close()
		}
		return res
	}
	cleanup := true
	defer func() {
		if cleanup && mux != nil {
			_ = mux.Close()
		}
	}()

	attempts := udp.ProbeAttempts
	timeout := time.Duration(udp.ProbeTimeoutMs) * time.Millisecond
	if cfg.ProbeTimeout.Duration() > 0 && (timeout <= 0 || cfg.ProbeTimeout.Duration() < timeout) {
		timeout = cfg.ProbeTimeout.Duration()
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if ctx.Err() != nil {
		res.err = ctx.Err()
		return res
	}
	firstErr := probeUDP(ctx, mux, addr, tok, attempts, timeout)
	if firstErr != nil {
		if errors.Is(firstErr, context.Canceled) || ctx.Err() != nil {
			res.err = firstErr
			return res
		}
		if !cfg.AllowHA {
			if log != nil {
				log.Error("udp probe failed and --allow-ha not specified", "err", firstErr)
			}
			failErr := fmt.Errorf("udp route unavailable and --allow-ha not specified: %w", firstErr)
			p.fail(failErr)
			_ = tcpConn.Close()
			res.err = failErr
			return res
		}
		if log != nil {
			log.Info("udp probe failed; operating on tcp in HA mode", "err", firstErr)
		}
	}

	interval := cfg.HAProbeInterval.Duration()
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if firstErr != nil {
			select {
			case <-ctx.Done():
				res.err = ctx.Err()
				return res
			case <-p.sessCtx.Done():
				res.err = p.sessCtx.Err()
				return res
			case <-ticker.C:
				if err := probeUDP(ctx, mux, addr, tok, attempts, timeout); err != nil {
					if log != nil {
						log.Debug("ha udp probe attempt failed", "err", err)
					}
					continue
				}
				if log != nil {
					log.Info("udp route became available; initiating HA upgrade")
				}
			}
		}
		firstErr = nil

		st := p.cfg.switchTimeout
		up, down, err := p.waitQuiesced(ctx, st)
		if err != nil {
			if log != nil {
				log.Info("path switch aborted; staying on tcp", "err", err)
			}
			if !cfg.AllowHA {
				res.err = err
				return res
			}
			firstErr = err
			continue
		}

		p.upgrading.Store(true)

		if testFailQUICDial.Load() && target != "kcp" {
			p.upgrading.Store(false)
			p.abortQuiesce()
			res.err = errors.New("test: quic dial fail")
			if !cfg.AllowHA {
				return res
			}
			firstErr = res.err
			continue
		}

		var uconn transport.Conn
		if target == "kcp" {
			uconn, err = transport.DialKCP(ctx, mux.KCP(), addr)
		} else {
			qconf := transport.NewQUICConfig(p.cfg.idle, p.cfg.keepalive, p.cfg.window)
			uconn, err = transport.DialQUIC(ctx, mux.QUIC(), addr, qconf)
		}
		if err != nil {
			p.upgrading.Store(false)
			p.abortQuiesce()
			if log != nil {
				log.Info("udp dial failed; staying on tcp", "err", err)
			}
			if !cfg.AllowHA {
				res.err = err
				return res
			}
			_ = mux.Close()
			mux, err = transport.ListenUDPMux(transport.UDPBindAll(addr))
			if err != nil {
				res.err = err
				return res
			}
			firstErr = err
			continue
		}
		if err := p.sendSwitch(ctx, proto.Switch{
			Dir:    proto.DirBoth,
			From:   "tcp",
			Offset: proto.SwitchOffset{Up: up, Down: down},
		}); err != nil {
			p.upgrading.Store(false)
			_ = uconn.Close()
			p.abortQuiesce()
			res.err = err
			return res
		}
		rok, err := writeResumeOn(ctx, uconn, cfg, sessionID, token, p.delivered.Load())
		if err != nil {
			p.upgrading.Store(false)
			_ = uconn.Close()
			p.abortQuiesce()
			if log != nil {
				log.Info("udp resume failed; staying on tcp", "err", err)
			}
			if !cfg.AllowHA {
				res.err = err
				return res
			}
			_ = mux.Close()
			mux, err = transport.ListenUDPMux(transport.UDPBindAll(addr))
			if err != nil {
				res.err = err
				return res
			}
			firstErr = err
			continue
		}
		cleanup = false
		_ = tcpConn.Close()
		res.conn = uconn
		res.rok = rok
		res.hold = mux
		return res
	}
}

func writeResumeOn(ctx context.Context, conn transport.Conn, cfg config.Client, sessionID, token string, downAcked uint64) (proto.ResumeOK, error) {
	return writeResumeRole(ctx, conn, cfg, sessionID, token, downAcked, "")
}

func writeResumeRole(ctx context.Context, conn transport.Conn, cfg config.Client, sessionID, token string, downAcked uint64, role string) (proto.ResumeOK, error) {
	var none proto.ResumeOK
	nonce, err := proto.RandomNonce()
	if err != nil {
		return none, err
	}
	a := clientAuth(cfg)
	trans := cfg.TransportPreference()
	if role == "standby" {
		trans = []string{"tcp"}
	}
	msg := proto.Resume{
		V:           1,
		SessionID:   sessionID,
		ResumeToken: token,
		Transport:   trans,
		DownAcked:   downAcked,
		ClientNonce: nonce,
		Role:        role,
	}
	if a.RequiresChallenge() {
		offer, err := a.Respond(auth.Challenge{Destination: cfg.Destination, ClientNonce: nonce})
		if err != nil {
			return none, err
		}
		msg.Auth = offer
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
	if err != nil {
		_ = conn.SetDeadline(time.Time{})
		return none, err
	}
	if reply.Type == proto.TypeAuthOK {
		ch := auth.Challenge{
			SessionID:   sessionID,
			Destination: cfg.Destination,
			ClientNonce: nonce,
			Canonical:   fr.Payload,
			Offer:       msg.Auth,
		}
		if err := completeClientAuth(conn, a, ch, reply); err != nil {
			_ = conn.SetDeadline(time.Time{})
			return none, err
		}
		reply, err = conn.ReadFrame()
		if err != nil {
			_ = conn.SetDeadline(time.Time{})
			return none, err
		}
	}
	_ = conn.SetDeadline(time.Time{})
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
