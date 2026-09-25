package relay

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/crypto/kex"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/session"
	"github.com/remote-relay/relay/internal/transport"
)

// nestedHop is the onward leg of a chained session at an intermediate relay.
//
// It presents itself to the inbound pump through the sessionIO seam
// (pump.go:33-44), so the pump's goroutine model is untouched (plan §2.1): the
// inbound pump's sink is a pipe this hop reads from, and its src is a pipe this
// hop writes to. Both directions are ordinary in-memory streams, which is why
// splice(2) cannot apply to a nested leg (J-D13).
type nestedHop struct {
	srv       *Server
	log       *slog.Logger
	hop       proto.HopSpec
	dest      string
	chainID   string
	resumeCfg config.Client

	// toOnward carries bytes from the originator toward the terminal; fromOnward
	// carries them back. io.Pipe is unbuffered, so nothing is stranded in the
	// bridge at teardown: a byte is either already in one of the two rings or
	// still in the writer's hands.
	toOnwardR   *io.PipeReader
	toOnwardW   *io.PipeWriter
	fromOnwardR *io.PipeReader
	fromOnwardW *io.PipeWriter

	pump *pump

	sessionID   string
	token       string
	transport   string
	udp         *proto.UdpInfo
	limits      proto.Limits
	holdTimeout time.Duration

	mu      sync.Mutex
	conn    transport.Conn
	termErr error

	cancel   context.CancelFunc
	once     sync.Once
	pumpOnce sync.Once
	onGone   func(error)

	inbound  *live
	hopIndex int

	chainHello proto.ChainHello
	selfAddr   string
	originIP   string
	startBuf   int
	startChunk int
	startWin   int
	startSw    time.Duration
	parentCtx  context.Context
	runDone    chan struct{}
}

func newNestedHop(srv *Server, log *slog.Logger, hop proto.HopSpec, dest, chainID string, resumeCfg config.Client) *nestedHop {
	toR, toW := io.Pipe()
	fromR, fromW := io.Pipe()
	return &nestedHop{
		srv:         srv,
		log:         log,
		hop:         hop,
		dest:        dest,
		chainID:     chainID,
		resumeCfg:   resumeCfg,
		toOnwardR:   toR,
		toOnwardW:   toW,
		fromOnwardR: fromR,
		fromOnwardW: fromW,
	}
}

func (n *nestedHop) setConn(c transport.Conn) {
	n.mu.Lock()
	n.conn = c
	n.mu.Unlock()
}

func (n *nestedHop) takeConn() transport.Conn {
	n.mu.Lock()
	c := n.conn
	n.mu.Unlock()
	return c
}

func (n *nestedHop) closeConn() {
	n.mu.Lock()
	c := n.conn
	n.conn = nil
	n.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (n *nestedHop) setTermError(err error) {
	n.mu.Lock()
	if n.termErr == nil {
		n.termErr = err
	}
	n.mu.Unlock()
}

func (n *nestedHop) termError() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.termErr
}

// close tears the onward leg down. It is safe to call from either pump's
// teardown path and from the nested runner; the Once makes the mutual
// recursion between the two pumps' closeSrc hooks terminate.
func (n *nestedHop) close() {
	n.once.Do(func() {
		// EOF the originator→terminal pipe first so the nested netWriter can
		// flush bytes already ACKed on hop-1 (JR3) before we cancel the runner.
		err := n.termError()
		_ = n.toOnwardW.CloseWithError(err)
		if n.pump != nil && n.pump.linkUp.Load() && n.pump.sendLog != nil {
			deadline := time.Now().Add(5 * time.Second)
			for n.pump.sendLog.Len() > 0 && n.pump.linkUp.Load() && time.Now().Before(deadline) {
				time.Sleep(2 * time.Millisecond)
			}
		}
		if n.cancel != nil {
			n.cancel()
		}
		_ = n.fromOnwardW.CloseWithError(err)
		_ = n.toOnwardR.Close()
		_ = n.fromOnwardR.Close()
		n.pumpOnce.Do(func() {
			if n.pump != nil {
				n.pump.shutdown()
			}
		})
		n.closeConn()
	})
}

// start builds the onward pump and runs it, including the nested resume loop
// that keeps the terminal's sshd socket alive across a carrier break on this
// leg alone (plan §2.10 Case B).
func (n *nestedHop) start(parent context.Context, bufCap, chunk, window int, switchTimeout time.Duration) {
	n.parentCtx = parent
	n.startBuf, n.startChunk, n.startWin, n.startSw = bufCap, chunk, window, switchTimeout
	ctx, cancel := context.WithCancel(parent)
	n.cancel = cancel

	sendLog := session.NewRing(bufCap, n.srv.budget)
	n.pump = newPump(ctx, sessionIO{
		conn:       n.takeConn(),
		src:        n.toOnwardR,
		sink:       n.fromOnwardW,
		closeWrite: func() error { return n.fromOnwardW.Close() },
		closeSrc:   func() error { n.closeConn(); return nil },
		outDir:     proto.DirUp,
		inDir:      proto.DirDown,
	}, pumpConfig{
		chunk:         chunk,
		window:        window,
		buffer:        bufCap,
		keepalive:     n.srv.Config().KeepaliveInterval.Duration(),
		idle:          n.srv.Config().IdleTimeout.Duration(),
		switchTimeout: switchTimeout,
		heartbeat:     n.srv.Config().HeartbeatInterval.Duration(),
		deadThreshold: n.srv.Config().DeadPeerThreshold,
		log:           n.log,
		splice:        false,
		resumeHook:    n.relayResumeChallenge,
	}, sendLog)

	n.launch(ctx)
}

// relaunch restarts the onward runner on the existing pump and pipes. Used by
// Case D rebuild so the inbound bridge is not torn down.
func (n *nestedHop) relaunch() {
	ctx, cancel := context.WithCancel(n.parentCtx)
	n.cancel = cancel
	n.launch(ctx)
}

func (n *nestedHop) launch(ctx context.Context) {
	n.runDone = make(chan struct{})
	go func() {
		defer close(n.runDone)
		n.run(ctx, n.takeConn())
	}()
}

// run drives the onward carrier. UDP upgrade runs once around the first
// serveConn when the hop advertised quic/kcp; the retry budget is clamped to
// hold_timeout. Nested splice stays off (R-D4).
func (n *nestedHop) run(ctx context.Context, first transport.Conn) {
	n.pump.startIO()
	schedule := parseBackoff(n.resumeCfg.ReconnectBackoff)
	maxElapsed := n.holdTimeout
	if maxElapsed <= 0 {
		maxElapsed = 5 * time.Minute
	}

	conn := first
	sendFrom := uint64(0)
	token := n.token
	target := n.transport
	udp := n.udp
	var udpHold io.Closer
	defer func() {
		if udpHold != nil {
			_ = udpHold.Close()
		}
	}()

	var err error
	if (target == "quic" || target == "kcp") && udp != nil {
		upgCh, upgCancel := startUpgrade(ctx, n.pump, n.resumeCfg, conn, n.sessionID, token, target, udp, n.log)
		err = n.pump.serveConn(ctx, conn, sendFrom)
		upg := takeUpgrade(upgCh, upgCancel, n.pump)
		if upg.conn != nil {
			udpHold = upg.hold
			conn = upg.conn
			n.setConn(conn)
			sendFrom = upg.rok.UpAcked
			token = upg.rok.ResumeToken
			n.token = token
			if upg.rok.UDP != nil {
				udp = upg.rok.UDP
			}
			if upg.rok.Transport != "" {
				target = upg.rok.Transport
			}
			n.pump.sendLog.AdvanceTo(sendFrom)
			err = n.pump.serveConn(ctx, conn, sendFrom)
		} else if upg.hold != nil {
			_ = upg.hold.Close()
		}
	} else {
		err = n.pump.serveConn(ctx, conn, sendFrom)
	}

	for reconnectable(err) && ctx.Err() == nil && n.pump.sessionErr() == nil {
		deadline := time.Now().Add(maxElapsed)
		attempt := 0
		resumed := false
		for reconnectable(err) && time.Now().Before(deadline) && ctx.Err() == nil {
			dialCtx, cancel := context.WithDeadline(ctx, deadline)
			nconn, rok, rerr := clientResumeHook(dialCtx, n.resumeCfg, n.sessionID, token, n.pump.delivered.Load(), "", n.relayResumeChallenge)
			cancel()
			if rerr != nil {
				if !reconnectable(rerr) && !errors.Is(rerr, context.DeadlineExceeded) {
					err = rerr
					break
				}
				err = rerr
				if serr := sleepBackoff(ctx, schedule, attempt, deadline); serr != nil {
					break
				}
				attempt++
				continue
			}
			token = rok.ResumeToken
			n.token = token
			if rok.UDP != nil {
				udp = rok.UDP
			}
			if rok.Transport != "" {
				target = rok.Transport
			}
			if rok.Limits.SwitchTimeoutMs > 0 {
				n.pump.cfg.switchTimeout = time.Duration(rok.Limits.SwitchTimeoutMs) * time.Millisecond
			}
			if rok.State.UpClosed && !n.pump.outEOF.Load() {
				n.pump.outFinal.Store(n.pump.sendLog.End())
				n.pump.outEOF.Store(true)
				n.pump.sendLog.Close()
			}
			n.pump.sendLog.AdvanceTo(rok.UpAcked)
			n.setConn(nconn)
			conn = nconn
			sendFrom = rok.UpAcked
			resumed = true
			n.log.Info("onward hop resumed", "upstream", n.hop.Addr, "upstreamSession", n.sessionID)
			break
		}
		if !resumed {
			break
		}
		err = n.pump.serveConn(ctx, conn, sendFrom)
	}

	if se := n.pump.sessionErr(); se != nil {
		err = se
	}
	n.setTermError(n.pump.classify(err))
	if n.onGone != nil {
		n.onGone(n.termError())
	}
}

func (n *nestedHop) relayResumeChallenge(aok proto.AuthOK, canonical, kexInit, kexReply []byte) (proto.Auth, error) {
	if n.inbound == nil {
		return proto.Auth{}, proto.NewError(proto.CodeAuth, "no inbound session for chain auth")
	}
	aok.Hop = n.hopIndex
	aok.HelloJSON = string(canonical)
	attest := &proto.HopAttestation{
		Addr:     n.hop.Addr,
		KexInit:  base64.StdEncoding.EncodeToString(kexInit),
		KexReply: base64.StdEncoding.EncodeToString(kexReply),
	}
	if len(kexReply) == kex.KexReplyLen {
		if line, err := kex.RawEd25519ToAuthorizedKeysLine(kexReply[48:80]); err == nil {
			attest.HostKeySSH = line
		}
	}
	aok.Attest = attest
	return n.inbound.relayChainAuth(aok)
}
