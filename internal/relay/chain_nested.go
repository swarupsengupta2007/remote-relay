package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/config"
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
	limits      proto.Limits
	holdTimeout time.Duration

	mu      sync.Mutex
	conn    transport.Conn
	termErr error

	cancel   context.CancelFunc
	once     sync.Once
	pumpOnce sync.Once
	onGone   func(error)
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
		if n.cancel != nil {
			n.cancel()
		}
		// A clean finish closes with io.EOF semantics so the inbound pump's
		// srcReader reports a real end-of-stream; an abnormal one propagates
		// errChainGone so the inbound session fails instead of emitting a
		// CLOSE_DIR that never happened.
		err := n.termError()
		_ = n.toOnwardW.CloseWithError(err)
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
		keepalive:     n.srv.cfg.KeepaliveInterval.Duration(),
		idle:          n.srv.cfg.IdleTimeout.Duration(),
		switchTimeout: switchTimeout,
		heartbeat:     n.srv.cfg.HeartbeatInterval.Duration(),
		deadThreshold: n.srv.cfg.DeadPeerThreshold,
		log:           n.log,
		splice:        false,
	}, sendLog)

	go n.run(ctx, n.takeConn())
}

// run drives the onward carrier. The retry budget is clamped to the hold
// timeout the next hop advertised, so this leg gives up at the same moment the
// peer stops holding the session (mirrors client.go:139-144).
func (n *nestedHop) run(ctx context.Context, first transport.Conn) {
	n.pump.startIO()
	schedule := parseBackoff(n.resumeCfg.ReconnectBackoff)
	maxElapsed := n.holdTimeout
	if maxElapsed <= 0 {
		maxElapsed = 5 * time.Minute
	}

	conn := first
	sendFrom := uint64(0)
	err := n.pump.serveConn(ctx, conn, sendFrom)

	for reconnectable(err) && ctx.Err() == nil && n.pump.sessionErr() == nil {
		deadline := time.Now().Add(maxElapsed)
		attempt := 0
		resumed := false
		for reconnectable(err) && time.Now().Before(deadline) && ctx.Err() == nil {
			dialCtx, cancel := context.WithDeadline(ctx, deadline)
			nconn, rok, rerr := clientResume(dialCtx, n.resumeCfg, n.sessionID, n.token, n.pump.delivered.Load())
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
			n.token = rok.ResumeToken
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
	// classify() maps a clean BYE and a cancelled parent context to nil, so a
	// session that ended normally does not take the inbound leg down with it.
	n.setTermError(n.pump.classify(err))
	if n.onGone != nil {
		n.onGone(n.termError())
	}
}
