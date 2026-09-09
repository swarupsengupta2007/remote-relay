package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/remote-relay/relay/internal/bfd"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/session"
	"github.com/remote-relay/relay/internal/transport"
)

var (
	ErrDeadPeer      = errors.New("dead-peer detected: bfd timeout")
	errByeSent       = errors.New("bye sent")
	errByeReceived   = errors.New("bye received")
	errIdle          = errors.New("idle timeout")
	errTransportDown = errors.New("transport down")

	testSuppressAck atomic.Bool
)

type sessionIO struct {
	conn       transport.Conn
	src        io.Reader
	sink       io.Writer
	flushSink  func() error
	closeWrite func() error
	closeSrc   func() error
	outDir     string
	inDir      string
}

type pumpConfig struct {
	chunk         int
	window        int
	buffer        int
	keepalive     time.Duration
	idle          time.Duration
	switchTimeout time.Duration
	heartbeat     time.Duration
	deadThreshold int
	log           *slog.Logger
}

type dataFrag struct {
	data []byte
	eof  bool
}

type acker struct {
	mu    sync.Mutex
	acked uint64
	wait  chan struct{}
}

func newAcker() *acker {
	return &acker{wait: make(chan struct{})}
}

func (a *acker) Get() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.acked
}

func (a *acker) Advance(n uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n > a.acked {
		a.acked = n
		close(a.wait)
		a.wait = make(chan struct{})
	}
}

func (a *acker) WaitCh() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.wait
}

type pump struct {
	sessCtx    context.Context
	sessCancel context.CancelFunc
	io         sessionIO
	cfg        pumpConfig
	sendLog    *session.Ring

	ctrlQ    chan proto.Frame
	sinkQ    chan dataFrag
	kick     chan struct{}
	sinkKick chan struct{}
	ack      *acker

	onPeerFrame func()

	connMu           sync.Mutex
	writeMu          sync.Mutex
	conn             transport.Conn
	connCtx          context.Context
	connCancel       context.CancelFunc
	sendFrom         uint64
	bfdSession       *bfd.Session
	prefetchedFrames []proto.Frame

	outFinal   atomic.Uint64
	outEOF     atomic.Bool
	inFinal    atomic.Uint64
	inGotClose atomic.Bool
	delivered  atomic.Uint64
	expected   atomic.Uint64

	lastIn        atomic.Int64
	finished      atomic.Bool
	backpressured atomic.Bool
	linkUp        atomic.Bool

	quiesce       atomic.Bool
	quiesceSeen   atomic.Bool
	sentOff       atomic.Uint64
	upgrading     atomic.Bool
	switchUp      atomic.Uint64
	switchDown    atomic.Uint64
	quiesceParked chan struct{}
	switchWrote   chan struct{}

	srcWG  sync.WaitGroup
	sinkWG sync.WaitGroup
	ioOnce sync.Once
	cwOnce sync.Once

	fatalMu sync.Mutex
	fatal   error
}

func newPump(parent context.Context, io sessionIO, cfg pumpConfig, sendLog *session.Ring) *pump {
	if cfg.log == nil {
		cfg.log = slog.Default()
	}
	cfg.chunk = clampChunk(cfg.chunk)
	if cfg.window <= 0 {
		cfg.window = 4194304
	}
	if cfg.buffer <= 0 {
		cfg.buffer = cfg.window
	}
	if sendLog == nil {
		sendLog = session.NewRing(cfg.buffer, nil)
	}
	ctx, cancel := context.WithCancel(parent)
	p := &pump{
		sessCtx:       ctx,
		sessCancel:    cancel,
		io:            io,
		cfg:           cfg,
		sendLog:       sendLog,
		ctrlQ:         make(chan proto.Frame, 64),
		sinkQ:         make(chan dataFrag, 16),
		kick:          make(chan struct{}, 1),
		sinkKick:      make(chan struct{}, 1),
		ack:           newAcker(),
		quiesceParked: make(chan struct{}, 1),
		switchWrote:   make(chan struct{}, 1),
	}
	if p.cfg.switchTimeout <= 0 {
		p.cfg.switchTimeout = 5 * time.Second
	}
	p.lastIn.Store(time.Now().UnixNano())
	return p
}

func (p *pump) startIO() {
	p.ioOnce.Do(func() {
		p.srcWG.Add(1)
		go func() {
			defer p.srcWG.Done()
			if err := p.srcReader(); err != nil && p.sessCtx.Err() == nil {
				p.fail(err)
			}
		}()
		p.sinkWG.Add(1)
		go func() {
			defer p.sinkWG.Done()
			if err := p.sinkWriter(); err != nil && p.sessCtx.Err() == nil {
				p.fail(err)
			}
		}()
	})
}

func (p *pump) shutdown() {
	p.sessCancel()
	p.wakeSink()
	if p.io.closeSrc != nil {
		_ = p.io.closeSrc()
	}
	if p.sendLog != nil {
		p.sendLog.Release()
	}
	if p.io.closeSrc != nil {
		p.srcWG.Wait()
	}
	if p.io.closeWrite != nil {
		p.sinkWG.Wait()
	}
}

func (p *pump) fail(err error) {
	if err == nil {
		return
	}
	p.fatalMu.Lock()
	if p.fatal == nil {
		p.fatal = err
	}
	p.fatalMu.Unlock()
	p.sessCancel()
}

func (p *pump) sessionErr() error {
	p.fatalMu.Lock()
	defer p.fatalMu.Unlock()
	return p.fatal
}

func (p *pump) nudge() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func (p *pump) wakeSink() {
	select {
	case p.sinkKick <- struct{}{}:
	default:
	}
}

func (p *pump) notePeerFrame() {
	if f := p.onPeerFrame; f != nil {
		f()
	}
}

func (p *pump) dropConn() {
	p.connMu.Lock()
	c := p.conn
	cancel := p.connCancel
	p.connMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if c != nil {
		_ = c.SetDeadline(time.Now())
		_ = c.Close()
	}
}

func (p *pump) serveConn(ctx context.Context, conn transport.Conn, sendFrom uint64) error {
	return p.serveConnWithBFD(ctx, conn, sendFrom, nil, nil)
}

func (p *pump) serveConnWithBFD(ctx context.Context, conn transport.Conn, sendFrom uint64, existingBFD *bfd.Session, prefetched []proto.Frame) (err error) {
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	bfdSess := existingBFD
	if bfdSess == nil {
		bfdCfg := bfd.Config{
			DesiredMinTxInterval:  p.cfg.heartbeat,
			RequiredMinRxInterval: p.cfg.heartbeat,
			DetectMultiplier:      uint8(p.cfg.deadThreshold),
		}
		var err error
		bfdSess, err = bfd.NewSession(bfdCfg)
		if err != nil {
			return err
		}
	}

	p.connMu.Lock()
	p.conn = conn
	p.connCtx = connCtx
	p.connCancel = cancel
	p.sendFrom = sendFrom
	p.io.conn = conn
	p.bfdSession = bfdSess
	p.prefetchedFrames = prefetched
	p.connMu.Unlock()

	p.linkUp.Store(true)
	p.quiesce.Store(false)
	p.quiesceSeen.Store(false)
	p.sentOff.Store(sendFrom)
	select {
	case <-p.quiesceParked:
	default:
	}
	select {
	case <-p.switchWrote:
	default:
	}
	p.sendLog.SetSoftLimit(p.cfg.window)
	p.ack.Advance(sendFrom)
	p.sendLog.AdvanceTo(sendFrom)
	p.lastIn.Store(time.Now().UnixNano())
	p.nudge()
	if p.inGotClose.Load() {
		p.wakeSink()
	}

	defer func() {
		p.linkUp.Store(false)
		p.sendLog.SetSoftLimit(0)
		_ = conn.Close()
		p.connMu.Lock()
		if p.conn == conn {
			p.conn = nil
			p.connCancel = nil
			p.bfdSession = nil
			p.prefetchedFrames = nil
		}
		p.connMu.Unlock()
	}()

	errc := make(chan error, 4)
	var wg sync.WaitGroup
	start := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				select {
				case errc <- err:
				default:
				}
				cancel()
			}
		}()
	}
	start(p.netWriter)
	start(p.netReader)
	start(p.timer)

	select {
	case err = <-errc:
	case <-connCtx.Done():
		select {
		case err = <-errc:
		default:
			err = connCtx.Err()
		}
	case <-p.sessCtx.Done():
		if se := p.sessionErr(); se != nil {
			err = se
		} else {
			err = p.sessCtx.Err()
		}
	}
	p.cfg.log.Info("serveConn ending", "rawErr", err)
	cancel()
	_ = conn.Close()
	wg.Wait()
	if p.finished.Load() {
		return errByeSent
	}
	if se := p.sessionErr(); se != nil {
		return se
	}
	if p.sessCtx.Err() != nil {
		return p.sessCtx.Err()
	}
	if err == nil || isTransportGone(err) {
		if errors.Is(err, ErrDeadPeer) {
			return ErrDeadPeer
		}
		return errTransportDown
	}
	return err
}

func isTransportGone(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrDeadPeer) {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (p *pump) classify(err error) error {
	if err == nil || p.finished.Load() {
		return nil
	}
	if errors.Is(err, errByeSent) || errors.Is(err, errByeReceived) {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		if se := p.sessionErr(); se != nil {
			return se
		}
		return nil
	}
	return err
}

func reconnectable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errByeSent) || errors.Is(err, errByeReceived) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, session.ErrClosed) {
		return false
	}
	var pe *proto.Error
	if errors.As(err, &pe) {
		switch pe.Code {
		case proto.CodeProto, proto.CodeFrame, proto.CodeVersion,
			proto.CodeDestRefused, proto.CodeDestForbidden, proto.CodeNoCapacity,
			proto.CodeUnknownSession, proto.CodeBadToken, proto.CodeExpired,
			proto.CodeAuth, proto.CodeShutdown:
			return false
		}
	}
	return true
}

func (p *pump) sendCtrl(f proto.Frame) error {
	p.connMu.Lock()
	connCtx := p.connCtx
	p.connMu.Unlock()
	if connCtx == nil || !p.linkUp.Load() {
		p.nudge()
		return nil
	}
	select {
	case p.ctrlQ <- f:
		p.nudge()
		return nil
	case <-connCtx.Done():
		p.nudge()
		return nil
	case <-p.sessCtx.Done():
		return p.sessCtx.Err()
	}
}

// tryWriteShutdownBye best-effort writes BYE without blocking on a stuck
// netWriter or a full ctrlQ. Callers must still fail+dropConn.
func (p *pump) tryWriteShutdownBye() {
	fr, err := proto.MarshalFrame(proto.TypeBye, proto.Bye{
		Code: proto.CodeShutdown,
		Msg:  "shutting down",
	})
	if err != nil {
		return
	}
	if p.writeMu.TryLock() {
		p.connMu.Lock()
		c := p.conn
		up := p.linkUp.Load()
		p.connMu.Unlock()
		if c != nil && up {
			_ = c.SetDeadline(time.Now().Add(50 * time.Millisecond))
			if werr := c.WriteFrame(fr); werr == nil {
				p.finished.Store(true)
			}
		}
		p.writeMu.Unlock()
		return
	}
	select {
	case p.ctrlQ <- fr:
		p.nudge()
	default:
		p.nudge()
	}
}

func (p *pump) srcReader() error {
	buf := make([]byte, p.cfg.chunk)
	for {
		if err := p.sessCtx.Err(); err != nil {
			return err
		}
		n, err := p.io.src.Read(buf)
		if n > 0 {
			if aerr := p.sendLog.Append(p.sessCtx, buf[:n]); aerr != nil {
				if errors.Is(aerr, session.ErrClosed) || errors.Is(aerr, context.Canceled) {
					return nil
				}
				return aerr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				p.outFinal.Store(p.sendLog.End())
				p.outEOF.Store(true)
				p.sendLog.Close()
				p.nudge()
				return nil
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
		}
	}
}

func (p *pump) writeConn(f proto.Frame) error {
	p.connMu.Lock()
	c := p.conn
	p.connMu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := c.WriteFrame(f); err != nil {
		return err
	}
	if f.Type == proto.TypeSwitch {
		select {
		case p.switchWrote <- struct{}{}:
		default:
		}
	}
	return nil
}

func (p *pump) currentKind() transport.Kind {
	p.connMu.Lock()
	c := p.conn
	p.connMu.Unlock()
	if c == nil {
		return transport.KindTCP
	}
	return c.Kind()
}

func (p *pump) startQuiesce() {
	p.quiesceSeen.Store(false)
	p.quiesce.Store(true)
	p.nudge()
}

func (p *pump) abortQuiesce() {
	p.quiesce.Store(false)
	p.quiesceSeen.Store(false)
	p.nudge()
}

func (p *pump) parkQuiesce(sent uint64) {
	p.sentOff.Store(sent)
	p.quiesceSeen.Store(true)
	select {
	case p.quiesceParked <- struct{}{}:
	default:
	}
}

func (p *pump) drained() bool {
	return p.quiesceSeen.Load() && p.ack.Get() >= p.sentOff.Load()
}

var errSwitchTimeout = errors.New("switch timeout")

func (p *pump) waitQuiesced(ctx context.Context, d time.Duration) (up, down uint64, err error) {
	if d <= 0 {
		d = p.cfg.switchTimeout
	}
	if d <= 0 {
		d = 5 * time.Second
	}
	p.startQuiesce()
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		if p.drained() {
			return p.sentOff.Load(), p.expected.Load(), nil
		}
		p.connMu.Lock()
		connCtx := p.connCtx
		p.connMu.Unlock()
		if connCtx == nil {
			connCtx = p.sessCtx
		}
		select {
		case <-ctx.Done():
			p.abortQuiesce()
			return 0, 0, ctx.Err()
		case <-connCtx.Done():
			p.abortQuiesce()
			return 0, 0, connCtx.Err()
		case <-p.sessCtx.Done():
			p.abortQuiesce()
			return 0, 0, p.sessCtx.Err()
		case <-timer.C:
			if p.drained() {
				return p.sentOff.Load(), p.expected.Load(), nil
			}
			p.abortQuiesce()
			return 0, 0, errSwitchTimeout
		case <-p.ack.WaitCh():
		case <-p.quiesceParked:
		}
	}
}

// SWITCH.offset is the takeover point (D9). The new path emits from RESUME
// offsets (I2); bytes already on the old path are dropped by dedupe (I3).
func (p *pump) handleSwitch(sw proto.Switch) error {
	switch sw.Dir {
	case proto.DirBoth, p.io.inDir, p.io.outDir:
	default:
		_ = p.sendErr(proto.CodeProto, "SWITCH direction")
		return proto.ErrProto
	}
	switch sw.From {
	case "tcp", "quic", "kcp":
	default:
		_ = p.sendErr(proto.CodeProto, "SWITCH from")
		return proto.ErrProto
	}
	p.switchUp.Store(sw.Offset.Up)
	p.switchDown.Store(sw.Offset.Down)
	p.startQuiesce()
	d := p.cfg.switchTimeout
	if d <= 0 {
		d = 5 * time.Second
	}
	p.connMu.Lock()
	connCtx := p.connCtx
	p.connMu.Unlock()
	if connCtx == nil {
		connCtx = p.sessCtx
	}
	go func() {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
			p.connMu.Lock()
			still := p.connCtx == connCtx
			p.connMu.Unlock()
			if still && p.quiesce.Load() {
				p.abortQuiesce()
			}
		case <-connCtx.Done():
		case <-p.sessCtx.Done():
		}
	}()
	return nil
}

func (p *pump) sendSwitch(ctx context.Context, sw proto.Switch) error {
	fr, err := proto.MarshalFrame(proto.TypeSwitch, sw)
	if err != nil {
		return err
	}
	select {
	case <-p.switchWrote:
	default:
	}
	if err := p.sendCtrl(fr); err != nil {
		return err
	}
	p.connMu.Lock()
	connCtx := p.connCtx
	p.connMu.Unlock()
	if connCtx == nil {
		connCtx = p.sessCtx
	}
	select {
	case <-p.switchWrote:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-connCtx.Done():
		return connCtx.Err()
	case <-p.sessCtx.Done():
		return p.sessCtx.Err()
	}
}

func (p *pump) netWriter() error {
	sent := p.sendFrom
	if base := p.sendLog.Base(); base > sent {
		sent = base
	}
	p.sentOff.Store(sent)
	if d := p.delivered.Load(); d > 0 {
		if err := p.writeConn(proto.Frame{Type: proto.TypeAck, Payload: proto.EncodeAck(d)}); err != nil {
			return err
		}
	}
	closeSent := false
	for {
		if err := p.connCtx.Err(); err != nil {
			return err
		}
		for {
			select {
			case f := <-p.ctrlQ:
				if err := p.writeConn(f); err != nil {
					return err
				}
				if f.Type == proto.TypeBye {
					p.finished.Store(true)
					return errByeSent
				}
				continue
			default:
			}
			break
		}

		if p.quiesce.Load() {
			p.parkQuiesce(sent)
			select {
			case <-p.connCtx.Done():
				return p.connCtx.Err()
			case f := <-p.ctrlQ:
				if err := p.writeConn(f); err != nil {
					return err
				}
				if f.Type == proto.TypeBye {
					p.finished.Store(true)
					return errByeSent
				}
			case <-p.kick:
			case <-p.ack.WaitCh():
			}
			continue
		}

		acked := p.ack.Get()
		if p.cfg.window > 0 && sent > acked && sent-acked >= uint64(p.cfg.window) {
			select {
			case <-p.connCtx.Done():
				return p.connCtx.Err()
			case f := <-p.ctrlQ:
				if err := p.writeConn(f); err != nil {
					return err
				}
				if f.Type == proto.TypeBye {
					p.finished.Store(true)
					return errByeSent
				}
			case <-p.ack.WaitCh():
			case <-p.kick:
			}
			continue
		}

		from, data := p.sendLog.Slice(sent, p.cfg.chunk)
		if from > sent {
			sent = from
		}
		if len(data) > 0 {
			if p.quiesce.Load() {
				p.parkQuiesce(sent)
				continue
			}
			fr := proto.Frame{Type: proto.TypeData, Payload: proto.EncodeData(sent, data)}
			if err := p.writeConn(fr); err != nil {
				return err
			}
			sent += uint64(len(data))
			p.sentOff.Store(sent)
			continue
		}
		p.sentOff.Store(sent)

		if p.outEOF.Load() && sent >= p.outFinal.Load() {
			if !closeSent {
				fr, err := proto.MarshalFrame(proto.TypeCloseDir, proto.CloseDir{
					Dir:         p.io.outDir,
					FinalOffset: p.outFinal.Load(),
				})
				if err != nil {
					return err
				}
				if err := p.writeConn(fr); err != nil {
					return err
				}
				closeSent = true
			}
			if p.bothDrained() {
				fr, err := proto.MarshalFrame(proto.TypeBye, proto.Bye{Msg: "closed"})
				if err != nil {
					return err
				}
				if err := p.writeConn(fr); err != nil {
					return err
				}
				p.finished.Store(true)
				return errByeSent
			}
		}

		select {
		case <-p.connCtx.Done():
			return p.connCtx.Err()
		case f := <-p.ctrlQ:
			if err := p.writeConn(f); err != nil {
				return err
			}
			if f.Type == proto.TypeBye {
				p.finished.Store(true)
				return errByeSent
			}
		case <-p.sendLog.Notify():
		case <-p.kick:
		case <-p.ack.WaitCh():
		}
	}
}

func (p *pump) bothDrained() bool {
	if !p.outEOF.Load() || !p.inGotClose.Load() {
		return false
	}
	if p.delivered.Load() < p.inFinal.Load() {
		return false
	}
	if p.ack.Get() < p.outFinal.Load() {
		return false
	}
	return true
}

func (p *pump) enqueueSink(frag dataFrag) error {
	p.backpressured.Store(true)
	defer p.backpressured.Store(false)
	p.connMu.Lock()
	connCtx := p.connCtx
	p.connMu.Unlock()
	if connCtx == nil {
		connCtx = p.sessCtx
	}
	select {
	case p.sinkQ <- frag:
		return nil
	case <-connCtx.Done():
		return connCtx.Err()
	case <-p.sessCtx.Done():
		return p.sessCtx.Err()
	}
}

func (p *pump) netReader() error {
	expected := p.expected.Load()
	for {
		p.connMu.Lock()
		var f proto.Frame
		var err error
		if len(p.prefetchedFrames) > 0 {
			f = p.prefetchedFrames[0]
			p.prefetchedFrames = p.prefetchedFrames[1:]
			p.connMu.Unlock()
		} else {
			c := p.conn
			p.connMu.Unlock()
			if c == nil {
				return net.ErrClosed
			}
			f, err = c.ReadFrame()
			if err != nil {
				return err
			}
		}
		p.lastIn.Store(time.Now().UnixNano())
		p.notePeerFrame()
		switch f.Type {
		case proto.TypeData:
			seq, data, derr := proto.DecodeData(f.Payload)
			if derr != nil {
				_ = p.sendErr(proto.CodeProto, "bad DATA")
				return derr
			}
			seq, data, drop, derr := session.Dedupe(seq, data, expected)
			if derr != nil {
				_ = p.sendErr(proto.CodeProto, "gap in data stream")
				return derr
			}
			if drop {
				continue
			}
			if p.inGotClose.Load() && seq+uint64(len(data)) > p.inFinal.Load() {
				_ = p.sendErr(proto.CodeProto, "data past CLOSE_DIR")
				return proto.ErrProto
			}
			if err := p.enqueueSink(dataFrag{data: data}); err != nil {
				return err
			}
			expected += uint64(len(data))
			p.expected.Store(expected)
		case proto.TypeAck:
			acked, aerr := proto.DecodeAck(f.Payload)
			if aerr != nil {
				_ = p.sendErr(proto.CodeProto, "bad ACK")
				return aerr
			}
			p.sendLog.AdvanceTo(acked)
			p.ack.Advance(acked)
			p.nudge()
		case proto.TypeCloseDir:
			var cd proto.CloseDir
			if uerr := proto.UnmarshalPayload(f, &cd); uerr != nil {
				_ = p.sendErr(proto.CodeProto, "bad CLOSE_DIR")
				return uerr
			}
			if cd.Dir != p.io.inDir {
				_ = p.sendErr(proto.CodeProto, "CLOSE_DIR direction")
				return proto.ErrProto
			}
			if p.inGotClose.Load() {
				if cd.FinalOffset != p.inFinal.Load() {
					_ = p.sendErr(proto.CodeProto, "CLOSE_DIR offset mismatch")
					return proto.ErrProto
				}
				p.wakeSink()
				continue
			}
			if cd.FinalOffset != expected {
				_ = p.sendErr(proto.CodeProto, "CLOSE_DIR offset mismatch")
				return proto.ErrProto
			}
			p.inFinal.Store(cd.FinalOffset)
			p.inGotClose.Store(true)
			p.wakeSink()
			if err := p.enqueueSink(dataFrag{eof: true}); err != nil {
				return err
			}
			p.nudge()
		case proto.TypePing:
			pkt, err := bfd.DecodePacket(f.Payload)
			if err == nil {
				p.connMu.Lock()
				sess := p.bfdSession
				p.connMu.Unlock()
				if sess != nil {
					_, _ = sess.Receive(pkt)
				}
			}
		case proto.TypePong:
			// Dropped as per FEAT-ROB-01
		case proto.TypeSwitch:
			var sw proto.Switch
			if uerr := proto.UnmarshalPayload(f, &sw); uerr != nil {
				_ = p.sendErr(proto.CodeProto, "bad SWITCH")
				return uerr
			}
			if err := p.handleSwitch(sw); err != nil {
				return err
			}
		case proto.TypeBye:
			p.finished.Store(true)
			return errByeReceived
		case proto.TypeErr:
			var fail proto.Fail
			_ = proto.UnmarshalPayload(f, &fail)
			if fail.Code == "" {
				fail.Code = proto.CodeInternal
			}
			return proto.NewError(fail.Code, fail.Msg)
		default:
			_ = p.sendErr(proto.CodeProto, "unexpected frame type "+f.Type.String())
			return proto.ErrProto
		}
	}
}

func (p *pump) tryCloseWrite(delivered uint64) {
	if p.inGotClose.Load() && delivered >= p.inFinal.Load() {
		p.cwOnce.Do(func() {
			if p.io.closeWrite != nil {
				_ = p.io.closeWrite()
			}
		})
		p.nudge()
	}
}

func (p *pump) sinkWriter() error {
	var delivered uint64
	for {
		select {
		case <-p.sessCtx.Done():
			return p.sessCtx.Err()
		case frag := <-p.sinkQ:
			if len(frag.data) > 0 {
				if err := writeFull(p.io.sink, frag.data); err != nil {
					return err
				}
				if p.io.flushSink != nil {
					if err := p.io.flushSink(); err != nil {
						return err
					}
				}
				delivered += uint64(len(frag.data))
				p.delivered.Store(delivered)
				if !testSuppressAck.Load() {
					if err := p.sendCtrl(proto.Frame{Type: proto.TypeAck, Payload: proto.EncodeAck(delivered)}); err != nil {
						return err
					}
				}
				p.nudge()
			}
			p.tryCloseWrite(delivered)
		case <-p.sinkKick:
			p.tryCloseWrite(delivered)
		}
	}
}

func (p *pump) timer() error {
	p.connMu.Lock()
	sess := p.bfdSession
	p.connMu.Unlock()

	cadence := p.cfg.heartbeat
	if sess != nil {
		cadence = sess.TxInterval()
	}
	if cadence <= 0 {
		cadence = p.cfg.keepalive
	}
	if cadence <= 0 {
		cadence = 750 * time.Millisecond
	}

	t := time.NewTicker(cadence)
	defer t.Stop()

	for {
		select {
		case <-p.connCtx.Done():
			return p.connCtx.Err()
		case now := <-t.C:
			p.connMu.Lock()
			currentSess := p.bfdSession
			p.connMu.Unlock()

			if currentSess != nil && currentSess.CheckTimeout(now) {
				return ErrDeadPeer
			}

			last := time.Unix(0, p.lastIn.Load())
			if p.cfg.idle > 0 && !p.backpressured.Load() && now.Sub(last) > p.cfg.idle {
				p.connCancel()
				return errIdle
			}

			if currentSess != nil {
				newCadence := currentSess.TxInterval()
				if newCadence > 0 && newCadence != cadence {
					cadence = newCadence
					t.Reset(cadence)
				}
				pkt := currentSess.FormatTxPacket()
				payload := bfd.EncodePacket(pkt)
				if err := p.sendCtrl(proto.Frame{Type: proto.TypePing, Payload: payload}); err != nil {
					return err
				}
			}
		}
	}
}

func (p *pump) sendErr(code, msg string) error {
	fr, err := proto.MarshalFrame(proto.TypeErr, proto.Fail{Code: code, Msg: msg})
	if err != nil {
		return err
	}
	return p.sendCtrl(fr)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func writeFrameDeadline(conn transport.Conn, f proto.Frame) error {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	err := conn.WriteFrame(f)
	_ = conn.SetDeadline(time.Time{})
	return err
}

func writeErr(conn transport.Conn, code, msg string) {
	fr, err := proto.MarshalFrame(proto.TypeErr, proto.Fail{Code: code, Msg: msg})
	if err != nil {
		return
	}
	_ = writeFrameDeadline(conn, fr)
}

func writeResumeFail(conn transport.Conn, code, msg string) {
	fr, err := proto.MarshalFrame(proto.TypeResumeFail, proto.Fail{Code: code, Msg: msg})
	if err != nil {
		return
	}
	_ = writeFrameDeadline(conn, fr)
}

func clampChunk(n int) int {
	const max = proto.MaxFrameLen - 8
	if n <= 0 {
		return 65536
	}
	if n > max {
		return max
	}
	return n
}
