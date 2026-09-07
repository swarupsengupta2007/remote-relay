package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

var (
	errByeSent     = errors.New("bye sent")
	errByeReceived = errors.New("bye received")
	errIdle        = errors.New("idle timeout")
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
	chunk     int
	window    int
	keepalive time.Duration
	idle      time.Duration
	log       *slog.Logger
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

func (a *acker) WaitBelow(ctx context.Context, sent, window uint64) error {
	for {
		a.mu.Lock()
		acked := a.acked
		if acked >= sent || sent-acked < window {
			a.mu.Unlock()
			return nil
		}
		ch := a.wait
		a.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

type pump struct {
	ctx    context.Context
	cancel context.CancelFunc
	io     sessionIO
	cfg    pumpConfig

	outQ  chan proto.Frame
	sinkQ chan dataFrag
	ack   *acker

	outFinal atomic.Uint64
	outEOF   atomic.Bool

	inFinal    atomic.Uint64
	inGotClose atomic.Bool
	delivered  atomic.Uint64

	lastIn        atomic.Int64
	finished      atomic.Bool
	backpressured atomic.Bool
	byeOnce       sync.Once
	cwOnce        sync.Once
}

func runPump(ctx context.Context, io sessionIO, cfg pumpConfig) error {
	if cfg.log == nil {
		cfg.log = slog.Default()
	}
	cfg.chunk = clampChunk(cfg.chunk)
	if cfg.window <= 0 {
		cfg.window = 4194304
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p := &pump{
		ctx:    ctx,
		cancel: cancel,
		io:     io,
		cfg:    cfg,
		outQ:   make(chan proto.Frame, 32),
		sinkQ:  make(chan dataFrag, 16),
		ack:    newAcker(),
	}
	p.lastIn.Store(time.Now().UnixNano())

	errc := make(chan error, 8)
	var netWG, srcWG sync.WaitGroup
	start := func(fn func() error) {
		netWG.Add(1)
		go func() {
			defer netWG.Done()
			if err := fn(); err != nil {
				select {
				case errc <- err:
				default:
				}
				cancel()
			}
		}()
	}
	srcWG.Add(1)
	go func() {
		defer srcWG.Done()
		if err := p.srcReader(); err != nil {
			select {
			case errc <- err:
			default:
			}
			cancel()
		}
	}()
	start(p.netWriter)
	start(p.netReader)
	start(p.sinkWriter)
	start(p.timer)

	var err error
	select {
	case err = <-errc:
	case <-ctx.Done():
		err = ctx.Err()
	}
	cancel()
	_ = p.io.conn.Close()
	if p.io.closeSrc != nil {
		_ = p.io.closeSrc()
		srcWG.Wait()
	}
	netWG.Wait()
	return p.classify(err)
}

func (p *pump) classify(err error) error {
	if err == nil || p.finished.Load() {
		return nil
	}
	if errors.Is(err, errByeSent) || errors.Is(err, errByeReceived) {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (p *pump) send(f proto.Frame) error {
	select {
	case p.outQ <- f:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

func (p *pump) srcReader() error {
	buf := make([]byte, p.cfg.chunk)
	var offset uint64
	for {
		n, err := p.io.src.Read(buf)
		if n > 0 {
			if werr := p.ack.WaitBelow(p.ctx, offset, uint64(p.cfg.window)); werr != nil {
				return werr
			}
			frame := proto.Frame{Type: proto.TypeData, Payload: proto.EncodeData(offset, buf[:n])}
			if serr := p.send(frame); serr != nil {
				return serr
			}
			offset += uint64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				p.outFinal.Store(offset)
				p.outEOF.Store(true)
				fr, merr := proto.MarshalFrame(proto.TypeCloseDir, proto.CloseDir{
					Dir:         p.io.outDir,
					FinalOffset: offset,
				})
				if merr != nil {
					return merr
				}
				if serr := p.send(fr); serr != nil {
					return serr
				}
				p.maybeBye()
				return nil
			}
			return err
		}
	}
}

func (p *pump) netWriter() error {
	for {
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		case f := <-p.outQ:
			if err := p.io.conn.WriteFrame(f); err != nil {
				return err
			}
			if f.Type == proto.TypeBye {
				p.finished.Store(true)
				return errByeSent
			}
		}
	}
}

func (p *pump) enqueueSink(frag dataFrag) error {
	p.backpressured.Store(true)
	defer p.backpressured.Store(false)
	select {
	case p.sinkQ <- frag:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

func (p *pump) netReader() error {
	expected := uint64(0)
	for {
		f, err := p.io.conn.ReadFrame()
		if err != nil {
			return err
		}
		p.lastIn.Store(time.Now().UnixNano())
		switch f.Type {
		case proto.TypeData:
			seq, data, derr := proto.DecodeData(f.Payload)
			if derr != nil {
				_ = p.sendErr(proto.CodeProto, "bad DATA")
				return derr
			}
			end := seq + uint64(len(data))
			if end <= expected {
				continue
			}
			if seq < expected {
				data = data[expected-seq:]
				seq = expected
			}
			if seq > expected {
				_ = p.sendErr(proto.CodeProto, "gap in data stream")
				return proto.ErrProto
			}
			if p.inGotClose.Load() && seq+uint64(len(data)) > p.inFinal.Load() {
				_ = p.sendErr(proto.CodeProto, "data past CLOSE_DIR")
				return proto.ErrProto
			}
			if err := p.enqueueSink(dataFrag{data: data}); err != nil {
				return err
			}
			expected += uint64(len(data))
		case proto.TypeAck:
			acked, aerr := proto.DecodeAck(f.Payload)
			if aerr != nil {
				_ = p.sendErr(proto.CodeProto, "bad ACK")
				return aerr
			}
			p.ack.Advance(acked)
			p.maybeBye()
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
			if cd.FinalOffset != expected {
				_ = p.sendErr(proto.CodeProto, "CLOSE_DIR offset mismatch")
				return proto.ErrProto
			}
			p.inFinal.Store(cd.FinalOffset)
			p.inGotClose.Store(true)
			if err := p.enqueueSink(dataFrag{eof: true}); err != nil {
				return err
			}
			p.maybeBye()
		case proto.TypePing:
			if err := p.send(proto.Frame{Type: proto.TypePong, Payload: f.Payload}); err != nil {
				return err
			}
		case proto.TypePong:
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

func (p *pump) sinkWriter() error {
	var delivered uint64
	for {
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
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
				if err := p.send(proto.Frame{Type: proto.TypeAck, Payload: proto.EncodeAck(delivered)}); err != nil {
					return err
				}
			}
			if p.inGotClose.Load() && delivered >= p.inFinal.Load() {
				p.cwOnce.Do(func() {
					if p.io.closeWrite != nil {
						_ = p.io.closeWrite()
					}
				})
				p.maybeBye()
			}
		}
	}
}

func (p *pump) timer() error {
	if p.cfg.keepalive <= 0 {
		<-p.ctx.Done()
		return p.ctx.Err()
	}
	t := time.NewTicker(p.cfg.keepalive)
	defer t.Stop()
	var nonce uint64
	for {
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		case now := <-t.C:
			last := time.Unix(0, p.lastIn.Load())
			if p.cfg.idle > 0 && !p.backpressured.Load() && now.Sub(last) > p.cfg.idle {
				p.cancel()
				return errIdle
			}
			nonce++
			payload := proto.EncodePing(nonce, uint64(now.UnixMilli()))
			if err := p.send(proto.Frame{Type: proto.TypePing, Payload: payload}); err != nil {
				return err
			}
		}
	}
}

func (p *pump) maybeBye() {
	if !p.outEOF.Load() || !p.inGotClose.Load() {
		return
	}
	if p.delivered.Load() < p.inFinal.Load() {
		return
	}
	if p.ack.Get() < p.outFinal.Load() {
		return
	}
	p.byeOnce.Do(func() {
		fr, err := proto.MarshalFrame(proto.TypeBye, proto.Bye{Msg: "closed"})
		if err != nil {
			return
		}
		select {
		case p.outQ <- fr:
		case <-p.ctx.Done():
		}
	})
}

func (p *pump) sendErr(code, msg string) error {
	fr, err := proto.MarshalFrame(proto.TypeErr, proto.Fail{Code: code, Msg: msg})
	if err != nil {
		return err
	}
	return p.send(fr)
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
