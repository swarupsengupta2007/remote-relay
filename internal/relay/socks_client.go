package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/socks5"
)

// SocksConfig defines the configuration for the local SOCKS5 listener.
type SocksConfig struct {
	Listen     string
	MaxStreams int
	Log        *slog.Logger
	ReadyCh    chan struct{}
	OnBound    func(addr string)
}

type openResp struct {
	ok      bool
	rep     byte
	msg     string
	bndAddr string
}

type clientStream struct {
	id        uint32
	conn      net.Conn
	dataCh    chan []byte
	openCh    chan openResp
	closeWrCh chan struct{}
	resetCh   chan struct{}
	closed    atomic.Bool
	once      sync.Once
}

func (st *clientStream) close() {
	st.once.Do(func() {
		st.closed.Store(true)
		close(st.resetCh)
		if st.conn != nil {
			_ = st.conn.Close()
		}
	})
}

type clientMux struct {
	log          *slog.Logger
	toRelayR     *io.PipeReader
	toRelayW     *io.PipeWriter
	fromRelayR   *io.PipeReader
	fromRelayW   *io.PipeWriter
	wMu          sync.Mutex
	streams      map[uint32]*clientStream
	mu           sync.Mutex
	nextStreamID atomic.Uint32
	maxStreams   int
	closed       atomic.Bool
	closedCh     chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
}

func newClientMux(ctx context.Context, log *slog.Logger, toRelayR *io.PipeReader, toRelayW *io.PipeWriter, fromRelayR *io.PipeReader, fromRelayW *io.PipeWriter, maxStreams int) *clientMux {
	if maxStreams <= 0 {
		maxStreams = 512
	}
	muxCtx, cancel := context.WithCancel(ctx)
	return &clientMux{
		log:        log,
		toRelayR:   toRelayR,
		toRelayW:   toRelayW,
		fromRelayR: fromRelayR,
		fromRelayW: fromRelayW,
		streams:    make(map[uint32]*clientStream),
		maxStreams: maxStreams,
		closedCh:   make(chan struct{}),
		ctx:        muxCtx,
		cancel:     cancel,
	}
}

func (cmux *clientMux) sendFrame(f socks5.MuxFrame) error {
	cmux.wMu.Lock()
	defer cmux.wMu.Unlock()
	if cmux.closed.Load() {
		return io.ErrClosedPipe
	}
	return socks5.WriteMuxFrame(cmux.toRelayW, f)
}

func (cmux *clientMux) closeStream(id uint32) {
	cmux.mu.Lock()
	st := cmux.streams[id]
	delete(cmux.streams, id)
	cmux.mu.Unlock()

	if st != nil {
		st.close()
	}
}

func (cmux *clientMux) Close() error {
	if cmux.closed.CompareAndSwap(false, true) {
		cmux.cancel()
		close(cmux.closedCh)

		if cmux.toRelayW != nil {
			_ = cmux.toRelayW.CloseWithError(io.ErrClosedPipe)
		}
		if cmux.fromRelayW != nil {
			_ = cmux.fromRelayW.CloseWithError(io.ErrClosedPipe)
		}
		if cmux.toRelayR != nil {
			_ = cmux.toRelayR.Close()
		}
		if cmux.fromRelayR != nil {
			_ = cmux.fromRelayR.Close()
		}

		cmux.mu.Lock()
		for _, st := range cmux.streams {
			st.close()
		}
		cmux.streams = make(map[uint32]*clientStream)
		cmux.mu.Unlock()
	}
	return nil
}

func (cmux *clientMux) readTunnelLoop() {
	for {
		f, err := socks5.ReadMuxFrame(cmux.fromRelayR)
		if err != nil {
			_ = cmux.Close()
			return
		}

		cmux.mu.Lock()
		st := cmux.streams[f.StreamID]
		cmux.mu.Unlock()

		if st == nil {
			continue
		}

		switch f.Type {
		case socks5.TypeStreamOpenOK:
			select {
			case st.openCh <- openResp{ok: true, bndAddr: string(f.Payload)}:
			default:
			}
		case socks5.TypeStreamOpenFail:
			rep, msg := socks5.DecodeOpenFail(f.Payload)
			select {
			case st.openCh <- openResp{ok: false, rep: rep, msg: msg}:
			default:
			}
		case socks5.TypeStreamData:
			if !st.closed.Load() {
				select {
				case st.dataCh <- f.Payload:
				case <-st.resetCh:
				case <-cmux.ctx.Done():
				default:
					select {
					case st.dataCh <- f.Payload:
					case <-time.After(3 * time.Second):
						cmux.log.Warn("socks client write buffer saturated, dropping stream", "streamID", f.StreamID)
						cmux.closeStream(f.StreamID)
						_ = cmux.sendFrame(socks5.MuxFrame{
							StreamID: f.StreamID,
							Type:     socks5.TypeStreamReset,
							Payload:  []byte("client buffer saturated"),
						})
					}
				}
			}
		case socks5.TypeStreamClose:
			select {
			case st.closeWrCh <- struct{}{}:
			default:
			}
		case socks5.TypeStreamReset:
			cmux.closeStream(f.StreamID)
		}
	}
}

func (cmux *clientMux) handleClientConn(ctx context.Context, c net.Conn) {
	defer c.Close()

	// 10s handshake timeout
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	methods, err := socks5.ReadAuth(c)
	if err != nil {
		return
	}

	hasNoAuth := false
	for _, m := range methods {
		if m == socks5.MethodNoAuth {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		_ = socks5.WriteAuthReply(c, socks5.MethodNoAcceptable)
		return
	}
	if err := socks5.WriteAuthReply(c, socks5.MethodNoAuth); err != nil {
		return
	}

	req, err := socks5.ReadRequest(c)
	if err != nil {
		if errors.Is(err, socks5.ErrUnsupportedAddress) {
			_ = socks5.WriteReply(c, socks5.RepAddressNotSupported, "")
		} else if !errors.Is(err, socks5.ErrBadVersion) {
			_ = socks5.WriteReply(c, socks5.RepGeneralFailure, "")
		}
		return
	}
	_ = c.SetDeadline(time.Time{})

	if req.Command != socks5.CmdConnect {
		_ = socks5.WriteReply(c, socks5.RepCommandNotSupported, "")
		return
	}

	st, resp := cmux.openStream(ctx, c, req.Dest)
	if !resp.ok {
		_ = socks5.WriteReply(c, resp.rep, "")
		return
	}
	if err := socks5.WriteReply(c, socks5.RepSucceeded, resp.bndAddr); err != nil {
		cmux.closeStream(st.id)
		return
	}
	cmux.pumpStream(st)
}

// handleForwardConn relays a connection accepted on a -L listener to the
// fixed destination dest. There is no handshake with the local peer, so an
// open failure is reported only by closing the connection.
func (cmux *clientMux) handleForwardConn(ctx context.Context, c net.Conn, dest string) {
	defer c.Close()

	st, resp := cmux.openStream(ctx, c, dest)
	if !resp.ok {
		cmux.log.Warn("local forward open failed", "dest", dest, "peer", c.RemoteAddr().String(), "err", resp.msg)
		return
	}
	cmux.pumpStream(st)
}

// openStream registers a stream for c and asks the server to dial dest. On
// failure the stream is already removed, c is left open for the caller to
// reply on, and resp carries the SOCKS5 reply code and reason.
func (cmux *clientMux) openStream(ctx context.Context, c net.Conn, dest string) (*clientStream, openResp) {
	fail := func(msg string) openResp {
		return openResp{rep: socks5.RepGeneralFailure, msg: msg}
	}

	cmux.mu.Lock()
	if cmux.closed.Load() {
		cmux.mu.Unlock()
		return nil, fail("tunnel closed")
	}
	if len(cmux.streams) >= cmux.maxStreams {
		cmux.mu.Unlock()
		cmux.log.Warn("socks max streams exceeded on client", "limit", cmux.maxStreams)
		return nil, fail("max streams exceeded")
	}

	streamID := cmux.nextStreamID.Add(1)
	st := &clientStream{
		id:        streamID,
		conn:      c,
		dataCh:    make(chan []byte, 64),
		openCh:    make(chan openResp, 1),
		closeWrCh: make(chan struct{}, 1),
		resetCh:   make(chan struct{}),
	}
	cmux.streams[streamID] = st
	cmux.mu.Unlock()

	// Not closeStream: that closes c, and the caller still owns it.
	abort := func() {
		cmux.mu.Lock()
		delete(cmux.streams, streamID)
		cmux.mu.Unlock()
		st.once.Do(func() {
			st.closed.Store(true)
			close(st.resetCh)
		})
	}

	// Send STREAM_OPEN to server
	if err := cmux.sendFrame(socks5.MuxFrame{
		StreamID: streamID,
		Type:     socks5.TypeStreamOpen,
		Payload:  []byte(dest),
	}); err != nil {
		abort()
		return nil, fail(err.Error())
	}

	// Wait for server response
	select {
	case <-ctx.Done():
		abort()
		return nil, fail(ctx.Err().Error())
	case <-cmux.closedCh:
		abort()
		return nil, fail("tunnel closed")
	case resp := <-st.openCh:
		if !resp.ok {
			abort()
			return nil, resp
		}
		return st, resp
	}
}

// pumpStream relays bytes between an opened stream and its local connection
// until both directions finish or either side resets.
func (cmux *clientMux) pumpStream(st *clientStream) {
	c := st.conn
	streamID := st.id

	// Stream established! Start background socket writer
	writerDone := make(chan struct{})
	readerDone := make(chan struct{})

	go func() {
		defer close(writerDone)
		for {
			select {
			case data, ok := <-st.dataCh:
				if !ok {
					return
				}
				if _, err := st.conn.Write(data); err != nil {
					cmux.closeStream(st.id)
					_ = cmux.sendFrame(socks5.MuxFrame{
						StreamID: st.id,
						Type:     socks5.TypeStreamReset,
						Payload:  []byte(err.Error()),
					})
					return
				}
			case <-st.closeWrCh:
				for {
					select {
					case data, ok := <-st.dataCh:
						if ok && len(data) > 0 {
							if _, err := st.conn.Write(data); err != nil {
								return
							}
							continue
						}
					default:
					}
					break
				}
				if tc, ok := st.conn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				return
			case <-st.resetCh:
				return
			case <-cmux.ctx.Done():
				return
			}
		}
	}()

	// Foreground socket reader
	go func() {
		defer close(readerDone)
		buf := make([]byte, 32768)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				payload := make([]byte, n)
				copy(payload, buf[:n])
				if err := cmux.sendFrame(socks5.MuxFrame{
					StreamID: streamID,
					Type:     socks5.TypeStreamData,
					Payload:  payload,
				}); err != nil {
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					_ = cmux.sendFrame(socks5.MuxFrame{
						StreamID: streamID,
						Type:     socks5.TypeStreamClose,
						Payload:  []byte{socks5.CloseHalfWrite},
					})
				} else if !st.closed.Load() {
					_ = cmux.sendFrame(socks5.MuxFrame{
						StreamID: streamID,
						Type:     socks5.TypeStreamReset,
						Payload:  []byte(err.Error()),
					})
				}
				return
			}
		}
	}()

	// Wait for both directions to finish or reset
	select {
	case <-st.resetCh:
	case <-cmux.ctx.Done():
	case <-writerDone:
		<-readerDone
	case <-readerDone:
		<-writerDone
	}
	cmux.closeStream(streamID)
}

// RunSocks runs the SOCKS5 dynamic proxy mode (FEAT-UTL-03).
// It starts a local SOCKS5 TCP listener, connects a resilient relay tunnel to the server,
// and multiplexes local client streams over the tunnel.
func RunSocks(ctx context.Context, socksCfg SocksConfig, clientCfg config.Client) error {
	listenAddr := socksCfg.Listen
	if listenAddr == "" {
		listenAddr = clientCfg.SocksListen
	}
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}
	fwdCfg := ForwardConfig{
		SocksListen: listenAddr,
		MaxStreams:  socksCfg.MaxStreams,
		Log:         socksCfg.Log,
		ReadyCh:     socksCfg.ReadyCh,
	}
	if socksCfg.OnBound != nil {
		fwdCfg.OnBound = func(addrs []string) { socksCfg.OnBound(addrs[0]) }
	}
	return RunForward(ctx, fwdCfg, clientCfg)
}

// ForwardConfig defines the local listeners of a forwarding client: any
// number of fixed ssh -L style forwards and an optional SOCKS5 (-D) listener.
type ForwardConfig struct {
	Locals      []config.LocalForward
	SocksListen string // empty = no SOCKS5 listener
	MaxStreams  int
	Log         *slog.Logger
	ReadyCh     chan struct{}
	// OnBound receives the bound listener addresses: one per entry of
	// Locals in order, then the SOCKS5 listener if any.
	OnBound func(addrs []string)
}

type forwardListener struct {
	ln   net.Listener
	dest string // empty = SOCKS5
}

// RunForward binds every listener in fwdCfg, connects one resilient relay
// tunnel to the server and multiplexes all accepted connections over it as
// mux streams. -L connections are opened to their fixed destination; SOCKS5
// connections to the destination they request. The server applies the same
// allow_destinations and per-key policy to both.
func RunForward(ctx context.Context, fwdCfg ForwardConfig, clientCfg config.Client) error {
	log := fwdCfg.Log
	if log == nil {
		log = logging.New(nil, clientCfg.LogLevel, clientCfg.LogFormat)
	}
	if len(fwdCfg.Locals) == 0 && fwdCfg.SocksListen == "" {
		return errors.New("no local forwards or SOCKS listener configured")
	}

	var listeners []forwardListener
	defer func() {
		for _, fl := range listeners {
			_ = fl.ln.Close()
		}
	}()
	var bound []string
	for _, fwd := range fwdCfg.Locals {
		ln, err := net.Listen("tcp", fwd.Listen)
		if err != nil {
			return fmt.Errorf("local forward listen on %s failed: %w", fwd.Listen, err)
		}
		listeners = append(listeners, forwardListener{ln: ln, dest: fwd.Dest})
		bound = append(bound, ln.Addr().String())
		log.Info("local forward listening", "addr", ln.Addr().String(), "dest", fwd.Dest)
	}
	if fwdCfg.SocksListen != "" {
		ln, err := net.Listen("tcp", fwdCfg.SocksListen)
		if err != nil {
			return fmt.Errorf("socks listen on %s failed: %w", fwdCfg.SocksListen, err)
		}
		listeners = append(listeners, forwardListener{ln: ln})
		bound = append(bound, ln.Addr().String())
		log.Info("socks5 dynamic proxy listening", "addr", ln.Addr().String())
	}

	if fwdCfg.OnBound != nil {
		fwdCfg.OnBound(bound)
	}
	if fwdCfg.ReadyCh != nil {
		close(fwdCfg.ReadyCh)
	}

	// Streams ride the server's SOCKS5 mux mode whatever the listener kind.
	clientCfg.Destination = proto.DestSOCKS5

	toRelayR, toRelayW := io.Pipe()
	fromRelayR, fromRelayW := io.Pipe()

	cmux := newClientMux(ctx, log, toRelayR, toRelayW, fromRelayR, fromRelayW, fwdCfg.MaxStreams)
	defer cmux.Close()

	go cmux.readTunnelLoop()

	tunnelErrCh := make(chan error, 1)
	tunnelCtx, tunnelCancel := context.WithCancel(ctx)
	defer tunnelCancel()

	go func() {
		err := RunClient(tunnelCtx, clientCfg, toRelayR, fromRelayW, log)
		_ = toRelayR.CloseWithError(err)
		_ = fromRelayW.CloseWithError(err)
		tunnelErrCh <- err
	}()

	var tunnelErr atomic.Pointer[error]
	go func() {
		select {
		case <-ctx.Done():
		case err := <-tunnelErrCh:
			if err != nil {
				tunnelErr.Store(&err)
				log.Error("forward tunnel terminated", "err", err)
			}
		}
		for _, fl := range listeners {
			_ = fl.ln.Close()
		}
	}()

	errCh := make(chan error, len(listeners))
	for _, fl := range listeners {
		go func() {
			errCh <- acceptForward(ctx, fl, cmux, &tunnelErr, log)
		}()
	}
	// The first accept loop to stop has seen every listener close (or a
	// fatal error); close the rest so their loops return too.
	err := <-errCh
	for _, fl := range listeners {
		_ = fl.ln.Close()
	}
	for range len(listeners) - 1 {
		<-errCh
	}
	return err
}

func acceptForward(ctx context.Context, fl forwardListener, cmux *clientMux, tunnelErr *atomic.Pointer[error], log *slog.Logger) error {
	for {
		c, err := fl.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if ep := tunnelErr.Load(); ep != nil && *ep != nil {
				return fmt.Errorf("forward tunnel error: %w", *ep)
			}
			if errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			log.Debug("forward accept error", "addr", fl.ln.Addr().String(), "err", err)
			continue
		}
		if fl.dest == "" {
			go cmux.handleClientConn(ctx, c)
		} else {
			go cmux.handleForwardConn(ctx, c, fl.dest)
		}
	}
}
