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

	cmux.mu.Lock()
	if cmux.closed.Load() {
		cmux.mu.Unlock()
		_ = socks5.WriteReply(c, socks5.RepGeneralFailure, "")
		return
	}
	if len(cmux.streams) >= cmux.maxStreams {
		cmux.mu.Unlock()
		cmux.log.Warn("socks max streams exceeded on client", "limit", cmux.maxStreams)
		_ = socks5.WriteReply(c, socks5.RepGeneralFailure, "")
		return
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

	// Send STREAM_OPEN to server
	if err := cmux.sendFrame(socks5.MuxFrame{
		StreamID: streamID,
		Type:     socks5.TypeStreamOpen,
		Payload:  []byte(req.Dest),
	}); err != nil {
		_ = socks5.WriteReply(c, socks5.RepGeneralFailure, "")
		cmux.closeStream(streamID)
		return
	}

	// Wait for server response
	select {
	case <-ctx.Done():
		_ = socks5.WriteReply(c, socks5.RepGeneralFailure, "")
		cmux.closeStream(streamID)
		return
	case <-cmux.closedCh:
		_ = socks5.WriteReply(c, socks5.RepGeneralFailure, "")
		cmux.closeStream(streamID)
		return
	case resp := <-st.openCh:
		if !resp.ok {
			_ = socks5.WriteReply(c, resp.rep, "")
			cmux.closeStream(streamID)
			return
		}
		if err := socks5.WriteReply(c, socks5.RepSucceeded, resp.bndAddr); err != nil {
			cmux.closeStream(streamID)
			return
		}
	}

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
	log := socksCfg.Log
	if log == nil {
		log = logging.New(nil, clientCfg.LogLevel, clientCfg.LogFormat)
	}

	listenAddr := socksCfg.Listen
	if listenAddr == "" {
		listenAddr = clientCfg.SocksListen
	}
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("socks listen on %s failed: %w", listenAddr, err)
	}
	defer ln.Close()
	boundAddr := ln.Addr().String()
	log.Info("socks5 dynamic proxy listening", "addr", boundAddr)

	if socksCfg.OnBound != nil {
		socksCfg.OnBound(boundAddr)
	}
	if socksCfg.ReadyCh != nil {
		close(socksCfg.ReadyCh)
	}

	// Force SOCKS5 mode destination
	clientCfg.Destination = proto.DestSOCKS5

	toRelayR, toRelayW := io.Pipe()
	fromRelayR, fromRelayW := io.Pipe()

	cmux := newClientMux(ctx, log, toRelayR, toRelayW, fromRelayR, fromRelayW, socksCfg.MaxStreams)
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

	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case err := <-tunnelErrCh:
			if err != nil {
				log.Error("socks tunnel terminated", "err", err)
			}
			_ = ln.Close()
		}
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			select {
			case terr := <-tunnelErrCh:
				if terr != nil {
					return fmt.Errorf("socks tunnel error: %w", terr)
				}
				return nil
			default:
				log.Debug("socks accept error", "err", err)
				continue
			}
		}
		go cmux.handleClientConn(ctx, c)
	}
}
