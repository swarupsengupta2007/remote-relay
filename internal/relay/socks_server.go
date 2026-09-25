package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/socks5"
)

type serverStream struct {
	id         uint32
	target     string
	conn       net.Conn
	dataCh     chan []byte
	closeWrCh  chan struct{}
	resetCh    chan struct{}
	closed     atomic.Bool
	once       sync.Once
	readerDone chan struct{}
	writerDone chan struct{}
}

func (st *serverStream) close() {
	st.once.Do(func() {
		st.closed.Store(true)
		close(st.resetCh)
		if st.conn != nil {
			_ = st.conn.Close()
		}
	})
}

// socksServerMux multiplexes multiple logical TCP streams over a single
// resilient remote-relay session on the server side (FEAT-UTL-03).
type socksServerMux struct {
	srv                   *Server
	sessID                string
	log                   *slog.Logger
	toMuxR                *io.PipeReader
	toMuxW                *io.PipeWriter
	fromMuxR              *io.PipeReader
	fromMuxW              *io.PipeWriter
	wMu                   sync.Mutex
	streams               map[uint32]*serverStream
	mu                    sync.Mutex
	closed                atomic.Bool
	closeCh               chan struct{}
	ctx                   context.Context
	cancel                context.CancelFunc
	runDone               chan struct{}
	portForwardingBlocked bool
	userPermitted         []string
}

func newSocksServerMux(srv *Server, sessID string, toMuxR *io.PipeReader, toMuxW *io.PipeWriter, fromMuxR *io.PipeReader, fromMuxW *io.PipeWriter, portForwardingBlocked bool, userPermitted []string) *socksServerMux {
	ctx, cancel := context.WithCancel(srv.sessionContext())
	return &socksServerMux{
		srv:                   srv,
		sessID:                sessID,
		log:                   srv.log.With("component", "socks_server_mux", "session", sessID),
		toMuxR:                toMuxR,
		toMuxW:                toMuxW,
		fromMuxR:              fromMuxR,
		fromMuxW:              fromMuxW,
		streams:               make(map[uint32]*serverStream),
		closeCh:               make(chan struct{}),
		ctx:                   ctx,
		cancel:                cancel,
		runDone:               make(chan struct{}),
		portForwardingBlocked: portForwardingBlocked,
		userPermitted:         userPermitted,
	}
}

func (smux *socksServerMux) sendFrame(f socks5.MuxFrame) error {
	smux.wMu.Lock()
	defer smux.wMu.Unlock()
	if smux.closed.Load() {
		return io.ErrClosedPipe
	}
	return socks5.WriteMuxFrame(smux.fromMuxW, f)
}

func (smux *socksServerMux) Run(ctx context.Context) {
	defer func() {
		_ = smux.Close()
		close(smux.runDone)
	}()

	go func() {
		select {
		case <-ctx.Done():
			_ = smux.Close()
		case <-smux.closeCh:
		}
	}()

	for {
		f, err := socks5.ReadMuxFrame(smux.toMuxR)
		if err != nil {
			return
		}
		switch f.Type {
		case socks5.TypeStreamOpen:
			smux.handleOpen(f.StreamID, string(f.Payload))
		case socks5.TypeStreamData:
			smux.handleData(f.StreamID, f.Payload)
		case socks5.TypeStreamClose:
			smux.handleClose(f.StreamID, f.Payload)
		case socks5.TypeStreamReset:
			smux.handleReset(f.StreamID, string(f.Payload))
		default:
			smux.log.Debug("unknown mux frame type", "type", f.Type, "streamID", f.StreamID)
		}
	}
}

func (smux *socksServerMux) handleOpen(streamID uint32, target string) {
	smux.mu.Lock()
	if smux.closed.Load() {
		smux.mu.Unlock()
		return
	}
	maxStreams := smux.srv.Config().MaxSocksStreams
	if maxStreams <= 0 {
		maxStreams = 512
	}
	if len(smux.streams) >= maxStreams {
		smux.mu.Unlock()
		smux.log.Warn("socks max streams capacity reached", "limit", maxStreams, "streamID", streamID)
		_ = smux.sendFrame(socks5.MuxFrame{
			StreamID: streamID,
			Type:     socks5.TypeStreamOpenFail,
			Payload:  socks5.EncodeOpenFail(socks5.RepGeneralFailure, "max streams capacity reached"),
		})
		return
	}
	if _, exists := smux.streams[streamID]; exists {
		smux.mu.Unlock()
		return
	}
	smux.mu.Unlock()

	if _, _, err := net.SplitHostPort(target); err != nil {
		_ = smux.sendFrame(socks5.MuxFrame{
			StreamID: streamID,
			Type:     socks5.TypeStreamOpenFail,
			Payload:  socks5.EncodeOpenFail(socks5.RepAddressNotSupported, "invalid host:port: "+err.Error()),
		})
		return
	}

	// User RBAC Check: if port forwarding blocked for this key
	if smux.portForwardingBlocked {
		smux.log.Warn("socks destination blocked: port forwarding disabled for user", "target", target, "streamID", streamID)
		_ = smux.sendFrame(socks5.MuxFrame{
			StreamID: streamID,
			Type:     socks5.TypeStreamOpenFail,
			Payload:  socks5.EncodeOpenFail(socks5.RepConnectionNotAllowed, "port forwarding disabled for user"),
		})
		return
	}

	// Security ACL Check: strict enforcement of allow_destinations ruleset
	if !config.DestinationAllowed(target, smux.srv.Config().AllowDestinations) {
		smux.log.Warn("socks destination forbidden by ruleset", "target", target, "streamID", streamID)
		_ = smux.sendFrame(socks5.MuxFrame{
			StreamID: streamID,
			Type:     socks5.TypeStreamOpenFail,
			Payload:  socks5.EncodeOpenFail(socks5.RepConnectionNotAllowed, "destination forbidden by ruleset"),
		})
		return
	}

	// User RBAC Check: per-key permitopen restrictions
	if len(smux.userPermitted) > 0 && !config.DestinationAllowed(target, smux.userPermitted) {
		smux.log.Warn("socks destination forbidden by user policy", "target", target, "streamID", streamID)
		_ = smux.sendFrame(socks5.MuxFrame{
			StreamID: streamID,
			Type:     socks5.TypeStreamOpenFail,
			Payload:  socks5.EncodeOpenFail(socks5.RepConnectionNotAllowed, "destination forbidden by user policy"),
		})
		return
	}

	go func(streamID uint32, target string) {
		dialCtx, dialCancel := context.WithTimeout(smux.ctx, smux.srv.Config().DialTimeout.Duration())
		defer dialCancel()

		d := net.Dialer{KeepAlive: 15 * time.Second}
		dconn, err := d.DialContext(dialCtx, "tcp", target)
		if err != nil {
			rep := mapDialErrorToSocksRep(err)
			smux.log.Debug("socks destination dial failed", "target", target, "streamID", streamID, "err", err, "rep", rep)
			_ = smux.sendFrame(socks5.MuxFrame{
				StreamID: streamID,
				Type:     socks5.TypeStreamOpenFail,
				Payload:  socks5.EncodeOpenFail(rep, err.Error()),
			})
			return
		}

		st := &serverStream{
			id:         streamID,
			target:     target,
			conn:       dconn,
			dataCh:     make(chan []byte, 64),
			closeWrCh:  make(chan struct{}, 1),
			resetCh:    make(chan struct{}),
			readerDone: make(chan struct{}),
			writerDone: make(chan struct{}),
		}

		smux.mu.Lock()
		if smux.closed.Load() {
			smux.mu.Unlock()
			_ = dconn.Close()
			return
		}
		smux.streams[streamID] = st
		smux.mu.Unlock()

		bndAddr := dconn.LocalAddr().String()
		if err := smux.sendFrame(socks5.MuxFrame{
			StreamID: streamID,
			Type:     socks5.TypeStreamOpenOK,
			Payload:  []byte(bndAddr),
		}); err != nil {
			smux.closeStream(streamID)
			return
		}

		// Dedicated writer goroutine: moves data from channel to target TCP conn
		go func(st *serverStream) {
			defer close(st.writerDone)
			for {
				select {
				case data, ok := <-st.dataCh:
					if !ok {
						return
					}
					if _, err := st.conn.Write(data); err != nil {
						smux.closeStream(st.id)
						_ = smux.sendFrame(socks5.MuxFrame{
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
				case <-smux.ctx.Done():
					return
				}
			}
		}(st)

		// Dedicated reader goroutine: moves data from target TCP conn to tunnel
		go func(st *serverStream) {
			defer close(st.readerDone)

			buf := make([]byte, 32768)
			for {
				n, err := st.conn.Read(buf)
				if n > 0 {
					payload := make([]byte, n)
					copy(payload, buf[:n])
					if err := smux.sendFrame(socks5.MuxFrame{
						StreamID: st.id,
						Type:     socks5.TypeStreamData,
						Payload:  payload,
					}); err != nil {
						return
					}
				}
				if err != nil {
					if errors.Is(err, io.EOF) {
						_ = smux.sendFrame(socks5.MuxFrame{
							StreamID: st.id,
							Type:     socks5.TypeStreamClose,
							Payload:  []byte{socks5.CloseHalfWrite},
						})
					} else if !st.closed.Load() {
						_ = smux.sendFrame(socks5.MuxFrame{
							StreamID: st.id,
							Type:     socks5.TypeStreamReset,
							Payload:  []byte(err.Error()),
						})
					}
					return
				}
			}
		}(st)

		// Lifecycle coordinator: wait for both directions to complete or reset/cancel
		go func(st *serverStream) {
			select {
			case <-st.resetCh:
			case <-smux.ctx.Done():
			case <-st.readerDone:
				<-st.writerDone
			case <-st.writerDone:
				<-st.readerDone
			}
			smux.closeStream(st.id)
		}(st)
	}(streamID, target)
}

func (smux *socksServerMux) handleData(streamID uint32, payload []byte) {
	smux.mu.Lock()
	st := smux.streams[streamID]
	smux.mu.Unlock()
	if st == nil || st.closed.Load() {
		return
	}

	select {
	case st.dataCh <- payload:
	case <-st.resetCh:
	case <-smux.ctx.Done():
	default:
		// Brief bounded block to avoid dropping data under transient burst
		select {
		case st.dataCh <- payload:
		case <-time.After(3 * time.Second):
			smux.log.Warn("socks stream write buffer saturated, resetting", "streamID", streamID)
			smux.closeStream(streamID)
			_ = smux.sendFrame(socks5.MuxFrame{
				StreamID: streamID,
				Type:     socks5.TypeStreamReset,
				Payload:  []byte("write buffer saturated"),
			})
		}
	}
}

func (smux *socksServerMux) handleClose(streamID uint32, payload []byte) {
	smux.mu.Lock()
	st := smux.streams[streamID]
	smux.mu.Unlock()
	if st == nil {
		return
	}
	dir := socks5.CloseHalfWrite
	if len(payload) > 0 {
		dir = payload[0]
	}
	if dir == socks5.CloseHalfWrite {
		select {
		case st.closeWrCh <- struct{}{}:
		default:
		}
		return
	}
	smux.closeStream(streamID)
}

func (smux *socksServerMux) handleReset(streamID uint32, reason string) {
	smux.closeStream(streamID)
}

func (smux *socksServerMux) closeStream(streamID uint32) {
	smux.mu.Lock()
	st := smux.streams[streamID]
	delete(smux.streams, streamID)
	smux.mu.Unlock()

	if st != nil {
		st.close()
	}
}

func (smux *socksServerMux) Close() error {
	if smux.closed.CompareAndSwap(false, true) {
		smux.cancel()
		close(smux.closeCh)

		if smux.toMuxW != nil {
			_ = smux.toMuxW.CloseWithError(io.ErrClosedPipe)
		}
		if smux.fromMuxW != nil {
			_ = smux.fromMuxW.CloseWithError(io.ErrClosedPipe)
		}
		if smux.toMuxR != nil {
			_ = smux.toMuxR.Close()
		}
		if smux.fromMuxR != nil {
			_ = smux.fromMuxR.Close()
		}

		smux.mu.Lock()
		for _, st := range smux.streams {
			st.close()
		}
		smux.streams = make(map[uint32]*serverStream)
		smux.mu.Unlock()
	}
	return nil
}

func mapDialErrorToSocksRep(err error) byte {
	if err == nil {
		return socks5.RepSucceeded
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return socks5.RepHostUnreachable
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return socks5.RepHostUnreachable
		}
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return socks5.RepConnectionRefused
		}
		if errors.Is(opErr.Err, syscall.ENETUNREACH) {
			return socks5.RepNetworkUnreachable
		}
		if errors.Is(opErr.Err, syscall.EHOSTUNREACH) {
			return socks5.RepHostUnreachable
		}
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return socks5.RepConnectionRefused
	}
	if errors.Is(err, syscall.ENETUNREACH) {
		return socks5.RepNetworkUnreachable
	}
	if errors.Is(err, syscall.EHOSTUNREACH) {
		return socks5.RepHostUnreachable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return socks5.RepHostUnreachable
	}

	str := strings.ToLower(err.Error())
	if strings.Contains(str, "refused") {
		return socks5.RepConnectionRefused
	}
	if strings.Contains(str, "no such host") || strings.Contains(str, "host unreachable") || strings.Contains(str, "lookup") {
		return socks5.RepHostUnreachable
	}
	if strings.Contains(str, "network unreachable") {
		return socks5.RepNetworkUnreachable
	}
	return socks5.RepGeneralFailure
}
