package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/remote-relay/relay/internal/proto"
)

const quicBufSize = 128 * 1024

// NewQUICConfig maps relay idle/keepalive/window onto quic-go.
func NewQUICConfig(idle, keepalive time.Duration, window int) *quic.Config {
	w := uint64(window)
	if w < 512*1024 {
		w = 512 * 1024
	}
	return &quic.Config{
		MaxIdleTimeout:                 idle,
		KeepAlivePeriod:                keepalive,
		InitialStreamReceiveWindow:     w,
		InitialConnectionReceiveWindow: w,
		MaxIncomingStreams:             4,
		MaxIncomingUniStreams:          0,
		EnableDatagrams:                false,
	}
}

// QUICListener is one quic.Transport + Listener bound to the mux's QUIC PacketConn.
type QUICListener struct {
	tr *quic.Transport
	ln *quic.Listener
}

func ListenQUIC(pc net.PacketConn, tlsConf *tls.Config, qconf *quic.Config) (*QUICListener, error) {
	if tlsConf == nil {
		return nil, fmt.Errorf("quic: tls config required")
	}
	tr := &quic.Transport{Conn: pc}
	ln, err := tr.Listen(tlsConf, qconf)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}
	return &QUICListener{tr: tr, ln: ln}, nil
}

func (l *QUICListener) Accept(ctx context.Context) (*quic.Conn, error) {
	return l.ln.Accept(ctx)
}

func (l *QUICListener) Close() error {
	if l.ln != nil {
		_ = l.ln.Close()
	}
	if l.tr != nil {
		return l.tr.Close()
	}
	return nil
}

func (l *QUICListener) Addr() net.Addr {
	if l.ln == nil {
		return nil
	}
	return l.ln.Addr()
}

// AcceptQUICConn waits for the client-opened bidi stream and wraps it as Conn.
func AcceptQUICConn(ctx context.Context, qconn *quic.Conn) (Conn, error) {
	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return wrapQUIC(qconn, stream, nil), nil
}

// DialQUIC dials a QUIC connection on pc (already tag-stripped by udpMux)
// and opens one bidi stream carrying length-prefixed frames.
func DialQUIC(ctx context.Context, pc net.PacketConn, addr net.Addr, qconf *quic.Config) (Conn, error) {
	tr := &quic.Transport{Conn: pc}
	qconn, err := tr.Dial(ctx, addr, ClientTLSConfig(), qconf)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		go func() { _ = qconn.CloseWithError(1, "stream") }()
		_ = tr.Close()
		return nil, err
	}
	return wrapQUIC(qconn, stream, tr), nil
}

// One bidi stream carries the same length-prefixed frames as TCP so one codec
// serves all transports. Conn is a byte pipe of frames.
type quicConn struct {
	qc        *quic.Conn
	st        *quic.Stream
	tr        *quic.Transport
	br        *bufio.Reader
	bw        *bufio.Writer
	closeOnce sync.Once
}

func wrapQUIC(qc *quic.Conn, st *quic.Stream, tr *quic.Transport) Conn {
	return &quicConn{
		qc: qc,
		st: st,
		tr: tr,
		br: bufio.NewReaderSize(st, quicBufSize),
		bw: bufio.NewWriterSize(st, quicBufSize),
	}
}

func (c *quicConn) ReadFrame() (proto.Frame, error) {
	return proto.ReadFrame(c.br)
}

func (c *quicConn) WriteFrame(f proto.Frame) error {
	if err := proto.WriteFrame(c.bw, f); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *quicConn) SetDeadline(t time.Time) error {
	return c.st.SetDeadline(t)
}

func (c *quicConn) LocalAddr() net.Addr  { return c.qc.LocalAddr() }
func (c *quicConn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }
func (c *quicConn) Kind() Kind           { return KindQUIC }

func (c *quicConn) Close() error {
	// Stream FIN first so a just-written BYE can still be read. CloseWithError
	// waits for the close handshake, so it runs in the background.
	c.closeOnce.Do(func() {
		_ = c.st.Close()
		go func() {
			time.Sleep(30 * time.Millisecond)
			_ = c.qc.CloseWithError(0, "")
		}()
	})
	return nil
}

func ParseProbeToken(s string) ([16]byte, bool) {
	var tok [16]byte
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 16 {
		return tok, false
	}
	copy(tok[:], raw)
	return tok, true
}

func EncodeProbeToken(tok [16]byte) string {
	return base64.StdEncoding.EncodeToString(tok[:])
}
