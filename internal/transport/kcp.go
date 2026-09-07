package transport

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/proto"
	kcp "github.com/xtaci/kcp-go/v5"
)

const (
	kcpBufSize   = 128 * 1024
	kcpSocketBuf = 4 << 20
	// kcp-go SetMtu; MSS = MTU - IKCP_OVERHEAD(24) = 1376 as specified.
	kcpMTU = 1376 + 24
)

// TuneKCP applies §8.3 session parameters. Stream mode is a separate
// kcp-go knob from SetNoDelay's nc (no-congestion) argument.
func TuneKCP(sess *kcp.UDPSession) {
	if sess == nil {
		return
	}
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetStreamMode(true)
	sess.SetMtu(kcpMTU)
	sess.SetWindowSize(256, 256)
	sess.SetACKNoDelay(true)
	_ = sess.SetReadBuffer(kcpSocketBuf)
	_ = sess.SetWriteBuffer(kcpSocketBuf)
}

// KCPListener is one kcp.Listener bound to a PacketConn (mux tag 0x01).
// ServeConn keeps ownConn=false so Close does not take the shared socket.
type KCPListener struct {
	ln *kcp.Listener
}

func ListenKCP(pc net.PacketConn) (*KCPListener, error) {
	ln, err := kcp.ServeConn(nil, 0, 0, pc)
	if err != nil {
		return nil, err
	}
	_ = ln.SetReadBuffer(kcpSocketBuf)
	_ = ln.SetWriteBuffer(kcpSocketBuf)
	return &KCPListener{ln: ln}, nil
}

func (l *KCPListener) Accept() (Conn, error) {
	sess, err := l.ln.AcceptKCP()
	if err != nil {
		return nil, err
	}
	return wrapKCP(sess), nil
}

func (l *KCPListener) Close() error {
	if l == nil || l.ln == nil {
		return nil
	}
	return l.ln.Close()
}

func (l *KCPListener) Addr() net.Addr {
	if l == nil || l.ln == nil {
		return nil
	}
	return l.ln.Addr()
}

// DialKCP opens a KCP conversation on pc (already tag-stripped by udpMux).
// NewConn2 is the PacketConn form of DialWithOptions(remote, nil, 0, 0);
// conv is chosen by kcp-go, not forced.
func DialKCP(ctx context.Context, pc net.PacketConn, addr net.Addr) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sess, err := kcp.NewConn2(addr, nil, 0, 0, pc)
	if err != nil {
		return nil, err
	}
	return wrapKCP(sess), nil
}

type kcpConn struct {
	sess      *kcp.UDPSession
	br        *bufio.Reader
	bw        *bufio.Writer
	closeOnce sync.Once
}

func wrapKCP(sess *kcp.UDPSession) Conn {
	TuneKCP(sess)
	return &kcpConn{
		sess: sess,
		br:   bufio.NewReaderSize(sess, kcpBufSize),
		bw:   bufio.NewWriterSize(sess, kcpBufSize),
	}
}

func (c *kcpConn) ReadFrame() (proto.Frame, error) {
	return proto.ReadFrame(c.br)
}

func (c *kcpConn) WriteFrame(f proto.Frame) error {
	if err := proto.WriteFrame(c.bw, f); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *kcpConn) SetDeadline(t time.Time) error {
	return c.sess.SetDeadline(t)
}

func (c *kcpConn) LocalAddr() net.Addr  { return c.sess.LocalAddr() }
func (c *kcpConn) RemoteAddr() net.Addr { return c.sess.RemoteAddr() }
func (c *kcpConn) Kind() Kind           { return KindKCP }

func (c *kcpConn) Close() error {
	// Do not Flush here: WriteFrame is the only writer, and Close can race with it.
	// Wake readers immediately; delay sess.Close so a just-written BYE can be ACKed.
	c.closeOnce.Do(func() {
		_ = c.sess.SetDeadline(time.Now())
		go func() {
			time.Sleep(100 * time.Millisecond)
			_ = c.sess.Close()
		}()
	})
	return nil
}
