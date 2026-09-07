package transport

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

const (
	tcpBufSize   = 128 * 1024
	dialTimeout  = 10 * time.Second
	tcpKeepAlive = 15 * time.Second
)

type tcpConn struct {
	raw *net.TCPConn
	br  *bufio.Reader
	bw  *bufio.Writer
}

func DialTCP(ctx context.Context, addr string) (Conn, error) {
	d := net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: tcpKeepAlive,
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return WrapTCP(c)
}

func ListenTCP(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

func WrapTCP(c net.Conn) (Conn, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("transport: not a TCP connection")
	}
	if err := tc.SetNoDelay(true); err != nil {
		_ = tc.Close()
		return nil, err
	}
	if err := tc.SetKeepAlive(true); err != nil {
		_ = tc.Close()
		return nil, err
	}
	if err := tc.SetKeepAlivePeriod(tcpKeepAlive); err != nil {
		_ = tc.Close()
		return nil, err
	}
	return &tcpConn{
		raw: tc,
		br:  bufio.NewReaderSize(tc, tcpBufSize),
		bw:  bufio.NewWriterSize(tc, tcpBufSize),
	}, nil
}

func (c *tcpConn) ReadFrame() (proto.Frame, error) {
	return proto.ReadFrame(c.br)
}

func (c *tcpConn) WriteFrame(f proto.Frame) error {
	if err := proto.WriteFrame(c.bw, f); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

func (c *tcpConn) LocalAddr() net.Addr  { return c.raw.LocalAddr() }
func (c *tcpConn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }
func (c *tcpConn) Kind() Kind           { return KindTCP }

func (c *tcpConn) Close() error {
	// Do not Flush here: WriteFrame is the only writer, and Close can race with it.
	return c.raw.Close()
}
