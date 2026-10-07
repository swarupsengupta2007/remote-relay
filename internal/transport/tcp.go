package transport

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
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
	return DialHappyEyeballsTCP(ctx, addr, DefaultConnectionAttemptDelay)
}

func DialTCPWithDelay(ctx context.Context, addr string, delay time.Duration) (Conn, error) {
	return DialHappyEyeballsTCP(ctx, addr, delay)
}

func DialTCPWithBind(ctx context.Context, addr string, bind BindConfig) (Conn, error) {
	return DialHappyEyeballsTCPWithResolverAndBind(ctx, addr, DefaultConnectionAttemptDelay, nil, nil, bind)
}

func DialTCPWithDelayAndBind(ctx context.Context, addr string, delay time.Duration, bind BindConfig) (Conn, error) {
	return DialHappyEyeballsTCPWithResolverAndBind(ctx, addr, delay, nil, nil, bind)
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

func (c *tcpConn) RawTCPConn() *net.TCPConn {
	return c.raw
}

func (c *tcpConn) Buffered() int {
	return c.br.Buffered()
}

func (c *tcpConn) ReadFrameHeader() (proto.Type, uint32, error) {
	var hdr [5]byte
	if c.br.Buffered() >= 5 {
		if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
			return 0, 0, err
		}
	} else if c.br.Buffered() > 0 {
		if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
			return 0, 0, err
		}
	} else {
		if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
			return 0, 0, err
		}
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > proto.MaxFrameLen {
		return 0, 0, proto.ErrFrame
	}
	typ := proto.Type(hdr[0])
	if !typ.Known() {
		return 0, 0, proto.ErrProto
	}
	return typ, n, nil
}

func (c *tcpConn) ReadPayload(n uint32) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if c.br.Buffered() > 0 {
		if _, err := io.ReadFull(c.br, buf); err != nil {
			return nil, err
		}
	} else {
		if _, err := io.ReadFull(c.raw, buf); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func (c *tcpConn) ReadFrame() (proto.Frame, error) {
	typ, n, err := c.ReadFrameHeader()
	if err != nil {
		return proto.Frame{}, err
	}
	payload, err := c.ReadPayload(n)
	if err != nil {
		return proto.Frame{}, err
	}
	return proto.Frame{Type: typ, Payload: payload}, nil
}

func (c *tcpConn) WriteDataFrameHeader(seq uint64, dataLen int) error {
	if err := c.bw.Flush(); err != nil {
		return err
	}
	var hdr [13]byte
	hdr[0] = byte(proto.TypeData)
	binary.BigEndian.PutUint32(hdr[1:5], uint32(8+dataLen))
	binary.BigEndian.PutUint64(hdr[5:13], seq)
	_, err := c.raw.Write(hdr[:])
	return err
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

func (c *tcpConn) WaitFrame() error {
	_, err := c.br.Peek(1)
	return err
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

func (c *tcpConn) ResetReader() {
	c.br.Reset(c.raw)
}

var (
	_ Conn                  = (*tcpConn)(nil)
	_ TCPConnProvider       = (*tcpConn)(nil)
	_ FrameHeaderReader     = (*tcpConn)(nil)
	_ DataFrameHeaderWriter = (*tcpConn)(nil)
	_ FrameWaiter           = (*tcpConn)(nil)
)
