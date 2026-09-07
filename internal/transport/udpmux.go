package transport

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

// Stack tags (D10). Added on egress, stripped on ingress. Do not sniff payloads.
const (
	TagKCP  byte = 0x01
	TagQUIC byte = 0x02
)

const maxUDP = 64 * 1024

var errMuxClosed = errors.New("udp mux closed")

type datagram struct {
	buf  []byte
	addr net.Addr
}

// UDPMux owns one UDP socket and demuxes by the 1-byte stack tag.
type UDPMux struct {
	conn net.PacketConn

	quic *taggedConn
	kcp  *taggedConn

	writeMu sync.Mutex

	probeMu      sync.Mutex
	probeHandler func(token [16]byte, nonce uint64, addr net.Addr)
	probeWait    map[uint64]*probeWaiter

	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
}

func ListenUDPMux(addr string) (*UDPMux, error) {
	if addr == "" {
		addr = "0.0.0.0:7443"
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(4 << 20)
		_ = uc.SetWriteBuffer(4 << 20)
	}
	return NewUDPMux(pc), nil
}

func NewUDPMux(conn net.PacketConn) *UDPMux {
	m := &UDPMux{
		conn:      conn,
		probeWait: make(map[uint64]*probeWaiter),
		closed:    make(chan struct{}),
	}
	m.quic = newTaggedConn(m, TagQUIC)
	m.kcp = newTaggedConn(m, TagKCP)
	go m.readLoop()
	return m
}

func (m *UDPMux) QUIC() net.PacketConn { return m.quic }
func (m *UDPMux) KCP() net.PacketConn  { return m.kcp }

func (m *UDPMux) LocalAddr() net.Addr {
	if m == nil || m.conn == nil {
		return nil
	}
	return m.conn.LocalAddr()
}

func (m *UDPMux) SetProbeHandler(h func(token [16]byte, nonce uint64, addr net.Addr)) {
	m.probeMu.Lock()
	m.probeHandler = h
	m.probeMu.Unlock()
}

func (m *UDPMux) Close() error {
	m.closeOnce.Do(func() {
		close(m.closed)
		m.closeErr = m.conn.Close()
		m.quic.shutdown()
		m.kcp.shutdown()
	})
	return m.closeErr
}

func (m *UDPMux) readLoop() {
	buf := make([]byte, maxUDP)
	for {
		n, addr, err := m.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-m.closed:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n < 1 {
			continue
		}
		tag := buf[0]
		switch tag {
		case TagQUIC:
			m.quic.deliver(buf[1:n], addr)
		case TagKCP:
			m.kcp.deliver(buf[1:n], addr)
		case byte(proto.TypeProbe):
			if n != 1+24 {
				continue
			}
			token, nonce, perr := proto.DecodeProbe(buf[1:n])
			if perr != nil {
				continue
			}
			m.probeMu.Lock()
			h := m.probeHandler
			m.probeMu.Unlock()
			if h != nil {
				h(token, nonce, addr)
			}
		case byte(proto.TypeProbeOK):
			if n != 1+8 {
				continue
			}
			nonce, perr := proto.DecodeProbeOK(buf[1:n])
			if perr != nil {
				continue
			}
			m.signalProbeOK(nonce, addr)
		default:
			// unknown tag: drop (never sniff QUIC/KCP payloads)
		}
	}
}

func (m *UDPMux) writeTagged(tag byte, p []byte, addr net.Addr) (int, error) {
	if len(p)+1 > maxUDP {
		return 0, errors.New("udp mux: datagram too large")
	}
	out := make([]byte, 1+len(p))
	out[0] = tag
	copy(out[1:], p)
	m.writeMu.Lock()
	n, err := m.conn.WriteTo(out, addr)
	m.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	if n < 1 {
		return 0, err
	}
	sent := n - 1
	if sent > len(p) {
		sent = len(p)
	}
	if sent < 0 {
		sent = 0
	}
	return sent, nil
}

func (m *UDPMux) writeRaw(p []byte, addr net.Addr) error {
	m.writeMu.Lock()
	_, err := m.conn.WriteTo(p, addr)
	m.writeMu.Unlock()
	return err
}

func (m *UDPMux) WriteProbe(addr net.Addr, token [16]byte, nonce uint64) error {
	p := make([]byte, 1+24)
	p[0] = byte(proto.TypeProbe)
	copy(p[1:], proto.EncodeProbe(token, nonce))
	return m.writeRaw(p, addr)
}

func (m *UDPMux) WriteProbeOK(addr net.Addr, nonce uint64) error {
	p := make([]byte, 1+8)
	p[0] = byte(proto.TypeProbeOK)
	copy(p[1:], proto.EncodeProbeOK(nonce))
	return m.writeRaw(p, addr)
}

type probeWaiter struct {
	ch   chan struct{}
	addr net.Addr
}

func (m *UDPMux) armProbeWait(nonce uint64, addr net.Addr) <-chan struct{} {
	m.probeMu.Lock()
	defer m.probeMu.Unlock()
	if w, ok := m.probeWait[nonce]; ok {
		return w.ch
	}
	ch := make(chan struct{})
	m.probeWait[nonce] = &probeWaiter{ch: ch, addr: addr}
	return ch
}

func (m *UDPMux) disarmProbeWait(nonce uint64) {
	m.probeMu.Lock()
	delete(m.probeWait, nonce)
	m.probeMu.Unlock()
}

func (m *UDPMux) signalProbeOK(nonce uint64, from net.Addr) {
	m.probeMu.Lock()
	w, ok := m.probeWait[nonce]
	if !ok {
		m.probeMu.Unlock()
		return
	}
	if w.addr != nil && from != nil && !sameUDPAddr(w.addr, from) {
		m.probeMu.Unlock()
		return
	}
	delete(m.probeWait, nonce)
	m.probeMu.Unlock()
	select {
	case <-w.ch:
	default:
		close(w.ch)
	}
}

func sameUDPAddr(a, b net.Addr) bool {
	ua, ok1 := a.(*net.UDPAddr)
	ub, ok2 := b.(*net.UDPAddr)
	if ok1 && ok2 {
		return ua.Port == ub.Port && ua.IP.Equal(ub.IP)
	}
	return a != nil && b != nil && a.String() == b.String()
}

// Probe sends up to attempts PROBE datagrams and waits for a matching PROBE_OK.
// The waiter is armed before the first write so a fast localhost OK cannot be dropped.
func Probe(ctx context.Context, mux *UDPMux, addr net.Addr, token [16]byte, attempts int, timeout time.Duration) error {
	if attempts <= 0 {
		attempts = 2
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	const nonce = uint64(1)
	ch := mux.armProbeWait(nonce, addr)
	defer mux.disarmProbeWait(nonce)
	var last error
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := mux.WriteProbe(addr, token, nonce); err != nil {
			last = err
			continue
		}
		sub, cancel := context.WithTimeout(ctx, timeout)
		select {
		case <-ch:
			cancel()
			return nil
		case <-sub.Done():
			last = sub.Err()
			cancel()
		case <-mux.closed:
			cancel()
			return errMuxClosed
		case <-ctx.Done():
			cancel()
			return ctx.Err()
		}
	}
	if last == nil {
		last = errors.New("udp probe failed")
	}
	return last
}

// UDPBindAll returns a wildcard bind in the same address family as dst.
func UDPBindAll(dst net.Addr) string {
	ua, ok := dst.(*net.UDPAddr)
	if !ok || ua == nil || ua.IP == nil {
		return ":0"
	}
	if ua.IP.To4() != nil {
		return "0.0.0.0:0"
	}
	return "[::]:0"
}

type taggedConn struct {
	mux  *UDPMux
	tag  byte
	ch   chan datagram
	dead chan struct{}

	mu       sync.Mutex
	closed   bool
	readDead time.Time
	poke     chan struct{}
}

func newTaggedConn(m *UDPMux, tag byte) *taggedConn {
	return &taggedConn{
		mux:  m,
		tag:  tag,
		ch:   make(chan datagram, 128),
		dead: make(chan struct{}),
		poke: make(chan struct{}, 1),
	}
}

func (c *taggedConn) deliver(p []byte, addr net.Addr) {
	if len(p) == 0 {
		p = []byte{}
	} else {
		cp := make([]byte, len(p))
		copy(cp, p)
		p = cp
	}
	select {
	case <-c.dead:
		return
	default:
	}
	select {
	case c.ch <- datagram{buf: p, addr: addr}:
	default:
		// drop: UDP-like when the stack is slow or nobody is listening
	}
}

func (c *taggedConn) shutdown() {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.dead)
	}
	c.mu.Unlock()
}

func (c *taggedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		dl := c.readDead
		c.mu.Unlock()

		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}

		select {
		case pkt, ok := <-c.ch:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return 0, nil, net.ErrClosed
			}
			n := copy(p, pkt.buf)
			return n, pkt.addr, nil
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.dead:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-c.mux.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-c.poke:
			if timer != nil {
				timer.Stop()
			}
			continue
		}
	}
}

func (c *taggedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.dead:
		return 0, net.ErrClosed
	case <-c.mux.closed:
		return 0, net.ErrClosed
	default:
	}
	return c.mux.writeTagged(c.tag, p, addr)
}

func (c *taggedConn) Close() error {
	c.shutdown()
	return nil
}

func (c *taggedConn) LocalAddr() net.Addr { return c.mux.LocalAddr() }

func (c *taggedConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *taggedConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDead = t
	c.mu.Unlock()
	select {
	case c.poke <- struct{}{}:
	default:
	}
	return nil
}

func (c *taggedConn) SetWriteDeadline(time.Time) error { return nil }

type sockBuf interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

func (c *taggedConn) SetReadBuffer(n int) error {
	if s, ok := c.mux.conn.(sockBuf); ok {
		return s.SetReadBuffer(n)
	}
	return nil
}

func (c *taggedConn) SetWriteBuffer(n int) error {
	if s, ok := c.mux.conn.(sockBuf); ok {
		return s.SetWriteBuffer(n)
	}
	return nil
}
