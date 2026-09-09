package transport

import (
	"net"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

type Kind int

const (
	KindTCP Kind = iota
	KindQUIC
	KindKCP
)

func (k Kind) String() string {
	switch k {
	case KindTCP:
		return "tcp"
	case KindQUIC:
		return "quic"
	case KindKCP:
		return "kcp"
	default:
		return "unknown"
	}
}

type Conn interface {
	ReadFrame() (proto.Frame, error)
	WriteFrame(proto.Frame) error
	SetDeadline(time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Kind() Kind
	Close() error
	ResetReader()
}
