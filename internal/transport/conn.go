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
	KindWebSocket
)

func (k Kind) String() string {
	switch k {
	case KindTCP:
		return "tcp"
	case KindQUIC:
		return "quic"
	case KindKCP:
		return "kcp"
	case KindWebSocket:
		return "ws"
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

// TCPConnProvider allows unwrapping the raw underlying TCP connection for zero-copy operations.
type TCPConnProvider interface {
	RawTCPConn() *net.TCPConn
}

// FrameHeaderReader allows reading frame headers without over-buffering payload bytes.
type FrameHeaderReader interface {
	ReadFrameHeader() (proto.Type, uint32, error)
	ReadPayload(n uint32) ([]byte, error)
	Buffered() int
}

// DataFrameHeaderWriter allows writing only the 13-byte TypeData frame header before splicing payload bytes.
type DataFrameHeaderWriter interface {
	WriteDataFrameHeader(seq uint64, dataLen int) error
}

// KCPStatsProvider allows retrieving dynamic ARQ and congestion tuning statistics from a KCP connection.
type KCPStatsProvider interface {
	AdaptiveKCPStats() (TunerStats, bool)
}
