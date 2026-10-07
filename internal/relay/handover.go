package relay

import (
	"net"
	"os"
	"time"

	"github.com/remote-relay/relay/internal/session"
)

// HandoverSession holds serialized state for a single active or held session.
type HandoverSession struct {
	Session         session.SessionSnapshot `json:"session"`
	UpAcked         uint64                  `json:"up_acked"`
	DownNext        uint64                  `json:"down_next"`
	UpClosed        bool                    `json:"up_closed"`
	DownClosed      bool                    `json:"down_closed"`
	SendLogBase     uint64                  `json:"send_log_base"`
	SendLogData     []byte                  `json:"send_log_data,omitempty"`
	SendLogCap      int                     `json:"send_log_cap"`
	RemainingHoldMs int64                   `json:"remaining_hold_ms"`
	ClientIP        string                  `json:"client_ip,omitempty"`
	HasDestFD       bool                    `json:"has_dest_fd"`
}

// HandoverState is the root JSON structure passed across process re-exec.
type HandoverState struct {
	Version      int       `json:"v"`
	Timestamp    time.Time `json:"timestamp"`
	HasListenTCP bool      `json:"has_listen_tcp"`
	HasListenUDP bool      `json:"has_listen_udp"`
	// HasListenWS marks a WebSocket listener FD after the UDP one.
	HasListenWS bool `json:"has_listen_ws,omitempty"`
	// DebugListen names, in FD order after the WebSocket one, the configured
	// addresses of the metrics/pprof/expvar listeners being passed.
	DebugListen []string          `json:"debug_listen,omitempty"`
	Sessions    []HandoverSession `json:"sessions"`
}

// SendHandover transmits the HandoverState and associated file descriptors
// over a connected Unix domain socket.
func SendHandover(conn *net.UnixConn, state HandoverState, files []*os.File) error {
	return sendHandover(conn, state, files)
}

// ReceiveHandover receives the HandoverState and associated file descriptors
// from a connected Unix domain socket.
func ReceiveHandover(conn *net.UnixConn) (*HandoverState, []*os.File, error) {
	return receiveHandover(conn)
}
