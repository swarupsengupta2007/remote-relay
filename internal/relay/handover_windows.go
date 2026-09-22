//go:build windows

package relay

import (
	"errors"
	"net"
	"os"
)

var errNotSupported = errors.New("socket handover is not supported on Windows")

func sendHandover(conn *net.UnixConn, state HandoverState, files []*os.File) error {
	return errNotSupported
}

func receiveHandover(conn *net.UnixConn) (*HandoverState, []*os.File, error) {
	return nil, nil, errNotSupported
}
