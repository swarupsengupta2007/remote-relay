//go:build windows

package relay

import (
	"context"
	"errors"
	"net"
)

func (s *Server) setupHotRestartSignal(ctx context.Context) {}
func (s *Server) setupSIGHUPSignal(ctx context.Context)     {}

func (s *Server) HandoverTo(unixConn *net.UnixConn) error {
	return errors.New("socket handover is not supported on Windows")
}

func (s *Server) hotRestartPlatform() error {
	return errors.New("hot restart is not supported on Windows")
}
