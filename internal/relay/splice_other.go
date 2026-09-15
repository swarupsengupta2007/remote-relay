//go:build !linux

package relay

import (
	"errors"
	"net"
)

// SplicedStats returns zero on non-Linux platforms.
func SplicedStats() (in, out, calls uint64) {
	return 0, 0, 0
}

// ResetSplicedStats is a no-op on non-Linux platforms.
func ResetSplicedStats() {}

type pipePair struct{}

func newPipePair(bufSize int) (*pipePair, error) {
	return nil, errors.New("splice is not supported on non-linux systems")
}

func (p *pipePair) Close() error {
	return nil
}

func getFD(v any) (int, bool) {
	return -1, false
}

func isPipe(fd int) bool {
	return false
}

func isSocket(fd int) bool {
	return false
}

func spliceSocketToSink(rawTCP *net.TCPConn, sinkFd int, p *pipePair, count int) (int64, error) {
	return 0, errors.New("splice is not supported on non-linux systems")
}

func spliceSrcToSocket(srcFd int, rawTCP *net.TCPConn, p *pipePair, pRetain *pipePair, count int, writeHdr func(n int) error) (int64, []byte, error) {
	return 0, nil, errors.New("splice is not supported on non-linux systems")
}

func spliceSliceToSocket(rawTCP *net.TCPConn, p *pipePair, data []byte, writeHdr func() error) (int64, error) {
	return 0, errors.New("splice is not supported on non-linux systems")
}
