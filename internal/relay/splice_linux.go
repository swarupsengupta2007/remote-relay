//go:build linux

package relay

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	splicedBytesIn   atomic.Uint64
	splicedBytesOut  atomic.Uint64
	spliceCallsTotal atomic.Uint64
)

// SplicedStats returns the total spliced bytes transferred in and out, and the number of splice system calls.
func SplicedStats() (in, out, calls uint64) {
	return splicedBytesIn.Load(), splicedBytesOut.Load(), spliceCallsTotal.Load()
}

// ResetSplicedStats resets the splicing statistics counters to zero.
func ResetSplicedStats() {
	splicedBytesIn.Store(0)
	splicedBytesOut.Store(0)
	spliceCallsTotal.Store(0)
}

// pipePair manages an OS pipe used as an intermediate buffer for splice(2).
type pipePair struct {
	rfd atomic.Int32
	wfd atomic.Int32
}

func newPipePair(bufSize int) (*pipePair, error) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		return nil, err
	}
	if bufSize > 0 {
		_, _ = unix.FcntlInt(uintptr(fds[0]), unix.F_SETPIPE_SZ, bufSize)
	}
	p := &pipePair{}
	p.rfd.Store(int32(fds[0]))
	p.wfd.Store(int32(fds[1]))
	return p, nil
}

func (p *pipePair) R() int {
	return int(p.rfd.Load())
}

func (p *pipePair) W() int {
	return int(p.wfd.Load())
}

func (p *pipePair) Close() error {
	var errs []error
	if r := p.rfd.Swap(-1); r >= 0 {
		if err := unix.Close(int(r)); err != nil {
			errs = append(errs, err)
		}
	}
	if w := p.wfd.Swap(-1); w >= 0 {
		if err := unix.Close(int(w)); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// getFD attempts to resolve an OS file descriptor from the given value.
func getFD(v any) (int, bool) {
	if v == nil {
		return -1, false
	}
	switch f := v.(type) {
	case *os.File:
		return int(f.Fd()), true
	case interface{ Fd() uintptr }:
		fd := int(f.Fd())
		if fd >= 0 {
			return fd, true
		}
	case interface{ RawTCPConn() *net.TCPConn }:
		tc := f.RawTCPConn()
		if tc != nil {
			return getFDFromSyscallConn(tc)
		}
	case interface {
		SyscallConn() (syscall.RawConn, error)
	}:
		return getFDFromSyscallConn(f)
	}
	return -1, false
}

func getFDFromSyscallConn(s interface {
	SyscallConn() (syscall.RawConn, error)
}) (int, bool) {
	rc, err := s.SyscallConn()
	if err != nil {
		return -1, false
	}
	var res int = -1
	err = rc.Control(func(fd uintptr) {
		res = int(fd)
	})
	if err != nil || res < 0 {
		return -1, false
	}
	return res, true
}

func isPipe(fd int) bool {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	return (st.Mode & unix.S_IFMT) == unix.S_IFIFO
}

// waitWritable blocks until fd is writable or reports an error/hangup.
func waitWritable(fd int) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	for {
		_, err := unix.Poll(fds, 1000)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return syscall.EPIPE
		}
		if fds[0].Revents&unix.POLLOUT != 0 {
			return nil
		}
	}
}

// spliceSocketToSink splices exactly count bytes from rawTCP to sinkFd.
// It returns the number of bytes that reached sinkFd, even on error.
// If sinkFd is a pipe, it splices directly socket -> sinkFd.
// If sinkFd is not a pipe (e.g. destination TCP socket), it splices socket -> pipe -> sinkFd.
func spliceSocketToSink(rawTCP *net.TCPConn, sinkFd int, p *pipePair, count int, acct *byteAcct) (int64, error) {
	if count <= 0 {
		return 0, nil
	}
	rc, err := rawTCP.SyscallConn()
	if err != nil {
		return 0, err
	}

	sinkIsPipe := isPipe(sinkFd)
	var transferred int64

	for transferred < int64(count) {
		want := int(int64(count) - transferred)

		if sinkIsPipe {
			var nSplice int64
			var sysErr error
			err := rc.Read(func(sfd uintptr) bool {
				spliceCallsTotal.Add(1)
				nSplice, sysErr = unix.Splice(int(sfd), nil, sinkFd, nil, want, unix.SPLICE_F_NONBLOCK)
				if sysErr == unix.EAGAIN || sysErr == unix.EWOULDBLOCK {
					return false
				}
				return true
			})
			if err != nil {
				return transferred, err
			}
			if sysErr != nil {
				return transferred, sysErr
			}
			if nSplice == 0 {
				return transferred, io.EOF
			}
			transferred += nSplice
			splicedBytesIn.Add(uint64(nSplice))
			if acct != nil {
				acct.add(nSplice)
			}
		} else {
			// Two-stage splice: socket -> intermediate pipe -> sinkFd
			var nDrain int64
			var sysErr error
			err := rc.Read(func(sfd uintptr) bool {
				spliceCallsTotal.Add(1)
				wfd := p.W()
				if wfd < 0 {
					sysErr = net.ErrClosed
					return true
				}
				nDrain, sysErr = unix.Splice(int(sfd), nil, wfd, nil, want, unix.SPLICE_F_NONBLOCK)
				if sysErr == unix.EAGAIN || sysErr == unix.EWOULDBLOCK {
					return false
				}
				return true
			})
			if err != nil {
				return transferred, err
			}
			if sysErr != nil {
				return transferred, sysErr
			}
			if nDrain == 0 {
				return transferred, io.EOF
			}

			// Pump from intermediate pipe to sinkFd
			var pumped int64
			for pumped < nDrain {
				spliceCallsTotal.Add(1)
				rfd := p.R()
				if rfd < 0 {
					return transferred + pumped, net.ErrClosed
				}
				nPump, err := unix.Splice(rfd, nil, sinkFd, nil, int(nDrain-pumped), 0)
				if nPump > 0 {
					pumped += nPump
				}
				if err != nil {
					if err == unix.EINTR {
						continue
					}
					if err == unix.EAGAIN {
						// Non-blocking sink is full; wait rather than strand
						// drained bytes in the pipe.
						if werr := waitWritable(sinkFd); werr != nil {
							return transferred + pumped, werr
						}
						continue
					}
					return transferred + pumped, err
				}
				if nPump == 0 {
					return transferred + pumped, io.ErrUnexpectedEOF
				}
			}
			transferred += nDrain
			splicedBytesIn.Add(uint64(nDrain))
			if acct != nil {
				acct.add(nDrain)
			}
		}
	}
	return transferred, nil
}

// spliceSrcToSocket drains up to count bytes from srcFd into intermediate pipe p,
// optionally duplicates pages to pRetain via tee(2) to retain unacknowledged data in sendLog,
// writes the frame header via writeHdr, and splices the payload into rawTCP.
func spliceSrcToSocket(srcFd int, rawTCP *net.TCPConn, p *pipePair, pRetain *pipePair, count int, writeHdr func(n int) error, acct *byteAcct) (int64, []byte, error) {
	if count <= 0 {
		return 0, nil, nil
	}

	// Step 1: Drain from srcFd into intermediate pipe
	spliceCallsTotal.Add(1)
	wfd := p.W()
	if wfd < 0 {
		return 0, nil, net.ErrClosed
	}
	nDrain, err := unix.Splice(srcFd, nil, wfd, nil, count, 0)
	if err != nil {
		if err == unix.EINTR {
			return 0, nil, nil
		}
		return 0, nil, err
	}
	if nDrain == 0 {
		return 0, nil, io.EOF
	}

	// Step 2: Tee to retain pipe for sendLog ring buffer if requested
	var retained []byte
	if pRetain != nil {
		spliceCallsTotal.Add(1)
		rfd := p.R()
		rwfd := pRetain.W()
		if rfd >= 0 && rwfd >= 0 {
			_, tErr := unix.Tee(rfd, rwfd, int(nDrain), 0)
			if tErr == nil {
				buf := make([]byte, nDrain)
				rrfd := pRetain.R()
				if rrfd >= 0 {
					// Read the pooled pipe directly. Wrapping rrfd in os.NewFile
					// would let the runtime finalizer close the pooled descriptor.
					if rErr := readFullFD(rrfd, buf); rErr == nil {
						retained = buf
					}
				}
			}
		}
	}

	// Step 3: Write frame header
	if writeHdr != nil {
		if err := writeHdr(int(nDrain)); err != nil {
			return 0, retained, err
		}
	}

	// Step 4: Splice from intermediate pipe into rawTCP
	rc, err := rawTCP.SyscallConn()
	if err != nil {
		return 0, retained, err
	}

	var pumped int64
	for pumped < nDrain {
		want := int(nDrain - pumped)
		var nPump int64
		var sysErr error
		err := rc.Write(func(sfd uintptr) bool {
			spliceCallsTotal.Add(1)
			rfd := p.R()
			if rfd < 0 {
				sysErr = net.ErrClosed
				return true
			}
			nPump, sysErr = unix.Splice(rfd, nil, int(sfd), nil, want, unix.SPLICE_F_NONBLOCK)
			if sysErr == unix.EAGAIN || sysErr == unix.EWOULDBLOCK {
				return false
			}
			return true
		})
		if err != nil {
			return pumped, retained, err
		}
		if sysErr != nil {
			return pumped, retained, sysErr
		}
		pumped += nPump
	}

	splicedBytesOut.Add(uint64(pumped))
	if acct != nil {
		acct.add(pumped)
	}
	return pumped, retained, nil
}

// readFullFD reads len(buf) bytes from a raw file descriptor.
func readFullFD(fd int, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := unix.Read(fd, buf[total:])
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		total += n
	}
	return nil
}
