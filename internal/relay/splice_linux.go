//go:build linux

package relay

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

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
	rfd int
	wfd int
}

func newPipePair(bufSize int) (*pipePair, error) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		return nil, err
	}
	if bufSize > 0 {
		_, _ = unix.FcntlInt(uintptr(fds[0]), unix.F_SETPIPE_SZ, bufSize)
	}
	return &pipePair{rfd: fds[0], wfd: fds[1]}, nil
}

func (p *pipePair) Close() error {
	var errs []error
	if p.rfd >= 0 {
		if err := unix.Close(p.rfd); err != nil {
			errs = append(errs, err)
		}
		p.rfd = -1
	}
	if p.wfd >= 0 {
		if err := unix.Close(p.wfd); err != nil {
			errs = append(errs, err)
		}
		p.wfd = -1
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

func isSocket(fd int) bool {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	return (st.Mode & unix.S_IFMT) == unix.S_IFSOCK
}

// spliceSocketToSink splices exactly count bytes from rawTCP to sinkFd.
// If sinkFd is a pipe, it splices directly socket -> sinkFd.
// If sinkFd is not a pipe (e.g. destination TCP socket), it splices socket -> pipe -> sinkFd.
func spliceSocketToSink(rawTCP *net.TCPConn, sinkFd int, p *pipePair, count int) (int64, error) {
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
		} else {
			// Two-stage splice: socket -> intermediate pipe -> sinkFd
			var nDrain int64
			var sysErr error
			err := rc.Read(func(sfd uintptr) bool {
				spliceCallsTotal.Add(1)
				nDrain, sysErr = unix.Splice(int(sfd), nil, p.wfd, nil, want, unix.SPLICE_F_NONBLOCK)
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
				nPump, err := unix.Splice(p.rfd, nil, sinkFd, nil, int(nDrain-pumped), 0)
				if nPump > 0 {
					pumped += nPump
				}
				if err != nil {
					if err == unix.EINTR {
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
		}
	}
	return transferred, nil
}

// spliceSrcToSocket drains up to count bytes from srcFd into intermediate pipe p,
// optionally duplicates pages to pRetain via tee(2) to retain unacknowledged data in sendLog,
// writes the frame header via writeHdr, and splices the payload into rawTCP.
func spliceSrcToSocket(srcFd int, rawTCP *net.TCPConn, p *pipePair, pRetain *pipePair, count int, writeHdr func(n int) error) (int64, []byte, error) {
	if count <= 0 {
		return 0, nil, nil
	}

	// Step 1: Drain from srcFd into intermediate pipe
	spliceCallsTotal.Add(1)
	nDrain, err := unix.Splice(srcFd, nil, p.wfd, nil, count, 0)
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
		_, tErr := unix.Tee(p.rfd, pRetain.wfd, int(nDrain), 0)
		if tErr == nil {
			buf := make([]byte, nDrain)
			if _, rErr := io.ReadFull(os.NewFile(uintptr(pRetain.rfd), "retain"), buf); rErr == nil {
				retained = buf
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
			nPump, sysErr = unix.Splice(p.rfd, nil, int(sfd), nil, want, unix.SPLICE_F_NONBLOCK)
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
	return pumped, retained, nil
}

// spliceSliceToSocket sends data from a memory slice into rawTCP using vmsplice(2) and splice(2).
func spliceSliceToSocket(rawTCP *net.TCPConn, p *pipePair, data []byte, writeHdr func() error) (int64, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if p == nil {
		return 0, errors.New("nil pipePair")
	}
	if writeHdr != nil {
		if err := writeHdr(); err != nil {
			return 0, err
		}
	}
	iov := []unix.Iovec{
		{
			Base: (*byte)(unsafe.Pointer(&data[0])),
			Len:  uint64(len(data)),
		},
	}
	spliceCallsTotal.Add(1)
	nVmsplice, err := unix.Vmsplice(p.wfd, iov, 0)
	if err != nil {
		return 0, err
	}
	if nVmsplice == 0 {
		return 0, io.ErrUnexpectedEOF
	}

	rc, err := rawTCP.SyscallConn()
	if err != nil {
		return 0, err
	}

	var pumped int64
	for pumped < int64(nVmsplice) {
		want := int(int64(nVmsplice) - pumped)
		var nPump int64
		var sysErr error
		err := rc.Write(func(sfd uintptr) bool {
			spliceCallsTotal.Add(1)
			nPump, sysErr = unix.Splice(p.rfd, nil, int(sfd), nil, want, unix.SPLICE_F_NONBLOCK)
			if sysErr == unix.EAGAIN || sysErr == unix.EWOULDBLOCK {
				return false
			}
			return true
		})
		if err != nil {
			return pumped, err
		}
		if sysErr != nil {
			return pumped, sysErr
		}
		if nPump == 0 {
			return pumped, io.ErrUnexpectedEOF
		}
		pumped += nPump
	}
	splicedBytesOut.Add(uint64(pumped))
	return pumped, nil
}
