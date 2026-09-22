//go:build !windows

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func (s *Server) setupHotRestartSignal(ctx context.Context) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR2)
	go func() {
		defer signal.Stop(sigCh)
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.runCtx.Done():
				return
			case sig, ok := <-sigCh:
				if !ok {
					return
				}
				s.log.Info("received signal for zero-downtime hot restart", "signal", sig.String())
				if err := s.HotRestart(); err != nil {
					s.log.Error("hot restart failed", "err", err)
				}
			}
		}
	}()
}

func dupSocket(s interface {
	SyscallConn() (syscall.RawConn, error)
}, name string) (*os.File, error) {
	if s == nil {
		return nil, errors.New("nil socket")
	}
	sc, err := s.SyscallConn()
	if err != nil {
		return nil, err
	}
	var dupFD int
	var dupErr error
	err = sc.Control(func(fd uintptr) {
		dupFD, dupErr = syscall.Dup(int(fd))
	})
	if err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, dupErr
	}
	return os.NewFile(uintptr(dupFD), name), nil
}

// HandoverTo transfers listeners and active sessions to a connected Unix domain socket.
func (s *Server) HandoverTo(unixConn *net.UnixConn) error {
	s.restarting.Store(true)
	var passedFiles []*os.File
	hasListenTCP := false
	hasListenUDP := false

	// 1. Extract TCP listener FD via raw dup without setting blocking mode
	s.mu.Lock()
	if tl, ok := s.ln.(*net.TCPListener); ok {
		if tf, err := dupSocket(tl, "listen-tcp"); err == nil {
			passedFiles = append(passedFiles, tf)
			hasListenTCP = true
		} else {
			s.log.Warn("failed to dup TCP listener file", "err", err)
		}
	}
	s.mu.Unlock()

	// 2. Extract UDP listener FD via raw dup
	s.udpMu.Lock()
	if s.udp != nil && s.udp.mux != nil {
		if uc, ok := s.udp.mux.PacketConn().(*net.UDPConn); ok {
			if uf, err := dupSocket(uc, "listen-udp"); err == nil {
				passedFiles = append(passedFiles, uf)
				hasListenUDP = true
			} else {
				s.log.Warn("failed to dup UDP listener file", "err", err)
			}
		}
	}
	s.udpMu.Unlock()

	// Stop accepting on parent so clients only connect to child
	s.closeListener()
	s.closeUDP()

	// 3. Drop active client carriers so clients trigger fast RESUME reconnect
	s.dropLiveTransports()

	// 4. Snapshot sessions and extract destination TCP socket FDs
	s.livesMu.Lock()
	var handoverSessions []HandoverSession
	for _, l := range s.lives {
		sess := s.store.Get(l.id)
		if sess == nil {
			continue
		}
		snapSess := sess.Snapshot()
		base, data, capMax := l.sendLog.Snapshot()

		hasDestFD := false
		if l.dest != nil {
			if df, err := dupSocket(l.dest, "dest-tcp"); err == nil {
				passedFiles = append(passedFiles, df)
				hasDestFD = true
			} else {
				s.log.Warn("failed to dup dest TCP file", "sessionId", l.id, "err", err)
			}
		}

		remHold := int64(s.cfg.HoldTimeout.Duration() / time.Millisecond)
		l.mu.Lock()
		if !l.heldAt.IsZero() {
			elapsed := time.Since(l.heldAt)
			rem := s.cfg.HoldTimeout.Duration() - elapsed
			if rem < 0 {
				rem = 0
			}
			remHold = int64(rem / time.Millisecond)
		}
		l.mu.Unlock()

		handoverSessions = append(handoverSessions, HandoverSession{
			Session:         snapSess,
			UpAcked:         l.delivered.Load(),
			DownNext:        base + uint64(len(data)),
			UpClosed:        l.inGotClose.Load(),
			DownClosed:      l.outEOF.Load(),
			SendLogBase:     base,
			SendLogData:     data,
			SendLogCap:      capMax,
			RemainingHoldMs: remHold,
			ClientIP:        l.clientIP,
			HasDestFD:       hasDestFD,
		})
	}
	s.livesMu.Unlock()

	// 5. Send state and file descriptors
	state := HandoverState{
		Version:      1,
		Timestamp:    time.Now().UTC(),
		HasListenTCP: hasListenTCP,
		HasListenUDP: hasListenUDP,
		Sessions:     handoverSessions,
	}

	if err := SendHandover(unixConn, state, passedFiles); err != nil {
		for _, f := range passedFiles {
			_ = f.Close()
		}
		return fmt.Errorf("send handover: %w", err)
	}

	for _, f := range passedFiles {
		_ = f.Close()
	}

	// 6. Wait for acknowledgment
	_ = unixConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	ackBuf := make([]byte, 3)
	if _, err := io.ReadFull(unixConn, ackBuf); err != nil {
		return fmt.Errorf("wait for handover acknowledgment: %w", err)
	}
	if string(ackBuf) != "OK\n" {
		return fmt.Errorf("unexpected handover ack: %q", string(ackBuf))
	}

	s.log.Info("handover complete and acknowledged by child")

	// 7. Close parent's listeners now that child has adopted them
	s.closeListener()
	s.closeUDP()

	// 8. Disown and stop parent's session pumps now that child owns them
	s.livesMu.Lock()
	oldLives := s.lives
	s.lives = make(map[string]*live)
	s.livesMu.Unlock()

	for _, l := range oldLives {
		l.disarmDest()
	}

	return nil
}

func (s *Server) hotRestartPlatform() error {
	if !s.restarting.CompareAndSwap(false, true) {
		return errors.New("hot restart already in progress")
	}
	defer func() {
		select {
		case <-s.restartingDone:
		default:
			close(s.restartingDone)
		}
	}()

	// 1. Create UNIX domain socketpair
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		s.restarting.Store(false)
		return fmt.Errorf("socketpair: %w", err)
	}
	parentFile := os.NewFile(uintptr(fds[0]), "handover-parent")
	childFile := os.NewFile(uintptr(fds[1]), "handover-child")

	// 2. Prepare child command
	binPath := s.reexecPath
	if binPath == "" {
		binPath, err = os.Executable()
		if err != nil {
			parentFile.Close()
			childFile.Close()
			s.restarting.Store(false)
			return fmt.Errorf("resolve executable: %w", err)
		}
	}

	args := s.reexecArgs
	if args == nil {
		args = os.Args[1:]
	}

	cmd := exec.Command(binPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Child inherits childFile as FD 3
	cmd.ExtraFiles = []*os.File{childFile}

	// Filter out LISTEN_* env vars so child uses RELAY_HANDOVER_FD
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "LISTEN_PID=") || strings.HasPrefix(e, "LISTEN_FDS=") || strings.HasPrefix(e, "LISTEN_FDNAMES=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env, "RELAY_HANDOVER_FD=3")
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		parentFile.Close()
		childFile.Close()
		s.restarting.Store(false)
		return fmt.Errorf("spawn child process: %w", err)
	}
	s.log.Info("spawned child process for hot restart", "childPid", cmd.Process.Pid)
	if pidFile := os.Getenv("RELAY_CHILD_PID_FILE"); pidFile != "" {
		_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
	}
	_ = childFile.Close()

	parentConn, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		s.restarting.Store(false)
		return fmt.Errorf("wrap parent handover socket: %w", err)
	}
	unixConn := parentConn.(*net.UnixConn)
	defer unixConn.Close()

	// 3. Execute Handover
	if err := s.HandoverTo(unixConn); err != nil {
		s.restarting.Store(false)
		return err
	}

	// 4. Terminate or stop serving
	if !s.noExitOnRestart {
		s.log.Info("exiting parent process cleanly after hot restart")
		os.Exit(0)
	} else {
		s.stopRun()
	}

	return nil
}
