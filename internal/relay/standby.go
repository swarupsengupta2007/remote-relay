package relay

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/bfd"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

type clientStandby struct {
	mu           sync.Mutex
	conn         transport.Conn
	sess         *bfd.Session
	promoteCh    chan struct{}
	promotedDone chan struct{}
	cancel       context.CancelFunc
	dropped      chan struct{}
	closed       bool
	prefetched   []proto.Frame
	onData       func()
}

func (s *clientStandby) isReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.sess != nil && s.sess.IsUp()
}

func (s *clientStandby) promote() (transport.Conn, *bfd.Session, []proto.Frame, bool) {
	s.mu.Lock()
	if s.closed || s.sess == nil || !s.sess.IsUp() {
		s.mu.Unlock()
		return nil, nil, nil, false
	}
	s.closed = true
	promoteCh := s.promoteCh
	promotedDone := s.promotedDone
	conn := s.conn
	sess := s.sess
	prefetched := append([]proto.Frame(nil), s.prefetched...)
	s.mu.Unlock()

	close(promoteCh)
	<-promotedDone
	return conn, sess, prefetched, true
}

func startClientStandby(ctx context.Context, conn transport.Conn, sess *bfd.Session, log *slog.Logger, onData func()) *clientStandby {
	runCtx, runCancel := context.WithCancel(ctx)
	promoteCh := make(chan struct{})
	promotedDone := make(chan struct{})
	dropped := make(chan struct{})

	cs := &clientStandby{
		conn:         conn,
		sess:         sess,
		promoteCh:    promoteCh,
		promotedDone: promotedDone,
		cancel:       runCancel,
		dropped:      dropped,
		onData:       onData,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Standby BFD reader
	go func() {
		defer wg.Done()
		for {
			f, err := conn.ReadFrame()
			if err != nil {
				runCancel()
				return
			}
			if f.Type == proto.TypePing {
				pkt, perr := bfd.DecodePacket(f.Payload)
				if perr == nil {
					_, _ = sess.Receive(pkt)
				}
				continue
			}
			// A non-ping frame means the peer already promoted this carrier.
			// Keep the bytes and promote immediately instead of discarding
			// them until the UDP dead-peer timer fires.
			payload := append([]byte(nil), f.Payload...)
			f.Payload = payload
			cs.mu.Lock()
			cs.prefetched = append(cs.prefetched, f)
			cb := cs.onData
			cs.mu.Unlock()
			if cb != nil {
				cb()
			}
			return
		}
	}()

	// Standby BFD timer
	go func() {
		defer wg.Done()
		cadence := sess.TxInterval()
		if cadence <= 0 {
			cadence = 750 * time.Millisecond
		}
		t := time.NewTicker(cadence)
		defer t.Stop()

		for {
			select {
			case <-runCtx.Done():
				return
			case now := <-t.C:
				if sess.CheckTimeout(now) {
					noteDeadPeer(log, nil, "standby", sess, now)
					runCancel()
					return
				}
				newCadence := sess.TxInterval()
				if newCadence > 0 && newCadence != cadence {
					cadence = newCadence
					t.Reset(cadence)
				}
				pkt := sess.FormatTxPacket()
				payload := bfd.EncodePacket(pkt)
				if err := conn.WriteFrame(proto.Frame{Type: proto.TypePing, Payload: payload}); err != nil {
					runCancel()
					return
				}
			}
		}
	}()

	// Lifecycle watcher
	go func() {
		select {
		case <-promoteCh:
			runCancel()
			_ = conn.SetDeadline(time.Now())
			wg.Wait()
			_ = conn.SetDeadline(time.Time{})
			conn.ResetReader()
			close(promotedDone)
			if log != nil {
				log.Info("client standby promoted to active carrier", "transport", conn.Kind().String())
			}
			return
		case <-runCtx.Done():
			select {
			case <-promoteCh:
				runCancel()
				_ = conn.SetDeadline(time.Now())
				wg.Wait()
				_ = conn.SetDeadline(time.Time{})
				conn.ResetReader()
				close(promotedDone)
				return
			default:
			}
			_ = conn.SetDeadline(time.Now())
			wg.Wait()
			_ = conn.Close()
			close(dropped)
			if log != nil {
				log.Info("client standby connection dropped", "transport", conn.Kind().String())
			}
		case <-ctx.Done():
			runCancel()
			_ = conn.SetDeadline(time.Now())
			wg.Wait()
			_ = conn.Close()
			close(dropped)
		}
	}()

	return cs
}

type standbyManager struct {
	cfg       config.Client
	log       *slog.Logger
	sessionID string
	p         *pump

	tokenMu sync.Mutex
	token   string

	mu      sync.Mutex
	standby *clientStandby
	enabled bool
	started bool
	wakeCh  chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
}

func newStandbyManager(ctx context.Context, cfg config.Client, log *slog.Logger, sessionID, token string, p *pump) *standbyManager {
	mCtx, mCancel := context.WithCancel(ctx)
	return &standbyManager{
		cfg:       cfg,
		log:       log,
		sessionID: sessionID,
		token:     token,
		p:         p,
		wakeCh:    make(chan struct{}, 1),
		ctx:       mCtx,
		cancel:    mCancel,
	}
}

func (sm *standbyManager) updateToken(token string) {
	sm.tokenMu.Lock()
	sm.token = token
	sm.tokenMu.Unlock()
	sm.wake()
}

func (sm *standbyManager) getToken() string {
	sm.tokenMu.Lock()
	defer sm.tokenMu.Unlock()
	return sm.token
}

func (sm *standbyManager) wake() {
	select {
	case sm.wakeCh <- struct{}{}:
	default:
	}
}

func (sm *standbyManager) start() {
	sm.mu.Lock()
	sm.enabled = true
	if !sm.started {
		sm.started = true
		go sm.loop()
	}
	sm.mu.Unlock()
	sm.wake()
}

func (sm *standbyManager) setEnabled(enabled bool) {
	sm.mu.Lock()
	sm.enabled = enabled
	sm.mu.Unlock()
	sm.wake()
}

func (sm *standbyManager) loop() {
	for {
		sm.mu.Lock()
		if sm.ctx.Err() != nil {
			sm.mu.Unlock()
			return
		}
		enabled := sm.enabled
		st := sm.standby
		sm.mu.Unlock()

		if !enabled {
			select {
			case <-sm.ctx.Done():
				return
			case <-sm.wakeCh:
				continue
			}
		}

		if st != nil {
			select {
			case <-st.dropped:
				sm.mu.Lock()
				if sm.standby == st {
					sm.standby = nil
				}
				sm.mu.Unlock()
			case <-sm.wakeCh:
			case <-sm.ctx.Done():
				return
			}
			continue
		}

		// Attempt to establish standby connection over TCP
		dialCtx, dialCancel := context.WithTimeout(sm.ctx, 5*time.Second)
		token := sm.getToken()
		downAcked := sm.p.delivered.Load()
		conn, rok, err := clientResumeRole(dialCtx, sm.cfg, sm.sessionID, token, downAcked, "standby")
		dialCancel()

		if err != nil {
			select {
			case <-sm.ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
				continue
			case <-sm.wakeCh:
				continue
			}
		}
		if rok.ResumeToken != "" {
			sm.updateToken(rok.ResumeToken)
		}

		bfdCfg := bfd.Config{
			DesiredMinTxInterval:  sm.cfg.HeartbeatInterval.Duration(),
			RequiredMinRxInterval: sm.cfg.HeartbeatInterval.Duration(),
			DetectMultiplier:      uint8(sm.cfg.DeadPeerThreshold),
		}
		sess, err := bfd.NewSession(bfdCfg)
		if err != nil {
			_ = conn.Close()
			continue
		}

		sm.mu.Lock()
		if !sm.enabled || sm.ctx.Err() != nil {
			_ = conn.Close()
			sm.mu.Unlock()
			continue
		}
		sm.standby = startClientStandby(sm.ctx, conn, sess, sm.log, func() {
			if sm.p != nil {
				sm.p.dropConn()
			}
		})
		if sm.log != nil {
			sm.log.Info("standby connection attached", "transport", conn.Kind().String())
		}
		sm.mu.Unlock()
	}
}

func (sm *standbyManager) takeForPromotion() (transport.Conn, *bfd.Session, []proto.Frame, bool) {
	sm.mu.Lock()
	st := sm.standby
	if st == nil {
		sm.mu.Unlock()
		return nil, nil, nil, false
	}
	sm.standby = nil
	sm.enabled = false
	sm.mu.Unlock()
	sm.wake()

	conn, sess, prefetched, ok := st.promote()
	return conn, sess, prefetched, ok
}

func (sm *standbyManager) stop() {
	sm.cancel()
	sm.mu.Lock()
	if sm.standby != nil {
		sm.standby.cancel()
		sm.standby = nil
	}
	sm.mu.Unlock()
}
