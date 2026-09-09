package bfd

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

var (
	ErrDiscMismatch   = errors.New("bfd: your discriminator does not match local discriminator")
	ErrZeroDetectMult = errors.New("bfd: detect multiplier cannot be zero")
)

// Config defines the local timing and multiplier parameters for a BFD session.
type Config struct {
	DesiredMinTxInterval  time.Duration
	RequiredMinRxInterval time.Duration
	DetectMultiplier      uint8
}

func (c *Config) withDefaults() Config {
	res := *c
	if res.DesiredMinTxInterval <= 0 {
		res.DesiredMinTxInterval = 750 * time.Millisecond
	}
	if res.RequiredMinRxInterval <= 0 {
		res.RequiredMinRxInterval = 750 * time.Millisecond
	}
	if res.DetectMultiplier <= 0 {
		res.DetectMultiplier = 3
	}
	return res
}

// Session tracks the local RFC 5880 BFD state machine for a single connection.
type Session struct {
	mu                  sync.RWMutex
	cfg                 Config
	myDisc              uint32
	yourDisc            uint32
	state               State
	remoteState         State
	remoteMinRxInterval time.Duration
	remoteMinTxInterval time.Duration
	remoteDetectMult    uint8
	lastRx              time.Time
	createdAt           time.Time
	onStateChange       func(oldState, newState State)
}

// GenerateDiscriminator generates a cryptographically random, non-zero 32-bit discriminator.
func GenerateDiscriminator() (uint32, error) {
	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint32(b[:])
		if v != 0 {
			return v, nil
		}
	}
}

// NewSession creates and initializes a new BFD session starting in StateDown.
func NewSession(cfg Config) (*Session, error) {
	disc, err := GenerateDiscriminator()
	if err != nil {
		return nil, err
	}
	return NewSessionWithDisc(cfg, disc), nil
}

// NewSessionWithDisc creates a session with a fixed local discriminator (useful for testing).
func NewSessionWithDisc(cfg Config, disc uint32) *Session {
	cfg = cfg.withDefaults()
	now := time.Now()
	return &Session{
		cfg:       cfg,
		myDisc:    disc,
		state:     StateDown,
		lastRx:    now,
		createdAt: now,
	}
}

// SetOnStateChange registers a callback invoked when the local state transitions.
func (s *Session) SetOnStateChange(cb func(oldState, newState State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onStateChange = cb
}

// State returns the current local BFD state.
func (s *Session) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// IsUp returns true if the local session is currently in StateUp.
func (s *Session) IsUp() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state == StateUp
}

// MyDisc returns the local session discriminator.
func (s *Session) MyDisc() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.myDisc
}

// YourDisc returns the peer's discriminator.
func (s *Session) YourDisc() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.yourDisc
}

// FormatTxPacket prepares the BFD packet to be transmitted to the peer.
func (s *Session) FormatTxPacket() Packet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return Packet{
		State:                 s.state,
		DetectMult:            s.cfg.DetectMultiplier,
		MyDisc:                s.myDisc,
		YourDisc:              s.yourDisc,
		DesiredMinTxInterval:  s.cfg.DesiredMinTxInterval,
		RequiredMinRxInterval: s.cfg.RequiredMinRxInterval,
	}
}

// TxInterval returns the calculated transmission interval based on local desired
// interval and remote required RX interval.
func (s *Session) TxInterval() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	interval := s.cfg.DesiredMinTxInterval
	if s.remoteMinRxInterval > interval {
		interval = s.remoteMinRxInterval
	}
	return interval
}

// DetectionTimeout returns the duration of silence before declaring the peer dead.
func (s *Session) DetectionTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.detectionTimeoutLocked()
}

func (s *Session) detectionTimeoutLocked() time.Duration {
	interval := s.cfg.DesiredMinTxInterval
	if s.remoteMinRxInterval > interval {
		interval = s.remoteMinRxInterval
	}
	mult := s.cfg.DetectMultiplier
	return time.Duration(mult) * interval
}

// Receive processes an incoming BFD packet and advances the RFC 5880 state machine.
func (s *Session) Receive(pkt Packet) (stateChanged bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pkt.DetectMult == 0 {
		return false, ErrZeroDetectMult
	}

	// RFC 5880 §6.8.6 discriminator checks.
	if pkt.YourDisc == 0 {
		if s.state != StateDown {
			// Discard packet if YourDisc is zero and local session is not in Down state.
			return false, nil
		}
	} else if pkt.YourDisc != s.myDisc {
		// Discriminator mismatch. Discard packet.
		return false, ErrDiscMismatch
	}

	s.yourDisc = pkt.MyDisc
	s.remoteState = pkt.State
	s.remoteMinRxInterval = pkt.RequiredMinRxInterval
	s.remoteMinTxInterval = pkt.DesiredMinTxInterval
	s.remoteDetectMult = pkt.DetectMult
	s.lastRx = time.Now()

	oldState := s.state
	newState := oldState

	switch oldState {
	case StateDown:
		if pkt.State == StateDown {
			newState = StateInit
		} else if pkt.State == StateInit || pkt.State == StateUp {
			newState = StateUp
		}
	case StateInit:
		if pkt.State == StateInit || pkt.State == StateUp {
			newState = StateUp
		} else if pkt.State == StateDown {
			newState = StateDown
		}
	case StateUp:
		if pkt.State == StateDown {
			newState = StateDown
		}
	}

	if newState != oldState {
		s.state = newState
		if s.onStateChange != nil {
			s.onStateChange(oldState, newState)
		}
		return true, nil
	}

	return false, nil
}

// CheckTimeout tests if the peer has exceeded the detection timer.
// If timed out, transitions the state to StateDown and returns true.
func (s *Session) CheckTimeout(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	timeout := s.detectionTimeoutLocked()
	if now.Sub(s.lastRx) <= timeout {
		return false
	}

	oldState := s.state
	s.state = StateDown
	s.yourDisc = 0
	if oldState != StateDown && s.onStateChange != nil {
		s.onStateChange(oldState, StateDown)
	}
	return true
}
