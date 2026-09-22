package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

const (
	tombstoneTTL  = 10 * time.Minute
	maxTombstones = 4096
)

type Session struct {
	ID           string
	TokenHash    [32]byte
	PrevHash     [32]byte
	hasPrev      bool
	currentPlain string
	Destination  string
	CreatedAt    time.Time
	AuthMethod   string
	AuthUser     string
	Fingerprint  string
	PublicKey    []byte
}

type Store struct {
	mu      sync.RWMutex
	byID    map[string]*Session
	byHash  map[[32]byte]string
	expired map[string]time.Time
	max     int
}

func NewStore(max int) *Store {
	if max <= 0 {
		max = 1024
	}
	return &Store{
		byID:    make(map[string]*Session),
		byHash:  make(map[[32]byte]string),
		expired: make(map[string]time.Time),
		max:     max,
	}
}

func randomToken() (plain string, hash [32]byte, err error) {
	var tok [32]byte
	if _, err = rand.Read(tok[:]); err != nil {
		return "", hash, err
	}
	return base64.StdEncoding.EncodeToString(tok[:]), sha256.Sum256(tok[:]), nil
}

func New() (*Session, string, error) {
	var idb [6]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, "", err
	}
	plain, hash, err := randomToken()
	if err != nil {
		return nil, "", err
	}
	return &Session{
		ID:        "s-" + hex.EncodeToString(idb[:]),
		TokenHash: hash,
		CreatedAt: time.Now(),
	}, plain, nil
}

func (s *Store) Add(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.max > 0 && len(s.byID) >= s.max {
		return proto.ErrNoCapacity
	}
	if _, ok := s.byID[sess.ID]; ok {
		return proto.NewError(proto.CodeInternal, "duplicate session id")
	}
	s.byID[sess.ID] = sess
	s.byHash[sess.TokenHash] = sess.ID
	delete(s.expired, sess.ID)
	return nil
}

func (s *Store) Get(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byID[id]
}

func (s *Store) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(id)
}

func (s *Store) removeLocked(id string) {
	if sess, ok := s.byID[id]; ok {
		delete(s.byID, id)
		delete(s.byHash, sess.TokenHash)
		if sess.hasPrev {
			delete(s.byHash, sess.PrevHash)
		}
	}
}

func (s *Store) Expire(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(id)
	s.expired[id] = time.Now()
	s.pruneExpiredLocked(time.Now())
}

func (s *Store) IsExpired(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(time.Now())
	_, ok := s.expired[id]
	return ok
}

func (s *Store) pruneExpiredLocked(now time.Time) {
	for id, t := range s.expired {
		if now.Sub(t) > tombstoneTTL {
			delete(s.expired, id)
		}
	}
	for id := range s.expired {
		if len(s.expired) <= maxTombstones {
			break
		}
		delete(s.expired, id)
	}
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

func hashToken(plain string) ([32]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(plain)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256(raw), true
}

func (s *Store) VerifyToken(id, plain string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.byID[id]
	if !ok {
		if _, exp := s.expired[id]; exp {
			return proto.ErrExpired
		}
		return proto.ErrUnknownSession
	}
	h, ok := hashToken(plain)
	if !ok {
		return proto.ErrBadToken
	}
	cur := subtle.ConstantTimeCompare(h[:], sess.TokenHash[:])
	prev := 0
	if sess.hasPrev {
		prev = subtle.ConstantTimeCompare(h[:], sess.PrevHash[:])
	}
	if cur|prev != 1 {
		return proto.ErrBadToken
	}
	if hid, ok := s.byHash[h]; !ok || hid != id {
		return proto.ErrBadToken
	}
	return nil
}

// ResumeToken returns the token to put in RESUME_OK. An unconfirmed rotation is
// reused so a client that never saw RESUME_OK can still present the previous
// hash and receive the same new token.
func (s *Store) ResumeToken(id string) (string, error) {
	plain, hash, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return "", proto.ErrUnknownSession
	}
	if sess.currentPlain != "" {
		return sess.currentPlain, nil
	}
	if sess.hasPrev {
		delete(s.byHash, sess.PrevHash)
	}
	sess.PrevHash = sess.TokenHash
	sess.hasPrev = true
	s.byHash[sess.PrevHash] = id
	sess.TokenHash = hash
	s.byHash[hash] = id
	sess.currentPlain = plain
	return plain, nil
}

func (s *Store) RotateToken(id string) (string, error) {
	return s.ResumeToken(id)
}

// ForceResumeToken unconditionally clears any unconfirmed token cache and rotates
// to a brand-new generation token. Used during cryptographic fallback recovery.
func (s *Store) ForceResumeToken(id string) (string, error) {
	plain, hash, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return "", proto.ErrUnknownSession
	}
	sess.currentPlain = ""
	if sess.hasPrev {
		delete(s.byHash, sess.PrevHash)
	}
	sess.PrevHash = sess.TokenHash
	sess.hasPrev = true
	s.byHash[sess.PrevHash] = id
	sess.TokenHash = hash
	s.byHash[hash] = id
	sess.currentPlain = plain
	return plain, nil
}

// ConfirmToken drops the previous-generation hash once the new token is live.
func (s *Store) ConfirmToken(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return
	}
	sess.currentPlain = ""
	if sess.hasPrev {
		delete(s.byHash, sess.PrevHash)
		sess.PrevHash = [32]byte{}
		sess.hasPrev = false
	}
}

type SessionSnapshot struct {
	ID           string    `json:"id"`
	TokenHashHex string    `json:"token_hash"`
	PrevHashHex  string    `json:"prev_hash,omitempty"`
	HasPrev      bool      `json:"has_prev"`
	CurrentPlain string    `json:"current_plain,omitempty"`
	Destination  string    `json:"destination"`
	CreatedAt    time.Time `json:"created_at"`
	AuthMethod   string    `json:"auth_method,omitempty"`
	AuthUser     string    `json:"auth_user,omitempty"`
	Fingerprint  string    `json:"fingerprint,omitempty"`
	PublicKey    []byte    `json:"public_key,omitempty"`
}

func (s *Session) Snapshot() SessionSnapshot {
	var prevHex string
	if s.hasPrev {
		prevHex = hex.EncodeToString(s.PrevHash[:])
	}
	return SessionSnapshot{
		ID:           s.ID,
		TokenHashHex: hex.EncodeToString(s.TokenHash[:]),
		PrevHashHex:  prevHex,
		HasPrev:      s.hasPrev,
		CurrentPlain: s.currentPlain,
		Destination:  s.Destination,
		CreatedAt:    s.CreatedAt,
		AuthMethod:   s.AuthMethod,
		AuthUser:     s.AuthUser,
		Fingerprint:  s.Fingerprint,
		PublicKey:    s.PublicKey,
	}
}

func RestoreSession(snap SessionSnapshot) (*Session, error) {
	var tokHash [32]byte
	b, err := hex.DecodeString(snap.TokenHashHex)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("invalid token hash: %w", err)
	}
	copy(tokHash[:], b)

	var prevHash [32]byte
	if snap.HasPrev && snap.PrevHashHex != "" {
		pb, err := hex.DecodeString(snap.PrevHashHex)
		if err != nil || len(pb) != 32 {
			return nil, fmt.Errorf("invalid prev hash: %w", err)
		}
		copy(prevHash[:], pb)
	}

	return &Session{
		ID:           snap.ID,
		TokenHash:    tokHash,
		PrevHash:     prevHash,
		hasPrev:      snap.HasPrev,
		currentPlain: snap.CurrentPlain,
		Destination:  snap.Destination,
		CreatedAt:    snap.CreatedAt,
		AuthMethod:   snap.AuthMethod,
		AuthUser:     snap.AuthUser,
		Fingerprint:  snap.Fingerprint,
		PublicKey:    snap.PublicKey,
	}, nil
}

func (s *Store) Snapshot() []SessionSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SessionSnapshot, 0, len(s.byID))
	for _, sess := range s.byID {
		out = append(out, sess.Snapshot())
	}
	return out
}

func (s *Store) Restore(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[sess.ID] = sess
	s.byHash[sess.TokenHash] = sess.ID
	if sess.hasPrev {
		s.byHash[sess.PrevHash] = sess.ID
	}
	delete(s.expired, sess.ID)
}
