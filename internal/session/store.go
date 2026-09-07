package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

type Session struct {
	ID          string
	TokenHash   [32]byte
	Destination string
	CreatedAt   time.Time
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
	}
}

func (s *Store) Expire(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(id)
	s.expired[id] = time.Now()
}

func (s *Store) IsExpired(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.expired[id]
	return ok
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
	if subtle.ConstantTimeCompare(h[:], sess.TokenHash[:]) != 1 {
		return proto.ErrBadToken
	}
	return nil
}

func (s *Store) RotateToken(id string) (string, error) {
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
	delete(s.byHash, sess.TokenHash)
	sess.TokenHash = hash
	s.byHash[hash] = id
	return plain, nil
}
