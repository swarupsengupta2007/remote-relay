package session

import (
	"crypto/rand"
	"crypto/sha256"
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
	mu     sync.RWMutex
	byID   map[string]*Session
	byHash map[[32]byte]string
	max    int
}

func NewStore(max int) *Store {
	if max <= 0 {
		max = 1024
	}
	return &Store{
		byID:   make(map[string]*Session),
		byHash: make(map[[32]byte]string),
		max:    max,
	}
}

func New() (*Session, string, error) {
	var idb [6]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, "", err
	}
	var tok [32]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return nil, "", err
	}
	plain := base64.StdEncoding.EncodeToString(tok[:])
	return &Session{
		ID:        "s-" + hex.EncodeToString(idb[:]),
		TokenHash: sha256.Sum256(tok[:]),
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
	if sess, ok := s.byID[id]; ok {
		delete(s.byID, id)
		delete(s.byHash, sess.TokenHash)
	}
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}
