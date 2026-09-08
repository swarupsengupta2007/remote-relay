package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	MethodNone      = "none"
	MethodPublicKey = "ssh-publickey"

	// DefaultFailDelay is applied to ssh-publickey failures so key-not-found
	// and bad-signature cannot be told apart by timing.
	DefaultFailDelay = 200 * time.Millisecond
)

type Challenge struct {
	SessionID   string
	Destination string
	ClientNonce string
	ServerNonce string
	// Canonical is the exact HELLO or RESUME JSON payload being bound.
	Canonical []byte
	// Offer is HELLO.auth / RESUME.auth (method, user, pubkey).
	Offer json.RawMessage
	// BoundFP is the fingerprint captured at HELLO; required on RESUME.
	BoundFP string
	// RawPubKey is the verified ssh public key from the session (RESUME).
	RawPubKey []byte
	// Digest, when set, is the precomputed SHA-256 challenge.
	Digest []byte
}

type Identity struct {
	Method      string
	Name        string
	Fingerprint string
	RawPubKey   []byte
}

type Authenticator interface {
	Name() string // "none" | "ssh-publickey"
	// RequiresChallenge is true when the server must finish AUTH/AUTH_OK
	// before allocating a session or dialing the destination.
	RequiresChallenge() bool
	Verify(challenge Challenge, auth json.RawMessage) (Identity, error)
	Respond(challenge Challenge) (json.RawMessage, error)
	// Sign produces the AUTH JSON {sig} over the challenge. none returns {}.
	Sign(challenge Challenge) (json.RawMessage, error)
	FailDelay() time.Duration
}

// Config selects and configures an Authenticator.
type Config struct {
	Method         string
	User           string
	AuthorizedKeys string
	IdentityFiles  []string
	FailDelay      time.Duration
}

func New(cfg Config) Authenticator {
	switch strings.ToLower(strings.TrimSpace(cfg.Method)) {
	case MethodPublicKey:
		return NewPublicKey(cfg)
	default:
		return None{}
	}
}

// DeriveChallenge is SHA256(sessionId ‖ clientNonce ‖ serverNonce ‖ destination ‖ canonical).
func DeriveChallenge(ch Challenge) []byte {
	if len(ch.Digest) == sha256.Size {
		return ch.Digest
	}
	h := sha256.New()
	h.Write([]byte(ch.SessionID))
	h.Write([]byte(ch.ClientNonce))
	h.Write([]byte(ch.ServerNonce))
	h.Write([]byte(ch.Destination))
	h.Write(ch.Canonical)
	return h.Sum(nil)
}

// None is the v1 authenticator: empty/{} auth, no identity.
type None struct{}

func (None) Name() string { return MethodNone }

func (None) RequiresChallenge() bool { return false }

func (None) FailDelay() time.Duration { return 0 }

func (None) Verify(_ Challenge, raw json.RawMessage) (Identity, error) {
	id := Identity{Method: MethodNone, Name: "anonymous"}
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 || string(trim) == "null" {
		return id, nil
	}
	var m map[string]any
	if err := json.Unmarshal(trim, &m); err != nil {
		return Identity{}, fmt.Errorf("auth: %w", err)
	}
	if len(m) != 0 {
		return Identity{}, fmt.Errorf("none authenticator expected empty auth")
	}
	return id, nil
}

func (None) Respond(_ Challenge) (json.RawMessage, error) {
	return json.RawMessage("{}"), nil
}

func (None) Sign(_ Challenge) (json.RawMessage, error) {
	return json.RawMessage("{}"), nil
}
