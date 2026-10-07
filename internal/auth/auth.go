package auth

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

const (
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
	Method                string
	Name                  string
	Fingerprint           string
	RawPubKey             []byte
	PortForwardingBlocked bool
	PermittedDestinations []string
	PermittedTargets      []string
}

type Authenticator interface {
	Name() string // "ssh-publickey"
	// RequiresChallenge is true when the server must finish AUTH/AUTH_OK
	// before allocating a session or dialing the destination.
	RequiresChallenge() bool
	Verify(challenge Challenge, auth json.RawMessage) (Identity, error)
	Respond(challenge Challenge) (json.RawMessage, error)
	// Sign produces the AUTH JSON {sig} over the challenge.
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
	AuthSock       string      // Unix domain socket for ssh-agent (defaults to $SSH_AUTH_SOCK if empty)
	Agent          agent.Agent // Optional injected agent for testing or custom programmatic use
}

func New(cfg Config) Authenticator {
	return NewPublicKey(cfg)
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
