package kex

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	KexInitLen  = 48  // 32B clientEphemeral + 16B clientNonce
	KexReplyLen = 144 // 32B serverEphemeral + 16B serverNonce + 32B serverHostKey + 64B sig
	KeyLen      = 32
	NonceLen    = 16
)

var (
	hkdfInfoC2S = []byte("relay/control/c2s")
	hkdfInfoS2C = []byte("relay/control/s2c")
)

// ExchangeHash computes SHA-256 over (clientEph || serverEph || clientNonce || serverNonce || serverHostKey).
func ExchangeHash(clientEph, serverEph, clientNonce, serverNonce, serverHostKey []byte) []byte {
	h := sha256.New()
	h.Write(clientEph)
	h.Write(serverEph)
	h.Write(clientNonce)
	h.Write(serverNonce)
	h.Write(serverHostKey)
	return h.Sum(nil)
}

// DeriveKeys extracts and expands the shared X25519 secret into client->server and server->client keys.
func DeriveKeys(sharedSecret, clientNonce, serverNonce []byte) (c2sKey, s2cKey []byte, err error) {
	salt := make([]byte, 0, len(clientNonce)+len(serverNonce))
	salt = append(salt, clientNonce...)
	salt = append(salt, serverNonce...)

	prk := hkdf.Extract(sha256.New, sharedSecret, salt)

	c2s := make([]byte, KeyLen)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, hkdfInfoC2S), c2s); err != nil {
		return nil, nil, fmt.Errorf("kex: derive c2s: %w", err)
	}

	s2c := make([]byte, KeyLen)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, hkdfInfoS2C), s2c); err != nil {
		return nil, nil, fmt.Errorf("kex: derive s2c: %w", err)
	}

	return c2s, s2c, nil
}

// ClientSession manages the client side of the ephemeral X25519 key exchange.
type ClientSession struct {
	priv  *ecdh.PrivateKey
	pub   *ecdh.PublicKey
	nonce [NonceLen]byte
}

func NewClientSession() (*ClientSession, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("kex: generate client key: %w", err)
	}
	var nonce [NonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("kex: generate client nonce: %w", err)
	}
	return &ClientSession{
		priv:  priv,
		pub:   priv.PublicKey(),
		nonce: nonce,
	}, nil
}

func (c *ClientSession) InitPayload() []byte {
	payload := make([]byte, KexInitLen)
	copy(payload[:32], c.pub.Bytes())
	copy(payload[32:], c.nonce[:])
	return payload
}

func (c *ClientSession) ProcessReply(reply []byte, verifyHostKey func(pub ed25519.PublicKey) error) (c2sKey, s2cKey []byte, err error) {
	if len(reply) != KexReplyLen {
		return nil, nil, fmt.Errorf("kex: invalid reply length %d, expected %d", len(reply), KexReplyLen)
	}
	serverEphBytes := reply[:32]
	serverNonce := reply[32:48]
	serverHostKey := reply[48:80]
	sig := reply[80:144]

	// 1. Verify Ed25519 signature over transcript exchange hash
	hash := ExchangeHash(c.pub.Bytes(), serverEphBytes, c.nonce[:], serverNonce, serverHostKey)
	if !ed25519.Verify(ed25519.PublicKey(serverHostKey), hash, sig) {
		return nil, nil, fmt.Errorf("kex: invalid server signature over exchange transcript")
	}

	// 2. Validate host key with caller (known_hosts, pinned fingerprint)
	if verifyHostKey != nil {
		if err := verifyHostKey(ed25519.PublicKey(serverHostKey)); err != nil {
			return nil, nil, err
		}
	}

	// 3. Compute X25519 shared secret
	remotePub, err := ecdh.X25519().NewPublicKey(serverEphBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("kex: invalid server ephemeral key: %w", err)
	}
	sharedSecret, err := c.priv.ECDH(remotePub)
	if err != nil {
		return nil, nil, fmt.Errorf("kex: ecdh computation failed: %w", err)
	}

	// 4. Derive symmetric keys
	return DeriveKeys(sharedSecret, c.nonce[:], serverNonce)
}

// ServerSession manages the server side of the ephemeral X25519 key exchange.
type ServerSession struct {
	hostPriv ed25519.PrivateKey
	hostPub  ed25519.PublicKey
}

func NewServerSession(hostPriv ed25519.PrivateKey) (*ServerSession, error) {
	if len(hostPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("kex: invalid host private key size %d", len(hostPriv))
	}
	pub := hostPriv.Public().(ed25519.PublicKey)
	return &ServerSession{
		hostPriv: hostPriv,
		hostPub:  pub,
	}, nil
}

func (s *ServerSession) HostPublicKey() ed25519.PublicKey {
	return s.hostPub
}

func (s *ServerSession) ProcessInit(init []byte) (reply []byte, c2sKey, s2cKey []byte, err error) {
	if len(init) != KexInitLen {
		return nil, nil, nil, fmt.Errorf("kex: invalid init length %d, expected %d", len(init), KexInitLen)
	}
	clientEphBytes := init[:32]
	clientNonce := init[32:48]

	// 1. Generate server ephemeral key and nonce
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kex: generate server key: %w", err)
	}
	serverPub := serverPriv.PublicKey()

	var serverNonce [NonceLen]byte
	if _, err := io.ReadFull(rand.Reader, serverNonce[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("kex: generate server nonce: %w", err)
	}

	// 2. Compute exchange hash and sign with host key
	hash := ExchangeHash(clientEphBytes, serverPub.Bytes(), clientNonce, serverNonce[:], s.hostPub)
	sig := ed25519.Sign(s.hostPriv, hash)

	// 3. Compute shared secret
	clientPub, err := ecdh.X25519().NewPublicKey(clientEphBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kex: invalid client ephemeral key: %w", err)
	}
	sharedSecret, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kex: ecdh computation failed: %w", err)
	}

	// 4. Derive symmetric keys
	c2sKey, s2cKey, err = DeriveKeys(sharedSecret, clientNonce, serverNonce[:])
	if err != nil {
		return nil, nil, nil, err
	}

	// 5. Construct reply payload (144 bytes)
	reply = make([]byte, KexReplyLen)
	copy(reply[:32], serverPub.Bytes())
	copy(reply[32:48], serverNonce[:])
	copy(reply[48:80], s.hostPub)
	copy(reply[80:144], sig)

	return reply, c2sKey, s2cKey, nil
}
