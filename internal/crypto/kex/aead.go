package kex

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

const (
	SeqNumLen = 8
	NonceSize = chacha20poly1305.NonceSize // 12 bytes
	TagSize   = 16
)

// CipherConn wraps an underlying transport.Conn to encrypt/decrypt control frames
// using ChaCha20-Poly1305 AEAD with sequence-number based replay protection.
type CipherConn struct {
	underlying transport.Conn
	sendAead   cipher.AEAD
	recvAead   cipher.AEAD
	sendSeq    uint64
	recvSeq    uint64
}

// NewCipherConn constructs a CipherConn.
// If isClient is true: sendKey is c2sKey, recvKey is s2cKey.
// If isClient is false: sendKey is s2cKey, recvKey is c2sKey.
func NewCipherConn(conn transport.Conn, sendKey, recvKey []byte) (*CipherConn, error) {
	sendAead, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, fmt.Errorf("kex: create send aead: %w", err)
	}
	recvAead, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, fmt.Errorf("kex: create recv aead: %w", err)
	}
	return &CipherConn{
		underlying: conn,
		sendAead:   sendAead,
		recvAead:   recvAead,
	}, nil
}

var _ transport.Conn = (*CipherConn)(nil)

func (c *CipherConn) Underlying() transport.Conn {
	return c.underlying
}

func (c *CipherConn) Close() error {
	return c.underlying.Close()
}

func (c *CipherConn) SetDeadline(t time.Time) error {
	return c.underlying.SetDeadline(t)
}

func (c *CipherConn) LocalAddr() net.Addr {
	return c.underlying.LocalAddr()
}

func (c *CipherConn) RemoteAddr() net.Addr {
	return c.underlying.RemoteAddr()
}

func (c *CipherConn) Kind() transport.Kind {
	return c.underlying.Kind()
}

func (c *CipherConn) ResetReader() {
	c.underlying.ResetReader()
}

func (c *CipherConn) WriteFrame(f proto.Frame) error {
	return c.WriteControlFrame(f)
}

func (c *CipherConn) ReadFrame() (proto.Frame, error) {
	return c.ReadControlFrame()
}

// makeNonce constructs the 12-byte nonce: 4 bytes zero prefix + 8 bytes sequence number (big-endian).
func makeNonce(seq uint64) []byte {
	nonce := make([]byte, NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

// WriteControlFrame encrypts an inner proto.Frame into a proto.TypeEncrypted outer frame.
func (c *CipherConn) WriteControlFrame(inner proto.Frame) error {
	payloadLen := len(inner.Payload)
	innerWire := make([]byte, 1+4+payloadLen)
	innerWire[0] = byte(inner.Type)
	binary.BigEndian.PutUint32(innerWire[1:5], uint32(payloadLen))
	copy(innerWire[5:], inner.Payload)

	seq := c.sendSeq
	c.sendSeq++

	nonce := makeNonce(seq)
	ad := make([]byte, SeqNumLen)
	binary.BigEndian.PutUint64(ad, seq)

	ciphertext := c.sendAead.Seal(nil, nonce, innerWire, ad)

	outerPayload := make([]byte, SeqNumLen+len(ciphertext))
	copy(outerPayload[:SeqNumLen], ad)
	copy(outerPayload[SeqNumLen:], ciphertext)

	return c.underlying.WriteFrame(proto.Frame{
		Type:    proto.TypeEncrypted,
		Payload: outerPayload,
	})
}

// ReadControlFrame reads a proto.TypeEncrypted outer frame and decrypts the inner proto.Frame.
func (c *CipherConn) ReadControlFrame() (proto.Frame, error) {
	outer, err := c.underlying.ReadFrame()
	if err != nil {
		return proto.Frame{}, err
	}
	if outer.Type != proto.TypeEncrypted {
		return proto.Frame{}, proto.NewError(proto.CodeProto, fmt.Sprintf("expected encrypted frame (0x0D), got %s (0x%02X)", outer.Type, byte(outer.Type)))
	}
	if len(outer.Payload) < SeqNumLen+TagSize+5 {
		return proto.Frame{}, proto.NewError(proto.CodeProto, fmt.Sprintf("encrypted payload too short: %d bytes", len(outer.Payload)))
	}

	seq := binary.BigEndian.Uint64(outer.Payload[:SeqNumLen])
	if seq != c.recvSeq {
		return proto.Frame{}, proto.NewError(proto.CodeProto, fmt.Sprintf("aead sequence mismatch: expected %d, got %d", c.recvSeq, seq))
	}
	c.recvSeq++

	nonce := makeNonce(seq)
	ad := outer.Payload[:SeqNumLen]
	ciphertext := outer.Payload[SeqNumLen:]

	plaintext, err := c.recvAead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return proto.Frame{}, proto.NewError(proto.CodeProto, fmt.Sprintf("aead authentication failed: %v", err))
	}

	if len(plaintext) < 5 {
		return proto.Frame{}, proto.NewError(proto.CodeProto, "decrypted frame header too short")
	}

	innerType := proto.Type(plaintext[0])
	innerLen := binary.BigEndian.Uint32(plaintext[1:5])
	if len(plaintext) != 5+int(innerLen) {
		return proto.Frame{}, proto.NewError(proto.CodeProto, fmt.Sprintf("decrypted frame length mismatch: declared %d, got %d", innerLen, len(plaintext)-5))
	}

	return proto.Frame{
		Type:    innerType,
		Payload: plaintext[5:],
	}, nil
}
