package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const minRSABits = 2048

// Offer is HELLO.auth / RESUME.auth for ssh-publickey.
type Offer struct {
	Method      string `json:"method"`
	User        string `json:"user"`
	PubKey      string `json:"pubkey"`
	ClientNonce string `json:"clientNonce,omitempty"`
}

type authMsg struct {
	Sig string `json:"sig"`
}

// PublicKey is the M5 authenticator: authorized_keys verify, ~/.ssh/id_* sign.
type PublicKey struct {
	cfg Config

	mu      sync.Mutex
	signers []ssh.Signer
}

func NewPublicKey(cfg Config) *PublicKey {
	if len(cfg.IdentityFiles) > 0 {
		cfg.IdentityFiles = append([]string(nil), cfg.IdentityFiles...)
	}
	return &PublicKey{cfg: cfg}
}

func (p *PublicKey) Name() string { return MethodPublicKey }

func (p *PublicKey) RequiresChallenge() bool { return true }

func (p *PublicKey) FailDelay() time.Duration {
	if p.cfg.FailDelay > 0 {
		return p.cfg.FailDelay
	}
	return DefaultFailDelay
}

func (p *PublicKey) Respond(ch Challenge) (json.RawMessage, error) {
	signers, err := p.getSigners()
	if err != nil {
		return nil, err
	}
	pub := signers[0].PublicKey()
	offer := Offer{
		Method:      MethodPublicKey,
		User:        p.user(),
		PubKey:      strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		ClientNonce: ch.ClientNonce,
	}
	b, err := json.Marshal(offer)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (p *PublicKey) Sign(ch Challenge) (json.RawMessage, error) {
	digest := DeriveChallenge(ch)
	var want ssh.PublicKey
	if pub, _, err := parseOfferKey(ch.Offer); err == nil {
		want = pub
	}
	signer, err := p.signerFor(want)
	if err != nil {
		return nil, err
	}
	sig, err := signDigest(signer, digest)
	if err != nil {
		return nil, err
	}
	enc, err := marshalSig(sig)
	if err != nil {
		return nil, err
	}
	return json.Marshal(authMsg{Sig: enc})
}

func (p *PublicKey) Verify(ch Challenge, raw json.RawMessage) (Identity, error) {
	digest := DeriveChallenge(ch)
	pub, name, err := p.publicKeyFor(ch)
	if err != nil {
		return Identity{}, errAuth
	}
	if err := checkKeyPolicy(pub); err != nil {
		return Identity{}, errAuth
	}
	fp := ssh.FingerprintSHA256(pub)
	if ch.BoundFP != "" && !fingerprintEqual(fp, ch.BoundFP) {
		return Identity{}, errAuth
	}
	if !p.keyAuthorized(pub) {
		return Identity{}, errAuth
	}
	var msg authMsg
	if err := json.Unmarshal(bytes.TrimSpace(raw), &msg); err != nil {
		return Identity{}, errAuth
	}
	sig, err := unmarshalSig(msg.Sig)
	if err != nil {
		return Identity{}, errAuth
	}
	if !allowedSigFormat(sig.Format, pub) {
		return Identity{}, errAuth
	}
	if err := pub.Verify(digest, sig); err != nil {
		return Identity{}, errAuth
	}
	return Identity{
		Method:      MethodPublicKey,
		Name:        name,
		Fingerprint: fp,
		RawPubKey:   pub.Marshal(),
	}, nil
}

func (p *PublicKey) publicKeyFor(ch Challenge) (ssh.PublicKey, string, error) {
	pub, name, err := parseOfferKey(ch.Offer)
	if err == nil && pub != nil {
		return pub, name, nil
	}
	if len(ch.RawPubKey) > 0 {
		pub, err := ssh.ParsePublicKey(ch.RawPubKey)
		if err != nil {
			return nil, "", errAuth
		}
		return pub, p.user(), nil
	}
	return nil, "", errAuth
}

func (p *PublicKey) user() string {
	if u := strings.TrimSpace(p.cfg.User); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

func (p *PublicKey) authorizedKeysPath() string {
	if p.cfg.AuthorizedKeys != "" {
		return expandHome(p.cfg.AuthorizedKeys)
	}
	return DefaultAuthorizedKeys()
}

func (p *PublicKey) keyAuthorized(pub ssh.PublicKey) bool {
	keys, err := loadAuthorizedKeys(p.authorizedKeysPath())
	if err != nil {
		return false
	}
	want := pub.Marshal()
	for _, k := range keys {
		if checkKeyPolicy(k) != nil {
			continue
		}
		got := k.Marshal()
		if len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1 {
			return true
		}
	}
	return false
}

func (p *PublicKey) getSigners() ([]ssh.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.signers != nil {
		return p.signers, nil
	}
	signers, err := p.loadSigners()
	if err != nil {
		return nil, err
	}
	p.signers = signers
	return signers, nil
}

func (p *PublicKey) loadSigners() ([]ssh.Signer, error) {
	files := p.cfg.IdentityFiles
	if len(files) == 0 {
		files = DefaultIdentityFiles()
	}
	var out []ssh.Signer
	for _, f := range files {
		b, err := os.ReadFile(expandHome(f))
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(b)
		if err != nil {
			continue
		}
		if err := checkKeyPolicy(signer.PublicKey()); err != nil {
			continue
		}
		out = append(out, signer)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("auth: no usable identity file")
	}
	return out, nil
}

func (p *PublicKey) signerFor(pub ssh.PublicKey) (ssh.Signer, error) {
	signers, err := p.getSigners()
	if err != nil {
		return nil, err
	}
	if pub != nil {
		want := pub.Marshal()
		for _, s := range signers {
			got := s.PublicKey().Marshal()
			if len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1 {
				return s, nil
			}
		}
		return nil, errAuth
	}
	return signers[0], nil
}

var errAuth = fmt.Errorf("auth failed")

func DefaultAuthorizedKeys() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".ssh", "authorized_keys")
}

func DefaultIdentityFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	dir := filepath.Join(home, ".ssh")
	return []string{
		filepath.Join(dir, "id_ed25519"),
		filepath.Join(dir, "id_ecdsa"),
		filepath.Join(dir, "id_rsa"),
	}
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func parseOfferKey(raw json.RawMessage) (ssh.PublicKey, string, error) {
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 || string(trim) == "null" || string(trim) == "{}" {
		return nil, "", errAuth
	}
	var offer Offer
	if err := json.Unmarshal(trim, &offer); err != nil {
		return nil, "", errAuth
	}
	if offer.Method != MethodPublicKey {
		return nil, "", errAuth
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(offer.PubKey)))
	if err != nil {
		return nil, "", errAuth
	}
	return pub, offer.User, nil
}

func loadAuthorizedKeys(path string) ([]ssh.PublicKey, error) {
	if path == "" {
		return nil, errAuth
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []ssh.PublicKey
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue
		}
		keys = append(keys, pub)
	}
	return keys, nil
}

func checkKeyPolicy(pub ssh.PublicKey) error {
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return nil
	case ssh.KeyAlgoRSA:
		cp, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return errAuth
		}
		rsaPub, ok := cp.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rsaPub.N.BitLen() < minRSABits {
			return errAuth
		}
		return nil
	default:
		return errAuth
	}
}

func allowedSigFormat(format string, pub ssh.PublicKey) bool {
	switch format {
	case ssh.KeyAlgoED25519:
		return pub.Type() == ssh.KeyAlgoED25519
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return pub.Type() == format
	case ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return pub.Type() == ssh.KeyAlgoRSA
	default:
		return false
	}
}

func signDigest(signer ssh.Signer, digest []byte) (*ssh.Signature, error) {
	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		if as, ok := signer.(ssh.AlgorithmSigner); ok {
			return as.SignWithAlgorithm(rand.Reader, digest, ssh.KeyAlgoRSASHA256)
		}
	}
	return signer.Sign(rand.Reader, digest)
}

func marshalSig(sig *ssh.Signature) (string, error) {
	if sig == nil || len(sig.Blob) == 0 {
		return "", errAuth
	}
	raw := ssh.Marshal(ssh.Signature{Format: sig.Format, Blob: sig.Blob})
	return base64.StdEncoding.EncodeToString(raw), nil
}

func unmarshalSig(s string) (*ssh.Signature, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 {
		return nil, errAuth
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(raw, &sig); err != nil {
		return nil, errAuth
	}
	if sig.Format == "" || len(sig.Blob) == 0 {
		return nil, errAuth
	}
	return &sig, nil
}

func fingerprintEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
