package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

	mu        sync.Mutex
	signers   []ssh.Signer
	agentConn io.Closer
	entries   []AuthorizedKeyEntry
}

func NewPublicKey(cfg Config) *PublicKey {
	if len(cfg.IdentityFiles) > 0 {
		cfg.IdentityFiles = append([]string(nil), cfg.IdentityFiles...)
	}
	p := &PublicKey{cfg: cfg}
	akPath := p.authorizedKeysPath()
	if akPath != "" {
		if entries, err := LoadAuthorizedKeyEntries(akPath); err == nil && len(entries) > 0 {
			p.entries = entries
		}
	}
	return p
}

func (p *PublicKey) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.agentConn != nil {
		err := p.agentConn.Close()
		p.agentConn = nil
		return err
	}
	return nil
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
	var pub ssh.PublicKey
	if ch.BoundFP != "" {
		for _, s := range signers {
			if fingerprintEqual(ssh.FingerprintSHA256(s.PublicKey()), ch.BoundFP) {
				pub = s.PublicKey()
				break
			}
		}
	}
	if pub == nil {
		pub = signers[0].PublicKey()
	}
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
	if err != nil && ch.BoundFP != "" {
		p.mu.Lock()
		for _, s := range p.signers {
			if fingerprintEqual(ssh.FingerprintSHA256(s.PublicKey()), ch.BoundFP) {
				signer = s
				err = nil
				break
			}
		}
		p.mu.Unlock()
	}
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
	entry, ok := p.findAuthorizedEntry(pub)
	if !ok {
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
	userName := name
	if userName == "" && entry.Comment != "" {
		userName = entry.Comment
	}
	return Identity{
		Method:                MethodPublicKey,
		Name:                  userName,
		Fingerprint:           fp,
		RawPubKey:             pub.Marshal(),
		PortForwardingBlocked: entry.PortForwardingBlocked,
		PermittedDestinations: entry.PermittedDestinations,
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

func (p *PublicKey) findAuthorizedEntry(pub ssh.PublicKey) (*AuthorizedKeyEntry, bool) {
	p.mu.Lock()
	entries := p.entries
	p.mu.Unlock()
	if len(entries) == 0 {
		if diskEntries, err := LoadAuthorizedKeyEntries(p.authorizedKeysPath()); err == nil && len(diskEntries) > 0 {
			p.mu.Lock()
			if len(p.entries) == 0 {
				p.entries = diskEntries
			}
			entries = p.entries
			p.mu.Unlock()
		}
	}
	want := pub.Marshal()
	for _, e := range entries {
		if checkKeyPolicy(e.PublicKey) != nil {
			continue
		}
		got := e.PublicKey.Marshal()
		if len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1 {
			return &e, true
		}
	}
	return nil, false
}

func (p *PublicKey) keyAuthorized(pub ssh.PublicKey) bool {
	_, ok := p.findAuthorizedEntry(pub)
	return ok
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

func (p *PublicKey) connectAgent() (agent.Agent, io.Closer) {
	if p.cfg.Agent != nil {
		return p.cfg.Agent, nil
	}
	sock := p.cfg.AuthSock
	if sock == "" {
		sock = defaultAuthSock()
	}
	if sock == "" || sock == "none" {
		return nil, nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil
	}
	return agent.NewClient(conn), conn
}

func defaultAuthSock() string {
	if s := os.Getenv("RELAY_TEST_AUTH_SOCK"); s != "" {
		return s
	}
	if os.Getenv("RELAY_TEST_IDENTITY") != "" {
		return ""
	}
	return os.Getenv("SSH_AUTH_SOCK")
}

func (p *PublicKey) loadSigners() ([]ssh.Signer, error) {
	var agentSigners []ssh.Signer
	ag, closer := p.connectAgent()
	if closer != nil {
		p.agentConn = closer
	}
	if ag != nil {
		if rawSigners, err := ag.Signers(); err == nil {
			for _, s := range rawSigners {
				if err := checkKeyPolicy(s.PublicKey()); err == nil {
					agentSigners = append(agentSigners, s)
				}
			}
		}
	}

	var out []ssh.Signer

	// Case 1: Specific identity files requested
	if len(p.cfg.IdentityFiles) > 0 {
		for _, f := range p.cfg.IdentityFiles {
			exp := expandHome(f)
			// A. Check if matching signer exists in ssh-agent
			pub := extractPublicKey(exp)
			var matched ssh.Signer
			if pub != nil {
				want := pub.Marshal()
				for _, as := range agentSigners {
					got := as.PublicKey().Marshal()
					if len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1 {
						matched = as
						break
					}
				}
			}
			if matched != nil {
				out = append(out, matched)
				continue
			}

			// B. Fall back to unencrypted file on disk
			b, err := os.ReadFile(exp)
			if err == nil {
				signer, err := ssh.ParsePrivateKey(b)
				if err == nil && checkKeyPolicy(signer.PublicKey()) == nil {
					out = append(out, signer)
					continue
				}
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("auth: no usable identity found for specified identity_files (specify valid unencrypted key or load in ssh-agent)")
		}
		return out, nil
	}

	// Case 2: No specific identity files: Fallback Chain
	// 1. Try active ssh-agent keys
	if len(agentSigners) > 0 {
		out = append(out, agentSigners...)
	}

	// 2. Fall back to unencrypted default files on disk
	for _, f := range DefaultIdentityFiles() {
		exp := expandHome(f)
		b, err := os.ReadFile(exp)
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
		if !containsSigner(out, signer.PublicKey()) {
			out = append(out, signer)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("auth: no usable identity found in ssh-agent or identity files (specify --identity/-i, add a key to ssh-agent, or configure ~/.ssh/id_ed25519)")
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
	if p := os.Getenv("RELAY_TEST_AUTHORIZED_KEYS"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".ssh", "authorized_keys")
}

func DefaultIdentityFiles() []string {
	if p := os.Getenv("RELAY_TEST_IDENTITY"); p != "" {
		return []string{p}
	}
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

// AuthorizedKeyEntry represents a parsed authorized_keys entry with its key,
// comment, raw options, and evaluated RBAC restrictions.
type AuthorizedKeyEntry struct {
	PublicKey             ssh.PublicKey
	Comment               string
	Options               []string
	PortForwardingBlocked bool
	PermittedDestinations []string
}

// ParseAuthorizedKeyOptions evaluates OpenSSH authorized_keys options according
// to sshd(8) semantics:
//   - "no-port-forwarding": blocks all destination port forwarding.
//   - "permitopen=\"none\"" or "permitopen=\"\"": blocks all destination port forwarding.
//   - "permitopen=\"host:port\"": specifies an allowed destination. Can appear
//     multiple times or contain comma-separated destinations.
//   - "restrict": disables port forwarding unless explicitly enabled via "port-forwarding".
//   - "port-forwarding": re-enables port forwarding when preceded or paired with "restrict".
func ParseAuthorizedKeyOptions(options []string) (blocked bool, permitted []string) {
	var permitOpenEntries []string
	restrict := false
	allowPF := false

	for _, opt := range options {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		lower := strings.ToLower(opt)
		if lower == "no-port-forwarding" {
			blocked = true
			continue
		}
		if lower == "restrict" {
			restrict = true
			continue
		}
		if lower == "port-forwarding" {
			allowPF = true
			continue
		}
		if strings.HasPrefix(lower, "permitopen=") {
			val := opt[len("permitopen="):]
			val = strings.Trim(val, `"`)
			val = strings.TrimSpace(val)
			if val == "" || strings.EqualFold(val, "none") {
				blocked = true
				continue
			}
			for _, part := range strings.Split(val, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					permitOpenEntries = append(permitOpenEntries, part)
				}
			}
		}
	}

	if restrict && !allowPF {
		blocked = true
	}

	return blocked, permitOpenEntries
}

// LoadAuthorizedKeyEntries reads and parses all OpenSSH public keys and options from path.
func LoadAuthorizedKeyEntries(path string) ([]AuthorizedKeyEntry, error) {
	if path == "" {
		return nil, errAuth
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []AuthorizedKeyEntry
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pub, comment, options, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue
		}
		blocked, permitted := ParseAuthorizedKeyOptions(options)
		entries = append(entries, AuthorizedKeyEntry{
			PublicKey:             pub,
			Comment:               comment,
			Options:               options,
			PortForwardingBlocked: blocked,
			PermittedDestinations: permitted,
		})
	}
	return entries, nil
}

// LoadAuthorizedKeys reads and parses all OpenSSH public keys from path.
func LoadAuthorizedKeys(path string) ([]ssh.PublicKey, error) {
	entries, err := LoadAuthorizedKeyEntries(path)
	if err != nil {
		return nil, err
	}
	keys := make([]ssh.PublicKey, len(entries))
	for i, e := range entries {
		keys[i] = e.PublicKey
	}
	return keys, nil
}

// HasValidAuthorizedKeys returns true if path exists and contains at least one valid public key.
func HasValidAuthorizedKeys(path string) bool {
	keys, err := LoadAuthorizedKeys(path)
	return err == nil && len(keys) > 0
}

func loadAuthorizedKeys(path string) ([]ssh.PublicKey, error) {
	return LoadAuthorizedKeys(path)
}

func containsSigner(signers []ssh.Signer, pub ssh.PublicKey) bool {
	want := pub.Marshal()
	for _, s := range signers {
		got := s.PublicKey().Marshal()
		if len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1 {
			return true
		}
	}
	return false
}

func extractPublicKey(path string) ssh.PublicKey {
	if pubBytes, err := os.ReadFile(path + ".pub"); err == nil {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes); err == nil {
			return pub
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if signer, err := ssh.ParsePrivateKey(data); err == nil {
		return signer.PublicKey()
	}
	if pub, _, _, _, err := ssh.ParseAuthorizedKey(data); err == nil {
		return pub
	}
	if pub, err := extractOpenSSHPublicKey(data); err == nil {
		return pub
	}
	return nil
}

func extractOpenSSHPublicKey(data []byte) (ssh.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return nil, fmt.Errorf("not openssh private key")
	}
	b := block.Bytes
	prefix := append([]byte("openssh-key-v1"), 0x00)
	if !bytes.HasPrefix(b, prefix) {
		return nil, fmt.Errorf("bad openssh key header")
	}
	b = b[len(prefix):]
	readString := func() ([]byte, bool) {
		if len(b) < 4 {
			return nil, false
		}
		l := binary.BigEndian.Uint32(b)
		b = b[4:]
		if uint32(len(b)) < l {
			return nil, false
		}
		s := b[:l]
		b = b[l:]
		return s, true
	}
	if _, ok := readString(); !ok {
		return nil, fmt.Errorf("bad cipher")
	}
	if _, ok := readString(); !ok {
		return nil, fmt.Errorf("bad kdf")
	}
	if _, ok := readString(); !ok {
		return nil, fmt.Errorf("bad kdfopts")
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("bad num keys")
	}
	nkeys := binary.BigEndian.Uint32(b)
	b = b[4:]
	if nkeys == 0 {
		return nil, fmt.Errorf("zero keys")
	}
	pubBytes, ok := readString()
	if !ok {
		return nil, fmt.Errorf("bad pub bytes")
	}
	return ssh.ParsePublicKey(pubBytes)
}

func checkKeyPolicy(pub ssh.PublicKey) error {
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return nil
	case ssh.KeyAlgoRSA:
		cp, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			parsed, err := ssh.ParsePublicKey(pub.Marshal())
			if err != nil {
				return errAuth
			}
			cp, ok = parsed.(ssh.CryptoPublicKey)
			if !ok {
				return errAuth
			}
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
	case ssh.KeyAlgoSKED25519:
		return pub.Type() == ssh.KeyAlgoSKED25519
	case ssh.KeyAlgoSKECDSA256:
		return pub.Type() == ssh.KeyAlgoSKECDSA256
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
