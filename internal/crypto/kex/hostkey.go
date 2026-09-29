package kex

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/crypto/ssh/terminal"
)

// LoadOrGenerateHostKey loads an OpenSSH Ed25519 private key from path.
// If the file does not exist, it generates a new Ed25519 key, saves it with 0600 permissions,
// and saves the corresponding public key to path + ".pub".
func LoadOrGenerateHostKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("kex: host key path cannot be empty")
	}

	data, err := os.ReadFile(path)
	if err == nil {
		rawKey, err := ssh.ParseRawPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("kex: parse host key %s: %w", path, err)
		}
		edKey, ok := rawKey.(*ed25519.PrivateKey)
		if !ok {
			edKeyVal, okVal := rawKey.(ed25519.PrivateKey)
			if !okVal {
				return nil, fmt.Errorf("kex: host key %s is %T, expected Ed25519 private key", path, rawKey)
			}
			return edKeyVal, nil
		}
		return *edKey, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("kex: read host key %s: %w", path, err)
	}

	// Auto-generate on first run
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("kex: generate host key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "remote-relay host key")
	if err != nil {
		return nil, fmt.Errorf("kex: marshal host key: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("kex: create host key dir %s: %w", dir, err)
	}

	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("kex: write host key %s: %w", path, err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err == nil {
		pubBytes := ssh.MarshalAuthorizedKey(sshPub)
		_ = os.WriteFile(path+".pub", pubBytes, 0644)
	}

	return priv, nil
}

// FingerprintSHA256 returns standard OpenSSH format SHA256 fingerprint ("SHA256:...").
func FingerprintSHA256(pub ed25519.PublicKey) string {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(sshPub)
}

// RawEd25519ToAuthorizedKeysLine renders a raw 32-byte Ed25519 public key in
// OpenSSH wire form ("ssh-ed25519 AAAA…"). KexReply carries the raw key while
// known_hosts matching and operator-facing fingerprints use the wire form.
func RawEd25519ToAuthorizedKeysLine(pub []byte) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("kex: %w: invalid ed25519 public key size %d", ErrHostKey, len(pub))
	}
	sshPub, err := ssh.NewPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		return "", fmt.Errorf("kex: %w: invalid host key: %v", ErrHostKey, err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
}

// VerifyAttestation validates a KEX transcript relayed by an intermediate
// (FEAT-UTL-05 J-D3). kexInit is the 48-byte payload the dialling relay sent
// (clientEph ‖ clientNonce) and kexReply the 144-byte reply it received
// (serverEph ‖ serverNonce ‖ hostKey ‖ sig).
//
// It recomputes ExchangeHash over the transcript, checks the host-key signature,
// then matches the host key against a pin or known_hosts under addr — the
// address the *verifier* asked for, never one chosen by the relaying party.
//
// The returned serverNonce is the value covered by the host-key signature; per
// J-D16 a server reuses it as its auth-challenge nonce, so callers must compare
// it against AUTH_OK.serverNonce before signing a relayed challenge.
func VerifyAttestation(kexInit, kexReply []byte, knownHostsPath, addr, pinnedFingerprint, strictChecking string) ([]byte, error) {
	if len(kexInit) != KexInitLen {
		return nil, fmt.Errorf("kex: %w: attestation KEX_INIT length %d, expected %d", ErrHostKey, len(kexInit), KexInitLen)
	}
	if len(kexReply) != KexReplyLen {
		return nil, fmt.Errorf("kex: %w: attestation KEX_REPLY length %d, expected %d", ErrHostKey, len(kexReply), KexReplyLen)
	}
	clientEph := kexInit[:32]
	clientNonce := kexInit[32:48]
	serverEph := kexReply[:32]
	serverNonce := kexReply[32:48]
	hostKey := kexReply[48:80]
	sig := kexReply[80:144]

	hash := ExchangeHash(clientEph, serverEph, clientNonce, serverNonce, hostKey)
	if !ed25519.Verify(ed25519.PublicKey(hostKey), hash, sig) {
		return nil, fmt.Errorf("kex: %w: attested transcript has no valid host key signature", ErrHostKey)
	}
	if err := VerifyKnownHosts(knownHostsPath, addr, ed25519.PublicKey(hostKey), pinnedFingerprint, strictChecking); err != nil {
		return nil, err
	}
	out := make([]byte, len(serverNonce))
	copy(out, serverNonce)
	return out, nil
}

// ErrHostKey is returned when host key verification fails (mismatch, untrusted, MITM).
var ErrHostKey = errors.New("host key verification failed")

var (
	PromptReader io.Reader = os.Stdin
	PromptWriter io.Writer = os.Stderr
	PromptUser             = defaultPromptUser
)

func defaultPromptUser(serverAddr, fp string) (bool, error) {
	if f, ok := PromptReader.(*os.File); ok && f == os.Stdin {
		if !terminal.IsTerminal(int(f.Fd())) {
			return false, fmt.Errorf("no interactive terminal available to prompt for host key verification")
		}
	}

	fmt.Fprintf(PromptWriter, "The authenticity of host '%s' can't be established.\n", serverAddr)
	fmt.Fprintf(PromptWriter, "ED25519 key fingerprint is %s.\n", fp)
	fmt.Fprintf(PromptWriter, "Are you sure you want to continue connecting (yes/no)? ")

	reader := bufio.NewReader(PromptReader)
	line, err := reader.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
		return false, fmt.Errorf("read user input: %w", err)
	}

	ans := strings.ToLower(strings.TrimSpace(line))
	if ans == "yes" || ans == "y" {
		return true, nil
	}
	return false, nil
}

func handleTOFU(knownHostsPath, serverAddr, normAddr string, sshPub ssh.PublicKey, fp, strictChecking, notFoundReason string) error {
	mode := strings.ToLower(strings.TrimSpace(strictChecking))
	if mode == "" {
		if terminal.IsTerminal(int(os.Stdin.Fd())) && terminal.IsTerminal(int(os.Stderr.Fd())) {
			mode = "ask"
		} else {
			mode = "yes"
		}
	}

	switch mode {
	case "yes":
		return fmt.Errorf("kex: %w: %s and strict host key checking is enabled", ErrHostKey, notFoundReason)
	case "accept-new", "no":
		return appendKnownHost(knownHostsPath, normAddr, sshPub)
	case "ask":
		ok, err := PromptUser(serverAddr, fp)
		if err != nil {
			return fmt.Errorf("kex: %w: %v", ErrHostKey, err)
		}
		if !ok {
			return fmt.Errorf("kex: %w: host key verification failed for %s", ErrHostKey, serverAddr)
		}
		if err := appendKnownHost(knownHostsPath, normAddr, sshPub); err != nil {
			return err
		}
		fmt.Fprintf(PromptWriter, "Warning: Permanently added '%s' (ED25519) to the list of known hosts.\n", normAddr)
		return nil
	default:
		return fmt.Errorf("kex: %w: unknown strict host key checking mode %q", ErrHostKey, strictChecking)
	}
}

// VerifyKnownHosts checks a server's Ed25519 public host key against:
// 1. Pinned fingerprint (if provided)
// 2. OpenSSH known_hosts file
func VerifyKnownHosts(knownHostsPath, serverAddr string, pub ed25519.PublicKey, pinnedFingerprint string, strictChecking string) error {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("kex: %w: invalid server public key: %v", ErrHostKey, err)
	}

	fp := ssh.FingerprintSHA256(sshPub)

	// 1. Pinned fingerprint check
	if pinnedFingerprint != "" {
		normPinned := pinnedFingerprint
		if !strings.HasPrefix(normPinned, "SHA256:") {
			normPinned = "SHA256:" + normPinned
		}
		if fp != normPinned {
			return fmt.Errorf("kex: %w: host key fingerprint mismatch: got %s, want %s", ErrHostKey, fp, normPinned)
		}
		return nil
	}

	// 2. known_hosts file verification
	if knownHostsPath == "" {
		if env := os.Getenv("RELAY_TEST_KNOWN_HOSTS"); env != "" {
			knownHostsPath = env
		} else {
			home, err := os.UserHomeDir()
			if err == nil && home != "" {
				knownHostsPath = filepath.Join(home, ".config", "relay", "known_hosts")
			}
		}
	}

	if knownHostsPath == "" {
		if strings.ToLower(strings.TrimSpace(strictChecking)) == "no" {
			return nil
		}
		return fmt.Errorf("kex: %w: no known_hosts file path available (configure --known-hosts, --server-fingerprint, or ensure HOME is set)", ErrHostKey)
	}

	cleanAddr := serverAddr
	if idx := strings.Index(cleanAddr, "://"); idx >= 0 {
		cleanAddr = cleanAddr[idx+3:]
	}
	if idx := strings.Index(cleanAddr, "/"); idx >= 0 {
		cleanAddr = cleanAddr[:idx]
	}

	normAddr := knownhosts.Normalize(cleanAddr)

	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File does not exist yet -> TOFU
			reason := fmt.Sprintf("known_hosts file %s does not exist", knownHostsPath)
			return handleTOFU(knownHostsPath, cleanAddr, normAddr, sshPub, fp, strictChecking, reason)
		}
		return fmt.Errorf("kex: %w: read known_hosts %s: %v", ErrHostKey, knownHostsPath, err)
	}

	var remoteAddr net.Addr
	tcpAddr, err := net.ResolveTCPAddr("tcp", cleanAddr)
	if err == nil {
		remoteAddr = tcpAddr
	} else {
		port := 7443
		if _, portStr, splitErr := net.SplitHostPort(cleanAddr); splitErr == nil {
			if p, convErr := strconv.Atoi(portStr); convErr == nil && p > 0 {
				port = p
			}
		}
		remoteAddr = &net.TCPAddr{IP: net.IPv4zero, Port: port}
	}

	checkErr := cb(normAddr, remoteAddr, sshPub)
	if checkErr == nil {
		return nil // Exact match
	}

	var keyErr *knownhosts.KeyError
	if errors.As(checkErr, &keyErr) {
		if len(keyErr.Want) > 0 {
			// Host key mismatch: active MITM danger!
			return fmt.Errorf("kex: %w: REMOTE HOST IDENTIFICATION HAS CHANGED for %s! Found mismatched entry in %s", ErrHostKey, serverAddr, knownHostsPath)
		}
		// Unknown host: TOFU
		reason := fmt.Sprintf("host key for %s is not in %s", serverAddr, knownHostsPath)
		return handleTOFU(knownHostsPath, serverAddr, normAddr, sshPub, fp, strictChecking, reason)
	}

	return fmt.Errorf("kex: %w: %v", ErrHostKey, checkErr)
}

func appendKnownHost(path, normAddr string, key ssh.PublicKey) error {
	if path == os.DevNull || path == "/dev/null" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("kex: create known_hosts dir %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("kex: open known_hosts %s for append: %w", path, err)
	}
	defer f.Close()

	line := knownhosts.Line([]string{normAddr}, key)
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("kex: write to known_hosts %s: %w", path, err)
	}
	return nil
}
