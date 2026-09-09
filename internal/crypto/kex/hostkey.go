package kex

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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

// ErrHostKey is returned when host key verification fails (mismatch, untrusted, MITM).
var ErrHostKey = errors.New("host key verification failed")

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
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			knownHostsPath = filepath.Join(home, ".config", "relay", "known_hosts")
		}
	}

	if knownHostsPath == "" {
		return nil // No known_hosts configured and no home directory
	}

	normAddr := knownhosts.Normalize(serverAddr)

	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File does not exist yet -> TOFU
			if strictChecking == "yes" {
				return fmt.Errorf("kex: %w: known_hosts file %s does not exist and strict host key checking is enabled", ErrHostKey, knownHostsPath)
			}
			return appendKnownHost(knownHostsPath, normAddr, sshPub)
		}
		return fmt.Errorf("kex: %w: read known_hosts %s: %v", ErrHostKey, knownHostsPath, err)
	}

	var remoteAddr net.Addr
	tcpAddr, err := net.ResolveTCPAddr("tcp", serverAddr)
	if err == nil {
		remoteAddr = tcpAddr
	} else {
		remoteAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 7443}
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
		if strictChecking == "yes" {
			return fmt.Errorf("kex: %w: host key for %s is not in %s and strict host key checking is enabled", ErrHostKey, serverAddr, knownHostsPath)
		}
		return appendKnownHost(knownHostsPath, normAddr, sshPub)
	}

	return fmt.Errorf("kex: %w: %v", ErrHostKey, checkErr)
}

func appendKnownHost(path, normAddr string, key ssh.PublicKey) error {
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
