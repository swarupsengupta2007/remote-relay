package kex

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// attestTranscript runs a real server-side KEX and returns the two payloads an
// intermediate would relay: the KEX_INIT it sent and the KEX_REPLY it got.
func attestTranscript(t *testing.T, hostPriv ed25519.PrivateKey) (init, reply []byte) {
	t.Helper()
	srv, err := NewServerSession(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewClientSession()
	if err != nil {
		t.Fatal(err)
	}
	init = cli.InitPayload()
	reply, _, _, err = srv.ProcessInit(init)
	if err != nil {
		t.Fatal(err)
	}
	return init, reply
}

func writeKnownHostsFor(t *testing.T, addr string, pub ed25519.PublicKey) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, sshPub)
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyAttestationSuccess(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr := "s.example.com:7443"
	init, reply := attestTranscript(t, priv)
	kh := writeKnownHostsFor(t, addr, pub)

	nonce, err := VerifyAttestation(init, reply, kh, addr, "", "yes")
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	if got, want := base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(reply[32:48]); got != want {
		t.Fatalf("attested nonce %s, want the KEX_REPLY nonce %s", got, want)
	}
}

func TestVerifyAttestationPin(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr := "s.example.com:7443"
	init, reply := attestTranscript(t, priv)
	fp := FingerprintSHA256(pub)

	if _, err := VerifyAttestation(init, reply, "", addr, fp, "yes"); err != nil {
		t.Fatalf("matching pin: %v", err)
	}

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAttestation(init, reply, "", addr, FingerprintSHA256(other), "yes"); !errors.Is(err, ErrHostKey) {
		t.Fatalf("mismatched pin: got %v, want ErrHostKey", err)
	}
}

func TestVerifyAttestationRejects(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr := "s.example.com:7443"
	init, reply := attestTranscript(t, priv)
	kh := writeKnownHostsFor(t, addr, pub)

	t.Run("unknown host key", func(t *testing.T) {
		// The rogue signed its own transcript correctly, but its key is not the
		// one the verifier knows for addr.
		_, rogueReply := attestTranscript(t, roguePriv)
		if _, err := VerifyAttestation(init, rogueReply, kh, addr, "", "yes"); !errors.Is(err, ErrHostKey) {
			t.Fatalf("got %v, want ErrHostKey", err)
		}
		if _, err := VerifyAttestation(init, rogueReply, "", addr, FingerprintSHA256(pub), "yes"); !errors.Is(err, ErrHostKey) {
			t.Fatalf("pin: got %v, want ErrHostKey", err)
		}
	})

	t.Run("forged signature", func(t *testing.T) {
		bad := append([]byte(nil), reply...)
		bad[len(bad)-1] ^= 0xff
		if _, err := VerifyAttestation(init, bad, kh, addr, "", "yes"); !errors.Is(err, ErrHostKey) {
			t.Fatalf("got %v, want ErrHostKey", err)
		}
	})

	t.Run("transcript substitution", func(t *testing.T) {
		// A genuine reply paired with a different KEX_INIT changes the exchange
		// hash, so the host key signature no longer verifies.
		cli, err := NewClientSession()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyAttestation(cli.InitPayload(), reply, kh, addr, "", "yes"); !errors.Is(err, ErrHostKey) {
			t.Fatalf("got %v, want ErrHostKey", err)
		}
	})

	t.Run("bad lengths", func(t *testing.T) {
		if _, err := VerifyAttestation(init[:32], reply, kh, addr, "", "yes"); !errors.Is(err, ErrHostKey) {
			t.Fatalf("short init: got %v, want ErrHostKey", err)
		}
		if _, err := VerifyAttestation(init, reply[:100], kh, addr, "", "yes"); !errors.Is(err, ErrHostKey) {
			t.Fatalf("short reply: got %v, want ErrHostKey", err)
		}
	})
}

func TestRawEd25519ToAuthorizedKeysLine(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	line, err := RawEd25519ToAuthorizedKeysLine(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Fatalf("line = %q", line)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(parsed.Type(), "ssh-ed25519") {
		t.Fatalf("type = %q", parsed.Type())
	}
	want, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(parsed) != ssh.FingerprintSHA256(want) {
		t.Fatal("round-tripped key differs")
	}

	if _, err := RawEd25519ToAuthorizedKeysLine(pub[:16]); !errors.Is(err, ErrHostKey) {
		t.Fatalf("short key: got %v, want ErrHostKey", err)
	}
}
