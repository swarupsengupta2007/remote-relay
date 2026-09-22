package session

import (
	"errors"
	"testing"

	"github.com/remote-relay/relay/internal/proto"
)

func TestTokenRotateAndVerify(t *testing.T) {
	st := NewStore(8)
	sess, token, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Add(sess); err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyToken(sess.ID, token); err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyToken(sess.ID, "not-a-token"); !errors.Is(err, proto.ErrBadToken) {
		t.Fatalf("got %v", err)
	}
	next, err := st.RotateToken(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if next == token {
		t.Fatal("token was not rotated")
	}
	if err := st.VerifyToken(sess.ID, token); err != nil {
		t.Fatalf("previous generation should still verify: %v", err)
	}
	if err := st.VerifyToken(sess.ID, next); err != nil {
		t.Fatal(err)
	}
	again, err := st.ResumeToken(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again != next {
		t.Fatal("unconfirmed rotation must reuse the current token")
	}
	st.ConfirmToken(sess.ID)
	if err := st.VerifyToken(sess.ID, token); !errors.Is(err, proto.ErrBadToken) {
		t.Fatalf("old token after confirm: %v", err)
	}
	if err := st.VerifyToken(sess.ID, next); err != nil {
		t.Fatal(err)
	}
}

func TestStoreMaxCapacity(t *testing.T) {
	st := NewStore(1)
	s1, _, err := New()
	if err != nil {
		t.Fatal(err)
	}
	s2, _, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Add(s1); err != nil {
		t.Fatal(err)
	}
	if err := st.Add(s2); !errors.Is(err, proto.ErrNoCapacity) {
		t.Fatalf("got %v want ERR_NO_CAPACITY", err)
	}
	if st.Len() != 1 {
		t.Fatalf("len=%d", st.Len())
	}
}

func TestExpireTombstone(t *testing.T) {
	st := NewStore(8)
	sess, token, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Add(sess); err != nil {
		t.Fatal(err)
	}
	st.Expire(sess.ID)
	if st.Get(sess.ID) != nil {
		t.Fatal("live after expire")
	}
	if err := st.VerifyToken(sess.ID, token); !errors.Is(err, proto.ErrExpired) {
		t.Fatalf("got %v want expired", err)
	}
	if err := st.VerifyToken("s-missing", token); !errors.Is(err, proto.ErrUnknownSession) {
		t.Fatalf("got %v want unknown", err)
	}
}

func TestForceResumeToken(t *testing.T) {
	st := NewStore(8)
	sess, token, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Add(sess); err != nil {
		t.Fatal(err)
	}
	unconfirmed, err := st.ResumeToken(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	// ForceResumeToken should bypass cached unconfirmed token
	forced, err := st.ForceResumeToken(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if forced == unconfirmed || forced == token {
		t.Fatalf("forced token must be brand new, got %v", forced)
	}
	if err := st.VerifyToken(sess.ID, forced); err != nil {
		t.Fatalf("forced token should verify: %v", err)
	}
}

func TestSessionSnapshotRestore(t *testing.T) {
	st := NewStore(10)
	sess, token, err := New()
	if err != nil {
		t.Fatal(err)
	}
	sess.Destination = "127.0.0.1:2222"
	sess.AuthMethod = "ssh-publickey"
	sess.AuthUser = "alice"
	sess.Fingerprint = "SHA256:test"
	sess.PublicKey = []byte("test-key")

	if err := st.Add(sess); err != nil {
		t.Fatal(err)
	}

	// Rotate token once
	rotToken, err := st.ResumeToken(sess.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Verify both current and previous token verify
	if err := st.VerifyToken(sess.ID, rotToken); err != nil {
		t.Fatalf("rotToken should verify: %v", err)
	}
	if err := st.VerifyToken(sess.ID, token); err != nil {
		t.Fatalf("old token should verify: %v", err)
	}

	// Snapshot all sessions
	snaps := st.Snapshot()
	if len(snaps) != 1 {
		t.Fatalf("expected 1 snap, got %d", len(snaps))
	}
	snap := snaps[0]
	if snap.ID != sess.ID {
		t.Fatalf("snap ID: got %s want %s", snap.ID, sess.ID)
	}
	if snap.Destination != "127.0.0.1:2222" {
		t.Fatalf("snap dest: got %s want 127.0.0.1:2222", snap.Destination)
	}
	if !snap.HasPrev {
		t.Fatal("expected snap.HasPrev to be true")
	}

	// Restore into a brand new store
	st2 := NewStore(10)
	restoredSess, err := RestoreSession(snap)
	if err != nil {
		t.Fatalf("RestoreSession failed: %v", err)
	}
	st2.Restore(restoredSess)

	if st2.Len() != 1 {
		t.Fatalf("st2 len: got %d want 1", st2.Len())
	}
	// Verify both current and previous token still verify in restored store!
	if err := st2.VerifyToken(sess.ID, rotToken); err != nil {
		t.Fatalf("restored rotToken verify: %v", err)
	}
	if err := st2.VerifyToken(sess.ID, token); err != nil {
		t.Fatalf("restored old token verify: %v", err)
	}
	// Verify metadata preserved
	s2 := st2.Get(sess.ID)
	if s2.Destination != "127.0.0.1:2222" || s2.AuthUser != "alice" || string(s2.PublicKey) != "test-key" {
		t.Fatalf("metadata mismatch: %+v", s2)
	}

	// Confirm token drops previous
	st2.ConfirmToken(sess.ID)
	if err := st2.VerifyToken(sess.ID, token); err == nil {
		t.Fatal("old token should fail after confirm")
	}
	if err := st2.VerifyToken(sess.ID, rotToken); err != nil {
		t.Fatalf("rotToken should still verify after confirm: %v", err)
	}
}
