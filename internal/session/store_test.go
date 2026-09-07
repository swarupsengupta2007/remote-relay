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
