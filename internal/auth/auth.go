package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type Challenge struct {
	SessionID   string
	Destination string
	ClientNonce string
	ServerNonce string
}

type Identity struct {
	Method string
	Name   string
}

type Authenticator interface {
	Name() string
	Verify(challenge Challenge, auth json.RawMessage) (Identity, error)
	Respond(challenge Challenge) (json.RawMessage, error)
}

// None is the v1 authenticator: empty/{} auth, no identity.
type None struct{}

func (None) Name() string { return "none" }

func (None) Verify(_ Challenge, raw json.RawMessage) (Identity, error) {
	id := Identity{Method: "none", Name: "anonymous"}
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 || string(trim) == "null" {
		return id, nil
	}
	var m map[string]any
	if err := json.Unmarshal(trim, &m); err != nil {
		return Identity{}, fmt.Errorf("auth: %w", err)
	}
	if len(m) != 0 {
		return Identity{}, fmt.Errorf("none authenticator expected empty auth")
	}
	return id, nil
}

func (None) Respond(_ Challenge) (json.RawMessage, error) {
	return json.RawMessage("{}"), nil
}
