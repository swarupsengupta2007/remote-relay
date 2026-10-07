package proto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)

type Hello struct {
	V           int             `json:"v"`
	SessionID   string          `json:"sessionId"`
	ResumeToken string          `json:"resumeToken"`
	Transport   []string        `json:"transport"`
	Destination string          `json:"destination"`
	ClientNonce string          `json:"clientNonce"`
	Auth        json.RawMessage `json:"auth"`
	Window      int             `json:"window"`
	Traceparent string          `json:"traceparent,omitempty"`
	Target      string          `json:"target,omitempty"`
	Role        string          `json:"role,omitempty"`
}

type HelloOK struct {
	V           int      `json:"v"`
	SessionID   string   `json:"sessionId"`
	ResumeToken string   `json:"resumeToken"`
	Transport   string   `json:"transport"`
	UDP         *UdpInfo `json:"udp"`
	Limits      Limits   `json:"limits"`
	ServerNonce string   `json:"serverNonce"`
}

type Resume struct {
	V           int             `json:"v"`
	SessionID   string          `json:"sessionId"`
	ResumeToken string          `json:"resumeToken"`
	Transport   []string        `json:"transport"`
	DownAcked   uint64          `json:"downAcked"`
	ClientNonce string          `json:"clientNonce"`
	Auth        json.RawMessage `json:"auth,omitempty"`
	Role        string          `json:"role,omitempty"`
	Traceparent string          `json:"traceparent,omitempty"`
}

// Auth is C→S TypeAuth: the signature over the AUTH_OK challenge.
//
// Hop tags a relayed signature on a chained path (FEAT-UTL-05); it is 0 for an
// ordinary session. An intermediate strips it before forwarding, because the
// challenge binds the HELLO bytes, never the AUTH bytes.
type Auth struct {
	Sig string `json:"sig"`
	Hop int    `json:"hop,omitempty"`
}

// AuthOK is S→C TypeAuthOK: the pre-session / pre-attach challenge.
// It is not a success verdict; HELLO_OK / RESUME_OK follows a valid AUTH.
//
// The three optional chain fields are only meaningful after a CHAIN has been
// accepted (J-D10), so an old peer that ignores them cannot be talked into a
// chained handshake.
type AuthOK struct {
	SessionID   string `json:"sessionId"`
	ServerNonce string `json:"serverNonce"`
	Challenge   string `json:"challenge"`
	Destination string `json:"destination"`

	// Hop is the 1-based position, counted from the originator, of the session
	// being challenged. 0 means "the peer that sent this frame".
	Hop int `json:"hop,omitempty"`
	// HelloJSON is the canonical HELLO/CHAIN payload the challenged party
	// received. The originator recomputes DeriveChallenge over exactly these
	// bytes before signing, so a rogue intermediate cannot swap in a HELLO
	// naming a different destination or transport.
	HelloJSON string `json:"helloJson,omitempty"`
	// Attest is the onward KEX transcript proving the challenged party's host
	// key. Absent for hop 1, where the originator ran the KEX itself.
	Attest *HopAttestation `json:"attest,omitempty"`
}

// HopSpec names one relay server on a chain path. Hops are listed in dial
// order after the receiver, with the terminal server last (§2.3).
type HopSpec struct {
	Addr string `json:"addr"`
	// Transport is the preference for the hop INTO this server; empty means
	// "whatever this server offers" (J-D4).
	Transport []string `json:"transport,omitempty"`
	AllowHA   bool     `json:"allowHa,omitempty"`
	// Fp is an inline SHA256 host-key pin. It short-circuits known_hosts and
	// removes the TOFU window for that hop.
	Fp   string `json:"fp,omitempty"`
	User string `json:"user,omitempty"`
	// Target is reserved for rendezvous naming of a NATed terminal
	// (FEAT-UTL-04, Phase 3). Declared now so no wire break is needed later.
	Target string `json:"target,omitempty"`
}

// HopAttestation is the KEX transcript of an onward hop, relayed by the
// intermediate that performed it so the originator can verify that hop's host
// key without being the KEX party on it (J-D3).
type HopAttestation struct {
	Addr string `json:"addr"`
	// KexInit is the base64 48-byte payload the dialling relay sent:
	// clientEph ‖ clientNonce.
	KexInit string `json:"kexInit"`
	// KexReply is the base64 144-byte reply it received:
	// serverEph ‖ serverNonce ‖ hostKey ‖ sig.
	KexReply string `json:"kexReply"`
	// HostKeySSH is the raw host key in OpenSSH wire form, for known_hosts
	// matching and operator-facing logs.
	HostKeySSH string `json:"hostKeySsh,omitempty"`
}

// ChainHello is C→S TypeChain: HELLO for a multi-hop path. Destination is what
// the TERMINAL server dials; every intermediate strips itself from Hops and
// forwards the tail, emitting an ordinary Hello once the tail is empty.
type ChainHello struct {
	V           int             `json:"v"`
	ChainID     string          `json:"chainId"`
	Hops        []HopSpec       `json:"hops"`
	Destination string          `json:"destination"`
	Visited     []string        `json:"visited,omitempty"`
	OriginIP    string          `json:"originIp,omitempty"`
	Transport   []string        `json:"transport"`
	ClientNonce string          `json:"clientNonce"`
	Auth        json.RawMessage `json:"auth"`
	Window      int             `json:"window"`
	SessionID   string          `json:"sessionId,omitempty"`
	ResumeToken string          `json:"resumeToken,omitempty"`
	Traceparent string          `json:"traceparent,omitempty"`
}

// ChainHelloOK is S→C TypeChainOK: one per completed onward hop, sent before
// the HELLO_OK of the hop the originator actually dialled.
//
// It deliberately carries no resume token. The nested session belongs to the
// intermediate; a token the originator can never present is pure exposure.
type ChainHelloOK struct {
	V         int      `json:"v"`
	Hop       int      `json:"hop"`
	Addr      string   `json:"addr"`
	SessionID string   `json:"sessionId"`
	Transport string   `json:"transport"`
	Limits    Limits   `json:"limits"`
	UDP       *UdpInfo `json:"udp,omitempty"`
	SetupMs   int64    `json:"setupMs,omitempty"`
}

type ResumeOK struct {
	V           int          `json:"v"`
	SessionID   string       `json:"sessionId"`
	ResumeToken string       `json:"resumeToken"`
	UpAcked     uint64       `json:"upAcked"`
	DownNext    uint64       `json:"downNext"`
	State       SessionState `json:"state"`
	Transport   string       `json:"transport"`
	UDP         *UdpInfo     `json:"udp"`
	Limits      Limits       `json:"limits"`
	Role        string       `json:"role,omitempty"`
}

type SessionState struct {
	UpClosed   bool `json:"upClosed"`
	DownClosed bool `json:"downClosed"`
	HeldMs     int  `json:"heldMs"`
}

type Fail struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	// Completed is set on a RESUME_FAIL for a session the server already
	// finished cleanly. Older clients ignore it and see the plain code.
	Completed *Completed `json:"completed,omitempty"`
}

// Completed carries a finished session's final offsets: UpFinal is the
// client-to-server stream length the server received, DownFinal the
// server-to-client length the client acknowledged.
type Completed struct {
	UpFinal   uint64 `json:"upFinal"`
	DownFinal uint64 `json:"downFinal"`
}

type SwitchOffset struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

type Switch struct {
	Dir    string       `json:"dir"`
	From   string       `json:"from"`
	Offset SwitchOffset `json:"offset"`
}

type Bye struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}

type CloseDir struct {
	Dir         string `json:"dir"`
	FinalOffset uint64 `json:"finalOffset"`
}

type UdpInfo struct {
	Addr           string `json:"addr"`
	ProbeToken     string `json:"probeToken"`
	ProbeTimeoutMs int    `json:"probeTimeoutMs"`
	ProbeAttempts  int    `json:"probeAttempts"`
}

type Limits struct {
	BufferBytes     int `json:"bufferBytes"`
	HoldTimeoutMs   int `json:"holdTimeoutMs"`
	Window          int `json:"window"`
	DataChunkBytes  int `json:"dataChunkBytes"`
	SwitchTimeoutMs int `json:"switchTimeoutMs"`
}

func MarshalFrame(typ Type, v any) (Frame, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Type: typ, Payload: b}, nil
}

func UnmarshalPayload(f Frame, v any) error {
	if err := json.Unmarshal(f.Payload, v); err != nil {
		return NewError(CodeProto, "invalid JSON payload")
	}
	return nil
}

func RandomNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

func EmptyAuth() json.RawMessage {
	return json.RawMessage("{}")
}

// AgentRegister is A→S TypeAgentRegister: register a reverse agent target.
type AgentRegister struct {
	V           int             `json:"v"`
	Name        string          `json:"name"`
	Dest        string          `json:"dest"`
	AllowDest   []string        `json:"allowDest,omitempty"`
	Auth        json.RawMessage `json:"auth,omitempty"`
	ClientNonce string          `json:"clientNonce,omitempty"`
	Traceparent string          `json:"traceparent,omitempty"`
}

// AgentRegisterOK is S→A TypeAgentRegisterOK: confirmation of target registration.
type AgentRegisterOK struct {
	V            int    `json:"v"`
	Target       string `json:"target"`
	ServerNonce  string `json:"serverNonce,omitempty"`
	ExpiresInSec int    `json:"expiresInSec,omitempty"`
}

// AgentBind is S→A TypeAgentBind: notification that a client has requested this target.
type AgentBind struct {
	V           int    `json:"v"`
	BindID      string `json:"bindId"`
	Target      string `json:"target"`
	Destination string `json:"destination,omitempty"`
	ClientIP    string `json:"clientIp,omitempty"`
	Traceparent string `json:"traceparent,omitempty"`
}

// AgentBindOK is A→S TypeAgentBindOK: agent confirms local destination connection.
type AgentBindOK struct {
	V      int    `json:"v"`
	BindID string `json:"bindId"`
	Status string `json:"status"` // "ok" or error code
	Msg    string `json:"msg,omitempty"`
}
