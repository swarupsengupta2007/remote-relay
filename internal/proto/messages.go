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
	V           int      `json:"v"`
	SessionID   string   `json:"sessionId"`
	ResumeToken string   `json:"resumeToken"`
	Transport   []string `json:"transport"`
	DownAcked   uint64   `json:"downAcked"`
	ClientNonce string   `json:"clientNonce"`
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
}

type SessionState struct {
	UpClosed   bool `json:"upClosed"`
	DownClosed bool `json:"downClosed"`
	HeldMs     int  `json:"heldMs"`
}

type Fail struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
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
