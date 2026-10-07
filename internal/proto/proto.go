package proto

import "fmt"

const MaxFrameLen = 1 << 20 // 1 MiB; a larger declared length is fatal

type Type uint8

const (
	TypeHello      Type = 0x01
	TypeHelloOK    Type = 0x02
	TypeResume     Type = 0x03
	TypeResumeOK   Type = 0x04
	TypeResumeFail Type = 0x05
	TypeSwitch     Type = 0x06
	TypeBye        Type = 0x07
	TypeErr        Type = 0x08
	// TypeAuth (0x09) and TypeAuthOK (0x0A) are M5 JSON control frames.
	// §5.2 has no AUTH type; we add them for ssh-publickey:
	//   AUTH     C→S  Auth{sig}     signature over the challenge
	//   AUTH_OK  S→C  AuthOK{...}   challenge (not a success verdict)
	// none: HELLO → HELLO_OK (unchanged).
	// ssh-publickey HELLO:  HELLO → AUTH_OK(challenge) → AUTH(sig) → HELLO_OK
	// ssh-publickey RESUME: RESUME → AUTH_OK(challenge) → AUTH(sig) → RESUME_OK
	// AUTH_OK is sent before allocating a session or dialing the destination.
	// Success is HELLO_OK / RESUME_OK after Verify. Failure is ERR{ERR_AUTH}
	// after a fixed delay.
	TypeAuth      Type = 0x09
	TypeAuthOK    Type = 0x0A
	TypeKexInit   Type = 0x0B
	TypeKexReply  Type = 0x0C
	TypeEncrypted Type = 0x0D
	// TypeChain (0x0E) and TypeChainOK (0x0F) are FEAT-UTL-05 multi-hop
	// jumphost chaining frames. They are new frame types rather than optional
	// HELLO fields on purpose: ReadFrame rejects an unknown type with ErrProto,
	// so a server that predates chaining fails closed. An optional HELLO field
	// would be silently dropped by encoding/json and such a server would dial
	// its own default destination instead — a fail-open (J-D10).
	//   CHAIN     C→S  ChainHello    replaces HELLO when -J is non-empty
	//   CHAIN_OK  S→C  ChainHelloOK  one per completed onward hop, then HELLO_OK
	TypeChain    Type = 0x0E
	TypeChainOK  Type = 0x0F
	TypeData     Type = 0x10
	TypeAck      Type = 0x11
	TypeCloseDir Type = 0x12
	TypeProbe    Type = 0x13
	TypeProbeOK  Type = 0x14
	TypePing     Type = 0x15
	TypePong     Type = 0x16

	// FEAT-UTL-04 reverse relay & NAT gateway mode frames.
	TypeAgentRegister   Type = 0x17
	TypeAgentRegisterOK Type = 0x18
	TypeAgentBind       Type = 0x19
	TypeAgentBindOK     Type = 0x1A
)

const (
	DirUp   = "up"
	DirDown = "down"
	DirBoth = "both"

	// DestSOCKS5 is the sentinel destination in Hello indicating that the session
	// is a dynamic multiplexed SOCKS5 proxy session (FEAT-UTL-03).
	DestSOCKS5 = "socks5"

	// DestTargetPrefix is the destination prefix identifying an agent rendezvous target (FEAT-UTL-04).
	DestTargetPrefix = "target:"

	// RoleAgentData is the Hello Role identifying a reverse agent data stream session.
	RoleAgentData = "agent-data"
)

func (t Type) Known() bool {
	switch t {
	case TypeHello, TypeHelloOK, TypeResume, TypeResumeOK, TypeResumeFail,
		TypeSwitch, TypeBye, TypeErr, TypeAuth, TypeAuthOK,
		TypeKexInit, TypeKexReply, TypeEncrypted,
		TypeChain, TypeChainOK,
		TypeData, TypeAck, TypeCloseDir,
		TypeProbe, TypeProbeOK, TypePing, TypePong,
		TypeAgentRegister, TypeAgentRegisterOK, TypeAgentBind, TypeAgentBindOK:
		return true
	default:
		return false
	}
}

func (t Type) String() string {
	switch t {
	case TypeKexInit:
		return "KEX_INIT"
	case TypeKexReply:
		return "KEX_REPLY"
	case TypeEncrypted:
		return "ENCRYPTED"
	case TypeHello:
		return "HELLO"
	case TypeHelloOK:
		return "HELLO_OK"
	case TypeResume:
		return "RESUME"
	case TypeResumeOK:
		return "RESUME_OK"
	case TypeResumeFail:
		return "RESUME_FAIL"
	case TypeSwitch:
		return "SWITCH"
	case TypeBye:
		return "BYE"
	case TypeErr:
		return "ERR"
	case TypeAuth:
		return "AUTH"
	case TypeAuthOK:
		return "AUTH_OK"
	case TypeChain:
		return "CHAIN"
	case TypeChainOK:
		return "CHAIN_OK"
	case TypeData:
		return "DATA"
	case TypeAck:
		return "ACK"
	case TypeCloseDir:
		return "CLOSE_DIR"
	case TypeProbe:
		return "PROBE"
	case TypeProbeOK:
		return "PROBE_OK"
	case TypePing:
		return "PING"
	case TypePong:
		return "PONG"
	case TypeAgentRegister:
		return "AGENT_REGISTER"
	case TypeAgentRegisterOK:
		return "AGENT_REGISTER_OK"
	case TypeAgentBind:
		return "AGENT_BIND"
	case TypeAgentBindOK:
		return "AGENT_BIND_OK"
	default:
		return fmt.Sprintf("0x%02x", uint8(t))
	}
}

type Frame struct {
	Type    Type
	Payload []byte
}
