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
	TypeAuth     Type = 0x09
	TypeAuthOK   Type = 0x0A
	TypeData     Type = 0x10
	TypeAck      Type = 0x11
	TypeCloseDir Type = 0x12
	TypeProbe    Type = 0x13
	TypeProbeOK  Type = 0x14
	TypePing     Type = 0x15
	TypePong     Type = 0x16
)

const (
	DirUp   = "up"
	DirDown = "down"
	DirBoth = "both"
)

func (t Type) Known() bool {
	switch t {
	case TypeHello, TypeHelloOK, TypeResume, TypeResumeOK, TypeResumeFail,
		TypeSwitch, TypeBye, TypeErr, TypeAuth, TypeAuthOK,
		TypeData, TypeAck, TypeCloseDir,
		TypeProbe, TypeProbeOK, TypePing, TypePong:
		return true
	default:
		return false
	}
}

func (t Type) String() string {
	switch t {
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
	default:
		return fmt.Sprintf("0x%02x", uint8(t))
	}
}

type Frame struct {
	Type    Type
	Payload []byte
}
