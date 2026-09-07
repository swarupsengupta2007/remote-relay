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
	TypeData       Type = 0x10
	TypeAck        Type = 0x11
	TypeCloseDir   Type = 0x12
	TypeProbe      Type = 0x13
	TypeProbeOK    Type = 0x14
	TypePing       Type = 0x15
	TypePong       Type = 0x16
)

const (
	DirUp   = "up"
	DirDown = "down"
	DirBoth = "both"
)

func (t Type) Known() bool {
	switch t {
	case TypeHello, TypeHelloOK, TypeResume, TypeResumeOK, TypeResumeFail,
		TypeSwitch, TypeBye, TypeErr,
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
