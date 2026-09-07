package proto

const (
	CodeVersion        = "ERR_VERSION"
	CodeProto          = "ERR_PROTO"
	CodeFrame          = "ERR_FRAME"
	CodeDestRefused    = "ERR_DEST_REFUSED"
	CodeDestForbidden  = "ERR_DEST_FORBIDDEN"
	CodeNoCapacity     = "ERR_NO_CAPACITY"
	CodeUnknownSession = "ERR_UNKNOWN_SESSION"
	CodeBadToken       = "ERR_BAD_TOKEN"
	CodeExpired        = "ERR_EXPIRED"
	CodeAuth           = "ERR_AUTH"
	CodeShutdown       = "ERR_SHUTDOWN"
	CodeInternal       = "ERR_INTERNAL"
)

// Error is a protocol-level failure carrying a wire error code.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Msg == "" {
		return e.Code
	}
	return e.Code + ": " + e.Msg
}

func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && e != nil && t != nil && e.Code == t.Code
}

func NewError(code, msg string) *Error {
	return &Error{Code: code, Msg: msg}
}

var (
	ErrVersion        = &Error{Code: CodeVersion, Msg: "unsupported version"}
	ErrProto          = &Error{Code: CodeProto, Msg: "protocol error"}
	ErrFrame          = &Error{Code: CodeFrame, Msg: "frame too large"}
	ErrDestRefused    = &Error{Code: CodeDestRefused, Msg: "destination refused"}
	ErrDestForbidden  = &Error{Code: CodeDestForbidden, Msg: "destination not allowed"}
	ErrNoCapacity     = &Error{Code: CodeNoCapacity, Msg: "no capacity"}
	ErrUnknownSession = &Error{Code: CodeUnknownSession, Msg: "unknown session"}
	ErrBadToken       = &Error{Code: CodeBadToken, Msg: "bad token"}
	ErrExpired        = &Error{Code: CodeExpired, Msg: "session expired"}
	ErrAuth           = &Error{Code: CodeAuth, Msg: "auth failed"}
	ErrShutdown       = &Error{Code: CodeShutdown, Msg: "shutting down"}
	ErrInternal       = &Error{Code: CodeInternal, Msg: "internal error"}
)
