package session

import "github.com/remote-relay/relay/internal/proto"

// Dedupe applies I3/I4 to a DATA range against the next expected offset.
// drop means the whole frame is a duplicate and must be ignored.
func Dedupe(seq uint64, payload []byte, expected uint64) (newSeq uint64, out []byte, drop bool, err error) {
	if seq < expected {
		skip := expected - seq
		if skip >= uint64(len(payload)) {
			return seq, nil, true, nil
		}
		payload = payload[skip:]
		seq = expected
	}
	if seq > expected {
		return seq, nil, false, proto.ErrProto
	}
	if len(payload) == 0 {
		return seq, payload, true, nil
	}
	return seq, payload, false, nil
}
