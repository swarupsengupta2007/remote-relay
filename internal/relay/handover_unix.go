//go:build !windows

package relay

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

func sendHandover(conn *net.UnixConn, state HandoverState, files []*os.File) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal handover state: %w", err)
	}

	fds := make([]int, len(files))
	for i, f := range files {
		fds[i] = int(f.Fd())
	}

	// 1. Send 8-byte header: uint32 jsonLen, uint32 numFDs
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(data)))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(fds)))
	if _, err := conn.Write(hdr); err != nil {
		return fmt.Errorf("write handover header: %w", err)
	}

	// 2. Send FDs in batches of up to 250 via SCM_RIGHTS (Linux SCM_MAX_FD is 253)
	const batchSize = 250
	remaining := fds
	for len(remaining) > 0 {
		n := len(remaining)
		if n > batchSize {
			n = batchSize
		}
		chunk := remaining[:n]
		remaining = remaining[n:]

		rights := syscall.UnixRights(chunk...)
		dummy := []byte{0}
		if _, _, err := conn.WriteMsgUnix(dummy, rights, nil); err != nil {
			return fmt.Errorf("write SCM_RIGHTS: %w", err)
		}
	}

	// 3. Send JSON payload
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write handover payload: %w", err)
	}

	return nil
}

func receiveHandover(conn *net.UnixConn) (*HandoverState, []*os.File, error) {
	// 1. Read 8-byte header
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, nil, fmt.Errorf("read handover header: %w", err)
	}
	jsonLen := binary.BigEndian.Uint32(hdr[0:4])
	numFDs := int(binary.BigEndian.Uint32(hdr[4:8]))

	// 2. Receive FDs
	var files []*os.File
	for len(files) < numFDs {
		dummy := make([]byte, 1)
		oob := make([]byte, syscall.CmsgSpace(256*4))
		_, oobn, _, _, err := conn.ReadMsgUnix(dummy, oob)
		if err != nil {
			for _, f := range files {
				_ = f.Close()
			}
			return nil, nil, fmt.Errorf("read SCM_RIGHTS: %w", err)
		}
		cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			for _, f := range files {
				_ = f.Close()
			}
			return nil, nil, fmt.Errorf("parse control message: %w", err)
		}
		for _, cmsg := range cmsgs {
			newFDs, err := syscall.ParseUnixRights(&cmsg)
			if err != nil {
				for _, f := range files {
					_ = f.Close()
				}
				return nil, nil, fmt.Errorf("parse unix rights: %w", err)
			}
			for _, fd := range newFDs {
				f := os.NewFile(uintptr(fd), fmt.Sprintf("handover-fd-%d", fd))
				files = append(files, f)
			}
		}
	}

	// 3. Read JSON data
	jsonBytes := make([]byte, jsonLen)
	if _, err := io.ReadFull(conn, jsonBytes); err != nil {
		for _, f := range files {
			_ = f.Close()
		}
		return nil, nil, fmt.Errorf("read handover payload: %w", err)
	}

	var state HandoverState
	if err := json.Unmarshal(jsonBytes, &state); err != nil {
		for _, f := range files {
			_ = f.Close()
		}
		return nil, nil, fmt.Errorf("unmarshal handover state: %w", err)
	}

	return &state, files, nil
}
