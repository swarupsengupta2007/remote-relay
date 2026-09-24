package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	Version5 = 0x05

	MethodNoAuth           = 0x00
	MethodGSSAPI           = 0x01
	MethodUsernamePassword = 0x02
	MethodNoAcceptable     = 0xFF

	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	AtypIPv4       = 0x01
	AtypDomainName = 0x03
	AtypIPv6       = 0x04

	RepSucceeded            = 0x00
	RepGeneralFailure       = 0x01
	RepConnectionNotAllowed = 0x02
	RepNetworkUnreachable   = 0x03
	RepHostUnreachable      = 0x04
	RepConnectionRefused    = 0x05
	RepTTLExpired           = 0x06
	RepCommandNotSupported  = 0x07
	RepAddressNotSupported  = 0x08
)

var (
	ErrBadVersion         = errors.New("unsupported socks version")
	ErrNoAcceptableMethod = errors.New("no acceptable authentication methods")
	ErrUnsupportedCommand = errors.New("unsupported socks command")
	ErrUnsupportedAddress = errors.New("unsupported socks address type")
	ErrMalformedRequest   = errors.New("malformed socks request")
	ErrDomainTooLong      = errors.New("domain name exceeds 255 bytes")
)

// Request represents an RFC 1928 SOCKS5 client connection request.
type Request struct {
	Version  byte
	Command  byte
	DestAddr string // IP or domain name
	DestPort uint16
	Dest     string // "host:port"
}

// ReadAuth reads the RFC 1928 version and authentication method list from client.
func ReadAuth(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != Version5 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrBadVersion, hdr[0])
	}
	nmethods := int(hdr[1])
	if nmethods == 0 {
		return nil, fmt.Errorf("%w: zero methods offered", ErrMalformedRequest)
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

// WriteAuthReply writes the selected authentication method to the client.
func WriteAuthReply(w io.Writer, method byte) error {
	_, err := w.Write([]byte{Version5, method})
	return err
}

// ReadRequest reads and parses an RFC 1928 request message from the client.
func ReadRequest(r io.Reader) (*Request, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != Version5 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrBadVersion, hdr[0])
	}
	cmd := hdr[1]
	if hdr[2] != 0x00 { // RSV MUST be 0x00
		return nil, fmt.Errorf("%w: RSV field must be 0x00", ErrMalformedRequest)
	}
	atyp := hdr[3]

	var destAddr string
	switch atyp {
	case AtypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, err
		}
		destAddr = net.IP(ip[:]).String()
	case AtypDomainName:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, err
		}
		nameLen := int(lenBuf[0])
		if nameLen == 0 {
			return nil, fmt.Errorf("%w: empty domain name", ErrMalformedRequest)
		}
		domain := make([]byte, nameLen)
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, err
		}
		destAddr = string(domain)
	case AtypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, err
		}
		destAddr = net.IP(ip[:]).String()
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedAddress, atyp)
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return nil, err
	}
	destPort := binary.BigEndian.Uint16(portBuf[:])
	dest := net.JoinHostPort(destAddr, strconv.Itoa(int(destPort)))

	return &Request{
		Version:  hdr[0],
		Command:  cmd,
		DestAddr: destAddr,
		DestPort: destPort,
		Dest:     dest,
	}, nil
}

// WriteReply writes an RFC 1928 reply message to the client.
func WriteReply(w io.Writer, rep byte, bndAddr string) error {
	var atyp byte = AtypIPv4
	var addrBytes []byte = []byte{0, 0, 0, 0}
	var portBytes [2]byte

	if bndAddr != "" {
		host, portStr, err := net.SplitHostPort(bndAddr)
		if err == nil {
			if port, err := strconv.Atoi(portStr); err == nil && port >= 0 && port <= 65535 {
				binary.BigEndian.PutUint16(portBytes[:], uint16(port))
			}
			ip := net.ParseIP(host)
			if ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					atyp = AtypIPv4
					addrBytes = ip4
				} else if ip6 := ip.To16(); ip6 != nil {
					atyp = AtypIPv6
					addrBytes = ip6
				}
			} else {
				atyp = AtypDomainName
				addrBytes = append([]byte{byte(len(host))}, []byte(host)...)
			}
		}
	}

	buf := make([]byte, 4, 4+len(addrBytes)+2)
	buf[0] = Version5
	buf[1] = rep
	buf[2] = 0x00 // RSV
	buf[3] = atyp
	buf = append(buf, addrBytes...)
	buf = append(buf, portBytes[:]...)
	_, err := w.Write(buf)
	return err
}
