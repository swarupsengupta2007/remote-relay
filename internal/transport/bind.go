package transport

import (
	"net"
)

// BindConfig specifies interface and source IP binding configuration for network connections.
type BindConfig struct {
	Interface string
	SourceIP  net.IP
}

// IsEmpty returns true if neither interface nor source IP is specified.
func (b BindConfig) IsEmpty() bool {
	return b.Interface == "" && b.SourceIP == nil
}
