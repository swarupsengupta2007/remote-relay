//go:build linux

package transport

import (
	"syscall"

	"golang.org/x/sys/unix"
)

var bindToDeviceFn = func(fd uintptr, iface string) error {
	return unix.BindToDevice(int(fd), iface)
}

// BindToDevice binds a socket file descriptor to a network interface name on Linux.
func BindToDevice(fd uintptr, iface string) error {
	if iface == "" {
		return nil
	}
	return bindToDeviceFn(fd, iface)
}

// BindToDeviceControl returns a socket control function suitable for net.Dialer or net.ListenConfig.
func BindToDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = BindToDevice(fd, iface)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
