//go:build !linux

package transport

import (
	"errors"
	"syscall"
)

var ErrBindToDeviceUnsupported = errors.New("binding to network interface is only supported on Linux")

var bindToDeviceFn = func(fd uintptr, iface string) error {
	return ErrBindToDeviceUnsupported
}

// BindToDevice returns ErrBindToDeviceUnsupported on non-Linux platforms.
func BindToDevice(fd uintptr, iface string) error {
	if iface == "" {
		return nil
	}
	return bindToDeviceFn(fd, iface)
}

// BindToDeviceControl returns a control function that errors on non-Linux platforms if iface is non-empty.
func BindToDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		return ErrBindToDeviceUnsupported
	}
}
