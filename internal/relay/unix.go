//go:build linux || darwin

package relay

import "golang.org/x/sys/unix"

func control(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
