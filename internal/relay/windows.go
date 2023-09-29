//go:build windows

package relay

import "golang.org/x/sys/windows"

func control(fd uintptr) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
}
