// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !windows

package authenticator

import (
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

// drainFile discards any input already buffered on f, reading it with the
// descriptor temporarily switched to non-blocking mode.
func drainFile(f *os.File) {
	fd := int(f.Fd())
	if err := setNonBlocking(fd, true); err != nil {
		return
	}
	// Read and discard any pending data
	buf := make([]byte, 1024)
	for {
		n, err := f.Read(buf)
		if n == 0 || err != nil {
			break
		}
	}
	// Restore blocking mode. A failure here is worth knowing about: every
	// prompt after this one reads from the same fd, and a stdin left
	// non-blocking would turn its scanner reads into spurious EOFs.
	if err := setNonBlocking(fd, false); err != nil {
		slog.Debug("authenticator: failed to restore blocking mode on stdin", "error", err)
	}
}

// setNonBlocking sets or clears the O_NONBLOCK flag on a file descriptor.
func setNonBlocking(fd int, nonBlocking bool) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if nonBlocking {
		flags |= unix.O_NONBLOCK
	} else {
		flags &^= unix.O_NONBLOCK
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
	return err
}
