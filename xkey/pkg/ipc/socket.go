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

package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const (
	socketDir  = "xkey"
	socketName = "xkey.sock"
)

// DefaultSocketPath returns the default IPC socket path. It uses
// $XDG_RUNTIME_DIR/xkey/xkey.sock when the environment variable is set,
// and falls back to /tmp/xkey-$UID/xkey.sock otherwise.
//
// When running as root via sudo, it uses the original user's UID from SUDO_UID
// to ensure consistent socket paths between the daemon and client commands.
func DefaultSocketPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, socketDir, socketName)
	}
	return filepath.Join("/tmp", fmt.Sprintf("xkey-%d", effectiveUID()), socketName)
}

// effectiveUID returns the UID to use for socket path construction. When
// running as root via sudo, it returns the original user's UID from SUDO_UID
// so that the daemon and client commands use the same socket path.
func effectiveUID() int {
	// If running as root via sudo, use the original user's UID
	if os.Getuid() == 0 {
		if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
			if uid, err := strconv.Atoi(sudoUID); err == nil {
				return uid
			}
		}
	}
	return os.Getuid()
}
