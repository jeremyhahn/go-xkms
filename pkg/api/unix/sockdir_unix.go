// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build unix

package unix

import (
	"io/fs"
	"os"
	"syscall"
)

// checkSocketDirOwner rejects a socket directory owned by another user. A
// directory somebody else owns can be chmod'd or have its entries replaced
// regardless of the mode validateSocketDir observed, so the socket pathname
// inside it is not this process's to trust.
func checkSocketDirOwner(dir string, info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Geteuid() {
		return &InsecureSocketDirError{Path: dir, Reason: "is owned by another user"}
	}
	return nil
}
