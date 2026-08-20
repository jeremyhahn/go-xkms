// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

//go:build unix

package agent

import (
	"io/fs"
	"os"
	"syscall"
)

// checkOwner rejects a work directory owned by another user. A directory
// somebody else owns can be chmod'd or have its entries replaced regardless of
// the mode we observed, so the socket pathname inside it is not ours to trust.
func checkOwner(dir string, info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Geteuid() {
		return &InsecureWorkDirError{Path: dir, Reason: "is owned by another user"}
	}
	return nil
}
