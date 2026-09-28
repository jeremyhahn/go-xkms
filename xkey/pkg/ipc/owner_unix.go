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

//go:build unix

package ipc

import (
	"io/fs"
	"syscall"
)

// fileOwner returns the uid that owns the file described by info, which must
// come from os.Stat or os.Lstat.
func fileOwner(info fs.FileInfo) (int, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, &DetailError{Err: ErrSocketDirInsecure, Detail: ": file owner is unavailable"}
	}
	return int(st.Uid), nil
}
