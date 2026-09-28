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

//go:build !unix

package ipc

import "io/fs"

// fileOwner reports that file ownership cannot be verified on this platform,
// so every socket directory is refused rather than trusted blindly.
func fileOwner(_ fs.FileInfo) (int, error) {
	return 0, &DetailError{Err: ErrSocketDirInsecure, Detail: ": file ownership cannot be verified on this platform"}
}
