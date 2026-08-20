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

//go:build !unix

package agent

import "io/fs"

// checkOwner refuses a caller-supplied directory off Unix, because the
// isolation the rest of this package relies on is expressed in Unix mode bits
// and simply is not represented here. Windows access is governed by ACLs, which
// are inherited rather than implied by a Mkdir mode, are invisible to
// fs.FileInfo, and cannot be compared against a uid. A check that cannot see
// the permissions it is checking has no business returning "safe".
//
// Sessions that create their own directory are unaffected: os.MkdirTemp lands
// under the per-user temp location, which is the platform's own isolation
// rather than a claim this package is making. Only a directory the caller chose
// -- and therefore vouched for on terms we cannot verify -- is refused.
func checkOwner(dir string, _ fs.FileInfo) error {
	return &InsecureWorkDirError{
		Path:   dir,
		Reason: "cannot be verified on this platform (ownership and ACLs are not visible through file modes)",
	}
}
