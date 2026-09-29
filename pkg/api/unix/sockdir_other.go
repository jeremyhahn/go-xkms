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

//go:build !unix

package unix

import "io/fs"

// checkSocketDirOwner refuses a caller-supplied directory off Unix, because
// the isolation validateSocketDir relies on is expressed in Unix mode bits
// and ownership, neither of which this platform's access-control model
// (ACLs) maps onto fs.FileInfo. A check that cannot see the permissions it
// is checking has no business returning "safe".
func checkSocketDirOwner(dir string, _ fs.FileInfo) error {
	return &InsecureSocketDirError{
		Path:   dir,
		Reason: "ownership cannot be verified on this platform (ACLs are not visible through file modes)",
	}
}
