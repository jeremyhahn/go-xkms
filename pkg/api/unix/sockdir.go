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

package unix

import (
	"fmt"
	"os"
)

// InsecureSocketDirError reports that an existing socket directory failed
// the ownership/permission check validateSocketDir applies before Start
// binds a listener inside it.
type InsecureSocketDirError struct {
	Path   string
	Reason string
}

// Error implements the error interface.
func (e *InsecureSocketDirError) Error() string {
	return fmt.Sprintf("insecure socket directory %q: %s", e.Path, e.Reason)
}

// validateSocketDir refuses to reuse an existing socket directory that is
// not privately owned by this process, mirroring the check pkg/ssh/agent
// applies to its own socket directory (see pkg/ssh/agent/session.go
// checkWorkDir): the Unix socket's own file mode does not protect it, since
// whether the *pathname* can be replaced is governed by the containing
// directory. A directory writable by group or other lets another user
// unlink the socket and bind their own listener at the same path; a
// directory owned by someone else could have its mode changed out from
// under this check between the stat and the bind. A directory that does not
// exist yet -- or cannot be statted at all, e.g. because a path component
// above it is not a directory -- is not a problem for this check: there is
// nothing yet to distrust, and the os.MkdirAll call that follows reports
// whichever of those conditions applies with its own, more specific error.
func validateSocketDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// A symlink can be re-pointed between this check and the bind.
		return &InsecureSocketDirError{Path: dir, Reason: "is a symlink"}
	}
	if !info.IsDir() {
		return &InsecureSocketDirError{Path: dir, Reason: "is not a directory"}
	}
	if info.Mode().Perm()&0o022 != 0 {
		return &InsecureSocketDirError{Path: dir, Reason: "is writable by group or other"}
	}
	return checkSocketDirOwner(dir, info)
}
