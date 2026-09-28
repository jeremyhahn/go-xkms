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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// trustedUIDs returns the users allowed to own the socket directory, the
// socket file, and the process at the other end of a connection: this
// process's effective uid, root, and — when running as root via sudo — the
// invoking user from SUDO_UID.
//
// Root is trusted because a root process can already read everything the
// socket protects. The sudo user is trusted because a daemon started with
// sudo (the FIDO2 daemon needs /dev/uhid) serves that user's clients: it
// creates the directory as root and hands it to the invoking user (see
// ensureSocketDir), and that user's clients then see a server whose peer
// uid is 0.
func trustedUIDs() []int {
	uids := []int{os.Geteuid()}
	if uid, _, ok := sudoOwnership(); ok {
		uids = append(uids, uid)
	}
	if !slices.Contains(uids, 0) {
		uids = append(uids, 0)
	}
	return uids
}

// validateSocketDir checks that dir is a real directory (not a symbolic
// link), owned by one of trusted, with permission bits exactly 0700. It never
// changes the directory: a directory that fails is refused, not repaired,
// because repairing it would mean trusting whoever created it.
func validateSocketDir(dir string, trusted []int) error {
	return validateSocketDirWith(os.Lstat, dir, trusted)
}

// validateSocketDirWith implements validateSocketDir with lstat standing in
// for os.Lstat, so a caller that must stay free of file-system access (see
// runtimeDirFor) can inject it.
func validateSocketDirWith(lstat func(string) (fs.FileInfo, error), dir string, trusted []int) error {
	info, err := lstat(dir)
	if err != nil {
		return &WrappedError{Msg: "ipc: stat socket directory " + dir, Err: err}
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return &DetailError{Err: ErrSocketDirInsecure, Detail: fmt.Sprintf(": %s is a symbolic link", dir)}
	}
	if !info.IsDir() {
		return &DetailError{Err: ErrSocketDirInsecure, Detail: fmt.Sprintf(": %s is not a directory", dir)}
	}
	if err := checkOwner(dir, info, trusted, ErrSocketDirInsecure); err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm != socketDirMode {
		return &DetailError{Err: ErrSocketDirInsecure, Detail: fmt.Sprintf(": %s has mode %04o, want %04o", dir, perm, socketDirMode)}
	}
	return nil
}

// checkOwner verifies that info, the Lstat result for path, is owned by one
// of trusted, reporting a mismatch as sentinel.
func checkOwner(path string, info fs.FileInfo, trusted []int, sentinel error) error {
	uid, err := fileOwner(info)
	if err != nil {
		return &SentinelCauseError{Sentinel: sentinel, Cause: err}
	}
	if !slices.Contains(trusted, uid) {
		return &DetailError{Err: sentinel, Detail: fmt.Sprintf(": %s is owned by uid %d", path, uid)}
	}
	return nil
}

// ensureSocketDir creates dir and any missing parents with mode 0700 and
// validates dir with validateSocketDir. Every component it creates is
// validated immediately after creation, which closes the window in which
// another user could create the same path first: if Mkdir loses that race,
// the other user's directory fails validation and is refused.
//
// When running as root via sudo, the components it creates — and only
// those — are handed to the invoking user so that user's clients can reach
// the socket. A directory that already existed is never chowned or chmoded.
func ensureSocketDir(dir string, trusted []int) error {
	_, err := os.Lstat(dir)
	if err == nil {
		return validateSocketDir(dir, trusted)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return &SentinelCauseError{Sentinel: ErrSocketCreateFailed, Cause: err}
	}

	if parent := filepath.Dir(dir); parent != dir {
		if _, parentErr := os.Lstat(parent); errors.Is(parentErr, fs.ErrNotExist) {
			if err := ensureSocketDir(parent, trusted); err != nil {
				return err
			}
		}
	}

	if err := os.Mkdir(dir, socketDirMode); err != nil {
		if errors.Is(err, fs.ErrExist) {
			// Someone created it between our Lstat and Mkdir. It is not
			// ours to change; accept it only if it passes validation.
			return validateSocketDir(dir, trusted)
		}
		return &SentinelCauseError{Sentinel: ErrSocketCreateFailed, Cause: err}
	}
	if uid, gid, ok := sudoOwnership(); ok {
		// Lchown: if the path were swapped for a symbolic link after
		// Mkdir, this changes the link, not its target, and validation
		// below then refuses the link.
		if err := os.Lchown(dir, uid, gid); err != nil {
			return &DetailError{Err: ErrSocketCreateFailed, Detail: fmt.Sprintf(": chown directory: %v", err)}
		}
	}
	return validateSocketDir(dir, trusted)
}

// ReclaimSocket removes the socket file at socketPath so a new server can
// bind it, after verifying that its directory passes the socket directory
// checks and that the file is a socket owned by this user (or root, or the
// sudo user). A missing file is not an error. It refuses to remove anything
// else, so a --socket path pointing at a regular file, or a socket planted
// by another user, is left alone.
func ReclaimSocket(socketPath string) error {
	return reclaimSocket(socketPath, trustedUIDs())
}

// reclaimSocket implements ReclaimSocket for an explicit trusted-uid set.
func reclaimSocket(socketPath string, trusted []int) error {
	if err := validateSocketDir(filepath.Dir(socketPath), trusted); err != nil {
		return err
	}
	info, err := os.Lstat(socketPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSocketNotOwned, Cause: err}
	}
	if info.Mode().Type() != fs.ModeSocket {
		return &DetailError{Err: ErrSocketNotOwned, Detail: fmt.Sprintf(": %s is not a socket", socketPath)}
	}
	if err := checkOwner(socketPath, info, trusted, ErrSocketNotOwned); err != nil {
		return err
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return &SentinelCauseError{Sentinel: ErrSocketCreateFailed, Cause: err}
	}
	return nil
}
