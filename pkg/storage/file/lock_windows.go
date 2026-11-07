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

package file

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// dirLock is a LockFileEx lock guarding a store directory.
type dirLock struct {
	file *os.File
}

// openDirLock opens "<dir>.lock", a sibling of the store directory, as the
// lock handle. Windows cannot place a byte-range lock on a directory handle,
// and a lock file inside dir would make go-qrdb's file engine refuse to
// initialise the directory, so the lock file lives beside it. dir itself
// must already exist, as it must on every other platform.
func openDirLock(dir string) (*dirLock, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "lock", Path: dir, Err: syscall.ENOTDIR}
	}
	f, err := os.OpenFile(filepath.Clean(dir)+".lock", os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- dir is the store root New resolved
	if err != nil {
		return nil, err
	}
	return &dirLock{file: f}, nil
}

// tryLock takes the exclusive lock without blocking. It reports false when
// another handle holds it.
func (l *dirLock) tryLock() (bool, error) {
	err := windows.LockFileEx(windows.Handle(l.file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped))
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return err == nil, err
}

// lock blocks until it takes the exclusive lock on the sibling lock file's
// first byte.
func (l *dirLock) lock() error {
	return windows.LockFileEx(windows.Handle(l.file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped))
}

func (l *dirLock) unlock() error {
	return windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, new(windows.Overlapped))
}

func (l *dirLock) close() error {
	return l.file.Close()
}
