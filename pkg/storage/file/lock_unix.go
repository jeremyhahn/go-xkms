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

//go:build !windows

package file

import (
	"os"

	"golang.org/x/sys/unix"
)

// dirLock is an flock(2) advisory lock on a store directory.
type dirLock struct {
	dir *os.File
}

// openDirLock opens dir itself as the lock handle, not a lock file inside
// it: go-qrdb's file engine refuses to initialise a directory that already
// holds anything but its format marker, so a lock file created before the
// first open would make the store unopenable. Locking the directory also
// leaves nothing behind on disk.
func openDirLock(dir string) (*dirLock, error) {
	f, err := os.Open(dir) // #nosec G304 -- dir is the store root New resolved
	if err != nil {
		return nil, err
	}
	return &dirLock{dir: f}, nil
}

// tryLock takes the exclusive lock without blocking. It reports false when
// another handle holds it.
func (l *dirLock) tryLock() (bool, error) {
	err := unix.Flock(int(l.dir.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == unix.EWOULDBLOCK {
		return false, nil
	}
	return err == nil, err
}

func (l *dirLock) unlock() error {
	return unix.Flock(int(l.dir.Fd()), unix.LOCK_UN)
}

func (l *dirLock) close() error {
	return l.dir.Close()
}
