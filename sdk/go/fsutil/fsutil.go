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

// Package fsutil writes files that hold secret material.
//
// A plain os.WriteFile applies its mode only when it creates the file, follows
// a symlink at the target, and truncates in place, so a crash leaves a partial
// file and an existing 0644 file stays world-readable. The writers here never
// expose either state.
package fsutil

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Typed errors returned (wrapped with the cause) by the writers.
var (
	// ErrWriteFile reports a failure while writing, syncing or renaming.
	ErrWriteFile = errors.New("fsutil: write file failed")
	// ErrSymlinkTarget reports a symlink at the final path.
	ErrSymlinkTarget = errors.New("fsutil: target is a symlink")
	// ErrTargetNotRegular reports a final path that is not a regular file.
	ErrTargetNotRegular = errors.New("fsutil: target is not a regular file")
	// ErrExists reports that CreateExclusive found an existing path.
	ErrExists = errors.New("fsutil: file already exists")
)

// syncFile is the part of *os.File the writers use, so tests can inject a
// handle that fails mid-write.
type syncFile interface {
	io.WriteCloser
	Sync() error
	Stat() (os.FileInfo, error)
}

// Hooks let tests inject failures between the steps of the writers.
var (
	renameFile    = os.Rename
	syncDir       = syncDirectory
	openExclusive = func(path string, perm os.FileMode) (syncFile, error) {
		return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	}
)

// WriteFileAtomic writes data to path so that a reader sees either the old
// content or the new content, never a partial file, and so that the result has
// mode perm even when path already existed with a wider mode.
//
// It creates a temp file (0600) in the same directory, writes and fsyncs it,
// chmods it to perm, renames it over path and fsyncs the directory. The temp
// file is removed on every failure. A symlink or non-regular file at path is
// refused rather than followed or replaced.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	if err := checkTarget(path); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return errors.Join(ErrWriteFile, err)
	}
	tmpPath := tmp.Name()

	renamed := false
	defer func() {
		if !renamed {
			if rmErr := os.Remove(tmpPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				err = errors.Join(err, rmErr)
			}
		}
	}()

	if err := writeSync(tmp, data); err != nil {
		return errors.Join(ErrWriteFile, err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return errors.Join(ErrWriteFile, err)
	}
	if err := renameFile(tmpPath, path); err != nil {
		return errors.Join(ErrWriteFile, err)
	}
	renamed = true

	if err := syncDir(dir); err != nil {
		return errors.Join(ErrWriteFile, err)
	}
	return nil
}

// CreateExclusive creates path with mode perm and writes data to it, failing
// with ErrExists when path already exists. A failed write removes the file it
// created, but only while the path still names that file, so a concurrent
// substitution is never deleted.
func CreateExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := openExclusive(path, perm)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.Join(ErrExists, err)
		}
		return errors.Join(ErrWriteFile, err)
	}

	// Identify the file while the descriptor is open; a failed stat means
	// "do not remove" on the failure path.
	created, statErr := f.Stat()
	if statErr != nil {
		created = nil
	}

	err = writeSync(f, data)
	if err == nil {
		// O_EXCL honours the umask; make the mode exact.
		err = os.Chmod(path, perm)
	}
	if err != nil {
		removeIfSame(created, path)
		return errors.Join(ErrWriteFile, err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return errors.Join(ErrWriteFile, err)
	}
	return nil
}

// writeSync writes data to f, fsyncs and closes it, reporting the first error.
func writeSync(f syncFile, data []byte) error {
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

// checkTarget refuses a symlink or non-regular file at path. A missing path is
// fine.
func checkTarget(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrWriteFile, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrSymlinkTarget, errors.New(path))
	}
	if !info.Mode().IsRegular() {
		return errors.Join(ErrTargetNotRegular, errors.New(path))
	}
	return nil
}

// syncDirectory fsyncs dir so a rename or create within it is durable.
func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// removeIfSame unlinks path only while it still names the file described by
// created. Removing by name alone could delete an unrelated file that was
// swapped in; when identity is unknown the file is left in place. The check
// and unlink are not atomic, which the platform cannot offer.
func removeIfSame(created os.FileInfo, path string) {
	if created == nil {
		return
	}
	onDisk, err := os.Lstat(path)
	if err != nil || !os.SameFile(created, onDisk) {
		return
	}
	// Best effort: the caller already returns the write error, and a
	// stranded partial file is refused by the next CreateExclusive.
	if err := os.Remove(path); err != nil {
		return
	}
}
