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

package gadget

import (
	"os"
	"syscall"
)

// FileSystem abstracts filesystem operations for testability.
// The production implementation delegates to os package functions.
// Unit tests inject a mock to verify ConfigFS directory structure
// without requiring root or real ConfigFS.
type FileSystem interface {
	// MkdirAll creates a directory path and all parents.
	MkdirAll(path string, perm os.FileMode) error

	// WriteFile writes data to a file, creating it if necessary.
	WriteFile(path string, data []byte, perm os.FileMode) error

	// ReadFile reads the entire contents of a file.
	ReadFile(path string) ([]byte, error)

	// Symlink creates a symbolic link.
	Symlink(oldname, newname string) error

	// RemoveAll removes a path and all children.
	RemoveAll(path string) error

	// ReadDir reads a directory and returns its entries.
	ReadDir(path string) ([]os.DirEntry, error)

	// Mount mounts a filesystem. Used for FunctionFS mounting.
	Mount(source, target, fstype string, flags uintptr, data string) error

	// Unmount unmounts a filesystem.
	Unmount(target string, flags int) error
}

// OSFileSystem implements FileSystem using real OS and syscall operations.
type OSFileSystem struct{}

// MkdirAll creates a directory path and all parents using os.MkdirAll.
func (f *OSFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// WriteFile writes data to a file using os.WriteFile.
func (f *OSFileSystem) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// ReadFile reads the entire contents of a file using os.ReadFile.
func (f *OSFileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// Symlink creates a symbolic link using os.Symlink.
func (f *OSFileSystem) Symlink(oldname, newname string) error {
	return os.Symlink(oldname, newname)
}

// RemoveAll removes a path and all children using os.RemoveAll.
func (f *OSFileSystem) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

// ReadDir reads a directory and returns its entries using os.ReadDir.
func (f *OSFileSystem) ReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

// Mount mounts a filesystem using syscall.Mount.
func (f *OSFileSystem) Mount(source, target, fstype string, flags uintptr, data string) error {
	return syscall.Mount(source, target, fstype, flags, data)
}

// Unmount unmounts a filesystem using syscall.Unmount.
func (f *OSFileSystem) Unmount(target string, flags int) error {
	return syscall.Unmount(target, flags)
}
