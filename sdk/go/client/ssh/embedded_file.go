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

package ssh

import (
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// EmbeddedFileOptions configures a file-backed embedded Client. The
// rootDir directory is created with mode 0700 if it does not exist so
// callers don't need to pre-provision it. The mode is chosen to match
// the OpenSSH ~/.ssh convention.
type EmbeddedFileOptions struct {
	// RootDir is the filesystem directory used as the SSH key store
	// root. The directory is created (mode 0700) if missing. Required.
	RootDir string
}

// NewEmbeddedFile constructs an embedded Client backed by a local
// directory. It is a convenience over NewEmbedded for callers (such as
// the xkey CLI) that want a standalone mode without taking a direct
// dependency on pkg/storage.
func NewEmbeddedFile(opts EmbeddedFileOptions) (Client, error) {
	if opts.RootDir == "" {
		return nil, &NilInputError{Field: "RootDir"}
	}
	if err := os.MkdirAll(opts.RootDir, 0o700); err != nil {
		return nil, &EmbeddedFileStoreError{Op: "mkdir", Path: opts.RootDir, Err: err}
	}
	backend, err := file.New(opts.RootDir)
	if err != nil {
		return nil, &EmbeddedFileStoreError{Op: "open", Path: opts.RootDir, Err: err}
	}
	return NewEmbedded(EmbeddedOptions{Backend: backend})
}

// EmbeddedFileStoreError wraps a filesystem failure encountered while
// constructing a file-backed embedded Client.
type EmbeddedFileStoreError struct {
	Op   string
	Path string
	Err  error
}

// Error implements the error interface.
func (e *EmbeddedFileStoreError) Error() string {
	return "sdk/ssh: file store " + e.Op + " " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying filesystem error.
func (e *EmbeddedFileStoreError) Unwrap() error { return e.Err }
