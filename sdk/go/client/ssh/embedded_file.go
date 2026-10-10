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

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// EmbeddedFileOptions configures a file-backed embedded Client. The
// rootDir directory is created with mode 0700 if it does not exist so
// callers don't need to pre-provision it. The mode is chosen to match
// the OpenSSH ~/.ssh convention.
type EmbeddedFileOptions struct {
	// RootDir is the filesystem directory holding the client's go-qrdb
	// datastore. The directory is created (mode 0700) if missing. Required.
	RootDir string
}

// NewEmbeddedFile constructs an embedded Client whose Stores live in a
// go-qrdb datastore kept in a local directory. It is the composition root
// for callers (such as the xkmsctl CLI) that run without a server. Closing
// the Client closes the datastore.
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
	kv, err := kvadapter.New(backend)
	if err != nil {
		return nil, &EmbeddedFileStoreError{Op: "open", Path: opts.RootDir, Err: err}
	}
	stores, err := NewStores(dao.NewStoreFactory(kv))
	if err != nil {
		return nil, err
	}
	client, err := NewEmbedded(EmbeddedOptions{Stores: stores})
	if err != nil {
		return nil, err
	}
	return &fileClient{Client: client, backend: backend}, nil
}

// fileClient is an embedded Client that owns its datastore's backend.
type fileClient struct {
	Client
	backend storage.Backend
}

// Close closes the datastore backend.
func (c *fileClient) Close() error {
	return c.backend.Close()
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
