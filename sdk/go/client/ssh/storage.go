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

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// NewFileStorage opens a file-backed storage backend rooted at rootDir, creating
// the directory if needed. The CLI uses it to back the embedded SSH profile and
// host-key pin stores (alongside the file-backed key store).
func NewFileStorage(rootDir string) (storage.Backend, error) {
	if rootDir == "" {
		return nil, &NilInputError{Field: "RootDir"}
	}
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return nil, &EmbeddedFileStoreError{Op: "mkdir", Path: rootDir, Err: err}
	}
	return file.New(rootDir)
}
