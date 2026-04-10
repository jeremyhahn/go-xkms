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

package cmd

import (
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// newFileStorageBackend creates a file-based storage backend at the
// given directory path. The directory is created if it does not exist.
func newFileStorageBackend(path string) (storage.Backend, error) {
	return file.New(path)
}

// newKVAdapter wraps a storage.Backend with the kvadapter to produce
// a kvstore.KVStore suitable for the DAO layer.
func newKVAdapter(backend storage.Backend) (kvstore.KVStore, error) {
	return kvadapter.New(backend)
}
