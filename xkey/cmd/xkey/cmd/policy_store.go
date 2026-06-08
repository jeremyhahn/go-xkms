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
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// newFileStorageBackend creates a file-based storage backend at the
// given directory path. The directory is created if it does not exist.
func newFileStorageBackend(path string) (xkms.StorageBackend, error) {
	return xkms.NewFileStorageBackend(path)
}

// newKVAdapter wraps a xkms.StorageBackend with the kvadapter to produce
// a kvstore.KVStore suitable for the DAO layer.
func newKVAdapter(backend xkms.StorageBackend) (qrdbsdk.KVStore, error) {
	return xkms.NewKVStoreAdapter(backend)
}
