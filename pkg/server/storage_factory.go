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

package server

import (
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// createStorage opens a storage view for subdir on the server's single
// shared datastore (s.qrdbStorage, built once in initializeQRDBStorage).
// Every subsystem -- keys, users, RBAC, custodian, shares, CA serials and
// revocations, ACME state, everything -- goes through this one seam: the
// subdir becomes a key namespace via a prefixed view. The view's Close is a
// no-op on the shared inner backend, which only the server closes
// (closeQRDBStorage). There is no per-subsystem private storage engine:
// datastore.engine and datastore.mode (config.DatastoreConfig) select the
// ONE engine and topology the whole server uses.
func (s *Server) createStorage(subdir string) (storage.Backend, error) {
	return storage.NewPrefixBackend(s.qrdbStorage, subdir+"/")
}

// createStorageAt opens a storage view on the single shared datastore for an
// absolute path, used for backend key storage paths that are configured
// independently of the datastore root (e.g., Backends.Software.Path,
// Backends.PKCS8.Path). The absolute path maps to a key namespace derived
// from its final path segment, sharing the single datastore from
// initializeQRDBStorage -- never a separate, private storage engine.
func (s *Server) createStorageAt(path string) (storage.Backend, error) {
	base := filepath.Base(path)
	return storage.NewPrefixBackend(s.qrdbStorage, base+"/")
}
