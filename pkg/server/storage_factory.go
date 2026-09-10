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
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// createStorage opens the storage backend the server configuration names,
// rooted at subdir under the configured path; a qrdb backend is a prefixed
// view of the shared qrdb store.
func (s *Server) createStorage(subdir string) (storage.Backend, error) {
	cfg := s.config.Storage
	switch cfg.Backend {
	case "memory":
		return storage.NewMemoryBackend()
	case "pebble", "":
		// Empty defaults to durable PebbleDB (see config validation); never a
		// non-durable store in a production path.
		path := filepath.Join(cfg.Path, subdir)
		return storage.NewPebble(path)
	case "file":
		path := filepath.Join(cfg.Path, subdir)
		return file.New(path)
	case "qrdb":
		// All subdirs share the single qrdb backend built in New; the subdir
		// becomes a key namespace via a prefixed view. The view's Close is a
		// no-op on the shared inner backend, which only the server closes.
		return storage.NewPrefixBackend(s.qrdbStorage, subdir+"/")
	default:
		return nil, &ErrUnsupportedStorageBackend{Backend: cfg.Backend}
	}
}

// createStorageAt creates a storage backend using the server's configured
// storage engine but at the given absolute path. This is used for backend
// key storage paths that are configured independently of the metadata
// storage root (e.g., Backends.Software.Path, Backends.PKCS8.Path).
func (s *Server) createStorageAt(path string) (storage.Backend, error) {
	cfg := s.config.Storage
	switch cfg.Backend {
	case "memory":
		return storage.NewMemoryBackend()
	case "pebble", "":
		return storage.NewPebble(path)
	case "file":
		return file.New(path)
	case "qrdb":
		// File-style absolute paths map to a qrdb key namespace derived from
		// the final path segment, sharing the single qrdb backend from New.
		base := filepath.Base(path)
		return storage.NewPrefixBackend(s.qrdbStorage, base+"/")
	default:
		return nil, &ErrUnsupportedStorageBackend{Backend: cfg.Backend}
	}
}
