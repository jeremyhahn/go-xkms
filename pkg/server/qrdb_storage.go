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
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// initializeQRDBStorage builds the single shared datastore backend every
// subsystem stores through (see createStorage/createStorageAt). It must be
// called once, early in New, before the first createStorage call.
//
// Mode selection (config.DatastoreConfig.Mode, defaulted by config.Validate):
//
//	"standalone" -> a persistent qrdb stack hosted in this process, rooted at
//	                Datastore.Path and using the Datastore.Engine local
//	                storage engine (memory, file, or pebble). Runs the whole
//	                qrdb stack in-process, including Raft clustering when
//	                Cluster.Enabled.
//	"remote"     -> a remote client dialed at Datastore.Remote.Address over
//	                Datastore.Remote.Transport (rest or grpc) with the
//	                configured TLS. Writes go through Raft consensus on the
//	                remote cluster; this process hosts no local engine.
//
// The standalone path is Server-specific (the unified API server, its
// modules, TLS, and node-barrier adoption -- initEmbeddedQRDBNode); the
// remote path dials via datastore.DialRemote, the SAME Server-independent
// implementation pkg/datastore.Open uses for callers without a *Server (the
// SDK/library composition path) -- there is exactly one remote-dial
// implementation (go-xkms#1345 batch 2).
//
// The resulting backend is stored on s.qrdbStorage and is owned by the server:
// only Shutdown closes it. Per-subdir storage views are key-prefixed views over
// this backend (see createStorage) whose Close is a no-op on the shared inner.
func (s *Server) initializeQRDBStorage() error {
	mode := strings.ToLower(strings.TrimSpace(s.config.Datastore.Mode))
	if mode == "" {
		mode = "standalone"
	}

	switch mode {
	case "standalone":
		// Host the qrdb engine in-process as xkms's single core (storage +
		// identity + bootstrap + clustering). The server's storage backend is
		// the node's KV; xkms's barrier (initializeBarrier) layers over it.
		if err := s.initEmbeddedQRDBNode(); err != nil {
			return &ErrStorageCreate{Resource: "embedded qrdb node", Err: err}
		}
		s.qrdbStorage = qrdbstorage.NewBackend(s.qrdbClient.KV())
		s.logger.Info("Initialized standalone datastore",
			"engine", s.config.Datastore.Engine, "path", s.config.Datastore.Path)
		return nil

	case "remote":
		backend, err := datastore.DialRemote(s.ctx, s.config.Datastore.Remote)
		if err != nil {
			return &ErrStorageCreate{Resource: "remote datastore", Err: err}
		}
		s.qrdbStorage = backend
		s.logger.Info("Initialized remote datastore",
			"transport", s.config.Datastore.Remote.Transport, "address", s.config.Datastore.Remote.Address)
		return nil

	default:
		return &datastore.ErrUnsupportedDatastoreMode{Mode: s.config.Datastore.Mode}
	}
}

// closeQRDBStorage closes the shared qrdb storage backend if one was created
// and tears down the in-process qrdb node when xkms hosts it (embedded mode).
// It is safe to call when no qrdb backend is in use. For the embedded node the
// storage backend wraps the node's KV client (a no-op Close), so the node
// itself is the lifecycle owner and is closed via stopQRDBNode.
func (s *Server) closeQRDBStorage() error {
	var storageErr error
	if s.qrdbStorage != nil {
		storageErr = s.qrdbStorage.Close()
		s.qrdbStorage = nil
	}
	if err := s.stopQRDBNode(); err != nil {
		if storageErr == nil {
			return err
		}
	}
	return storageErr
}
