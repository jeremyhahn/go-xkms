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
	"context"
	"errors"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
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
// modules, TLS, and node-barrier adoption -- initEmbeddedQRDBNode) and hands
// the node's client to datastore.New; the remote path is datastore.Open, the
// SAME Server-independent implementation the SDK/library composition path
// uses -- there is exactly one remote-dial implementation.
//
// Either way the server holds the datastore (s.datastore: the client and the
// DAO factory) and a storage backend over the datastore's client
// (s.qrdbStorage). The backend is built over the client's KV rather than the
// DAO factory because the seal barrier's views need fenced creates, which
// the factory's KVStore does not carry. Per-subdir storage views are
// key-prefixed views over this backend (see createStorage) whose Close is a
// no-op on the shared inner; only Shutdown closes the datastore.
func (s *Server) initializeQRDBStorage() error {
	mode := strings.ToLower(strings.TrimSpace(s.config.Datastore.Mode))
	if mode == "" {
		mode = "standalone"
	}

	switch mode {
	case "standalone":
		// Host the qrdb engine in-process as xkms's single core (storage +
		// identity + bootstrap + clustering). The node's own barrier is
		// xkms's barrier; initEmbeddedQRDBNode adopts it.
		if err := s.initEmbeddedQRDBNode(); err != nil {
			return &ErrStorageCreate{Resource: "embedded qrdb node", Err: err}
		}
		// Feature DAOs are xkms's own persistence, as the storage backend
		// is (storageCallContext): they run as the node's service principal.
		ds, err := datastore.New(s.qrdbClient, s.config.Datastore,
			datastore.WithCallContext(s.qrdbNode.ServiceContext))
		if err != nil {
			return &ErrStorageCreate{Resource: "standalone datastore", Err: err}
		}
		s.datastore.Store(ds)
		if err := s.bindPeerEvidenceStorage(); err != nil {
			return err
		}
		s.logger.Info("Initialized standalone datastore",
			"engine", s.config.Datastore.Engine, "path", s.config.Datastore.Path)

	case "remote":
		ds, err := datastore.Open(s.ctx, s.config, s.logger)
		if err != nil {
			return &ErrStorageCreate{Resource: "remote datastore", Err: err}
		}
		s.datastore.Store(ds)
		s.logger.Info("Initialized remote datastore",
			"transport", s.config.Datastore.Remote.Transport, "address", s.config.Datastore.Remote.Address)

	default:
		return &datastore.ErrUnsupportedDatastoreMode{Mode: s.config.Datastore.Mode}
	}

	s.setSharedStorage(qrdbstorage.NewBackend(s.datastore.Load().Client().KV(), s.storageCallContext()...))
	return nil
}

// storageCallContext returns the options that make the shared storage
// backend's calls xkms's own: over the embedded node they run as its service
// principal (embeddednode.ServicePrincipal), whatever context the caller
// passes -- a request's storage is xkms persisting what it has already
// authorized, exactly as a remote datastore runs it under xkms's own client
// certificate. A remote datastore needs no binding.
func (s *Server) storageCallContext() []qrdbstorage.Option {
	if s.qrdbNode == nil {
		return nil
	}
	return []qrdbstorage.Option{qrdbstorage.WithCallContext(s.qrdbNode.ServiceContext)}
}

// relyingPartyCallContext returns the binder for the WebAuthn relying
// party's qrdb user-record calls. Over the embedded node they run as its
// service principal (embeddednode.ServicePrincipal) whatever the request
// carries, as the relying party's credential records do (storageCallContext):
// the records are the relying party's own, and the service decides every
// ceremony before it touches one -- the sign-up policy on a public
// registration, the session-account binding on an added passkey. An
// authenticated session's own identity holds no grant over user records, so
// keeping it would refuse the session's lookup of its own account. Nil
// without an embedded node.
func (s *Server) relyingPartyCallContext() func(ctx context.Context) (context.Context, error) {
	if s.qrdbNode == nil {
		return nil
	}
	return s.qrdbNode.ServiceContext
}

// publicCallContext returns the binder for the qrdb identity-plane calls
// xkms makes while serving an unauthenticated request: the token issuer's
// refresh records and refresh-time user lookups. Such a request carries no identity go-qrdb's
// authorization accepts, so the call runs as the node's service principal
// (embeddednode.ServicePrincipal). A call made for an authenticated request
// keeps the caller's identity: it never runs as the principal. Nil without
// an embedded node.
func (s *Server) publicCallContext() func(ctx context.Context) (context.Context, error) {
	node := s.qrdbNode
	if node == nil {
		return nil
	}
	return func(ctx context.Context) (context.Context, error) {
		if auth.GetIdentity(ctx) != nil {
			return ctx, nil
		}
		return node.ServiceContext(ctx)
	}
}

// closeQRDBStorage tears down the in-process qrdb node when xkms hosts it
// (embedded mode), then retracts and closes the shared storage backend and
// the datastore if they were created. It is safe to call when no datastore is
// in use, and more than once. The datastore closes the client it dialed
// (remote mode); the embedded node's client is borrowed, so the node itself
// is the lifecycle owner and closes it in stopQRDBNode. A caller that reaches
// for the datastore afterwards gets ErrNoDatastore (daoFactory).
func (s *Server) closeQRDBStorage() error {
	// The node goes first: its Close stops the transports it serves and
	// drains the requests in flight, whose handlers read the storage and the
	// datastore retracted below.
	errs := []error{s.stopQRDBNode()}
	if backend := s.qrdbStorage.Swap(nil); backend != nil {
		errs = append(errs, (*backend).Close())
	}
	if ds := s.datastore.Swap(nil); ds != nil {
		errs = append(errs, ds.Close())
	}
	return errors.Join(errs...)
}

// sharedStorage returns the shared storage backend, or nil before
// initializeQRDBStorage has built it and after closeQRDBStorage.
func (s *Server) sharedStorage() storage.Backend {
	if backend := s.qrdbStorage.Load(); backend != nil {
		return *backend
	}
	return nil
}

// setSharedStorage publishes backend as the shared storage backend.
func (s *Server) setSharedStorage(backend storage.Backend) {
	s.qrdbStorage.Store(&backend)
}
