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
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	qrdbgrpc "github.com/jeremyhahn/go-qrdb/sdk/go/transport/grpc"
	qrdbrest "github.com/jeremyhahn/go-qrdb/sdk/go/transport/rest"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// remoteTransportFactory provides O(1) qrdb-transport dispatch for remote
// (clustered) qrdb storage. Each constructor builds a transport.Transport
// from the supplied options.
var remoteTransportFactory = map[string]func(...qrdbtransport.Option) (qrdbtransport.Transport, error){
	"rest": func(opts ...qrdbtransport.Option) (qrdbtransport.Transport, error) { return qrdbrest.New(opts...) },
	"grpc": func(opts ...qrdbtransport.Option) (qrdbtransport.Transport, error) { return qrdbgrpc.New(opts...) },
}

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
		transport := strings.ToLower(strings.TrimSpace(s.config.Datastore.Remote.Transport))
		backend, err := s.newRemoteQRDBStorage(transport)
		if err != nil {
			return &ErrStorageCreate{Resource: "remote datastore", Err: err}
		}
		s.qrdbStorage = backend
		s.logger.Info("Initialized remote datastore",
			"transport", transport, "address", s.config.Datastore.Remote.Address)
		return nil

	default:
		return &ErrUnsupportedDatastoreMode{Mode: s.config.Datastore.Mode}
	}
}

// newRemoteQRDBStorage dials a remote qrdb cluster over the given transport and
// wraps the resulting KV client as a storage.Backend. The backend does not own
// the dialed client lifecycle through qrdbstorage.NewBackend, so the client is
// retained on a closer and torn down in Shutdown via the server-owned wrapper.
func (s *Server) newRemoteQRDBStorage(transport string) (storage.Backend, error) {
	constructor, ok := remoteTransportFactory[transport]
	if !ok {
		return nil, &ErrUnsupportedStorageBackend{Backend: "qrdb:" + transport}
	}

	opts := s.qrdbTransportOptions()

	rt, err := constructor(opts...)
	if err != nil {
		return nil, err
	}

	client, err := qrdbsdk.NewClient(rt)
	if err != nil {
		return nil, err
	}

	if err := client.Connect(context.Background()); err != nil {
		return nil, err
	}

	// NewBackend wraps the KV client without owning its lifecycle, so wrap it
	// in a server-owned backend whose Close tears down the SDK client (which in
	// turn closes the transport).
	return &ownedRemoteBackend{
		Backend: qrdbstorage.NewBackend(client.KV()),
		client:  client,
	}, nil
}

// qrdbTransportOptions builds the qrdb transport options from the datastore
// remote config: address plus TLS when a CA file is configured.
func (s *Server) qrdbTransportOptions() []qrdbtransport.Option {
	qcfg := s.config.Datastore.Remote
	opts := make([]qrdbtransport.Option, 0, 3)

	if qcfg.Address != "" {
		opts = append(opts, qrdbtransport.WithAddress(qcfg.Address))
	}

	if qcfg.TLS.Enabled && qcfg.TLS.CAFile != "" {
		opts = append(opts, qrdbtransport.WithTLS(
			qcfg.TLS.CertFile,
			qcfg.TLS.KeyFile,
			qcfg.TLS.CAFile,
		))
	}

	return opts
}

// ownedRemoteBackend wraps a remote qrdb storage.Backend together with the SDK
// client that backs it so the server can close both in one step during
// Shutdown. The embedded *qrdbstorage.Backend provides all storage operations.
type ownedRemoteBackend struct {
	*qrdbstorage.Backend
	client *qrdbsdk.Client
}

// Close tears down the SDK client (and its transport) backing this remote
// storage. The embedded backend's own Close is a no-op for externally-provided
// clients, so closing the client is sufficient.
func (b *ownedRemoteBackend) Close() error {
	return b.client.Close()
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
