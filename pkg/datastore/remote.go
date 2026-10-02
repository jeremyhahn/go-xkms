// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package datastore

import (
	"context"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	qrdbgrpc "github.com/jeremyhahn/go-qrdb/sdk/go/transport/grpc"
	qrdbrest "github.com/jeremyhahn/go-qrdb/sdk/go/transport/rest"

	"github.com/jeremyhahn/go-xkms/pkg/config"
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

// DialRemote dials a remote, already-running qrdb cluster over cfg.Transport
// ("rest" or "grpc") and wraps the resulting KV client as a storage.Backend.
// This is the single implementation of remote-datastore dialing in the
// stack: Server.initializeQRDBStorage uses it for an xkmsd-hosted deployment
// with datastore.mode=="remote", and Open (below) uses it for callers
// without a *Server (the SDK/library composition path) -- go-xkms#1345
// batch 2 moved it out of pkg/server so there is exactly one implementation.
func DialRemote(ctx context.Context, cfg config.DatastoreRemoteConfig) (storage.Backend, error) {
	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	constructor, ok := remoteTransportFactory[transport]
	if !ok {
		return nil, &ErrUnsupportedStorageBackend{Backend: "qrdb:" + transport}
	}

	opts := TransportOptions(cfg)

	rt, err := constructor(opts...)
	if err != nil {
		return nil, err
	}

	client, err := qrdbsdk.NewClient(rt)
	if err != nil {
		return nil, err
	}

	if err := client.Connect(ctx); err != nil {
		return nil, err
	}

	// NewBackend wraps the KV client without owning its lifecycle, so wrap it
	// in a backend whose Close tears down the SDK client (which in turn
	// closes the transport).
	return &remoteBackend{
		Backend: qrdbstorage.NewBackend(client.KV()),
		client:  client,
	}, nil
}

// TransportOptions builds the qrdb transport options from the datastore
// remote config: address plus TLS when a CA file is configured.
func TransportOptions(cfg config.DatastoreRemoteConfig) []qrdbtransport.Option {
	opts := make([]qrdbtransport.Option, 0, 3)

	if cfg.Address != "" {
		opts = append(opts, qrdbtransport.WithAddress(cfg.Address))
	}

	if cfg.TLS.Enabled && cfg.TLS.CAFile != "" {
		opts = append(opts, qrdbtransport.WithTLS(
			cfg.TLS.CertFile,
			cfg.TLS.KeyFile,
			cfg.TLS.CAFile,
		))
	}

	return opts
}

// remoteBackend wraps a remote qrdb storage.Backend together with the SDK
// client that backs it so Close tears down both in one step. The embedded
// *qrdbstorage.Backend provides all storage operations.
type remoteBackend struct {
	*qrdbstorage.Backend
	client *qrdbsdk.Client
}

// Close tears down the SDK client (and its transport) backing this remote
// storage. The embedded backend's own Close is a no-op for externally-
// provided clients, so closing the client is sufficient.
func (b *remoteBackend) Close() error {
	return b.client.Close()
}

// Client returns the go-qrdb SDK client dialed to the remote cluster,
// implementing ClientBackend so DatabaseKVStore can reach capabilities
// (per-database scoping, database management) beyond storage.Backend.
func (b *remoteBackend) Client() *qrdbsdk.Client {
	return b.client
}
