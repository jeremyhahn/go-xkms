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

// Package datastore opens the deployment's one shared go-qrdb datastore and
// hands out what features persist through: the go-qrdb SDK client and a DAO
// factory over it. It is the same in every mode -- an embedded node
// (pkg/embeddednode) or a remote cluster (DialRemote) -- so feature code
// never branches on topology, and never sees a raw KV store or key layout:
// it receives the factory and builds its GenericDAOs through pkg/dao.
// See docs/datastore/architecture.md.
package datastore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// Datastore is an open go-qrdb datastore: the SDK client, the DAO factory
// over it, and the named databases features have opened on it.
//
// The factory's shard store is the client's default database. Its
// partitioned provider serves each database DatabaseKVStore has opened,
// keyed by name, so pkg/dao builds a feature's DAO over the feature's own
// database. The shard ID is ignored: the client already targets its node's
// data plane.
type Datastore struct {
	client    *qrdbsdk.Client
	daos      *qrdbsdk.DAOFactory
	cfg       config.DatastoreConfig
	databases sync.Map  // database name -> qrdbsdk.KVStore
	owned     io.Closer // the node or client Open built; nil for New

	// bind derives the context every call into go-qrdb runs on; nil runs it
	// on the caller's context (WithCallContext).
	bind qrdbstorage.CallContext
}

// Open opens the shared datastore cfg.Datastore describes:
//
//   - "standalone" (default) hosts an embedded qrdb node in this process,
//     rooted at cfg.Datastore.Path and using cfg.Datastore.Engine, via
//     embeddednode.OpenEmbeddedNode -- the same construction xkmsd init
//     uses. Datastore.Path is required for every Engine, "memory" included:
//     go-qrdb roots the node's on-disk state (its vector-storage subsystem in
//     particular) under it regardless of the primary KV engine.
//   - "remote" dials an already-running qrdb cluster at
//     cfg.Datastore.Remote.Address, via DialRemote.
//
// The Datastore owns the node or client it built; Close releases it.
func Open(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Datastore, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Datastore.Mode))
	if mode == "" {
		mode = "standalone"
	}

	switch mode {
	case "standalone":
		if cfg.Datastore.Path == "" {
			return nil, &embeddednode.ErrDatastorePathRequired{Reason: "the standalone datastore"}
		}
		node, _, err := embeddednode.OpenEmbeddedNode(ctx, embeddednode.EmbeddedNodeOptions{
			Config: cfg,
			Logger: logger,
		})
		if err != nil {
			return nil, &ErrOpenDatastore{Mode: mode, Err: err}
		}
		// The node is this datastore's own, so its calls run as the node's
		// service principal, exactly as xkmsd's datastore over its node does.
		return openDatastore(mode, node.Client(), cfg.Datastore, node, WithCallContext(node.ServiceContext))

	case "remote":
		client, err := DialRemote(ctx, cfg.Datastore.Remote)
		if err != nil {
			return nil, &ErrOpenDatastore{Mode: mode, Err: err}
		}
		return openDatastore(mode, client, cfg.Datastore, client)

	default:
		return nil, &ErrUnsupportedDatastoreMode{Mode: cfg.Datastore.Mode}
	}
}

// openDatastore builds the Datastore Open returns over what it opened,
// closing that again when the build fails.
func openDatastore(mode string, client *qrdbsdk.Client, cfg config.DatastoreConfig, owned io.Closer, opts ...Option) (*Datastore, error) {
	d, err := newDatastore(client, cfg, owned, opts...)
	if err != nil {
		return nil, &ErrOpenDatastore{Mode: mode, Err: errors.Join(err, owned.Close())}
	}
	return d, nil
}

// New builds a Datastore over a client the caller already holds -- xkmsd's
// own embedded node, for instance. The caller keeps ownership of the
// client: Close does not close it. cfg supplies the engine new databases
// are created with.
func New(client *qrdbsdk.Client, cfg config.DatastoreConfig, opts ...Option) (*Datastore, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	return newDatastore(client, cfg, nil, opts...)
}

func newDatastore(client *qrdbsdk.Client, cfg config.DatastoreConfig, owned io.Closer, opts ...Option) (*Datastore, error) {
	d := &Datastore{client: client, cfg: cfg, owned: owned}
	for _, opt := range opts {
		opt(d)
	}
	store, err := d.kvStore(client)
	if err != nil {
		return nil, err
	}
	d.daos = qrdbsdk.NewDAOFactoryWithConfig(&qrdbsdk.DAOFactoryConfig{
		KVStoreProvider:     func(uint64) qrdbsdk.KVStore { return store },
		PartitionedProvider: d.databaseStore,
	})
	return d, nil
}

// Client returns the go-qrdb SDK client the datastore runs on.
func (d *Datastore) Client() *qrdbsdk.Client {
	return d.client
}

// DAOFactory returns the factory features build their DAOs from (through
// pkg/dao). It serves the default database and every database
// DatabaseKVStore has opened.
func (d *Datastore) DAOFactory() *qrdbsdk.DAOFactory {
	return d.daos
}

// HealthCheckName is the name HealthCheck reports under.
const HealthCheckName = "datastore"

// HealthCheck is a go-qrdb SDK readiness check (qrdbsdk.HealthCheckFunc) on
// the datastore's client: register it on a qrdbsdk.HealthChecker so a feature
// persisting through the datastore reports the datastore's health.
func (d *Datastore) HealthCheck(ctx context.Context) qrdbsdk.HealthCheckResult {
	if !d.client.Healthy(ctx) {
		return qrdbsdk.HealthCheckResult{
			Name:    HealthCheckName,
			Status:  qrdbsdk.HealthCheckStatusUnhealthy,
			Message: "go-qrdb client is not healthy",
		}
	}
	return qrdbsdk.HealthCheckResult{
		Name:    HealthCheckName,
		Status:  qrdbsdk.HealthCheckStatusHealthy,
		Message: "go-qrdb client is healthy",
	}
}

// DatabaseKVStore opens the named go-qrdb database -- creating it when it
// does not exist yet -- and returns a KVStore confined to it. From then on
// the DAO factory serves the database by name. name is a constant a feature
// declares in code (e.g. pkg/oidc.DatabaseName); only a composition root
// calls this, never the feature itself.
//
// The database is created with cfg.Datastore.Databases' Backend for name
// when one is configured, and cfg.Datastore.Engine otherwise. Creation and
// scoping go through go-qrdb's Database and DatabaseScoped client
// capabilities, which every transport implements identically, so this
// behaves the same in standalone and remote mode.
func (d *Datastore) DatabaseKVStore(ctx context.Context, name string) (qrdbsdk.KVStore, error) {
	if name == "" {
		return nil, ErrDatabaseNameRequired
	}
	if store, ok := d.databases.Load(name); ok {
		return store.(qrdbsdk.KVStore), nil
	}

	// Scoping first refuses a transport with no database plane with a typed
	// error before ensureDatabase reaches for the plane it lacks.
	scoped, err := d.client.DatabaseScoped(name)
	if err != nil {
		return nil, &ErrDatabaseScope{Name: name, Err: err}
	}
	callCtx, err := d.callContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := ensureDatabase(callCtx, d.client, d.cfg, name); err != nil {
		return nil, err
	}
	kv, err := d.kvStore(scoped)
	if err != nil {
		return nil, &ErrDatabaseScope{Name: name, Err: err}
	}
	store, _ := d.databases.LoadOrStore(name, kv)
	return store.(qrdbsdk.KVStore), nil
}

// databaseStore is the DAO factory's partitioned provider: the store of a
// database DatabaseKVStore has opened, or nil for one it has not.
func (d *Datastore) databaseStore(name string, _ uint64) qrdbsdk.KVStore {
	store, ok := d.databases.Load(name)
	if !ok {
		return nil
	}
	return store.(qrdbsdk.KVStore)
}

// Close releases the node or client Open built. A Datastore from New owns
// nothing, so its Close does nothing.
func (d *Datastore) Close() error {
	if d.owned == nil {
		return nil
	}
	return d.owned.Close()
}
