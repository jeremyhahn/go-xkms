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
	"errors"
	"fmt"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// databaseEngine is the go-qrdb database engine every feature-owned
// database is created with: EngineKV, the general-purpose key-value engine
// -- the right engine for a DAO, which only ever needs Put/Get/Delete/Scan
// plus the guarded-write capability, never the SQL/timeseries/vector
// surfaces the other engines add. This is go-qrdb's own
// transport.CreateDatabaseRequest.Engine (validated against
// database.EngineType, go-qrdb#types.go) -- a dynamically created database's
// engine is a different vocabulary from the "mvcc" state-machine kind the
// datastore's own statically-declared "default" database uses
// (EmbeddedNodeStorageConfig), so the two must not be confused.
const databaseEngine = string(qrdbsdk.EngineKV)

// ClientBackend is implemented by every storage.Backend Open returns
// (standalone and remote alike). It exposes the underlying go-qrdb SDK
// client so a composition root can reach capabilities beyond the
// storage.Backend surface -- in particular DatabaseKVStore, a feature's one
// way to reach its own named go-qrdb database.
type ClientBackend interface {
	storage.Backend

	// Client returns the go-qrdb SDK client this backend's KV operations
	// run through.
	Client() *qrdbsdk.Client
}

// DatabaseKVStore returns a go-qrdb KVStore confined to the named database,
// ensuring the database exists first. name is a constant a feature package
// declares in code (e.g. pkg/oidc.DatabaseName); backend is the
// storage.Backend datastore.Open returned for this deployment.
//
// This is the ONE way a feature's DAO reaches its own go-qrdb database.
// Only a composition root (pkg/compose, xkey's own wiring) calls it -- never
// the feature package itself, which only ever declares the database name
// and accepts a qrdbsdk.KVStore in its constructor.
//
// The database's storage backend is cfg.Datastore.Databases' entry for name
// when one is configured with a non-empty Backend, and cfg.Datastore.Engine
// otherwise -- the same default the datastore's own "default" database
// uses. Database creation and scoping go through go-qrdb's own Database and
// DatabaseScoped client capabilities (sdk/go/transport/embedded and every
// network transport implement both identically), so this function behaves
// the same in standalone and remote mode, and over any transport: the
// feature code downstream of it never branches on topology.
func DatabaseKVStore(ctx context.Context, backend storage.Backend, cfg *config.Config, name string) (qrdbsdk.KVStore, error) {
	cb, ok := backend.(ClientBackend)
	if !ok {
		return nil, &ErrClientUnavailable{Backend: fmt.Sprintf("%T", backend)}
	}
	client := cb.Client()

	if err := ensureDatabase(ctx, client, cfg, name); err != nil {
		return nil, err
	}

	scoped, err := client.DatabaseScoped(name)
	if err != nil {
		return nil, &ErrDatabaseScope{Name: name, Err: err}
	}
	return scoped.KVStore(), nil
}

// ensureDatabase confirms the named database exists, creating it with its
// resolved backend when it does not. A CreateDatabase race -- another
// composition root ensuring the same database concurrently -- resolves to
// success rather than an error: the database existing is the postcondition
// ensureDatabase promises, regardless of who created it.
func ensureDatabase(ctx context.Context, client *qrdbsdk.Client, cfg *config.Config, name string) error {
	if _, err := client.Database().GetDatabase(ctx, name); err == nil {
		return nil
	}

	backend := resolveDatabaseBackend(cfg, name)
	_, err := client.Database().CreateDatabase(ctx, qrdbtransport.CreateDatabaseRequest{
		Name:    name,
		Engine:  databaseEngine,
		Backend: backend,
	})
	if err == nil {
		return nil
	}

	var exists *qrdbsdk.DBAlreadyExistsError
	if errors.As(err, &exists) {
		return nil
	}
	return &ErrEnsureDatabase{Name: name, Err: err}
}

// resolveDatabaseBackend returns the go-qrdb storage backend ("memory",
// "file", "pebble", or "raft") the named database is created with: the
// cfg.Datastore.Databases override for name when one is configured with a
// non-empty Backend, and cfg.Datastore.Engine (already defaulted to
// "pebble" by config.Validate) otherwise.
func resolveDatabaseBackend(cfg *config.Config, name string) string {
	for _, db := range cfg.Datastore.Databases {
		if db.Name == name && db.Backend != "" {
			return strings.ToLower(strings.TrimSpace(db.Backend))
		}
	}
	engine := strings.ToLower(strings.TrimSpace(cfg.Datastore.Engine))
	if engine == "" {
		engine = "pebble"
	}
	return engine
}
