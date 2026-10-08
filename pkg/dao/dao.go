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

// Package dao is the one place go-xkms builds a go-qrdb GenericDAO from the
// injected DAO factory. A feature receives a *qrdbsdk.DAOFactory from its
// composition root and calls New; it never holds a KVStore or writes a raw
// key, so the store behind the factory can change without touching it.
//
// The go-qrdb SDK's NewDAO takes a KVStore, and the SDK re-exports no
// factory-based constructor. New resolves the store from the factory and
// hands it to NewDAO. When the SDK gains a factory-based constructor, New
// becomes a call to it and no feature changes.
package dao

import (
	"errors"
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ErrNilFactory is returned by New when it is given no factory.
var ErrNilFactory = errors.New("dao: a DAO factory is required")

// DatabaseUnavailableError is returned by New when the factory serves no
// store for the database: it was never opened on the datastore (see
// datastore.Datastore.DatabaseKVStore).
type DatabaseUnavailableError struct {
	Database string
}

// Error returns the error message.
func (e *DatabaseUnavailableError) Error() string {
	return fmt.Sprintf("dao: database %q is not open on the DAO factory", e.Database)
}

// NewDAOError wraps go-qrdb's refusal to build a DAO for an entity type.
type NewDAOError struct {
	EntityType string
	Err        error
}

// Error returns the error message.
func (e *NewDAOError) Error() string {
	return fmt.Sprintf("dao: failed to build the %q DAO: %v", e.EntityType, e.Err)
}

// Unwrap exposes Err so errors.Is/errors.As can reach it.
func (e *NewDAOError) Unwrap() error {
	return e.Err
}

// New builds the GenericDAO for entityType in the named database from
// factory. An empty database means the datastore's default database.
//
// A factory with no partitioned provider would hand a named database the
// default store; New refuses that, so a feature's entities never land in
// another database.
func New[E qrdbsdk.Entity](factory *qrdbsdk.DAOFactory, database, entityType string, newEntity func() E, opts ...qrdbsdk.DAOOption) (qrdbsdk.GenericDAO[E], error) {
	if factory == nil {
		return nil, ErrNilFactory
	}
	if database != "" && !factory.HasPartitionedProvider() {
		return nil, &DatabaseUnavailableError{Database: database}
	}
	store := factory.KVStoreForPartition(database, 0)
	if store == nil {
		return nil, &DatabaseUnavailableError{Database: database}
	}
	d, err := qrdbsdk.NewDAO(store, entityType, newEntity, opts...)
	if err != nil {
		return nil, &NewDAOError{EntityType: entityType, Err: err}
	}
	return d, nil
}

// NewStoreFactory returns a DAO factory that serves store for the default
// database and for every named one. It is the factory of a host with one
// store and no go-qrdb node -- xkey over its barrier, or a test over a
// memory store -- where a feature's named database is a view of the same
// store. Entity types keep the features apart. New refuses every DAO of a
// factory built over a nil store with DatabaseUnavailableError.
func NewStoreFactory(store qrdbsdk.KVStore) *qrdbsdk.DAOFactory {
	return qrdbsdk.NewDAOFactoryWithConfig(&qrdbsdk.DAOFactoryConfig{
		KVStoreProvider:     func(uint64) qrdbsdk.KVStore { return store },
		PartitionedProvider: func(string, uint64) qrdbsdk.KVStore { return store },
	})
}
