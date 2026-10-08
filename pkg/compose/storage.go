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

package compose

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// FactoryBackend returns a storage.Backend over the default database of
// the injected DAO factory: the bridge for a feature that persists through
// a storage.Backend rather than a DAO. The backend does not own the
// factory's store; its Close is a no-op.
//
// It carries the single-key guarded writes but no fenced create (see
// qrdbstorage.KVStoreBackend), which no feature this package composes
// needs.
func FactoryBackend(daos *qrdbsdk.DAOFactory) (storage.Backend, error) {
	if daos == nil {
		return nil, ErrNilDAOFactory
	}
	backend, err := qrdbstorage.NewKVStoreBackend(daos.KVStoreForPartition("", 0))
	if err != nil {
		return nil, err
	}
	return backend, nil
}

// FactoryStorage returns the StorageFactory that opens each feature's
// storage as the view prefix+name+"/" over FactoryBackend(daos). The views
// share one backend.
func FactoryStorage(daos *qrdbsdk.DAOFactory, prefix string) (StorageFactory, error) {
	shared, err := FactoryBackend(daos)
	if err != nil {
		return nil, err
	}
	return func(name string) (storage.Backend, error) {
		return storage.NewPrefixBackend(shared, prefix+name+"/")
	}, nil
}
