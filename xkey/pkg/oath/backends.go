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

package oath

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// DefaultBackendID is the software backend, which the backend registry
// always registers (backendregistry.SoftwareBackendID). Its partition is the
// historical store location ("oath/" keys, oath.json), so credentials stored
// before multi-backend routing, which carry no BackendID, stay reachable.
const DefaultBackendID = "software"

const defaultKeyPrefix = "oath/"

// ErrInvalidBackendID is returned for a backend ID that cannot name a store
// partition (empty, or holding anything but letters, digits, '-', '_', '.').
var ErrInvalidBackendID = errors.New("oath: invalid backend id")

// ErrBackendStoreOpen is returned when one backend's store cannot be opened.
var ErrBackendStoreOpen = errors.New("oath: open backend store")

// ErrInvalidStorePath is returned for a file store path that is empty or
// whose file name holds '@', the partition separator: such a file could be
// another store's backend partition.
var ErrInvalidStorePath = errors.New("oath: invalid store path")

// OpenStores returns a CompositeStore holding one store per backend in ids,
// with defaultID receiving credentials that name no backend. It is the one
// constructor of the OATH store set: the CLI, the GUI, the extension server
// and backups all open credentials through it, so each sees every partition.
//
// With storage non-nil (the unsealed barrier) each backend is a BackendStore,
// DefaultBackendID under the "oath/" prefix and any other backend under
// "oath@<id>/". Otherwise each backend is a FileStore at
// FilePartitionPath(path, id).
func OpenStores(storage xkms.StorageBackend, path string, ids []string, defaultID string) (*CompositeStore, error) {
	if storage != nil {
		return newPartitionedStore(ids, defaultID, func(id string) (Store, error) {
			return NewBackendStore(storage, keyPrefix(id))
		})
	}
	return newPartitionedStore(ids, defaultID, func(id string) (Store, error) {
		partition, err := FilePartitionPath(path, id)
		if err != nil {
			return nil, err
		}
		return NewFileStore(partition)
	})
}

// FilePartitionPath returns the file holding backend id's credentials for
// the file store at path: path itself for DefaultBackendID, any other backend
// a sibling named after path's file, <name>@<id><ext> (oath.json gives
// oath@token1.json, a.json gives a@token1.json). Stores at different paths
// therefore never share a partition. A path whose file name holds '@' is
// refused with ErrInvalidStorePath, so no store's own file can be another
// store's partition.
func FilePartitionPath(path, id string) (string, error) {
	base := filepath.Base(path)
	if path == "" || strings.Contains(base, "@") {
		return "", &DetailError{Err: ErrInvalidStorePath, Detail: ": " + strconv.Quote(path)}
	}
	if id == DefaultBackendID {
		return path, nil
	}
	ext := filepath.Ext(base)
	return filepath.Join(filepath.Dir(path), strings.TrimSuffix(base, ext)+"@"+id+ext), nil
}

// keyPrefix returns the barrier key prefix of backend id's partition.
func keyPrefix(id string) string {
	if id == DefaultBackendID {
		return defaultKeyPrefix
	}
	return "oath@" + id + "/"
}

// newPartitionedStore validates ids, opens one Store per backend with open,
// and registers each under its ID. Stores already opened are closed when a
// later one fails.
func newPartitionedStore(ids []string, defaultID string, open func(id string) (Store, error)) (*CompositeStore, error) {
	for _, id := range ids {
		if !validBackendID(id) {
			return nil, &BackendError{Err: ErrInvalidBackendID, BackendID: id}
		}
	}

	composite := NewCompositeStore(defaultID)
	for _, id := range ids {
		store, err := open(id)
		if err != nil {
			return nil, errors.Join(&BackendError{Err: ErrBackendStoreOpen, BackendID: id}, err, composite.Close())
		}
		composite.Register(id, store)
	}
	return composite, nil
}

// validBackendID reports whether id can name a key prefix and a file name.
func validBackendID(id string) bool {
	if id == "" || strings.Trim(id, ".") == "" {
		return false
	}
	for _, r := range id {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.'
		if !ok {
			return false
		}
	}
	return true
}
