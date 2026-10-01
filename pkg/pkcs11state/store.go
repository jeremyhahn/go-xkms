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

// Package pkcs11state is the server-side store for the PKCS#11 module's durable
// token and object state when a module runs with StorageType "remote".
//
// It is a thin, namespacing wrapper over a storage.Backend — the same pattern
// pkg/staticpw uses for passwords — so it inherits the backend's atomic
// PutIfAbsent and whatever at-rest protection the backend has. xkmsd builds ONE
// store over one backend for every tenant (pkg/server createStorage); it is not
// behind a tenant barrier, so tenants are separated only by the key prefix, and
// the caller must supply a tenant it has derived from the authenticated identity,
// never one taken from a request. The values are opaque: the module serialises
// its own PersistentTokenState / PersistentObject records and this store keeps
// them verbatim, so the server never has to track the module's record schema.
package pkcs11state

import (
	"context"
	"errors"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// keyPrefix namespaces every record this package writes so it cannot collide
// with other consumers of the same backend.
const keyPrefix = "pkcs11state/"

// ErrNilBackend is returned when a Store is constructed without a backend.
var ErrNilBackend = errors.New("pkcs11state: storage backend is required")

// Store persists opaque PKCS#11 module state records, namespaced by tenant and
// token, on a storage.Backend.
type Store struct {
	backend storage.Backend
}

// NewStore wraps a storage.Backend. The store adds only key namespacing on top:
// it does not scope or encrypt per tenant, so isolation between tenants rests on
// the caller passing the authenticated tenant to every method.
func NewStore(backend storage.Backend) (*Store, error) {
	if backend == nil {
		return nil, ErrNilBackend
	}
	return &Store{backend: backend}, nil
}

// storageKey builds the backend key for a (tenant, token, key) triple.
func storageKey(tenantID, token, key string) string {
	return scopePrefix(tenantID, token) + key
}

// scopePrefix builds the backend key prefix for a (tenant, token) namespace,
// used to translate a List within a token back to namespace-relative keys.
//
// An empty tenant is the system scope and is stored under the system tenant's
// own ID, the scope the service already treats it as. It used to occupy an
// empty path segment ("pkcs11state//<token>/"), which a path-normalizing
// backend such as file storage collapses: List then returned keys the scope
// prefix no longer stripped, a remote-mode module loaded none of its objects,
// and the next key it created reused handle 1 and overwrote an existing one.
func scopePrefix(tenantID, token string) string {
	if tenantID == "" {
		tenantID = qrdbsdk.SystemTenantID
	}
	return keyPrefix + tenantID + "/" + token + "/"
}

// Put stores a record, overwriting any existing value.
func (s *Store) Put(ctx context.Context, tenantID, token, key string, value []byte) error {
	return s.backend.Put(ctx, storageKey(tenantID, token, key), value)
}

// PutIfAbsent atomically stores a record only if the key does not already
// exist, returning whether the write happened.
func (s *Store) PutIfAbsent(ctx context.Context, tenantID, token, key string, value []byte) (bool, error) {
	return s.backend.PutIfAbsent(ctx, storageKey(tenantID, token, key), value)
}

// ErrCompareAndSwapUnsupported is returned when CompareAndSwap is requested but
// the underlying backend does not implement storage.CompareAndSwapper (e.g. a
// backend with no linearizable value-CAS). Remote-mode deployments back this
// store with the embedded qrdb node, which does support it.
var ErrCompareAndSwapUnsupported = errors.New("pkcs11state: backend does not support compare-and-swap")

// CompareAndSwap atomically stores newValue at the record only if the current
// value equals expected (or, when expected is nil, only if the key is absent),
// returning the current value when it does not swap. It backs the multi-client
// lockout-counter update: several clients sharing one remote token increment the
// same failed-attempt counter, and only a value-CAS keeps those read-modify-write
// updates from clobbering each other. The guarantee is exactly the backend's —
// linearizable across nodes when backed by the qrdb node (see pkg/storage/qrdb).
func (s *Store) CompareAndSwap(ctx context.Context, tenantID, token, key string, expected, newValue []byte) (swapped bool, current []byte, err error) {
	cas, ok := s.backend.(storage.CompareAndSwapper)
	if !ok {
		return false, nil, ErrCompareAndSwapUnsupported
	}
	return cas.CompareAndSwap(ctx, storageKey(tenantID, token, key), expected, newValue)
}

// ErrCompareAndDeleteUnsupported is returned when CompareAndDelete is requested
// but the underlying backend does not implement storage.CompareAndDeleter.
// Remote-mode deployments back this store with the embedded qrdb node, which
// evaluates the guard inside the cluster.
var ErrCompareAndDeleteUnsupported = errors.New("pkcs11state: backend does not support compare-and-delete")

// CompareAndDelete atomically removes the record only if its current value
// equals expected, reporting whether this call removed it. An absent key or a
// different value is an ordinary refusal (false, nil), not an error, exactly
// as storage.CompareAndDeleter specifies; a nil expected matches a stored empty
// value only. It is the guarded release that pairs with PutIfAbsent's guarded
// create for clients sharing one remote token, and the guarantee is the
// backend's: linearizable across nodes when backed by the qrdb node.
func (s *Store) CompareAndDelete(ctx context.Context, tenantID, token, key string, expected []byte) (deleted bool, err error) {
	cad, ok := s.backend.(storage.CompareAndDeleter)
	if !ok {
		return false, ErrCompareAndDeleteUnsupported
	}
	return cad.CompareAndDelete(ctx, storageKey(tenantID, token, key), expected)
}

// Get retrieves a record. found distinguishes an absent key from a present
// empty value, which the module relies on to tell "no persisted state" from
// "state that is legitimately empty".
func (s *Store) Get(ctx context.Context, tenantID, token, key string) (value []byte, found bool, err error) {
	value, err = s.backend.Get(ctx, storageKey(tenantID, token, key))
	if errors.Is(err, storage.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

// Delete removes a record. A missing key is not an error, so a caller can
// delete idempotently.
func (s *Store) Delete(ctx context.Context, tenantID, token, key string) error {
	err := s.backend.Delete(ctx, storageKey(tenantID, token, key))
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	return err
}

// List returns the namespace-relative keys under a prefix within a token's
// namespace. An empty prefix lists every key for the token.
func (s *Store) List(ctx context.Context, tenantID, token, prefix string) ([]string, error) {
	scope := scopePrefix(tenantID, token)
	full, err := s.backend.List(ctx, scope+prefix)
	if err != nil {
		return nil, err
	}
	rel := make([]string, 0, len(full))
	for _, k := range full {
		rel = append(rel, strings.TrimPrefix(k, scope))
	}
	return rel, nil
}
