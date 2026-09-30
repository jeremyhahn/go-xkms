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

package keyversion

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Storage key layout: one record per key, under its tenant's prefix.
//
//	{tenant}/key-versions/<backend>/<keyID>
//
// The system tenant's keys are stored under SystemTenant.
const (
	recordSegment = "/key-versions/"

	// SystemTenant is the tenant segment of the system tenant's records.
	SystemTenant = "system"
)

// Store persists key-version records.
//
// Mutations of one key's versions are serialized in-process through Lock.
// The store records the versions of the keys this node's backends hold, so
// it has one writer per key.
type Store struct {
	store storage.Backend

	// locks holds one *sync.Mutex per record key.
	locks sync.Map
}

// NewStore returns a Store over store.
func NewStore(store storage.Backend) (*Store, error) {
	if store == nil {
		return nil, ErrNilStore
	}
	return &Store{store: store}, nil
}

// TenantSegment returns the tenant segment records of tenant are stored
// under: SystemTenant for the empty (system) tenant, tenant otherwise.
func TenantSegment(tenant string) string {
	if tenant == "" {
		return SystemTenant
	}
	return tenant
}

// recordKey returns the storage key of the record of keyID in backend for
// tenant.
func recordKey(tenant, backend, keyID string) (string, error) {
	segment := TenantSegment(tenant)
	if err := storage.ValidateTenantID(segment); err != nil {
		return "", &InvalidRecordKeyError{Field: "tenant", Value: tenant}
	}
	if !validSegment(backend) {
		return "", &InvalidRecordKeyError{Field: "backend", Value: backend}
	}
	if !validSegment(keyID) {
		return "", &InvalidRecordKeyError{Field: "key ID", Value: keyID}
	}
	return segment + recordSegment + backend + "/" + keyID, nil
}

// validSegment reports whether s can be one segment of a storage key.
func validSegment(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

// Load returns the record of keyID in backend for tenant. A key with no
// stored record has the implicit one (Implicit), and found reports false.
func (s *Store) Load(ctx context.Context, tenant, backend, keyID string) (rec *Record, found bool, err error) {
	k, err := recordKey(tenant, backend, keyID)
	if err != nil {
		return nil, false, err
	}
	data, err := s.store.Get(ctx, k)
	if errors.Is(err, storage.ErrNotFound) {
		return Implicit(keyID, backend), false, nil
	}
	if err != nil {
		return nil, false, &StoreError{Op: "get", Key: k, Err: err}
	}
	var stored Record
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, false, &StoreError{Op: "decode", Key: k, Err: err}
	}
	return &stored, true, nil
}

// Put stores rec as the record of its key for tenant.
func (s *Store) Put(ctx context.Context, tenant string, rec *Record) error {
	if rec == nil {
		return ErrNilRecord
	}
	k, err := recordKey(tenant, rec.Backend, rec.KeyID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return &StoreError{Op: "encode", Key: k, Err: err}
	}
	if err := s.store.Put(ctx, k, data); err != nil {
		return &StoreError{Op: "put", Key: k, Err: err}
	}
	return nil
}

// Delete removes the record of keyID in backend for tenant. An absent record
// is not an error.
func (s *Store) Delete(ctx context.Context, tenant, backend, keyID string) error {
	k, err := recordKey(tenant, backend, keyID)
	if err != nil {
		return err
	}
	if err := s.store.Delete(ctx, k); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return &StoreError{Op: "delete", Key: k, Err: err}
	}
	return nil
}

// Lock acquires the lock serializing changes to the versions of keyID in
// backend for tenant and returns the function that releases it. A rotation
// holds it from reading the record until the new version is recorded, so
// two rotations of one key never create the same version.
func (s *Store) Lock(tenant, backend, keyID string) (unlock func()) {
	k := TenantSegment(tenant) + recordSegment + backend + "/" + keyID
	actual, _ := s.locks.LoadOrStore(k, &sync.Mutex{})
	mu := actual.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
