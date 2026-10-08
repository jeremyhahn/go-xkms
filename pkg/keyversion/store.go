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
	"strings"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

const (
	// DatabaseName is the go-qrdb database key-version records live in. A
	// composition root opens it on the datastore before calling NewStore.
	DatabaseName = "keyversion"

	// entityType is the DAO entity type of a key-version record.
	entityType = "key_versions"

	// SystemTenant is the tenant segment of the system tenant's records.
	SystemTenant = "system"
)

// Store persists key-version records, one Entity per key, through a go-qrdb
// DAO.
//
// Mutations of one key's versions are serialized in-process through Lock.
// The store records the versions of the keys this node's backends hold, so
// it has one writer per key.
type Store struct {
	records qrdbsdk.GenericDAO[*Entity]

	// locks holds one *sync.Mutex per record name.
	locks sync.Map
}

// NewStore returns a Store whose DAO daos builds over DatabaseName.
func NewStore(daos *qrdbsdk.DAOFactory) (*Store, error) {
	if daos == nil {
		return nil, ErrNilDAOFactory
	}
	records, err := newRecordDAO(daos)
	if err != nil {
		return nil, &StoreError{Op: "open", Key: DatabaseName, Err: err}
	}
	return &Store{records: records}, nil
}

// newRecordDAO builds the record DAO: entity IDs derive from Name.
func newRecordDAO(daos *qrdbsdk.DAOFactory) (qrdbsdk.GenericDAO[*Entity], error) {
	return dao.New(daos, DatabaseName, entityType, newEntity,
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Name")))
}

// TenantSegment returns the tenant segment records of tenant are stored
// under: SystemTenant for the empty (system) tenant, tenant otherwise.
func TenantSegment(tenant string) string {
	if tenant == "" {
		return SystemTenant
	}
	return tenant
}

// recordName returns the natural key of the record of keyID in backend for
// tenant: "{tenant}/{backend}/{keyID}".
func recordName(tenant, backend, keyID string) (string, error) {
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
	return segment + "/" + backend + "/" + keyID, nil
}

// validSegment reports whether s can be one segment of a record name.
func validSegment(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

// Load returns the record of keyID in backend for tenant. A key with no
// stored record has the implicit one (Implicit), and found reports false.
func (s *Store) Load(ctx context.Context, tenant, backend, keyID string) (rec *Record, found bool, err error) {
	name, err := recordName(tenant, backend, keyID)
	if err != nil {
		return nil, false, err
	}
	stored, err := s.records.GetByNaturalKey(ctx, name)
	if qrdbsdk.IsDAONotFound(err) {
		return Implicit(keyID, backend), false, nil
	}
	if err != nil {
		return nil, false, &StoreError{Op: "get", Key: name, Err: err}
	}
	return &stored.Record, true, nil
}

// Put stores rec as the record of its key for tenant.
func (s *Store) Put(ctx context.Context, tenant string, rec *Record) error {
	if rec == nil {
		return ErrNilRecord
	}
	name, err := recordName(tenant, rec.Backend, rec.KeyID)
	if err != nil {
		return err
	}
	if err := s.records.Save(ctx, &Entity{Name: name, Record: *rec}); err != nil {
		return &StoreError{Op: "put", Key: name, Err: err}
	}
	return nil
}

// Delete removes the record of keyID in backend for tenant. An absent record
// is not an error.
func (s *Store) Delete(ctx context.Context, tenant, backend, keyID string) error {
	name, err := recordName(tenant, backend, keyID)
	if err != nil {
		return err
	}
	stored, err := s.records.GetByNaturalKey(ctx, name)
	if qrdbsdk.IsDAONotFound(err) {
		return nil
	}
	if err == nil {
		err = s.records.Delete(ctx, stored)
	}
	if err != nil {
		return &StoreError{Op: "delete", Key: name, Err: err}
	}
	return nil
}

// Lock acquires the lock serializing changes to the versions of keyID in
// backend for tenant and returns the function that releases it. A rotation
// holds it from reading the record until the new version is recorded, so
// two rotations of one key never create the same version.
func (s *Store) Lock(tenant, backend, keyID string) (unlock func()) {
	k := TenantSegment(tenant) + "/" + backend + "/" + keyID
	actual, _ := s.locks.LoadOrStore(k, &sync.Mutex{})
	mu := actual.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
