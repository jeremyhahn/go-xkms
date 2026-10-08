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
// Each record is one go-qrdb DAO entity (Record) in the DatabaseName database.
// xkmsd builds ONE store for every tenant (pkg/server); it is not behind a
// tenant barrier, so tenants are separated only by the record name, and the
// caller must supply a tenant it has derived from the authenticated identity,
// never one taken from a request. The values are opaque: the module serialises
// its own PersistentTokenState / PersistentObject records and this store keeps
// them verbatim, so the server never has to track the module's record schema.
package pkcs11state

import (
	"bytes"
	"context"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

const (
	// DatabaseName is the go-qrdb database module records live in. A
	// composition root opens it on the datastore before calling NewStore.
	DatabaseName = "pkcs11state"

	// entityType is the DAO entity type of a module record.
	entityType = "pkcs11_state_records"

	// listPageSize is how many records List reads per page.
	listPageSize = 256
)

// Store persists opaque PKCS#11 module state records, namespaced by tenant and
// token, through a go-qrdb DAO.
type Store struct {
	records qrdbsdk.GenericDAO[*Record]
}

// NewStore returns a Store whose DAO daos builds over DatabaseName. The store
// does not scope or encrypt per tenant, so isolation between tenants rests on
// the caller passing the authenticated tenant to every method.
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
func newRecordDAO(daos *qrdbsdk.DAOFactory) (qrdbsdk.GenericDAO[*Record], error) {
	return dao.New(daos, DatabaseName, entityType, newRecord,
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Name")))
}

// scopeName returns the name of a (tenant, token) namespace. An empty tenant
// is the system scope and is stored under the system tenant's own ID, the
// scope the service already treats it as.
func scopeName(tenantID, token string) string {
	if tenantID == "" {
		tenantID = qrdbsdk.SystemTenantID
	}
	return tenantID + "/" + token + "/"
}

// newRecordFor returns the record of key in the (tenant, token) namespace.
func newRecordFor(tenantID, token, key string, value []byte) *Record {
	scope := scopeName(tenantID, token)
	return &Record{Name: scope + key, Scope: scope, Key: key, Value: value}
}

// load returns the stored record named name; found reports whether one
// exists.
func (s *Store) load(ctx context.Context, name string) (rec *Record, found bool, err error) {
	rec, err = s.records.GetByNaturalKey(ctx, name)
	if qrdbsdk.IsDAONotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return rec, true, nil
}

// Put stores a record, overwriting any existing value.
func (s *Store) Put(ctx context.Context, tenantID, token, key string, value []byte) error {
	rec := newRecordFor(tenantID, token, key, value)
	if err := s.records.Save(ctx, rec); err != nil {
		return &StoreError{Op: "put", Key: rec.Name, Err: err}
	}
	return nil
}

// PutIfAbsent atomically stores a record only if the key does not already
// exist, returning whether the write happened.
func (s *Store) PutIfAbsent(ctx context.Context, tenantID, token, key string, value []byte) (bool, error) {
	rec := newRecordFor(tenantID, token, key, value)
	stored, err := s.records.SaveIfAbsent(ctx, rec)
	if err != nil {
		return false, &StoreError{Op: "put-if-absent", Key: rec.Name, Err: err}
	}
	return stored, nil
}

// CompareAndSwap atomically stores newValue at the record only while its
// current value equals expected, returning the current value when it does not
// swap. It follows storage.CompareAndSwapper's contract: an absent record
// refuses whatever expected is, and a nil expected matches a stored empty
// value only. It backs the multi-client lockout-counter update: several
// clients sharing one remote token increment the same failed-attempt counter,
// and only a value-CAS keeps those read-modify-write updates from clobbering
// each other. The swap is the DAO's CompareAndSwap against the record just
// read, one guarded store operation, so a concurrent writer between the read
// and the write makes it refuse rather than be overwritten.
func (s *Store) CompareAndSwap(ctx context.Context, tenantID, token, key string, expected, newValue []byte) (swapped bool, current []byte, err error) {
	next := newRecordFor(tenantID, token, key, newValue)
	stored, found, err := s.load(ctx, next.Name)
	if err != nil {
		return false, nil, &StoreError{Op: "compare-and-swap", Key: next.Name, Err: err}
	}
	if !found {
		return false, nil, nil
	}
	if !bytes.Equal(stored.Value, expected) {
		return false, stored.Value, nil
	}
	next.ID = stored.ID
	swapped, err = s.records.CompareAndSwap(ctx, stored, next)
	if err != nil {
		return false, nil, &StoreError{Op: "compare-and-swap", Key: next.Name, Err: err}
	}
	if swapped {
		return true, nil, nil
	}
	// A concurrent writer changed the record after it was read: report what
	// is there now so the caller can recompute against it.
	stored, found, err = s.load(ctx, next.Name)
	if err != nil {
		return false, nil, &StoreError{Op: "compare-and-swap", Key: next.Name, Err: err}
	}
	if !found {
		return false, nil, nil
	}
	return false, stored.Value, nil
}

// CompareAndDelete atomically removes the record only while its current value
// equals expected, reporting whether this call removed it. An absent record or
// a different value is an ordinary refusal (false, nil), not an error, exactly
// as storage.CompareAndDeleter specifies; a nil expected matches a stored
// empty value only. It is the guarded release that pairs with PutIfAbsent's
// guarded create for clients sharing one remote token. The delete is the
// DAO's DeleteIfMatch against the record just read, one guarded store
// operation.
func (s *Store) CompareAndDelete(ctx context.Context, tenantID, token, key string, expected []byte) (deleted bool, err error) {
	name := newRecordFor(tenantID, token, key, nil).Name
	stored, found, err := s.load(ctx, name)
	if err != nil {
		return false, &StoreError{Op: "compare-and-delete", Key: name, Err: err}
	}
	if !found || !bytes.Equal(stored.Value, expected) {
		return false, nil
	}
	deleted, err = s.records.DeleteIfMatch(ctx, stored)
	if err != nil {
		return false, &StoreError{Op: "compare-and-delete", Key: name, Err: err}
	}
	return deleted, nil
}

// Get retrieves a record. found distinguishes an absent key from a present
// empty value, which the module relies on to tell "no persisted state" from
// "state that is legitimately empty".
func (s *Store) Get(ctx context.Context, tenantID, token, key string) (value []byte, found bool, err error) {
	name := newRecordFor(tenantID, token, key, nil).Name
	stored, found, err := s.load(ctx, name)
	if err != nil {
		return nil, false, &StoreError{Op: "get", Key: name, Err: err}
	}
	if !found {
		return nil, false, nil
	}
	return stored.Value, true, nil
}

// Delete removes a record. A missing key is not an error, so a caller can
// delete idempotently.
func (s *Store) Delete(ctx context.Context, tenantID, token, key string) error {
	name := newRecordFor(tenantID, token, key, nil).Name
	stored, found, err := s.load(ctx, name)
	if err == nil && found {
		err = s.records.Delete(ctx, stored)
	}
	if err != nil {
		return &StoreError{Op: "delete", Key: name, Err: err}
	}
	return nil
}

// List returns the namespace-relative keys under a prefix within a token's
// namespace. An empty prefix lists every key for the token.
func (s *Store) List(ctx context.Context, tenantID, token, prefix string) ([]string, error) {
	scope := scopeName(tenantID, token)
	keys := []string{}
	query := qrdbsdk.PageQuery{Page: 1, PageSize: listPageSize, SortOrder: qrdbsdk.DAOSortAscending}
	err := s.records.ForEachPage(ctx, query, func(page qrdbsdk.PageResult[*Record]) error {
		for _, rec := range page.Entities {
			if rec.Scope == scope && strings.HasPrefix(rec.Key, prefix) {
				keys = append(keys, rec.Key)
			}
		}
		return nil
	})
	if err != nil {
		return nil, &StoreError{Op: "list", Key: scope, Err: err}
	}
	return keys, nil
}
