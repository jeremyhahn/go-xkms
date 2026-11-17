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
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

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

	// now is the store's clock (SetClock); nil means time.Now.
	now func() time.Time
}

// SetClock sets the clock the store dates and expires rotation claims by
// (ClaimTTL); nil restores time.Now. It is for tests that model a claim
// expiring, or processes whose clocks differ, and must be set before the
// store is used.
func (s *Store) SetClock(now func() time.Time) {
	s.now = now
}

// clock returns the store's current time.
func (s *Store) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
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
	// The record is swapped in, not saved over, so a rotation's claim on the
	// stored record survives the write.
	for {
		current, err := s.records.GetByNaturalKey(ctx, name)
		if qrdbsdk.IsDAONotFound(err) {
			stored, err := s.records.SaveIfAbsent(ctx, &Entity{Name: name, Record: *rec})
			if err != nil {
				return &StoreError{Op: "put", Key: name, Err: err}
			}
			if stored {
				return nil
			}
			continue
		}
		if err != nil {
			return &StoreError{Op: "put", Key: name, Err: err}
		}
		swapped, err := s.records.CompareAndSwap(ctx, current,
			&Entity{ID: current.ID, Name: name, Record: *rec, Claim: current.Claim})
		if err != nil {
			return &StoreError{Op: "put", Key: name, Err: err}
		}
		if swapped {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return &StoreError{Op: "put", Key: name, Err: err}
		}
	}
}

// ClaimTTL is how long a rotation's claim (Store.Claim) excludes every other
// rotation of the key. A claim older than this was left by a rotation that
// died, and another rotation may take it over; the old holder then can no
// longer record its version (Store.CompareAndPut is fenced by the claim).
const ClaimTTL = 10 * time.Minute

// Claim claims the record of keyID in backend for tenant for one rotation,
// while the stored record is still expected, the record the caller read (a
// nil expected means the caller read no stored record). Only the holder of
// the returned token creates or removes the backend key under the next
// version's name, and records that version with CompareAndPut; it drops the
// claim with Release when it does not record it. A changed record, or a
// claim another rotation holds and has not let expire (ClaimTTL), is a
// *VersionConflictError (matching ErrVersionConflict).
func (s *Store) Claim(ctx context.Context, tenant, backend, keyID string, expected *Record) (token string, err error) {
	name, err := recordName(tenant, backend, keyID)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", &StoreError{Op: "claim", Key: name, Err: err}
	}
	claim := &rotationClaim{Token: hex.EncodeToString(nonce), Expires: s.clock().UTC().Add(ClaimTTL)}
	conflict := &VersionConflictError{KeyID: keyID, Backend: backend}
	if expected == nil {
		stored, err := s.records.SaveIfAbsent(ctx, &Entity{Name: name, Record: *Implicit(keyID, backend), Claim: claim})
		if err != nil {
			return "", &StoreError{Op: "claim", Key: name, Err: err}
		}
		if !stored {
			return "", conflict
		}
		return claim.Token, nil
	}
	current, err := s.records.GetByNaturalKey(ctx, name)
	if qrdbsdk.IsDAONotFound(err) {
		return "", conflict
	}
	if err != nil {
		return "", &StoreError{Op: "get", Key: name, Err: err}
	}
	if current.Claim != nil && s.clock().Before(current.Claim.Expires) {
		return "", conflict
	}
	// The swap compares the stored record against expected itself, and
	// against the expired claim, if any, it takes over.
	swapped, err := s.records.CompareAndSwap(ctx,
		&Entity{ID: current.ID, Name: name, Record: *expected, Claim: current.Claim},
		&Entity{ID: current.ID, Name: name, Record: *expected, Claim: claim})
	if err != nil {
		return "", &StoreError{Op: "claim", Key: name, Err: err}
	}
	if !swapped {
		return "", conflict
	}
	return claim.Token, nil
}

// CompareAndPut stores next as the record of its key for tenant only while
// the stored record is still expected, the record the caller read, and is
// claimed by token; it drops the claim. A nil expected means the caller read
// no stored record. An empty token means the caller holds no claim: next is
// then stored only while the record is unclaimed (and, for a nil expected,
// while none is stored). The comparison and the write are one guarded store
// operation, so a stale or concurrent writer, or a rotation whose claim was
// taken over, gets a *VersionConflictError (matching ErrVersionConflict) and
// the stored record is left unchanged.
func (s *Store) CompareAndPut(ctx context.Context, tenant, token string, expected, next *Record) error {
	if next == nil {
		return ErrNilRecord
	}
	name, err := recordName(tenant, next.Backend, next.KeyID)
	if err != nil {
		return err
	}
	conflict := &VersionConflictError{KeyID: next.KeyID, Backend: next.Backend}
	if expected == nil && token == "" {
		stored, err := s.records.SaveIfAbsent(ctx, &Entity{Name: name, Record: *next})
		if err != nil {
			return &StoreError{Op: "put", Key: name, Err: err}
		}
		if !stored {
			return conflict
		}
		return nil
	}
	if expected == nil {
		// Claim stored the implicit record for a key that had none.
		expected = Implicit(next.KeyID, next.Backend)
	}
	// The read only finds the record's ID and the claim held; the swap
	// compares the stored bytes against expected and that claim itself.
	current, err := s.records.GetByNaturalKey(ctx, name)
	if qrdbsdk.IsDAONotFound(err) {
		return conflict
	}
	if err != nil {
		return &StoreError{Op: "get", Key: name, Err: err}
	}
	var claim *rotationClaim
	if token != "" {
		if current.Claim == nil || current.Claim.Token != token {
			return conflict
		}
		claim = current.Claim
	}
	swapped, err := s.records.CompareAndSwap(ctx,
		&Entity{ID: current.ID, Name: name, Record: *expected, Claim: claim},
		&Entity{ID: current.ID, Name: name, Record: *next})
	if err != nil {
		return &StoreError{Op: "put", Key: name, Err: err}
	}
	if !swapped {
		return conflict
	}
	return nil
}

// Release drops the claim token holds on the record of keyID in backend for
// tenant, leaving the record as it is. A record no longer claimed by token
// is not an error.
func (s *Store) Release(ctx context.Context, tenant, backend, keyID, token string) error {
	name, err := recordName(tenant, backend, keyID)
	if err != nil {
		return err
	}
	for {
		current, err := s.records.GetByNaturalKey(ctx, name)
		if qrdbsdk.IsDAONotFound(err) {
			return nil
		}
		if err != nil {
			return &StoreError{Op: "get", Key: name, Err: err}
		}
		if current.Claim == nil || current.Claim.Token != token {
			return nil
		}
		swapped, err := s.records.CompareAndSwap(ctx, current,
			&Entity{ID: current.ID, Name: name, Record: current.Record})
		if err != nil {
			return &StoreError{Op: "release", Key: name, Err: err}
		}
		if swapped {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return &StoreError{Op: "release", Key: name, Err: err}
		}
	}
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
