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

package authenticator

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

const (
	// daoRPPolicyEntityType is the DAO entity type namespace for RP policies.
	daoRPPolicyEntityType = "fido2_rp_policies"
)

// DAORPPolicyStore implements RPPolicyStore using a go-qrdb GenericDAO
// backed by a kvstore.KVStore. Each RP policy is stored as an RPPolicyEntity
// with RPID as a unique index for deterministic deduplication.
//
// All methods are safe for concurrent use. Reads are lock-free via the
// atomic closed flag and the DAO's internal concurrency guarantees. Writes
// additionally serialize on writeMu: the DAO's SaveWithCondition evaluates
// its condition with a read followed by a write, so two in-process writers
// could both observe the same version and both save. The mutex makes this
// store's own read-modify-write atomic; the version condition remains to
// detect writers going through a different store instance over the same
// records.
type DAORPPolicyStore struct {
	closed  atomic.Bool
	writeMu sync.Mutex
	dao     qrdbsdk.GenericDAO[*RPPolicyEntity]
	idGen   *qrdbsdk.FieldHashGenerator
}

// Compile-time interface compliance check.
var _ RPPolicyStore = (*DAORPPolicyStore)(nil)

// NewDAORPPolicyStore creates a new DAORPPolicyStore using the given
// kvstore.KVStore. The DAO uses RPID as the deterministic entity ID field.
func NewDAORPPolicyStore(kvStore qrdbsdk.KVStore) (*DAORPPolicyStore, error) {
	if kvStore == nil {
		return nil, ErrNilStorage
	}

	idGen := qrdbsdk.NewFieldHashGenerator("RPID")

	policyDAO, err := qrdbsdk.NewDAO[*RPPolicyEntity](
		kvStore,
		daoRPPolicyEntityType,
		func() *RPPolicyEntity { return &RPPolicyEntity{} },
		qrdbsdk.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &DAORPPolicyStore{
		dao:   policyDAO,
		idGen: idGen,
	}, nil
}

// computeID returns the deterministic entity ID for an RPID.
func (s *DAORPPolicyStore) computeID(rpID string) uint64 {
	entity := &RPPolicyEntity{RPID: rpID}
	return s.idGen.NextID(entity)
}

// rpPolicyCASMaxAttempts bounds the optimistic-concurrency retry loop in
// saveWithVersionCheck. Each attempt re-reads the stored record, so an
// exhausted loop means a writer kept racing this one; the caller receives
// ErrRPPolicyConflict rather than a silent lost update.
const rpPolicyCASMaxAttempts = 5

// SetPolicy stores a complete per-RP policy, replacing any stored record
// wholesale (upsert behavior). Partial updates must go through UpdatePolicy.
// Returns ErrRPPolicyNil if the policy is nil.
// Returns ErrRPPolicyInvalidRPID if the RPID is empty.
// Returns ErrRPPolicyStoreClosed if the store has been closed.
// Returns ErrRPPolicyConflict if concurrent writers won every bounded retry.
func (s *DAORPPolicyStore) SetPolicy(policy *RPPolicy) error {
	if s.closed.Load() {
		return ErrRPPolicyStoreClosed
	}

	if policy == nil {
		return ErrRPPolicyNil
	}

	if err := policy.Validate(); err != nil {
		return err
	}

	return s.saveWithVersionCheck(policy.RPID, func(*RPPolicy) *RPPolicy {
		return policy
	})
}

// UpdatePolicy applies a partial update onto the stored policy for
// update.RPID, creating the policy if none exists. Fields the update does not
// carry keep their stored values, so a caller changing one setting cannot
// silently clear the SO's other overrides or lift an RP block.
// Returns ErrRPPolicyUpdateNil if the update is nil.
// Returns ErrRPPolicyInvalidRPID if the RPID is empty.
// Returns ErrRPPolicyStoreClosed if the store has been closed.
// Returns ErrRPPolicyConflict if concurrent writers won every bounded retry.
func (s *DAORPPolicyStore) UpdatePolicy(update *RPPolicyUpdate) error {
	if s.closed.Load() {
		return ErrRPPolicyStoreClosed
	}

	if err := update.Validate(); err != nil {
		return err
	}

	return s.saveWithVersionCheck(update.RPID, func(existing *RPPolicy) *RPPolicy {
		return applyRPPolicyUpdate(existing, update)
	})
}

// saveWithVersionCheck performs a compare-and-swap write of the policy for
// rpID. Each attempt reads the stored entity, derives the policy to store via
// mutate (which receives nil when no policy exists yet), and saves it
// conditioned on the stored version still being the one observed by the read.
// A failed condition means a concurrent writer landed in between; the attempt
// is retried against the fresh record up to rpPolicyCASMaxAttempts times, and
// ErrRPPolicyConflict is returned when the retries are exhausted — never a
// silent success over a lost update (#326).
//
// writeMu serializes in-process writers because SaveWithCondition is itself a
// read followed by a write (see the struct doc); the version condition guards
// against writers using a different store instance over the same records.
func (s *DAORPPolicyStore) saveWithVersionCheck(rpID string, mutate func(existing *RPPolicy) *RPPolicy) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	entityID := s.computeID(rpID)

	for attempt := 0; attempt < rpPolicyCASMaxAttempts; attempt++ {
		var observedVersion int64
		var createdAt time.Time
		var current *RPPolicy

		existing, err := s.dao.Get(context.Background(), entityID)
		switch {
		case err == nil && existing != nil:
			observedVersion = existing.GetVersion()
			createdAt = existing.CreatedAt
			current = entityToPolicy(existing)
		case err != nil && !qrdbsdk.IsDAONotFound(err):
			return wrapStorageError(err)
		}

		now := time.Now().UTC()
		if createdAt.IsZero() {
			createdAt = now
		}

		entity := policyToEntity(mutate(current))
		entity.CreatedAt = createdAt
		entity.UpdatedAt = now
		entity.SetEntityID(entityID)
		entity.SetVersion(observedVersion + 1)

		err = s.dao.SaveWithCondition(context.Background(), entity, qrdbsdk.Condition{
			Target:   qrdbsdk.ConditionVersion,
			Operator: qrdbsdk.OpEqual,
			Value:    observedVersion,
		})
		if err == nil {
			return nil
		}
		if !qrdbsdk.IsDAOConditionFailed(err) {
			return wrapStorageError(err)
		}
	}

	return ErrRPPolicyConflict
}

// GetPolicy retrieves the policy for a specific RPID.
// Returns ErrRPPolicyNotFound if no policy exists for the RPID.
// Returns ErrRPPolicyInvalidRPID if the RPID is empty.
// Returns ErrRPPolicyStoreClosed if the store has been closed.
func (s *DAORPPolicyStore) GetPolicy(rpID string) (*RPPolicy, error) {
	if s.closed.Load() {
		return nil, ErrRPPolicyStoreClosed
	}

	if rpID == "" {
		return nil, ErrRPPolicyInvalidRPID
	}

	entityID := s.computeID(rpID)

	entity, err := s.dao.Get(context.Background(), entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, ErrRPPolicyNotFound
		}
		return nil, wrapStorageError(err)
	}

	return entityToPolicy(entity), nil
}

// DeletePolicy removes the policy for a specific RPID.
// Returns ErrRPPolicyNotFound if no policy exists for the RPID.
// Returns ErrRPPolicyInvalidRPID if the RPID is empty.
// Returns ErrRPPolicyStoreClosed if the store has been closed.
func (s *DAORPPolicyStore) DeletePolicy(rpID string) error {
	if s.closed.Load() {
		return ErrRPPolicyStoreClosed
	}

	if rpID == "" {
		return ErrRPPolicyInvalidRPID
	}

	entityID := s.computeID(rpID)

	// Verify existence before delete.
	_, err := s.dao.Get(context.Background(), entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return ErrRPPolicyNotFound
		}
		return wrapStorageError(err)
	}

	stub := &RPPolicyEntity{}
	stub.SetEntityID(entityID)
	if err := s.dao.Delete(context.Background(), stub); err != nil {
		return wrapStorageError(err)
	}

	return nil
}

// ListPolicies returns all stored RP policies sorted by RPID.
// Returns ErrRPPolicyStoreClosed if the store has been closed.
func (s *DAORPPolicyStore) ListPolicies() ([]*RPPolicy, error) {
	if s.closed.Load() {
		return nil, ErrRPPolicyStoreClosed
	}

	var entities []*RPPolicyEntity
	err := s.dao.ForEachPage(context.Background(), qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*RPPolicyEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	if err != nil {
		return nil, wrapStorageError(err)
	}

	policies := make([]*RPPolicy, 0, len(entities))
	for _, entity := range entities {
		policies = append(policies, entityToPolicy(entity))
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].RPID < policies[j].RPID
	})

	return policies, nil
}

// Page retrieves a paginated set of RP policy entities.
func (s *DAORPPolicyStore) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*RPPolicyEntity], error) {
	if s.closed.Load() {
		return qrdbsdk.PageResult[*RPPolicyEntity]{}, ErrRPPolicyStoreClosed
	}
	return s.dao.Page(ctx, query)
}

// Close marks the store as closed. The underlying DAO lifecycle is managed
// externally. Close is idempotent and may be called multiple times safely.
func (s *DAORPPolicyStore) Close() error {
	s.closed.Store(true)
	return nil
}

// policyToEntity converts an RPPolicy to an RPPolicyEntity.
func policyToEntity(policy *RPPolicy) *RPPolicyEntity {
	return &RPPolicyEntity{
		RPID:                policy.RPID,
		UVOverride:          policy.UVOverride,
		UPOverride:          policy.UPOverride,
		AttestationOverride: policy.AttestationOverride,
		Enterprise:          policy.Enterprise,
		Blocked:             policy.Blocked,
	}
}

// entityToPolicy converts an RPPolicyEntity back to an RPPolicy.
func entityToPolicy(entity *RPPolicyEntity) *RPPolicy {
	return &RPPolicy{
		RPID:                entity.RPID,
		UVOverride:          entity.UVOverride,
		UPOverride:          entity.UPOverride,
		AttestationOverride: entity.AttestationOverride,
		Enterprise:          entity.Enterprise,
		Blocked:             entity.Blocked,
	}
}
