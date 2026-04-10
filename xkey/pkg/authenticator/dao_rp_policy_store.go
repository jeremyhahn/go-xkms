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
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
)

const (
	// daoRPPolicyEntityType is the DAO entity type namespace for RP policies.
	daoRPPolicyEntityType = "fido2_rp_policies"
)

// DAORPPolicyStore implements RPPolicyStore using a go-qrdb GenericDAO
// backed by a kvstore.KVStore. Each RP policy is stored as an RPPolicyEntity
// with RPID as a unique index for deterministic deduplication.
//
// All methods are safe for concurrent use via the atomic closed flag and
// the DAO's internal concurrency guarantees.
type DAORPPolicyStore struct {
	closed atomic.Bool
	dao    dao.GenericDAO[*RPPolicyEntity]
	idGen  *dao.FieldHashGenerator
}

// Compile-time interface compliance check.
var _ RPPolicyStore = (*DAORPPolicyStore)(nil)

// NewDAORPPolicyStore creates a new DAORPPolicyStore using the given
// kvstore.KVStore. The DAO uses RPID as the deterministic entity ID field.
func NewDAORPPolicyStore(kvStore kvstore.KVStore) (*DAORPPolicyStore, error) {
	if kvStore == nil {
		return nil, ErrNilStorage
	}

	idGen := dao.NewFieldHashGenerator("RPID")

	policyDAO, err := dao.New[*RPPolicyEntity](
		kvStore,
		daoRPPolicyEntityType,
		func() *RPPolicyEntity { return &RPPolicyEntity{} },
		dao.WithIDGenerator(idGen),
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

// SetPolicy creates or updates a per-RP policy (upsert behavior).
// Returns ErrRPPolicyNil if the policy is nil.
// Returns ErrRPPolicyInvalidRPID if the RPID is empty.
// Returns ErrRPPolicyStoreClosed if the store has been closed.
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

	now := time.Now().UTC()
	entity := policyToEntity(policy)

	entityID := s.computeID(policy.RPID)

	// Check if existing entity exists to preserve CreatedAt.
	existing, err := s.dao.Get(context.Background(), entityID)
	if err == nil && existing != nil {
		entity.CreatedAt = existing.CreatedAt
	} else {
		entity.CreatedAt = now
	}

	entity.UpdatedAt = now
	entity.SetEntityID(entityID)

	if err := s.dao.Save(context.Background(), entity); err != nil {
		return wrapStorageError(err)
	}

	return nil
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
		if dao.IsNotFound(err) {
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
		if dao.IsNotFound(err) {
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
	err := s.dao.ForEachPage(context.Background(), dao.PageQuery{Page: 1, PageSize: 1000}, func(result dao.PageResult[*RPPolicyEntity]) error {
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
func (s *DAORPPolicyStore) Page(ctx context.Context, query dao.PageQuery) (dao.PageResult[*RPPolicyEntity], error) {
	if s.closed.Load() {
		return dao.PageResult[*RPPolicyEntity]{}, ErrRPPolicyStoreClosed
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
