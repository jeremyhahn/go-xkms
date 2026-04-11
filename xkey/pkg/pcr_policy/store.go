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

package pcrpolicy

import (
	"context"
	"sort"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// validBanks is the set of supported PCR hash algorithm banks.
var validBanks = map[string]struct{}{
	"SHA1":   {},
	"SHA256": {},
	"SHA384": {},
}

// PolicyStore defines the interface for PCR policy persistence.
type PolicyStore interface {
	Create(ctx context.Context, name, bank string, pcrs map[uint][]byte) (*PCRPolicyEntity, error)
	Get(ctx context.Context, name string) (*PCRPolicyEntity, error)
	List(ctx context.Context) ([]*PCRPolicyEntity, error)
	Page(ctx context.Context, q qrdbsdk.PageQuery) (qrdbsdk.PageResult[*PCRPolicyEntity], error)
	Delete(ctx context.Context, name string) error
	SetAutoUnseal(ctx context.Context, name string) error
	ClearAutoUnseal(ctx context.Context) error
	GetAutoUnsealPolicy(ctx context.Context) (*PCRPolicyEntity, error)
	Close() error
}

// DAOStore implements PolicyStore using a go-qrdb GenericDAO backed by
// a kvstore.KVStore. Each policy is stored as a PCRPolicyEntity with
// a deterministic ID derived from the policy name.
type DAOStore struct {
	closed atomic.Bool
	dao    qrdbsdk.GenericDAO[*PCRPolicyEntity]
	idGen  *qrdbsdk.FieldHashGenerator
}

// Compile-time interface compliance check.
var _ PolicyStore = (*DAOStore)(nil)

// NewDAOStore creates a new DAOStore using the given kvstore.KVStore.
// The entity type namespace is "pcr_policies".
func NewDAOStore(kvStore qrdbsdk.KVStore) (*DAOStore, error) {
	if kvStore == nil {
		return nil, ErrNilKVStore
	}

	idGen := qrdbsdk.NewFieldHashGenerator("Name")

	policyDAO, err := qrdbsdk.NewDAO[*PCRPolicyEntity](
		kvStore,
		"pcr_policies",
		func() *PCRPolicyEntity { return &PCRPolicyEntity{} },
		qrdbsdk.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &DAOStore{
		dao:   policyDAO,
		idGen: idGen,
	}, nil
}

// computeID returns the deterministic entity ID for a policy name.
func (s *DAOStore) computeID(name string) uint64 {
	entity := &PCRPolicyEntity{Name: name}
	return s.idGen.NextID(entity)
}

// Create validates the inputs, builds a PCRPolicyEntity, and persists it.
// If a policy with the same name already exists, the DAO will overwrite it
// (upsert behavior).
func (s *DAOStore) Create(ctx context.Context, name, bank string, pcrs map[uint][]byte) (*PCRPolicyEntity, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	if name == "" {
		return nil, ErrInvalidName
	}
	if _, ok := validBanks[bank]; !ok {
		return nil, ErrInvalidBank
	}
	if len(pcrs) == 0 {
		return nil, ErrNoPCRs
	}

	now := time.Now().UTC()
	entity := &PCRPolicyEntity{
		Name:      name,
		Bank:      bank,
		PCRs:      pcrs,
		CreatedAt: now,
		UpdatedAt: now,
	}
	entity.SetEntityID(s.computeID(name))

	if err := s.dao.Save(ctx, entity); err != nil {
		return nil, err
	}

	return entity, nil
}

// Get retrieves a policy by its unique name.
func (s *DAOStore) Get(ctx context.Context, name string) (*PCRPolicyEntity, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	if name == "" {
		return nil, ErrInvalidName
	}

	entityID := s.computeID(name)
	entity, err := s.dao.Get(ctx, entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, ErrPolicyNotFound
		}
		return nil, err
	}

	return entity, nil
}

// List returns all stored policies sorted by name.
func (s *DAOStore) List(ctx context.Context) ([]*PCRPolicyEntity, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	var entities []*PCRPolicyEntity
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*PCRPolicyEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(entities, func(i, j int) bool {
		return entities[i].Name < entities[j].Name
	})

	return entities, nil
}

// Page retrieves a paginated set of policy entities.
func (s *DAOStore) Page(ctx context.Context, q qrdbsdk.PageQuery) (qrdbsdk.PageResult[*PCRPolicyEntity], error) {
	if s.closed.Load() {
		return qrdbsdk.PageResult[*PCRPolicyEntity]{}, ErrStoreClosed
	}
	return s.dao.Page(ctx, q)
}

// Delete removes a policy by name. It refuses to delete a policy that is
// currently the active auto-unseal policy.
func (s *DAOStore) Delete(ctx context.Context, name string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if name == "" {
		return ErrInvalidName
	}

	entityID := s.computeID(name)

	entity, err := s.dao.Get(ctx, entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return ErrPolicyNotFound
		}
		return err
	}

	if entity.AutoUnseal {
		return ErrDeleteAutoUnseal
	}

	stub := &PCRPolicyEntity{}
	stub.SetEntityID(entityID)
	return s.dao.Delete(ctx, stub)
}

// SetAutoUnseal designates the named policy as the auto-unseal policy.
// Any previously designated auto-unseal policy is cleared first.
func (s *DAOStore) SetAutoUnseal(ctx context.Context, name string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if name == "" {
		return ErrInvalidName
	}

	// Verify the target policy exists.
	targetID := s.computeID(name)
	target, err := s.dao.Get(ctx, targetID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return ErrPolicyNotFound
		}
		return err
	}

	// Scan all policies and clear any existing auto-unseal flag.
	if err := s.clearAutoUnsealExcept(ctx, targetID); err != nil {
		return err
	}

	// Set auto-unseal on the target.
	target.AutoUnseal = true
	target.UpdatedAt = time.Now().UTC()
	return s.dao.Save(ctx, target)
}

// ClearAutoUnseal removes the auto-unseal designation from whichever
// policy currently holds it. If no policy is designated, this is a no-op.
func (s *DAOStore) ClearAutoUnseal(ctx context.Context) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	// Clear all auto-unseal flags (passing 0 means exclude nothing).
	return s.clearAutoUnsealExcept(ctx, 0)
}

// clearAutoUnsealExcept clears the AutoUnseal flag on every policy
// whose entity ID is not equal to exceptID. Pass 0 to clear all.
func (s *DAOStore) clearAutoUnsealExcept(ctx context.Context, exceptID uint64) error {
	var toUpdate []*PCRPolicyEntity
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*PCRPolicyEntity]) error {
		for _, e := range result.Entities {
			if e.AutoUnseal && e.EntityID() != exceptID {
				e.AutoUnseal = false
				e.UpdatedAt = time.Now().UTC()
				toUpdate = append(toUpdate, e)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	for _, e := range toUpdate {
		if err := s.dao.Save(ctx, e); err != nil {
			return err
		}
	}

	return nil
}

// GetAutoUnsealPolicy returns the policy currently designated for
// auto-unseal. Returns ErrPolicyNotFound if no policy is designated.
func (s *DAOStore) GetAutoUnsealPolicy(ctx context.Context) (*PCRPolicyEntity, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	var found *PCRPolicyEntity
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*PCRPolicyEntity]) error {
		for _, e := range result.Entities {
			if e.AutoUnseal {
				found = e
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if found == nil {
		return nil, ErrPolicyNotFound
	}

	return found, nil
}

// Close marks the store as closed. The underlying DAO does not need
// explicit closing since its lifecycle is managed by the kvstore.
func (s *DAOStore) Close() error {
	s.closed.Store(true)
	return nil
}
