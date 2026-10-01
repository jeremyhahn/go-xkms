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

package oidc

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ErrDAOCreation is returned when the DAO layer fails to initialize.
type ErrDAOCreation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrDAOCreation) Error() string {
	return fmt.Sprintf("oidc: failed to create DAO: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrDAOCreation) Unwrap() error {
	return e.Cause
}

// DAOStore implements TokenStore using a go-qrdb GenericDAO backed by
// a kvstore.KVStore. Each OIDC token entry is stored as an OIDCTokenEntity
// with a deterministic ID derived from the normalized issuer URL.
type DAOStore struct {
	closed atomic.Bool
	dao    qrdbsdk.GenericDAO[*OIDCTokenEntity]
	idGen  *qrdbsdk.FieldHashGenerator
}

// Compile-time interface compliance check.
var _ TokenStore = (*DAOStore)(nil)

// NewDAOStore creates a new DAOStore using the given kvstore.KVStore.
// The entity type namespace is "oidc_tokens".
func NewDAOStore(kvStore qrdbsdk.KVStore) (*DAOStore, error) {
	if kvStore == nil {
		return nil, ErrNilBackend
	}

	idGen := qrdbsdk.NewFieldHashGenerator("Issuer")

	tokenDAO, err := qrdbsdk.NewDAO[*OIDCTokenEntity](
		kvStore,
		"oidc_tokens",
		func() *OIDCTokenEntity { return &OIDCTokenEntity{} },
		qrdbsdk.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &DAOStore{
		dao:   tokenDAO,
		idGen: idGen,
	}, nil
}

// computeID returns the deterministic entity ID for a normalized issuer.
func (s *DAOStore) computeID(issuer string) uint64 {
	entity := &OIDCTokenEntity{Issuer: issuer}
	return s.idGen.NextID(entity)
}

// Save stores tokens for the given issuer. If tokens for the same
// issuer already exist, they are overwritten (upsert behavior).
func (s *DAOStore) Save(issuer string, tokens *TokenResponse) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if issuer == "" {
		return ErrInvalidIssuer
	}

	if tokens == nil {
		return ErrTokenNotFound
	}

	normalized := normalizeIssuer(issuer)
	entity := OIDCTokenEntityFromResponse(normalized, tokens)
	entity.SetEntityID(s.computeID(normalized))

	return s.dao.Save(context.Background(), entity)
}

// Load retrieves tokens for the given issuer.
func (s *DAOStore) Load(issuer string) (*TokenResponse, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	if issuer == "" {
		return nil, ErrInvalidIssuer
	}

	normalized := normalizeIssuer(issuer)
	entityID := s.computeID(normalized)

	entity, err := s.dao.Get(context.Background(), entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	return entity.ToTokenResponse(), nil
}

// Delete removes tokens for the given issuer.
func (s *DAOStore) Delete(issuer string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if issuer == "" {
		return ErrInvalidIssuer
	}

	normalized := normalizeIssuer(issuer)
	entityID := s.computeID(normalized)

	// Verify the entry exists before deleting.
	_, err := s.dao.Get(context.Background(), entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return ErrTokenNotFound
		}
		return err
	}

	stub := &OIDCTokenEntity{}
	stub.SetEntityID(entityID)
	return s.dao.Delete(context.Background(), stub)
}

// List returns all issuers with stored tokens, sorted alphabetically.
func (s *DAOStore) List() ([]string, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	var entities []*OIDCTokenEntity
	err := s.dao.ForEachPage(context.Background(), qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*OIDCTokenEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	issuers := make([]string, 0, len(entities))
	for _, entity := range entities {
		issuers = append(issuers, entity.Issuer)
	}

	sort.Strings(issuers)
	return issuers, nil
}

// Page retrieves a paginated set of OIDC token entities.
func (s *DAOStore) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*OIDCTokenEntity], error) {
	if s.closed.Load() {
		return qrdbsdk.PageResult[*OIDCTokenEntity]{}, ErrStoreClosed
	}
	return s.dao.Page(ctx, query)
}

// Close marks the store as closed. The underlying DAO does not need
// explicit closing since its lifecycle is managed by the kvstore.
func (s *DAOStore) Close() error {
	s.closed.Store(true)
	return nil
}
