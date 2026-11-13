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

package appraisal

import (
	"context"
	"sort"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

const (
	// DatabaseName is the go-qrdb database the Verifier's endorsements and
	// reference values live in. A composition root opens it on the
	// datastore before calling NewStore.
	DatabaseName = "attestation"

	// endorsementFeature and referenceValuesFeature are the pkg/scope feature
	// segments the two record kinds are keyed under, per tenant.
	endorsementFeature     = "attestation-endorsements"
	referenceValuesFeature = "attestation-reference-values"

	// signingKeyFeature is the pkg/scope feature segment a tenant's
	// per-repository signing-key bindings are keyed under.
	signingKeyFeature = "attestation-signing-keys"

	// endorsementEntityType, referenceValuesEntityType and
	// signingKeyEntityType are the DAO entity types of the record kinds.
	endorsementEntityType     = "attestation_endorsements"
	referenceValuesEntityType = "attestation_reference_values"
	signingKeyEntityType      = "attestation_signing_keys"

	// maxNameLen is the longest endorsement or reference-values name.
	maxNameLen = 253

	// listPageSize is the page size lists read records in.
	listPageSize = 1000
)

// ValidateName applies the record-name rule of a write: a name is 1-253 bytes
// and holds no '/' that could escape its key prefix. It also refuses "." and
// "..": a client puts the name in a URL path segment, and URL normalization
// resolves those segments away, so a record so named could never be read or
// deleted over REST. It returns a *NameError.
func ValidateName(name string) error {
	if err := validateStoredName(name); err != nil {
		return err
	}
	if name == "." || name == ".." {
		return &NameError{Name: name}
	}
	return nil
}

// validateStoredName applies the rule a stored record's name is addressed
// by: 1-253 bytes and no '/'. It accepts "." and "..", which ValidateName
// refuses for a write, so a record stored under one of them before that rule
// can still be read and deleted. It returns a *NameError.
func validateStoredName(name string) error {
	if name == "" || len(name) > maxNameLen || strings.ContainsRune(name, '/') {
		return &NameError{Name: name}
	}
	return nil
}

// StoreConfig configures a Store.
type StoreConfig struct {
	// DAOs is the qrdb DAO factory the store persists through. DatabaseName
	// must already be ensured on it. Required.
	DAOs *qrdbsdk.DAOFactory
}

// Store persists the Verifier's endorsements and reference values through
// go-qrdb DAOs, each record keyed under its tenant's pkg/scope prefix, so one
// tenant never reads, lists or deletes another's.
type Store struct {
	endorsements    collection[Endorsement]
	referenceValues collection[ReferenceValues]
	signingKeys     collection[SigningKeyBinding]
}

// NewStore opens the endorsement, reference-values and signing-key binding
// DAOs on cfg.DAOs.
func NewStore(cfg StoreConfig) (*Store, error) {
	if cfg.DAOs == nil {
		return nil, &ConfigError{Field: "DAOs", Reason: "is required"}
	}
	endorsements, err := openCollection[Endorsement](cfg.DAOs, endorsementFeature, endorsementEntityType, ValidateName, validateStoredName)
	if err != nil {
		return nil, err
	}
	referenceValues, err := openCollection[ReferenceValues](cfg.DAOs, referenceValuesFeature, referenceValuesEntityType, ValidateName, validateStoredName)
	if err != nil {
		return nil, err
	}
	signingKeys, err := openCollection[SigningKeyBinding](cfg.DAOs, signingKeyFeature, signingKeyEntityType, ValidateRepository, ValidateRepository)
	if err != nil {
		return nil, err
	}
	return &Store{endorsements: endorsements, referenceValues: referenceValues, signingKeys: signingKeys}, nil
}

// PutEndorsement stores (or replaces) the tenant's endorsement e.Name.
func (s *Store) PutEndorsement(ctx context.Context, tenant string, e *Endorsement) error {
	if e == nil {
		return ErrNilRequest
	}
	return s.endorsements.put(ctx, tenant, e.Name, e)
}

// ListEndorsements returns the tenant's endorsements, ordered by name.
func (s *Store) ListEndorsements(ctx context.Context, tenant string) ([]*Endorsement, error) {
	return s.endorsements.list(ctx, tenant)
}

// DeleteEndorsement removes the tenant's endorsement name. A missing one is a
// *RecordNotFoundError.
func (s *Store) DeleteEndorsement(ctx context.Context, tenant, name string) error {
	return s.endorsements.delete(ctx, tenant, name, "endorsement")
}

// PutReferenceValues stores (or replaces) the tenant's reference values
// rv.Name.
func (s *Store) PutReferenceValues(ctx context.Context, tenant string, rv *ReferenceValues) error {
	if rv == nil {
		return ErrNilRequest
	}
	return s.referenceValues.put(ctx, tenant, rv.Name, rv)
}

// GetReferenceValues returns the tenant's reference values name. A missing
// record is a *RecordNotFoundError.
func (s *Store) GetReferenceValues(ctx context.Context, tenant, name string) (*ReferenceValues, error) {
	return s.referenceValues.get(ctx, tenant, name, "reference values")
}

// ListReferenceValues returns the tenant's reference values, ordered by name.
func (s *Store) ListReferenceValues(ctx context.Context, tenant string) ([]*ReferenceValues, error) {
	return s.referenceValues.list(ctx, tenant)
}

// DeleteReferenceValues removes the tenant's reference values name. A missing
// record is a *RecordNotFoundError.
func (s *Store) DeleteReferenceValues(ctx context.Context, tenant, name string) error {
	return s.referenceValues.delete(ctx, tenant, name, "reference values")
}

// PutSigningKeyBinding stores (or replaces) the tenant's signing-key binding
// for b.Repository.
func (s *Store) PutSigningKeyBinding(ctx context.Context, tenant string, b *SigningKeyBinding) error {
	if b == nil {
		return ErrNilRequest
	}
	return s.signingKeys.put(ctx, tenant, b.Repository, b)
}

// GetSigningKeyBinding returns the tenant's signing-key binding for
// repository. A missing binding is a *RecordNotFoundError.
func (s *Store) GetSigningKeyBinding(ctx context.Context, tenant, repository string) (*SigningKeyBinding, error) {
	return s.signingKeys.get(ctx, tenant, repository, signingKeyBindingKind)
}

// ListSigningKeyBindings returns the tenant's signing-key bindings, ordered
// by repository.
func (s *Store) ListSigningKeyBindings(ctx context.Context, tenant string) ([]*SigningKeyBinding, error) {
	return s.signingKeys.list(ctx, tenant)
}

// DeleteSigningKeyBinding removes the tenant's signing-key binding for
// repository. A missing binding is a *RecordNotFoundError.
func (s *Store) DeleteSigningKeyBinding(ctx context.Context, tenant, repository string) error {
	return s.signingKeys.delete(ctx, tenant, repository, signingKeyBindingKind)
}

// recordEntity is the DAO entity of one stored record: its tenant-scoped key
// and the record.
type recordEntity[T any] struct {
	ID     uint64 `json:"id"`
	Key    string `json:"key"`
	Record T      `json:"record"`
}

// EntityID returns the entity ID.
func (e *recordEntity[T]) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity ID.
func (e *recordEntity[T]) SetEntityID(id uint64) { e.ID = id }

// collection is one record kind's DAO, keyed per tenant under a feature.
// validate is the kind's record-name rule for a write; address is the rule a
// stored record's name is read and deleted by, which accepts every name a
// record was ever stored under.
type collection[T any] struct {
	feature  string
	validate func(name string) error
	address  func(name string) error
	records  qrdbsdk.GenericDAO[*recordEntity[T]]
}

// openCollection opens the DAO of one record kind, whose names validate
// accepts for a write and address accepts for a read or delete. The entity
// ID is a hash of the key, so putting a key again replaces its record.
func openCollection[T any](daos *qrdbsdk.DAOFactory, feature, entityType string, validate, address func(string) error) (collection[T], error) {
	newEntity := func() *recordEntity[T] { return &recordEntity[T]{} }
	records, err := dao.New(daos, DatabaseName, entityType, newEntity,
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Key")))
	if err != nil {
		return collection[T]{}, &ConfigError{Field: "DAOs", Reason: "cannot open the " + entityType + " DAO", Cause: err}
	}
	return collection[T]{feature: feature, validate: validate, address: address, records: records}, nil
}

// prefix returns the tenant's key prefix.
func (c collection[T]) prefix(tenant string) (string, error) {
	prefix, err := scope.SharedPrefix(tenant, c.feature)
	if err != nil {
		return "", &TenantError{Tenant: tenant, Cause: err}
	}
	return prefix, nil
}

// key returns the tenant-scoped key of name.
func (c collection[T]) key(tenant, name string) (string, error) {
	if err := c.address(name); err != nil {
		return "", err
	}
	prefix, err := c.prefix(tenant)
	if err != nil {
		return "", err
	}
	return prefix + name, nil
}

func (c collection[T]) put(ctx context.Context, tenant, name string, record *T) error {
	if err := c.validate(name); err != nil {
		return err
	}
	key, err := c.key(tenant, name)
	if err != nil {
		return err
	}
	if err := c.records.Save(ctx, &recordEntity[T]{Key: key, Record: *record}); err != nil {
		return &StoreError{Op: "put", Key: key, Err: err}
	}
	return nil
}

func (c collection[T]) get(ctx context.Context, tenant, name, kind string) (*T, error) {
	stored, err := c.load(ctx, tenant, name, kind)
	if err != nil {
		return nil, err
	}
	return &stored.Record, nil
}

func (c collection[T]) delete(ctx context.Context, tenant, name, kind string) error {
	stored, err := c.load(ctx, tenant, name, kind)
	if err != nil {
		return err
	}
	if err := c.records.Delete(ctx, stored); err != nil {
		return &StoreError{Op: "delete", Key: stored.Key, Err: err}
	}
	return nil
}

// load reads the entity of name, reporting a missing one as a
// *RecordNotFoundError of kind.
func (c collection[T]) load(ctx context.Context, tenant, name, kind string) (*recordEntity[T], error) {
	key, err := c.key(tenant, name)
	if err != nil {
		return nil, err
	}
	stored, err := c.records.GetByNaturalKey(ctx, key)
	if qrdbsdk.IsDAONotFound(err) {
		return nil, &RecordNotFoundError{Kind: kind, Name: name}
	}
	if err != nil {
		return nil, &StoreError{Op: "get", Key: key, Err: err}
	}
	return stored, nil
}

// list returns the tenant's records, ordered by key.
func (c collection[T]) list(ctx context.Context, tenant string) ([]*T, error) {
	prefix, err := c.prefix(tenant)
	if err != nil {
		return nil, err
	}
	var entities []*recordEntity[T]
	query := qrdbsdk.PageQuery{Page: 1, PageSize: listPageSize}
	err = c.records.ForEachPage(ctx, query, func(page qrdbsdk.PageResult[*recordEntity[T]]) error {
		for _, e := range page.Entities {
			if strings.HasPrefix(e.Key, prefix) {
				entities = append(entities, e)
			}
		}
		return nil
	})
	if err != nil {
		return nil, &StoreError{Op: "list", Key: prefix, Err: err}
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].Key < entities[j].Key })
	records := make([]*T, 0, len(entities))
	for _, e := range entities {
		records = append(records, &e.Record)
	}
	return records, nil
}
