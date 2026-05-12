// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package objstore

import (
	"context"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-objstore/pkg/common"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Compile-time interface checks.
var _ storage.TenantAwareFactory = (*TenantAwareFactory)(nil)

// TenantAwareFactory extends Factory with tenant-scoped DAO creation.
// It implements the storage.TenantAwareFactory interface using go-objstore,
// providing tenant data isolation via key prefix namespacing.
type TenantAwareFactory struct {
	Factory
	tenantID string
}

// NewTenantAwareFactory creates a new TenantAwareFactory with the provided storage backend.
func NewTenantAwareFactory(store common.Storage) (*TenantAwareFactory, error) {
	if store == nil {
		return nil, xkmssdk.QRDBDAOInvalidConfigError{
			Field:  "store",
			Reason: "storage backend not configured",
		}
	}
	return &TenantAwareFactory{
		Factory: Factory{
			kvStore: NewKVStoreAdapter(store),
		},
	}, nil
}

// TenantDAO returns a GenericDAO for managing tenants.
func (f *TenantAwareFactory) TenantDAO() (qrdbsdk.GenericDAO[*entities.Tenant], error) {
	return qrdbsdk.NewDAO(f.kvStore, "acme/tenants",
		func() *entities.Tenant { return &entities.Tenant{} })
}

// ForTenant returns a tenant-scoped Factory.
// All DAOs created by the returned factory operate within the
// specified tenant's data namespace.
func (f *TenantAwareFactory) ForTenant(tenantID string) (storage.Factory, error) {
	if tenantID == "" {
		return nil, xkmssdk.QRDBDAOInvalidConfigError{
			Field:  "tenantID",
			Reason: "tenant ID is required",
		}
	}
	prefix := fmt.Sprintf("acme/tenants/%s", tenantID)
	return &tenantScopedFactory{
		kvStore:  newPrefixedKVStore(f.kvStore, prefix),
		tenantID: tenantID,
	}, nil
}

// GetTenantID returns the current tenant ID, or empty string if not in tenant context.
func (f *TenantAwareFactory) GetTenantID() string {
	return f.tenantID
}

// tenantScopedFactory is a Factory that operates within a tenant's key namespace.
type tenantScopedFactory struct {
	kvStore  xkmssdk.QRDBKVStore
	tenantID string
}

// AccountDAO returns a tenant-scoped GenericDAO for ACME accounts.
func (f *tenantScopedFactory) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return qrdbsdk.NewDAO(f.kvStore, "accounts",
		func() *entities.ACMEAccount { return &entities.ACMEAccount{} })
}

// OrderDAO returns a tenant-scoped GenericDAO for ACME orders.
func (f *tenantScopedFactory) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	if accountID == 0 {
		return nil, xkmssdk.QRDBDAOInvalidEntityIDError{
			EntityType: "order",
			Reason:     "account ID must be non-zero",
		}
	}
	return qrdbsdk.NewDAO(f.kvStore, fmt.Sprintf("orders/%d", accountID),
		func() *entities.ACMEOrder { return &entities.ACMEOrder{} })
}

// AuthorizationDAO returns a tenant-scoped GenericDAO for ACME authorizations.
func (f *tenantScopedFactory) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	if accountID == 0 {
		return nil, xkmssdk.QRDBDAOInvalidEntityIDError{
			EntityType: "authorization",
			Reason:     "account ID must be non-zero",
		}
	}
	return qrdbsdk.NewDAO(f.kvStore, fmt.Sprintf("authorizations/%d", accountID),
		func() *entities.ACMEAuthorization { return &entities.ACMEAuthorization{} })
}

// ChallengeDAO returns a tenant-scoped GenericDAO for ACME challenges.
func (f *tenantScopedFactory) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	if accountID == 0 {
		return nil, xkmssdk.QRDBDAOInvalidEntityIDError{
			EntityType: "challenge",
			Reason:     "account ID must be non-zero",
		}
	}
	return qrdbsdk.NewDAO(f.kvStore, fmt.Sprintf("challenges/%d", accountID),
		func() *entities.ACMEChallenge { return &entities.ACMEChallenge{} })
}

// CertificateDAO returns a tenant-scoped GenericDAO for ACME certificates.
func (f *tenantScopedFactory) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return qrdbsdk.NewDAO(f.kvStore, "certificates",
		func() *entities.ACMECertificate { return &entities.ACMECertificate{} })
}

// NonceDAO returns a tenant-scoped GenericDAO for ACME nonces.
func (f *tenantScopedFactory) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return qrdbsdk.NewDAO(f.kvStore, "nonces",
		func() *entities.ACMENonce { return &entities.ACMENonce{} })
}

// ExternalAccountBindingDAO returns a tenant-scoped GenericDAO for external account bindings.
func (f *tenantScopedFactory) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return qrdbsdk.NewDAO(f.kvStore, "eab",
		func() *entities.ExternalAccountBinding { return &entities.ExternalAccountBinding{} })
}

// prefixedKVStore wraps a KVStore and prefixes all keys with a namespace.
type prefixedKVStore struct {
	inner  xkmssdk.QRDBKVStore
	prefix string
}

// newPrefixedKVStore creates a KVStore that prefixes all keys.
func newPrefixedKVStore(inner xkmssdk.QRDBKVStore, prefix string) xkmssdk.QRDBKVStore {
	return &prefixedKVStore{
		inner:  inner,
		prefix: prefix + "/",
	}
}

func (p *prefixedKVStore) Put(ctx context.Context, key string, value []byte) error {
	return p.inner.Put(ctx, p.prefix+key, value)
}

func (p *prefixedKVStore) Get(ctx context.Context, key string) ([]byte, error) {
	return p.inner.Get(ctx, p.prefix+key)
}

func (p *prefixedKVStore) Delete(ctx context.Context, key string) error {
	return p.inner.Delete(ctx, p.prefix+key)
}

func (p *prefixedKVStore) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	fullPrefix := p.prefix + prefix
	return p.inner.Scan(ctx, fullPrefix, func(key string, value []byte) error {
		// Strip the outer prefix so the caller sees relative keys.
		relativeKey := strings.TrimPrefix(key, p.prefix)
		return fn(relativeKey, value)
	})
}

func (p *prefixedKVStore) List(ctx context.Context, prefix string) ([]string, error) {
	fullPrefix := p.prefix + prefix
	keys, err := p.inner.List(ctx, fullPrefix)
	if err != nil {
		return nil, err
	}

	// Strip the outer prefix from each key.
	result := make([]string, len(keys))
	for i, key := range keys {
		result[i] = strings.TrimPrefix(key, p.prefix)
	}
	return result, nil
}

func (p *prefixedKVStore) Exists(ctx context.Context, key string) (bool, error) {
	return p.inner.Exists(ctx, p.prefix+key)
}

func (p *prefixedKVStore) RegisterEntityIndexes(entityType string, indexes []xkmssdk.QRDBEntityIndex) error {
	return p.inner.RegisterEntityIndexes(entityType, indexes)
}

func (p *prefixedKVStore) QueryIndex(ctx context.Context, indexName string, value []byte) ([][]byte, error) {
	return p.inner.QueryIndex(ctx, indexName, value)
}

func (p *prefixedKVStore) ScanIndex(ctx context.Context, indexName string, start, end []byte) (map[string][][]byte, error) {
	return p.inner.ScanIndex(ctx, indexName, start, end)
}

func (p *prefixedKVStore) QueryCompoundIndex(ctx context.Context, indexName string, values [][]byte) ([][]byte, error) {
	return p.inner.QueryCompoundIndex(ctx, indexName, values)
}

func (p *prefixedKVStore) ScanCompoundIndex(ctx context.Context, indexName string, prefixValues [][]byte, rangeStart, rangeEnd []byte) (map[string][][]byte, error) {
	return p.inner.ScanCompoundIndex(ctx, indexName, prefixValues, rangeStart, rangeEnd)
}
