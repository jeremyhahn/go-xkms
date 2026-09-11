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

package objstore

import (
	"context"
	"fmt"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Compile-time interface checks.
var _ storage.TenantAwareFactory = (*TenantAwareFactory)(nil)

// TenantAwareFactory extends Factory with tenant-scoped DAO creation.
// It implements the storage.TenantAwareFactory interface over a go-qrdb KVStore,
// providing tenant data isolation via key prefix namespacing.
type TenantAwareFactory struct {
	Factory
	tenantID string
}

// NewTenantAwareFactoryFromKVStore creates a TenantAwareFactory over a go-qrdb
// KVStore directly (the datastore path). Callers wrap any storage.Backend —
// including the object-storage engine — with kvadapter.New and pass it here.
func NewTenantAwareFactoryFromKVStore(kv xkmssdk.QRDBKVStore) (*TenantAwareFactory, error) {
	if kv == nil {
		return nil, xkmssdk.QRDBDAOInvalidConfigError{
			Field:  "kvStore",
			Reason: "kv store not configured",
		}
	}
	return &TenantAwareFactory{Factory: Factory{kvStore: kv}}, nil
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
//
// The returned store also offers the three guarded operations — PutIfAbsent,
// CompareAndDelete and CompareAndSwap — when the inner store does
// (go-xkms#89). go-qrdb's DAO layer discovers atomicity by asserting
// AtomicKVStore and fails closed when the assertion does not hold, so a
// decorator that dropped those methods made every tenant-scoped DAO
// non-atomic at run time while still building. It is prefixing keys, not
// writing, so it neither adds nor removes an atomicity guarantee: it must pass
// the inner store's capability through unchanged, and must not claim it when
// the inner store lacks it.
func newPrefixedKVStore(inner xkmssdk.QRDBKVStore, prefix string) xkmssdk.QRDBKVStore {
	base := &prefixedKVStore{
		inner:  inner,
		prefix: prefix + "/",
	}
	if atomic, ok := inner.(qrdbsdk.AtomicKVStore); ok {
		return &prefixedAtomicKVStore{prefixedKVStore: base, inner: atomic}
	}
	return base
}

// prefixedAtomicKVStore is the prefixed store an atomic inner store gets: the
// same key namespacing, with the guarded operations forwarded under the
// prefixed key.
type prefixedAtomicKVStore struct {
	*prefixedKVStore

	// inner is the same store *prefixedKVStore holds, typed to its guarded
	// surface. Keeping one field per view rather than asserting on each call
	// makes the capability a construction-time decision, which is where the
	// AtomicKVStore claim is made.
	inner qrdbsdk.AtomicKVStore
}

// Compile-time interface compliance check.
var _ qrdbsdk.AtomicKVStore = (*prefixedAtomicKVStore)(nil)

// PutIfAbsent prefixes the key and delegates. The atomicity guarantee is
// exactly the inner store's: this wrapper adds no writer of its own.
func (p *prefixedAtomicKVStore) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	return p.inner.PutIfAbsent(ctx, p.prefix+key, value)
}

// CompareAndDelete prefixes the key and delegates.
func (p *prefixedAtomicKVStore) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	return p.inner.CompareAndDelete(ctx, p.prefix+key, expected)
}

// CompareAndSwap prefixes the key and delegates.
func (p *prefixedAtomicKVStore) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	return p.inner.CompareAndSwap(ctx, p.prefix+key, expected, next)
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
