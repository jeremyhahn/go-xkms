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

package dao

import (
	"strconv"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
)

// Compile-time interface checks.
var (
	_ storage.Factory            = (*Factory)(nil)
	_ storage.TenantAwareFactory = (*Factory)(nil)
)

// Factory creates GenericDAO instances backed by QRDB's kvstore.KVStore.
// It implements both storage.Factory and storage.TenantAwareFactory.
type Factory struct {
	kvStore  qrdbsdk.KVStore
	tenantID string
	daoOpts  []qrdbsdk.DAOOption
}

// NewFactory creates a new Factory with the given KVStore.
func NewFactory(kvStore qrdbsdk.KVStore, daoOpts ...qrdbsdk.DAOOption) *Factory {
	return &Factory{
		kvStore: kvStore,
		daoOpts: daoOpts,
	}
}

// NewFactoryWithTenant creates a new Factory scoped to a specific tenant.
func NewFactoryWithTenant(kvStore qrdbsdk.KVStore, tenantID string, daoOpts ...qrdbsdk.DAOOption) *Factory {
	return &Factory{
		kvStore:  kvStore,
		tenantID: tenantID,
		daoOpts:  daoOpts,
	}
}

// prefix returns the key prefix for tenant-scoped operations.
// Returns empty string for global (non-tenant) scope.
func (f *Factory) prefix() string {
	if f.tenantID != "" {
		return "tenants/" + f.tenantID + "/"
	}
	return ""
}

// AccountDAO returns a GenericDAO for ACME accounts.
func (f *Factory) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return qrdbsdk.NewDAO(f.kvStore, f.prefix()+"accounts",
		func() *entities.ACMEAccount { return &entities.ACMEAccount{} },
		f.daoOpts...)
}

// OrderDAO returns a GenericDAO for ACME orders scoped to a specific account.
func (f *Factory) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return qrdbsdk.NewDAO(f.kvStore, f.prefix()+"accounts/"+strconv.FormatUint(accountID, 10)+"/orders",
		func() *entities.ACMEOrder { return &entities.ACMEOrder{} },
		f.daoOpts...)
}

// AuthorizationDAO returns a GenericDAO for ACME authorizations scoped to a specific account.
func (f *Factory) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return qrdbsdk.NewDAO(f.kvStore, f.prefix()+"accounts/"+strconv.FormatUint(accountID, 10)+"/authorizations",
		func() *entities.ACMEAuthorization { return &entities.ACMEAuthorization{} },
		f.daoOpts...)
}

// ChallengeDAO returns a GenericDAO for ACME challenges scoped to a specific account.
func (f *Factory) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return qrdbsdk.NewDAO(f.kvStore, f.prefix()+"accounts/"+strconv.FormatUint(accountID, 10)+"/challenges",
		func() *entities.ACMEChallenge { return &entities.ACMEChallenge{} },
		f.daoOpts...)
}

// CertificateDAO returns a GenericDAO for ACME certificates.
func (f *Factory) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return qrdbsdk.NewDAO(f.kvStore, f.prefix()+"certificates",
		func() *entities.ACMECertificate { return &entities.ACMECertificate{} },
		f.daoOpts...)
}

// NonceDAO returns a GenericDAO for ACME nonces.
func (f *Factory) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return qrdbsdk.NewDAO(f.kvStore, f.prefix()+"nonces",
		func() *entities.ACMENonce { return &entities.ACMENonce{} },
		f.daoOpts...)
}

// ExternalAccountBindingDAO returns a GenericDAO for external account bindings.
func (f *Factory) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return qrdbsdk.NewDAO(f.kvStore, f.prefix()+"eab",
		func() *entities.ExternalAccountBinding { return &entities.ExternalAccountBinding{} },
		f.daoOpts...)
}

// TenantDAO returns a GenericDAO for managing tenants.
func (f *Factory) TenantDAO() (qrdbsdk.GenericDAO[*entities.Tenant], error) {
	return qrdbsdk.NewDAO(f.kvStore, "tenants",
		func() *entities.Tenant { return &entities.Tenant{} },
		f.daoOpts...)
}

// ForTenant returns a tenant-scoped Factory.
func (f *Factory) ForTenant(tenantID string) (storage.Factory, error) {
	if tenantID == "" {
		return nil, InvalidIDError{EntityType: "tenant", Reason: "cannot be empty"}
	}
	return NewFactoryWithTenant(f.kvStore, tenantID, f.daoOpts...), nil
}

// GetTenantID returns the current tenant ID, or empty string if not in tenant context.
func (f *Factory) GetTenantID() string {
	return f.tenantID
}
