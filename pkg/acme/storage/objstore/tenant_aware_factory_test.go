//go:build codec_json

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
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewTenantAwareFactory verifies successful construction.
func TestNewTenantAwareFactory(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)
	assert.NotNil(t, factory)
}

// TestNewTenantAwareFactory_NilStore verifies that a nil store returns an InvalidConfigError.
func TestNewTenantAwareFactory_NilStore(t *testing.T) {
	_, err := NewTenantAwareFactory(nil)
	require.Error(t, err)
	var cfgErr qrdbsdk.DAOInvalidConfigError
	assert.True(t, errors.As(err, &cfgErr))
	assert.Equal(t, "store", cfgErr.Field)
}

// TestTenantAwareFactory_GetTenantID_Empty verifies GetTenantID returns empty for global factory.
func TestTenantAwareFactory_GetTenantID_Empty(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)
	assert.Equal(t, "", factory.GetTenantID())
}

// TestTenantAwareFactory_TenantDAO verifies that TenantDAO returns a working DAO.
func TestTenantAwareFactory_TenantDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	tenantDAO, err := factory.TenantDAO()
	require.NoError(t, err)
	assert.NotNil(t, tenantDAO)
}

// TestTenantAwareFactory_TenantDAO_SaveAndGet verifies Save and Get round-trip for tenants.
func TestTenantAwareFactory_TenantDAO_SaveAndGet(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	tenantDAO, err := factory.TenantDAO()
	require.NoError(t, err)

	ctx := context.Background()
	tenant := &entities.Tenant{
		NumericID: 1,
		ID:        "tenant-alpha",
		Name:      "Alpha Corp",
		Status:    entities.TenantStatusActive,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}

	err = tenantDAO.Save(ctx, tenant)
	require.NoError(t, err)

	got, err := tenantDAO.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, got.ID)
	assert.Equal(t, tenant.Name, got.Name)
	assert.Equal(t, tenant.Status, got.Status)
}

// TestTenantAwareFactory_ForTenant verifies ForTenant returns a scoped factory.
func TestTenantAwareFactory_ForTenant(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)
	assert.NotNil(t, scoped)
}

// TestTenantAwareFactory_ForTenant_EmptyID verifies ForTenant rejects empty tenant ID.
func TestTenantAwareFactory_ForTenant_EmptyID(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	_, err = factory.ForTenant("")
	require.Error(t, err)
	var cfgErr qrdbsdk.DAOInvalidConfigError
	assert.True(t, errors.As(err, &cfgErr))
	assert.Equal(t, "tenantID", cfgErr.Field)
}

// TestTenantScopedFactory_AccountDAO verifies tenant-scoped AccountDAO creation.
func TestTenantScopedFactory_AccountDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	d, err := scoped.AccountDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

// TestTenantScopedFactory_AccountDAO_SaveAndGet verifies CRUD through scoped AccountDAO.
func TestTenantScopedFactory_AccountDAO_SaveAndGet(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	d, err := scoped.AccountDAO()
	require.NoError(t, err)

	ctx := context.Background()
	account := &entities.ACMEAccount{
		ID:      100,
		Contact: []string{"mailto:admin@alpha.com"},
		Status:  "valid",
	}

	err = d.Save(ctx, account)
	require.NoError(t, err)

	got, err := d.Get(ctx, 100)
	require.NoError(t, err)
	assert.Equal(t, account.ID, got.ID)
	assert.Equal(t, account.Status, got.Status)
}

// TestTenantScopedFactory_OrderDAO verifies tenant-scoped OrderDAO creation.
func TestTenantScopedFactory_OrderDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	d, err := scoped.OrderDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

// TestTenantScopedFactory_OrderDAO_InvalidAccountID verifies zero account ID is rejected.
func TestTenantScopedFactory_OrderDAO_InvalidAccountID(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	_, err = scoped.OrderDAO(0)
	require.Error(t, err)
	var idErr qrdbsdk.DAOInvalidEntityIDError
	assert.True(t, errors.As(err, &idErr))
}

// TestTenantScopedFactory_AuthorizationDAO verifies tenant-scoped AuthorizationDAO creation.
func TestTenantScopedFactory_AuthorizationDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	d, err := scoped.AuthorizationDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

// TestTenantScopedFactory_AuthorizationDAO_InvalidAccountID verifies zero account ID is rejected.
func TestTenantScopedFactory_AuthorizationDAO_InvalidAccountID(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	_, err = scoped.AuthorizationDAO(0)
	require.Error(t, err)
	var idErr qrdbsdk.DAOInvalidEntityIDError
	assert.True(t, errors.As(err, &idErr))
}

// TestTenantScopedFactory_ChallengeDAO verifies tenant-scoped ChallengeDAO creation.
func TestTenantScopedFactory_ChallengeDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	d, err := scoped.ChallengeDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

// TestTenantScopedFactory_ChallengeDAO_InvalidAccountID verifies zero account ID is rejected.
func TestTenantScopedFactory_ChallengeDAO_InvalidAccountID(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	_, err = scoped.ChallengeDAO(0)
	require.Error(t, err)
	var idErr qrdbsdk.DAOInvalidEntityIDError
	assert.True(t, errors.As(err, &idErr))
}

// TestTenantScopedFactory_CertificateDAO verifies tenant-scoped CertificateDAO creation.
func TestTenantScopedFactory_CertificateDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	d, err := scoped.CertificateDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

// TestTenantScopedFactory_NonceDAO verifies tenant-scoped NonceDAO creation.
func TestTenantScopedFactory_NonceDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	d, err := scoped.NonceDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

// TestTenantScopedFactory_ExternalAccountBindingDAO verifies tenant-scoped EAB DAO creation.
func TestTenantScopedFactory_ExternalAccountBindingDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	d, err := scoped.ExternalAccountBindingDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

// TestTenantScopedFactory_DataIsolation verifies that tenant A cannot see tenant B's data.
func TestTenantScopedFactory_DataIsolation(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scopedA, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	scopedB, err := factory.ForTenant("tenant-beta")
	require.NoError(t, err)

	ctx := context.Background()

	// Save an account through tenant A's scoped factory.
	daoA, err := scopedA.AccountDAO()
	require.NoError(t, err)

	accountA := &entities.ACMEAccount{
		ID:      1,
		Contact: []string{"mailto:admin@alpha.com"},
		Status:  "valid",
	}
	err = daoA.Save(ctx, accountA)
	require.NoError(t, err)

	// Save a different account through tenant B's scoped factory.
	daoB, err := scopedB.AccountDAO()
	require.NoError(t, err)

	accountB := &entities.ACMEAccount{
		ID:      1,
		Contact: []string{"mailto:admin@beta.com"},
		Status:  "valid",
	}
	err = daoB.Save(ctx, accountB)
	require.NoError(t, err)

	// Retrieve through tenant A - should get A's data.
	gotA, err := daoA.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"mailto:admin@alpha.com"}, gotA.Contact)

	// Retrieve through tenant B - should get B's data.
	gotB, err := daoB.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"mailto:admin@beta.com"}, gotB.Contact)
}

// TestTenantScopedFactory_DataIsolation_Orders verifies order data isolation between tenants.
func TestTenantScopedFactory_DataIsolation_Orders(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scopedA, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	scopedB, err := factory.ForTenant("tenant-beta")
	require.NoError(t, err)

	ctx := context.Background()

	// Save an order through tenant A.
	orderDaoA, err := scopedA.OrderDAO(1)
	require.NoError(t, err)

	orderA := &entities.ACMEOrder{
		ID:     42,
		Status: "pending",
	}
	err = orderDaoA.Save(ctx, orderA)
	require.NoError(t, err)

	// Tenant B should not see tenant A's order.
	orderDaoB, err := scopedB.OrderDAO(1)
	require.NoError(t, err)

	_, err = orderDaoB.Get(ctx, 42)
	require.Error(t, err)
}

// TestTenantScopedFactory_GlobalVsTenantIsolation verifies that the global
// factory and tenant-scoped factory use different key namespaces.
func TestTenantScopedFactory_GlobalVsTenantIsolation(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	ctx := context.Background()

	// Save account through global (embedded Factory) DAO.
	globalDAO, err := factory.AccountDAO()
	require.NoError(t, err)

	globalAccount := &entities.ACMEAccount{
		ID:      1,
		Contact: []string{"mailto:global@example.com"},
		Status:  "valid",
	}
	err = globalDAO.Save(ctx, globalAccount)
	require.NoError(t, err)

	// Save account through tenant-scoped DAO.
	scoped, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	tenantDAO, err := scoped.AccountDAO()
	require.NoError(t, err)

	tenantAccount := &entities.ACMEAccount{
		ID:      1,
		Contact: []string{"mailto:tenant@alpha.com"},
		Status:  "valid",
	}
	err = tenantDAO.Save(ctx, tenantAccount)
	require.NoError(t, err)

	// Verify each DAO retrieves its own data.
	gotGlobal, err := globalDAO.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"mailto:global@example.com"}, gotGlobal.Contact)

	gotTenant, err := tenantDAO.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"mailto:tenant@alpha.com"}, gotTenant.Contact)
}

// TestTenantAwareFactory_EmbeddedFactoryDAOs verifies that the embedded Factory
// methods (AccountDAO, OrderDAO, etc.) work correctly on TenantAwareFactory.
func TestTenantAwareFactory_EmbeddedFactoryDAOs(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	t.Run("AccountDAO", func(t *testing.T) {
		d, err := factory.AccountDAO()
		assert.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("OrderDAO", func(t *testing.T) {
		d, err := factory.OrderDAO(1)
		assert.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("OrderDAO_InvalidAccountID", func(t *testing.T) {
		_, err := factory.OrderDAO(0)
		var idErr qrdbsdk.DAOInvalidEntityIDError
		assert.True(t, errors.As(err, &idErr))
	})

	t.Run("AuthorizationDAO", func(t *testing.T) {
		d, err := factory.AuthorizationDAO(1)
		assert.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("AuthorizationDAO_InvalidAccountID", func(t *testing.T) {
		_, err := factory.AuthorizationDAO(0)
		var idErr qrdbsdk.DAOInvalidEntityIDError
		assert.True(t, errors.As(err, &idErr))
	})

	t.Run("ChallengeDAO", func(t *testing.T) {
		d, err := factory.ChallengeDAO(1)
		assert.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("ChallengeDAO_InvalidAccountID", func(t *testing.T) {
		_, err := factory.ChallengeDAO(0)
		var idErr qrdbsdk.DAOInvalidEntityIDError
		assert.True(t, errors.As(err, &idErr))
	})

	t.Run("CertificateDAO", func(t *testing.T) {
		d, err := factory.CertificateDAO()
		assert.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("NonceDAO", func(t *testing.T) {
		d, err := factory.NonceDAO()
		assert.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("ExternalAccountBindingDAO", func(t *testing.T) {
		d, err := factory.ExternalAccountBindingDAO()
		assert.NoError(t, err)
		assert.NotNil(t, d)
	})
}

// TestTenantScopedFactory_AllDAOs_SaveAndGet exercises full CRUD through
// all scoped DAO types to verify key prefixing works for each entity type.
func TestTenantScopedFactory_AllDAOs_SaveAndGet(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("tenant-gamma")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("CertificateDAO", func(t *testing.T) {
		d, err := scoped.CertificateDAO()
		require.NoError(t, err)

		cert := &entities.ACMECertificate{
			ID:     10,
			Status: "valid",
		}
		err = d.Save(ctx, cert)
		require.NoError(t, err)

		got, err := d.Get(ctx, 10)
		require.NoError(t, err)
		assert.Equal(t, cert.ID, got.ID)
	})

	t.Run("NonceDAO", func(t *testing.T) {
		d, err := scoped.NonceDAO()
		require.NoError(t, err)

		nonce := &entities.ACMENonce{
			ID:    20,
			Value: []byte("random-nonce-value"),
		}
		err = d.Save(ctx, nonce)
		require.NoError(t, err)

		got, err := d.Get(ctx, 20)
		require.NoError(t, err)
		assert.Equal(t, nonce.Value, got.Value)
	})

	t.Run("ExternalAccountBindingDAO", func(t *testing.T) {
		d, err := scoped.ExternalAccountBindingDAO()
		require.NoError(t, err)

		eab := &entities.ExternalAccountBinding{
			NumericID: 30,
			ID:        "eab-test-id",
			Status:    "valid",
		}
		err = d.Save(ctx, eab)
		require.NoError(t, err)

		got, err := d.Get(ctx, 30)
		require.NoError(t, err)
		assert.Equal(t, eab.ID, got.ID)
	})

	t.Run("AuthorizationDAO", func(t *testing.T) {
		d, err := scoped.AuthorizationDAO(5)
		require.NoError(t, err)

		authz := &entities.ACMEAuthorization{
			ID:     40,
			Status: "pending",
		}
		err = d.Save(ctx, authz)
		require.NoError(t, err)

		got, err := d.Get(ctx, 40)
		require.NoError(t, err)
		assert.Equal(t, authz.Status, got.Status)
	})

	t.Run("ChallengeDAO", func(t *testing.T) {
		d, err := scoped.ChallengeDAO(5)
		require.NoError(t, err)

		challenge := &entities.ACMEChallenge{
			ID:     50,
			Type:   "http-01",
			Status: "pending",
		}
		err = d.Save(ctx, challenge)
		require.NoError(t, err)

		got, err := d.Get(ctx, 50)
		require.NoError(t, err)
		assert.Equal(t, challenge.Type, got.Type)
	})

	t.Run("OrderDAO", func(t *testing.T) {
		d, err := scoped.OrderDAO(5)
		require.NoError(t, err)

		order := &entities.ACMEOrder{
			ID:     60,
			Status: "ready",
		}
		err = d.Save(ctx, order)
		require.NoError(t, err)

		got, err := d.Get(ctx, 60)
		require.NoError(t, err)
		assert.Equal(t, order.Status, got.Status)
	})
}

// TestTenantScopedFactory_MultipleTenants verifies that multiple tenants
// can coexist and each has independent data.
func TestTenantScopedFactory_MultipleTenants(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	ctx := context.Background()
	tenantIDs := []string{"tenant-1", "tenant-2", "tenant-3"}

	// Save a unique account per tenant.
	for i, tid := range tenantIDs {
		scoped, err := factory.ForTenant(tid)
		require.NoError(t, err)

		d, err := scoped.AccountDAO()
		require.NoError(t, err)

		account := &entities.ACMEAccount{
			ID:      1,
			Contact: []string{"mailto:admin@" + tid + ".com"},
			Status:  "valid",
			Key:     "key-" + string(rune('A'+i)),
		}
		err = d.Save(ctx, account)
		require.NoError(t, err)
	}

	// Verify each tenant sees only its own account.
	for i, tid := range tenantIDs {
		scoped, err := factory.ForTenant(tid)
		require.NoError(t, err)

		d, err := scoped.AccountDAO()
		require.NoError(t, err)

		got, err := d.Get(ctx, 1)
		require.NoError(t, err)
		assert.Equal(t, "key-"+string(rune('A'+i)), got.Key)
	}
}

// TestTenantAwareFactory_CompileTimeInterfaceCheck verifies the compile-time
// interface assertion declared in the source file.
func TestTenantAwareFactory_CompileTimeInterfaceCheck(t *testing.T) {
	var _ storage.TenantAwareFactory = (*TenantAwareFactory)(nil)
}

// TestTenantScopedFactory_ImplementsFactory verifies the tenantScopedFactory
// satisfies the storage.Factory interface.
func TestTenantScopedFactory_ImplementsFactory(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("test-tenant")
	require.NoError(t, err)

	var _ storage.Factory = scoped
}

// TestTenantScopedFactory_Prefix_IndirectVerification verifies that the prefix function creates
// the expected namespace path by checking that scoped DAOs store data under keys that
// the global factory cannot find.
func TestTenantScopedFactory_Prefix_IndirectVerification(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	ctx := context.Background()

	scoped, err := factory.ForTenant("my-tenant")
	require.NoError(t, err)

	d, err := scoped.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{
		ID:     999,
		Status: "valid",
	}
	err = d.Save(ctx, account)
	require.NoError(t, err)

	// The global AccountDAO should NOT find this entity because keys
	// are prefixed differently.
	globalDAO, err := factory.AccountDAO()
	require.NoError(t, err)

	_, err = globalDAO.Get(ctx, 999)
	require.Error(t, err, "global DAO should not find tenant-scoped data")
}

// TestTenantAwareFactory_TenantDAO_Delete verifies tenant deletion through the TenantDAO.
func TestTenantAwareFactory_TenantDAO_Delete(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	ctx := context.Background()
	tenantDAO, err := factory.TenantDAO()
	require.NoError(t, err)

	tenant := &entities.Tenant{
		NumericID: 42,
		ID:        "delete-me",
		Name:      "Delete Me Corp",
		Status:    entities.TenantStatusActive,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}

	err = tenantDAO.Save(ctx, tenant)
	require.NoError(t, err)

	err = tenantDAO.Delete(ctx, tenant)
	require.NoError(t, err)

	_, err = tenantDAO.Get(ctx, 42)
	require.Error(t, err)
}

// TestTenantAwareFactory_TenantDAO_Count verifies counting tenants.
func TestTenantAwareFactory_TenantDAO_Count(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	ctx := context.Background()
	tenantDAO, err := factory.TenantDAO()
	require.NoError(t, err)

	for i := uint64(1); i <= 3; i++ {
		tenant := &entities.Tenant{
			NumericID: i,
			ID:        "tenant-" + string(rune('a'+i-1)),
			Name:      "Tenant " + string(rune('A'+i-1)),
			Status:    entities.TenantStatusActive,
			CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
			UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
		}
		err = tenantDAO.Save(ctx, tenant)
		require.NoError(t, err)
	}

	count, err := tenantDAO.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

// TestTenantScopedFactory_DataIsolation_Certificates verifies certificate
// data isolation between tenants.
func TestTenantScopedFactory_DataIsolation_Certificates(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scopedA, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	scopedB, err := factory.ForTenant("tenant-beta")
	require.NoError(t, err)

	ctx := context.Background()

	certDaoA, err := scopedA.CertificateDAO()
	require.NoError(t, err)

	certA := &entities.ACMECertificate{
		ID:     1,
		PEM:    "-----BEGIN CERTIFICATE-----\nalpha\n-----END CERTIFICATE-----",
		Status: "valid",
	}
	err = certDaoA.Save(ctx, certA)
	require.NoError(t, err)

	certDaoB, err := scopedB.CertificateDAO()
	require.NoError(t, err)

	// Tenant B should not see tenant A's certificate.
	_, err = certDaoB.Get(ctx, 1)
	require.Error(t, err)
}

// TestTenantScopedFactory_DataIsolation_Nonces verifies nonce
// data isolation between tenants.
func TestTenantScopedFactory_DataIsolation_Nonces(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scopedA, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	scopedB, err := factory.ForTenant("tenant-beta")
	require.NoError(t, err)

	ctx := context.Background()

	nonceDaoA, err := scopedA.NonceDAO()
	require.NoError(t, err)

	nonceA := &entities.ACMENonce{
		ID:    1,
		Value: []byte("nonce-alpha"),
	}
	err = nonceDaoA.Save(ctx, nonceA)
	require.NoError(t, err)

	nonceDaoB, err := scopedB.NonceDAO()
	require.NoError(t, err)

	// Tenant B should not see tenant A's nonce.
	_, err = nonceDaoB.Get(ctx, 1)
	require.Error(t, err)
}

// TestTenantScopedFactory_DataIsolation_EAB verifies external account binding
// data isolation between tenants.
func TestTenantScopedFactory_DataIsolation_EAB(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scopedA, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	scopedB, err := factory.ForTenant("tenant-beta")
	require.NoError(t, err)

	ctx := context.Background()

	eabDaoA, err := scopedA.ExternalAccountBindingDAO()
	require.NoError(t, err)

	eabA := &entities.ExternalAccountBinding{
		NumericID: 1,
		ID:        "eab-alpha",
		Status:    "valid",
	}
	err = eabDaoA.Save(ctx, eabA)
	require.NoError(t, err)

	eabDaoB, err := scopedB.ExternalAccountBindingDAO()
	require.NoError(t, err)

	// Tenant B should not see tenant A's EAB.
	_, err = eabDaoB.Get(ctx, 1)
	require.Error(t, err)
}

// TestTenantScopedFactory_DataIsolation_Challenges verifies challenge
// data isolation between tenants.
func TestTenantScopedFactory_DataIsolation_Challenges(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scopedA, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	scopedB, err := factory.ForTenant("tenant-beta")
	require.NoError(t, err)

	ctx := context.Background()

	challengeDaoA, err := scopedA.ChallengeDAO(1)
	require.NoError(t, err)

	challengeA := &entities.ACMEChallenge{
		ID:     1,
		Type:   "dns-01",
		Status: "pending",
	}
	err = challengeDaoA.Save(ctx, challengeA)
	require.NoError(t, err)

	challengeDaoB, err := scopedB.ChallengeDAO(1)
	require.NoError(t, err)

	// Tenant B should not see tenant A's challenge.
	_, err = challengeDaoB.Get(ctx, 1)
	require.Error(t, err)
}

// TestTenantScopedFactory_DataIsolation_Authorizations verifies authorization
// data isolation between tenants.
func TestTenantScopedFactory_DataIsolation_Authorizations(t *testing.T) {
	store := newMockStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scopedA, err := factory.ForTenant("tenant-alpha")
	require.NoError(t, err)

	scopedB, err := factory.ForTenant("tenant-beta")
	require.NoError(t, err)

	ctx := context.Background()

	authzDaoA, err := scopedA.AuthorizationDAO(1)
	require.NoError(t, err)

	authzA := &entities.ACMEAuthorization{
		ID:     1,
		Status: "valid",
	}
	err = authzDaoA.Save(ctx, authzA)
	require.NoError(t, err)

	authzDaoB, err := scopedB.AuthorizationDAO(1)
	require.NoError(t, err)

	// Tenant B should not see tenant A's authorization.
	_, err = authzDaoB.Get(ctx, 1)
	require.Error(t, err)
}

// TestFactory_AccountDAO_SaveAndGet verifies full Save and Get round-trip through AccountDAO.
func TestFactory_AccountDAO_SaveAndGet(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.AccountDAO()
	require.NoError(t, err)

	ctx := context.Background()
	account := &entities.ACMEAccount{
		ID:      1,
		Contact: []string{"mailto:test@example.com"},
		Status:  "valid",
	}

	err = d.Save(ctx, account)
	require.NoError(t, err)

	got, err := d.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, account.Status, got.Status)
	assert.Equal(t, account.Contact, got.Contact)
}

// TestFactory_CertificateDAO_SaveAndGet verifies full Save and Get round-trip through CertificateDAO.
func TestFactory_CertificateDAO_SaveAndGet(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.CertificateDAO()
	require.NoError(t, err)

	ctx := context.Background()
	cert := &entities.ACMECertificate{
		ID:     1,
		PEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		Status: "valid",
	}

	err = d.Save(ctx, cert)
	require.NoError(t, err)

	got, err := d.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, cert.PEM, got.PEM)
	assert.Equal(t, cert.Status, got.Status)
}

// TestFactory_NonceDAO_SaveAndGet verifies full Save and Get round-trip through NonceDAO.
func TestFactory_NonceDAO_SaveAndGet(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.NonceDAO()
	require.NoError(t, err)

	ctx := context.Background()
	nonce := &entities.ACMENonce{
		ID:        1,
		Value:     []byte("test-nonce-value"),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	err = d.Save(ctx, nonce)
	require.NoError(t, err)

	got, err := d.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, nonce.Value, got.Value)
	assert.Equal(t, nonce.ExpiresAt, got.ExpiresAt)
}

// TestFactory_ExternalAccountBindingDAO_SaveAndGet verifies full Save and Get
// round-trip through ExternalAccountBindingDAO.
func TestFactory_ExternalAccountBindingDAO_SaveAndGet(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	ctx := context.Background()
	eab := &entities.ExternalAccountBinding{
		NumericID: 1,
		ID:        "eab-test",
		Status:    "valid",
	}

	err = d.Save(ctx, eab)
	require.NoError(t, err)

	got, err := d.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, eab.ID, got.ID)
	assert.Equal(t, eab.Status, got.Status)
}

// TestFactory_OrderDAO_SaveAndGet verifies full Save and Get round-trip through OrderDAO.
func TestFactory_OrderDAO_SaveAndGet(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.OrderDAO(1)
	require.NoError(t, err)

	ctx := context.Background()
	order := &entities.ACMEOrder{
		ID:     1,
		Status: "pending",
	}

	err = d.Save(ctx, order)
	require.NoError(t, err)

	got, err := d.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, order.Status, got.Status)
}

// TestFactory_AuthorizationDAO_SaveAndGet verifies full Save and Get round-trip.
func TestFactory_AuthorizationDAO_SaveAndGet(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.AuthorizationDAO(1)
	require.NoError(t, err)

	ctx := context.Background()
	authz := &entities.ACMEAuthorization{
		ID:     1,
		Status: "pending",
	}

	err = d.Save(ctx, authz)
	require.NoError(t, err)

	got, err := d.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, authz.Status, got.Status)
}

// TestFactory_ChallengeDAO_SaveAndGet verifies full Save and Get round-trip.
func TestFactory_ChallengeDAO_SaveAndGet(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.ChallengeDAO(1)
	require.NoError(t, err)

	ctx := context.Background()
	challenge := &entities.ACMEChallenge{
		ID:     1,
		Type:   "http-01",
		Status: "pending",
	}

	err = d.Save(ctx, challenge)
	require.NoError(t, err)

	got, err := d.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, challenge.Type, got.Type)
	assert.Equal(t, challenge.Status, got.Status)
}
