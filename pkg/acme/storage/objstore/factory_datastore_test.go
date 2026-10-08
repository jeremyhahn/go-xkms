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
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
)

// openTestDatastore opens a standalone, memory-engine datastore -- a real
// in-process go-qrdb node -- and closes it when the test ends.
func openTestDatastore(t *testing.T) *datastore.Datastore {
	t.Helper()
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()},
	}
	ds, err := datastore.Open(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, ds.Close()) })
	return ds
}

// TestNewFactory_StoresThroughInjectedDAOFactory proves ACME accounts, orders
// and certificates saved through a Factory built over a datastore's DAO
// factory land in that datastore: a DAO built independently from the same
// factory reads each one back.
func TestNewFactory_StoresThroughInjectedDAOFactory(t *testing.T) {
	ctx := t.Context()
	ds := openTestDatastore(t)

	factory, err := NewFactory(ds.DAOFactory())
	require.NoError(t, err)

	accounts, err := factory.AccountDAO()
	require.NoError(t, err)
	account := &entities.ACMEAccount{Contact: []string{"mailto:ops@example.com"}, CreatedAt: time.Now().UTC()}
	require.NoError(t, accounts.Save(ctx, account))
	require.NotZero(t, account.ID)

	orders, err := factory.OrderDAO(account.ID)
	require.NoError(t, err)
	order := &entities.ACMEOrder{Status: "pending", AccountID: account.ID,
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "kms.example.com"}}}
	require.NoError(t, orders.Save(ctx, order))
	require.NotZero(t, order.ID)

	certs, err := factory.CertificateDAO()
	require.NoError(t, err)
	cert := &entities.ACMECertificate{Serial: "1a2b3c", PEM: "pem", Status: "valid", IssuedAt: time.Now().UTC()}
	require.NoError(t, storage.SaveCertificateNoCollision(ctx, certs, cert))

	gotAccounts, err := dao.New(ds.DAOFactory(), "", acmeAccountNamespace, func() *entities.ACMEAccount { return &entities.ACMEAccount{} })
	require.NoError(t, err)
	gotAccount, err := gotAccounts.Get(ctx, account.ID)
	require.NoError(t, err)
	assert.Equal(t, account.Contact, gotAccount.Contact)

	gotOrder, err := orders.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, "kms.example.com", gotOrder.Identifiers[0].Value)
	assert.Equal(t, account.ID, gotOrder.AccountID)

	gotCert, err := certs.Get(ctx, cert.EntityID())
	require.NoError(t, err)
	assert.Equal(t, "1a2b3c", gotCert.Serial)
}

// TestNewFactory_NilDAOFactory proves a Factory refuses to build without a
// DAO factory, with go-qrdb's typed configuration error.
func TestNewFactory_NilDAOFactory(t *testing.T) {
	_, err := NewFactory(nil)
	var cfgErr qrdbsdk.DAOInvalidConfigError
	require.True(t, errors.As(err, &cfgErr))
	assert.Equal(t, "daoFactory", cfgErr.Field)

	_, err = NewTenantAwareFactory(nil)
	require.True(t, errors.As(err, &cfgErr))
	assert.Equal(t, "daoFactory", cfgErr.Field)
}

// TestNewTenantAwareFactory_IsolatesTenantsOnInjectedDAOFactory proves the
// tenant-scoped factories share the datastore's store yet never see each
// other's entities.
func TestNewTenantAwareFactory_IsolatesTenantsOnInjectedDAOFactory(t *testing.T) {
	ctx := t.Context()
	ds := openTestDatastore(t)

	factory, err := NewTenantAwareFactory(ds.DAOFactory())
	require.NoError(t, err)

	tenantA, err := factory.ForTenant("tenant-a")
	require.NoError(t, err)
	tenantB, err := factory.ForTenant("tenant-b")
	require.NoError(t, err)

	accountsA, err := tenantA.AccountDAO()
	require.NoError(t, err)
	account := &entities.ACMEAccount{Contact: []string{"mailto:a@example.com"}}
	require.NoError(t, accountsA.Save(ctx, account))

	got, err := accountsA.Get(ctx, account.ID)
	require.NoError(t, err)
	assert.Equal(t, account.Contact, got.Contact)

	accountsB, err := tenantB.AccountDAO()
	require.NoError(t, err)
	_, err = accountsB.Get(ctx, account.ID)
	assert.True(t, qrdbsdk.IsDAONotFound(err), "tenant B must not read tenant A's account: %v", err)
}

// TestTenantAwareFactory_ForTenant_NoDefaultDatabase proves ForTenant refuses
// a DAO factory that serves no default database rather than scoping nothing.
func TestTenantAwareFactory_ForTenant_NoDefaultDatabase(t *testing.T) {
	empty := qrdbsdk.NewDAOFactoryWithConfig(&qrdbsdk.DAOFactoryConfig{
		KVStoreProvider: func(uint64) qrdbsdk.KVStore { return nil },
	})
	factory, err := NewTenantAwareFactory(empty)
	require.NoError(t, err)

	_, err = factory.ForTenant("tenant-a")
	var unavailable *dao.DatabaseUnavailableError
	assert.True(t, errors.As(err, &unavailable))
}
