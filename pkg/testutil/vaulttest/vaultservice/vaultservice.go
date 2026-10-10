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

// Package vaultservice builds the real service the personal-vault transport
// tests run against: an XKMSService over a real TenantPasswordStoreManager
// and in-memory tenant stores.
package vaultservice

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/kdftest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Tenant is the tenant the fixture's tests act in.
const Tenant = "tenant-1"

// Fixture is an XKMSService whose password store manager serves tenants over
// in-memory tenant stores, and the tenant stores behind it.
type Fixture struct {
	Service *xkms.XKMSService
	Stores  *testutil.TenantStores
}

// New builds a Fixture around a new XKMSService.
func New(t testing.TB) *Fixture {
	t.Helper()
	svc := &xkms.XKMSService{}
	return &Fixture{Service: svc, Stores: Wire(t, svc)}
}

// Wire gives svc a system password store and a password store manager over
// in-memory tenant stores, and returns the tenant stores behind them. A test
// that needs a fully configured service (backends, keystore) wires the vault
// into it with Wire.
func Wire(t testing.TB, svc *xkms.XKMSService) *testutil.TenantStores {
	t.Helper()

	systemStore, err := staticpw.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	stores := testutil.NewTenantStores()
	manager, err := staticpw.NewTenantPasswordStoreManager(stores, systemStore, staticpw.WithPasskeyRelyingParty("kms.example.com"), staticpw.WithPassphraseKDFParams(kdftest.CheapPassphraseParams))
	require.NoError(t, err)

	svc.SetPasswordStore(systemStore)
	svc.SetPasswordStoreManager(manager)
	return stores
}
