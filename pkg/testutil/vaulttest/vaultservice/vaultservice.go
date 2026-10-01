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
// and BarrierRegistry.
package vaultservice

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/kdftest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Tenant is the tenant New registers, initializes and unseals.
const Tenant = "tenant-1"

// Fixture is an XKMSService whose password store manager serves Tenant over
// a real, unsealed tenant barrier, and the barrier registry behind it.
type Fixture struct {
	Service  *xkms.XKMSService
	Registry *seal.BarrierRegistry
}

// New builds a Fixture around a new XKMSService.
func New(t testing.TB) *Fixture {
	t.Helper()
	svc := &xkms.XKMSService{}
	return &Fixture{Service: svc, Registry: Wire(t, svc)}
}

// Wire gives svc a system password store and a password store manager that
// serves Tenant over a real, unsealed tenant barrier, and returns the
// barrier registry behind them. A test that needs a fully configured
// service (backends, keystore) wires the vault into it with Wire.
func Wire(t testing.TB, svc *xkms.XKMSService) *seal.BarrierRegistry {
	t.Helper()
	ctx := context.Background()

	sysBackend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	sysBarrier, err := seal.NewBarrier(
		slog.New(slog.DiscardHandler),
		sysBackend,
		seal.BarrierConfig{RootKeyPath: "root-key", PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase}},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)
	sysCreds := seal.MustCredentials([]byte("system-passphrase"))
	defer sysCreds.Secret.Destroy()
	require.NoError(t, sysBarrier.Initialize(ctx, sysCreds))

	registry, err := seal.NewBarrierRegistry(sysBarrier)
	require.NoError(t, err)
	_, err = registry.RegisterTenant(Tenant)
	require.NoError(t, err)
	tenantCreds := seal.MustCredentials([]byte("tenant-passphrase"))
	defer tenantCreds.Secret.Destroy()
	require.NoError(t, registry.InitializeTenant(ctx, Tenant, tenantCreds))

	systemStore := staticpw.NewStore(storage.NewMemory())
	manager, err := staticpw.NewTenantPasswordStoreManager(registry, systemStore, staticpw.WithPasskeyRelyingParty("kms.example.com"), staticpw.WithPassphraseKDFParams(kdftest.CheapPassphraseParams))
	require.NoError(t, err)

	svc.SetPasswordStore(systemStore)
	svc.SetPasswordStoreManager(manager)
	return registry
}
