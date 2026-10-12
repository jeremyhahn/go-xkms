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

// Package barriertest builds real, in-memory tenant barriers for tests. It
// depends on pkg/seal and pkg/storage only, so a package that pkg/xkms
// itself imports can use it without an import cycle.
package barriertest

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// NewRegistry returns a tenant barrier registry over an initialized,
// unsealed in-memory system barrier.
func NewRegistry(t testing.TB) *seal.BarrierRegistry {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	barrier, err := seal.NewBarrier(slog.Default(), backend, seal.BarrierConfig{
		RootKeyPath:     "root-key",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)

	creds := seal.MustCredentials(t.Context(), []byte("host-barrier-passphrase"))
	defer func() { require.NoError(t, creds.Secret.Destroy()) }()
	require.NoError(t, barrier.Initialize(context.Background(), creds))

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	return registry
}

// RegisterTenant registers tenantID in registry with an initialized,
// unsealed tenant barrier.
func RegisterTenant(t testing.TB, registry *seal.BarrierRegistry, tenantID string) {
	t.Helper()
	_, err := registry.RegisterTenantDefault(tenantID)
	require.NoError(t, err)
	creds := seal.MustCredentials(t.Context(), []byte(tenantID+"-passphrase"))
	defer func() { require.NoError(t, creds.Secret.Destroy()) }()
	require.NoError(t, registry.InitializeTenant(context.Background(), tenantID, creds))
}
