//go:build vault

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

package xkms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAutoInitialize_VaultCompiled proves that in a build with the vault tag,
// configuring the vault backend passes the compiled-in check: AutoInitialize
// succeeds, and the vault factory runs (its failure on the missing token is
// tolerated like any backend that cannot start at run time).
func TestAutoInitialize_VaultCompiled(t *testing.T) {
	t.Cleanup(func() { Reset() })

	factory, err := RequireBackend(BackendVault)
	require.NoError(t, err)
	require.NotNil(t, factory)

	require.NoError(t, AutoInitialize(&AutoConfig{
		BackendConfigs: map[BackendType]map[string]interface{}{
			BackendVault: {"address": "https://vault.example.com:8200"},
		},
	}))
	assert.True(t, IsInitialized())
}
