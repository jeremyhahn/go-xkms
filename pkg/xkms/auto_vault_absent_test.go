//go:build !vault

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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAutoInitialize_VaultNotCompiled proves that in a build without the
// vault tag, configuring the vault backend fails AutoInitialize with a
// FeatureNotCompiledError naming WITH_VAULT, instead of starting without it.
func TestAutoInitialize_VaultNotCompiled(t *testing.T) {
	t.Cleanup(func() { Reset() })

	err := AutoInitialize(&AutoConfig{
		BackendConfigs: map[BackendType]map[string]interface{}{
			BackendVault: {"address": "https://vault.example.com:8200"},
		},
	})

	var featureErr *FeatureNotCompiledError
	require.True(t, errors.As(err, &featureErr), "expected *FeatureNotCompiledError, got %v", err)
	assert.Equal(t, FeatureNotCompiledError{Feature: "vault", Toggle: "WITH_VAULT", Tag: "vault"}, *featureErr)
	assert.False(t, IsInitialized())
}

// TestAutoInitialize_VaultDefaultNotCompiled proves the same for a
// DefaultBackend naming vault.
func TestAutoInitialize_VaultDefaultNotCompiled(t *testing.T) {
	t.Cleanup(func() { Reset() })

	err := AutoInitialize(&AutoConfig{DefaultBackend: string(BackendVault)})
	require.ErrorIs(t, err, ErrFeatureNotCompiled)
	assert.False(t, IsInitialized())
}
