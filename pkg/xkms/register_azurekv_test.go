//go:build azurekv

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

	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/stretchr/testify/require"
)

// localAzureVaultURL is a vault_url that is well-formed but names the local
// development endpoint, so azurekv.Config.Validate's AllowLocalVaultURL gate
// is exercised regardless of what happens afterward (#140).
const localAzureVaultURL = "https://127.0.0.1:8443/"

// TestNewAzureKVKeyProvider_AllowLocalVaultURLRefusedByDefault proves that
// the AutoInitialize map-based config path defaults "allow_local_vault_url"
// to false, both when the key is absent and when it is explicitly false: a
// local vault_url is refused with azurekv.ErrLocalVaultURLNotAllowed.
func TestNewAzureKVKeyProvider_AllowLocalVaultURLRefusedByDefault(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]interface{}
	}{
		{
			name: "key absent",
			config: map[string]interface{}{
				"vault_url": localAzureVaultURL,
			},
		},
		{
			name: "key explicitly false",
			config: map[string]interface{}{
				"vault_url":             localAzureVaultURL,
				"allow_local_vault_url": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newAzureKVKeyProvider(tt.config)
			require.Error(t, err)
			require.ErrorIs(t, err, azurekv.ErrLocalVaultURLNotAllowed)
		})
	}
}

// TestNewAzureKVKeyProvider_AllowLocalVaultURLTrue proves that
// "allow_local_vault_url": true reaches azurekv.Config.AllowLocalVaultURL:
// the local-vault-URL gate no longer fires, so Validate proceeds past it to
// the next required field (cert storage, which this factory does not set).
// Asserting progression past the gate, rather than a fully constructed
// backend, keeps this test independent of that unrelated construction gap.
func TestNewAzureKVKeyProvider_AllowLocalVaultURLTrue(t *testing.T) {
	_, err := newAzureKVKeyProvider(map[string]interface{}{
		"vault_url":             localAzureVaultURL,
		"allow_local_vault_url": true,
	})
	require.Error(t, err)
	require.False(t, errors.Is(err, azurekv.ErrLocalVaultURLNotAllowed),
		"allow_local_vault_url=true must bypass the local-vault-URL gate, got %v", err)
	require.ErrorIs(t, err, azurekv.ErrInvalidConfig)
}

// TestNewAzureKVKeyProvider_AllowLocalVaultURLInvalidType proves that a
// non-bool value under "allow_local_vault_url" fails with
// ErrInvalidBackendConfigValue instead of being silently ignored.
func TestNewAzureKVKeyProvider_AllowLocalVaultURLInvalidType(t *testing.T) {
	_, err := newAzureKVKeyProvider(map[string]interface{}{
		"vault_url":             "https://myvault.vault.azure.net/",
		"allow_local_vault_url": "yes",
	})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidBackendConfigValue)
}
