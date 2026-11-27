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

//go:build azurekv

package xkms

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// countingKeyVault counts every CreateKey, whatever the key name.
type countingKeyVault struct {
	*azurekv.MockKeyVaultClient
	created atomic.Int32
}

func (c *countingKeyVault) CreateKey(ctx context.Context, name string, params azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	c.created.Add(1)
	return c.MockKeyVaultClient.CreateKey(ctx, name, params, options)
}

// TestSignCoRIM_RefusesAReleaseKeyAzureKVCannotScope proves first use on
// Azure Key Vault, whose keys carry no tenant, refuses before any key is
// created.
func TestSignCoRIM_RefusesAReleaseKeyAzureKVCannotScope(t *testing.T) {
	client := &countingKeyVault{MockKeyVaultClient: azurekv.NewMockKeyVaultClient()}
	provider, err := azurekv.NewBackendWithClient(&azurekv.Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, client)
	require.NoError(t, err)
	Reset()
	t.Cleanup(Reset)
	b, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, Initialize(&ServiceConfig{Backends: map[string]Backend{"azurekv": b}, DefaultBackend: "azurekv"}))
	svc, err := Get()
	require.NoError(t, err)
	wireKeyVersionStore(t)
	ctx := withSigningKeys(t, svc, corimSignPermission)

	for range 2 {
		_, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
		var provision *ReleaseKeyProvisionError
		require.ErrorAs(t, err, &provision)
		assert.ErrorIs(t, err, ErrReleaseKeyBackendUnsupported)
		assert.Equal(t, int32(0), client.created.Load(), "no Key Vault key is created")
	}
}
