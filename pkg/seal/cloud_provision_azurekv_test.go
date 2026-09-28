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

//go:build azurekv

package seal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newAzureKVMockBackend builds an *azurekv.Backend against
// azurekv.NewMockKeyVaultClient and azurekv.NewMockSecretsClient
// (go-xkms#1090), reusing the backend package's own test doubles rather than
// a generic fake KeyProvider, so this proves the ACTUAL azurekv.Backend
// integrates correctly through BuildCloudKMSStrategy, not just the generic
// dispatch already covered by cloud_provision_test.go. Symmetric key
// material for azurekv goes through the Secrets API (SetSecret/GetSecret),
// never the Keys API (see azurekv_symmetric.go), so the secrets client --
// not the key-vault client -- is what GenerateSymmetricKey/GetSymmetricKey
// actually exercise here, and is what the returned *MockSecretsClient lets
// the tests observe.
func newAzureKVMockBackend(t *testing.T) (b *azurekv.Backend, secretsClient *azurekv.MockSecretsClient) {
	t.Helper()

	config := &azurekv.Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	secretsClient = azurekv.NewMockSecretsClient()
	b, err := azurekv.NewBackendWithClients(config, azurekv.NewMockKeyVaultClient(), secretsClient)
	require.NoError(t, err)
	return b, secretsClient
}

// TestBuildCloudKMSStrategy_AzureKVBackend_CreatesKeyOnFirstProvisioning
// proves BuildCloudKMSStrategy provisions the barrier's seal key through the
// real azurekv.Backend on first use (SetSecret runs exactly once, via
// EnsureSealKey's GetSymmetricKey/GenerateSymmetricKey check-and-skip) and
// that the resulting strategy performs a genuine Seal/Unseal round trip
// through AES-GCM using that key -- the round trip go-xkms#1090's
// SecretsClient seam makes possible without a live Azure Key Vault.
func TestBuildCloudKMSStrategy_AzureKVBackend_CreatesKeyOnFirstProvisioning(t *testing.T) {
	backend, secretsClient := newAzureKVMockBackend(t)
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	strategy, err := BuildCloudKMSStrategy(ctx, StrategyAzureKV, types.StoreAzureKV, backend)
	require.NoError(t, err)
	require.NotNil(t, strategy)
	require.True(t, strategy.Available())
	require.True(t, strategy.HardwareBacked())
	assert.Equal(t, 1, secretsClient.SetSecretCallCount(), "SetSecret must run once to provision the seal key")

	rootKey := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := strategy.SealRootKey(ctx, rootKey, Credentials{})
	require.NoError(t, err)
	require.NotNil(t, sealed)
	require.Equal(t, StrategyAzureKV, sealed.Strategy)

	unsealed, err := strategy.UnsealRootKey(ctx, sealed, Credentials{})
	require.NoError(t, err)
	require.Equal(t, rootKey, unsealed)
}

// TestBuildCloudKMSStrategy_AzureKVBackend_SecondProvisioningReusesKey
// proves that provisioning the same, still-live backend a second time (e.g.
// a second barrier operation in the same process) resolves the symmetric
// key SetSecret already created, through GetSymmetricKey, and does not call
// SetSecret again.
//
// Unlike awskms's equivalent restart test
// (TestBuildCloudKMSStrategy_AWSKMSBackend_RestartReusesPersistedKey in
// cloud_provision_awskms_test.go), azurekv.Backend keeps its key metadata
// only in an in-process map -- Config.KeyStorage/CertStorage are validated
// as required (config.go Validate) but nothing in the package ever reads or
// writes through them for key metadata, unlike awskms.Backend, which
// persists every CreateKey/CreateSecretKey result there (go-xkms#839). A
// genuinely restarted process (a new *azurekv.Backend over the same
// storage.Backend) would see no metadata and EnsureSealKey would generate a
// NEW seal key rather than reusing the first, orphaning data sealed under
// it. That is a pre-existing gap unrelated to go-xkms#1090's Secrets API
// seam; this test only proves reuse within one Backend's lifetime, which is
// what the seam makes newly testable.
func TestBuildCloudKMSStrategy_AzureKVBackend_SecondProvisioningReusesKey(t *testing.T) {
	backend, secretsClient := newAzureKVMockBackend(t)
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	_, err := BuildCloudKMSStrategy(ctx, StrategyAzureKV, types.StoreAzureKV, backend)
	require.NoError(t, err)
	require.Equal(t, 1, secretsClient.SetSecretCallCount())

	strategy, err := BuildCloudKMSStrategy(ctx, StrategyAzureKV, types.StoreAzureKV, backend)
	require.NoError(t, err)
	require.NotNil(t, strategy)
	assert.Equal(t, 1, secretsClient.SetSecretCallCount(),
		"second provisioning must reuse the persisted key, not call SetSecret again")
}

// TestBuildCloudKMSStrategy_AzureKVBackend_SetSecretError proves that a
// backend which cannot reach Azure Key Vault's Secrets API at all (SetSecret
// fails, simulating missing/invalid credentials or an unreachable vault)
// surfaces a real error from BuildCloudKMSStrategy itself: seal-key
// provisioning must reach the vault, so a failure is visible immediately
// rather than deferred to the first SealRootKey/UnsealRootKey call.
func TestBuildCloudKMSStrategy_AzureKVBackend_SetSecretError(t *testing.T) {
	backend, secretsClient := newAzureKVMockBackend(t)
	defer func() { _ = backend.Close() }()

	secretsClient.SetSetError(assert.AnError)

	ctx := context.Background()
	_, err := BuildCloudKMSStrategy(ctx, StrategyAzureKV, types.StoreAzureKV, backend)
	require.Error(t, err)
}
