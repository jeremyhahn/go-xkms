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

package azurekv

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackend_Signer_ResolveKeyVersion_NotFound verifies that an HTTP 404
// ResponseError encountered while resolving a key's current version (the
// GetKey call resolveKeyVersion makes on behalf of Signer/Decrypter) is
// classified as backend.ErrKeyNotFound, matching GetKey's own contract
// (go-xkms#808).
func TestBackend_Signer_ResolveKeyVersion_NotFound(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	mockClient.SetGetError(&azcore.ResponseError{StatusCode: http.StatusNotFound, ErrorCode: "KeyNotFound"})

	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "not-found-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: 0,
	}

	_, err = b.Signer(context.Background(), attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "expected errors.Is(err, backend.ErrKeyNotFound), got %v", err)
}

// TestBackend_Signer_ResolveKeyVersion_RetrievalError verifies that a Key
// Vault client failure that is NOT an HTTP 404 (throttling, an RBAC denial,
// a transport fault) encountered while resolving a key's current version is
// classified as ErrKeyRetrievalFailed and does NOT satisfy
// errors.Is(err, backend.ErrKeyNotFound) -- go-xkms#808. Collapsing this into
// "not found" would let a get-or-create caller silently generate a
// replacement key over one the backend merely failed to reach.
func TestBackend_Signer_ResolveKeyVersion_RetrievalError(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	mockClient.SetGetError(&azcore.ResponseError{StatusCode: http.StatusTooManyRequests, ErrorCode: "Throttled"})

	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "transient-failure-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: 0,
	}

	_, err = b.Signer(context.Background(), attrs)
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "a throttled GetKey failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}
