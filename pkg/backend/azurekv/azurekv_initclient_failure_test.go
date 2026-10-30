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
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCredentialFailureBackend returns a backend with no Key Vault client
// whose service-principal tenant ID azidentity rejects, so every lazy
// initClient call fails.
func newCredentialFailureBackend(t *testing.T) *Backend {
	t.Helper()

	b, err := NewBackend(&Config{
		VaultURL:     "https://test-vault.vault.azure.net/",
		TenantID:     "11111111-1111-1111-1111-111111111111",
		ClientID:     "22222222-2222-2222-2222-222222222222",
		ClientSecret: secrettest.Literal(t, []byte("super-secret")),
		KeyStorage:   storage.New(),
		CertStorage:  storage.New(),
	})
	require.NoError(t, err)

	// Set after NewBackend so the test reaches azidentity's own tenant ID
	// check, which allows only alphanumerics, '-' and '.'.
	b.config.TenantID = "invalid tenant!"
	return b
}

// TestBackend_Operations_CredentialFailure verifies that every Key Vault
// operation returns the credential error when the client cannot be created,
// instead of calling through a nil client, and that the failed attempt
// leaves no client behind.
func TestBackend_Operations_CredentialFailure(t *testing.T) {
	ctx := context.Background()
	attrs := &types.KeyAttributes{
		CN:           "credential-failure",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	operations := map[string]func(b *Backend) error{
		"Get": func(b *Backend) error {
			_, err := b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
			return err
		},
		"Save": func(b *Backend) error {
			return b.Save(attrs, []byte("data"), backend.FSEXT_PRIVATE_BLOB, true)
		},
		"Delete": func(b *Backend) error {
			return b.Delete(attrs)
		},
		"CreateKey": func(b *Backend) error {
			_, err := b.CreateKey(attrs)
			return err
		},
		"Sign": func(b *Backend) error {
			_, err := b.Sign(attrs, make([]byte, 32))
			return err
		},
		"Verify": func(b *Backend) error {
			return b.Verify(attrs, make([]byte, 32), []byte("signature"))
		},
		"CreateSecretKey": func(b *Backend) error {
			_, err := b.CreateSecretKey(attrs, 32)
			return err
		},
		"GenerateKey": func(b *Backend) error {
			_, err := b.GenerateKey(ctx, attrs)
			return err
		},
		"GetKey": func(b *Backend) error {
			_, err := b.GetKey(ctx, attrs)
			return err
		},
		"Signer": func(b *Backend) error {
			_, err := b.Signer(ctx, attrs)
			return err
		},
		"Decrypter": func(b *Backend) error {
			_, err := b.Decrypter(ctx, attrs)
			return err
		},
		"RotateKey": func(b *Backend) error {
			return b.RotateKey(ctx, attrs)
		},
		"GetSignerByID": func(b *Backend) error {
			_, err := b.GetSignerByID(attrs.CN)
			return err
		},
		"GetDecrypterByID": func(b *Backend) error {
			_, err := b.GetDecrypterByID(attrs.CN)
			return err
		},
	}

	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			b := newCredentialFailureBackend(t)

			err := operation(b)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to create client secret credential")
			assert.Nil(t, b.client, "a failed initClient must not leave a client behind")
		})
	}
}

// TestBackend_GenerateSymmetricKey_Failures verifies that GenerateSymmetricKey
// rejects asymmetric attributes, surfaces a secrets-client credential failure
// without leaving a client behind, and fails when the key's metadata cannot
// be stored, so no AES key is handed out that the backend cannot find again.
func TestBackend_GenerateSymmetricKey_Failures(t *testing.T) {
	ctx := context.Background()
	symmetricAttrs := &types.KeyAttributes{
		CN:                 "symmetric-failure",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	t.Run("asymmetric attributes", func(t *testing.T) {
		b, _ := testBackend(t)
		key, err := b.GenerateSymmetricKey(ctx, &types.KeyAttributes{
			CN:           "asymmetric",
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			KeyAlgorithm: x509.RSA,
		})
		require.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("credential fails", func(t *testing.T) {
		b := newCredentialFailureBackend(t)
		key, err := b.GenerateSymmetricKey(ctx, symmetricAttrs)
		require.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "failed to create client secret credential")
		assert.Nil(t, b.secretsClient, "a failed initSecretsClient must not leave a client behind")
	})

	t.Run("metadata write fails", func(t *testing.T) {
		b, err := NewBackendWithClients(&Config{
			VaultURL:    "https://test-vault.vault.azure.net/",
			KeyStorage:  &failingStorage{Backend: storage.New(), putErr: errMetadataWrite},
			CertStorage: storage.New(),
		}, NewMockKeyVaultClient(), NewMockSecretsClient())
		require.NoError(t, err)

		key, err := b.GenerateSymmetricKey(ctx, symmetricAttrs)
		require.ErrorIs(t, err, errMetadataWrite)
		assert.Nil(t, key)
	})
}
