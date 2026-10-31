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
	"crypto/x509"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errPublicKeyUnavailable = errors.New("public key unavailable")

// publicKeyFaultClient is a MockKeyVaultClient whose GetPublicKey returns a
// fixed result, so a test can make the public-key fetch fail after the key's
// version has resolved.
type publicKeyFaultClient struct {
	*MockKeyVaultClient
	pubKey []byte
	err    error
}

func (c *publicKeyFaultClient) GetPublicKey(context.Context, string, string) ([]byte, error) {
	return c.pubKey, c.err
}

// newPublicKeyFaultBackend returns a backend holding one EC P-256 key named
// cn, whose GetPublicKey returns pubKey and err.
func newPublicKeyFaultBackend(t *testing.T, cn string, pubKey []byte, err error) *Backend {
	t.Helper()

	mockClient := NewMockKeyVaultClient()
	kty := azkeys.KeyTypeEC
	curve := azkeys.CurveNameP256
	_, createErr := mockClient.CreateKey(context.Background(), cn, azkeys.CreateKeyParameters{Kty: &kty, Curve: &curve}, nil)
	require.NoError(t, createErr)

	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, newErr := NewBackendWithClient(config, &publicKeyFaultClient{MockKeyVaultClient: mockClient, pubKey: pubKey, err: err})
	require.NoError(t, newErr)
	return b
}

// TestBackend_SignerDecrypter_PublicKeyFailures verifies that Signer and
// Decrypter return an error, and no crypto handle, when the pinned version's
// public key cannot be fetched or is not a parseable PEM key. A handle built
// without a public key would sign or decrypt with a Public() that is nil.
func TestBackend_SignerDecrypter_PublicKeyFailures(t *testing.T) {
	tests := []struct {
		name    string
		pubKey  []byte
		err     error
		wantErr error
	}{
		{name: "fetch fails", err: errPublicKeyUnavailable, wantErr: errPublicKeyUnavailable},
		{name: "not PEM", pubKey: []byte("not a PEM public key")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newPublicKeyFaultBackend(t, "pubkey-fault", tt.pubKey, tt.err)
			attrs := &types.KeyAttributes{
				CN:           "pubkey-fault",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				KeyAlgorithm: x509.RSA,
			}

			signer, err := b.Signer(context.Background(), attrs)
			require.Error(t, err)
			assert.Nil(t, signer)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}

			decrypter, err := b.Decrypter(context.Background(), attrs)
			require.Error(t, err)
			assert.Nil(t, decrypter)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

var (
	errCreateRejected = errors.New("create rejected")
	errMetadataWrite  = errors.New("metadata write failed")
)

// TestBackend_CreateSecretKey_Failures verifies that CreateSecretKey surfaces
// a Key Vault create failure without recording metadata for a key that does
// not exist, and that a metadata write failure after the key was created
// still returns the new key's ID beside the error, so the caller can find
// the key it now owns in the vault.
func TestBackend_CreateSecretKey_Failures(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:        "secret-key-failure",
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_AZUREKV,
	}

	t.Run("create fails", func(t *testing.T) {
		keyStorage := storage.New()
		mockClient := NewMockKeyVaultClient()
		mockClient.SetCreateError(errCreateRejected)
		b, err := NewBackendWithClient(&Config{
			VaultURL:    "https://test-vault.vault.azure.net/",
			KeyStorage:  keyStorage,
			CertStorage: storage.New(),
		}, mockClient)
		require.NoError(t, err)

		keyID, err := b.CreateSecretKey(attrs, 32)
		require.ErrorIs(t, err, errCreateRejected)
		assert.Empty(t, keyID)

		_, err = storage.GetKey(context.Background(), keyStorage, attrs.CN)
		assert.Error(t, err, "no metadata may be stored for a key Key Vault did not create")
	})

	t.Run("metadata write fails", func(t *testing.T) {
		b, err := NewBackendWithClient(&Config{
			VaultURL:    "https://test-vault.vault.azure.net/",
			KeyStorage:  &failingStorage{Backend: storage.New(), putErr: errMetadataWrite},
			CertStorage: storage.New(),
		}, NewMockKeyVaultClient())
		require.NoError(t, err)

		keyID, err := b.CreateSecretKey(attrs, 32)
		require.ErrorIs(t, err, errMetadataWrite)
		assert.NotEmpty(t, keyID, "the created key's ID must be returned with the metadata error")
	})
}

var errVaultUnavailable = errors.New("vault unavailable")

// verifyFaultClient is a MockKeyVaultClient whose Verify returns a fixed
// result.
type verifyFaultClient struct {
	*MockKeyVaultClient
	valid *bool
	err   error
}

func (c *verifyFaultClient) Verify(context.Context, string, string, azkeys.VerifyParameters, *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
	return azkeys.VerifyResponse{KeyVerifyResult: azkeys.KeyVerifyResult{Value: c.valid}}, c.err
}

// TestBackend_Verify_Results verifies that Verify accepts a signature only
// when Key Vault answers true: a false or missing verdict is
// ErrSignatureFailed, and a failed call is returned, never read as valid.
func TestBackend_Verify_Results(t *testing.T) {
	valid, invalid := true, false
	tests := []struct {
		name    string
		valid   *bool
		err     error
		wantErr error
	}{
		{name: "valid", valid: &valid},
		{name: "invalid", valid: &invalid, wantErr: ErrSignatureFailed},
		{name: "no verdict", wantErr: ErrSignatureFailed},
		{name: "call fails", err: errVaultUnavailable, wantErr: errVaultUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &verifyFaultClient{MockKeyVaultClient: NewMockKeyVaultClient(), valid: tt.valid, err: tt.err}
			b, err := NewBackendWithClient(&Config{
				VaultURL:    "https://test-vault.vault.azure.net/",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}, client)
			require.NoError(t, err)

			attrs := &types.KeyAttributes{
				CN:           "verify-results",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				KeyAlgorithm: x509.RSA,
			}
			err = b.Verify(attrs, make([]byte, 32), []byte("signature"))
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestBackend_Get_PublicKeyFetchFails verifies that Get for a public-key
// extension reports ErrFileNotFound when Key Vault cannot return the key.
func TestBackend_Get_PublicKeyFetchFails(t *testing.T) {
	b := newPublicKeyFaultBackend(t, "get-fault", nil, errVaultUnavailable)
	attrs := &types.KeyAttributes{CN: "get-fault", KeyType: backend.KEY_TYPE_SIGNING, StoreType: backend.STORE_AZUREKV}

	data, err := b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
	require.ErrorIs(t, err, backend.ErrFileNotFound)
	assert.Nil(t, data)
}

// TestBackend_Sign_ClientFails verifies that a Key Vault sign failure is
// returned and yields no signature.
func TestBackend_Sign_ClientFails(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	mockClient.SetSignError(errVaultUnavailable)
	b, err := NewBackendWithClient(&Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{CN: "sign-fault", KeyType: backend.KEY_TYPE_SIGNING, StoreType: backend.STORE_AZUREKV, KeyAlgorithm: x509.RSA}
	signature, err := b.Sign(attrs, make([]byte, 32))
	require.ErrorIs(t, err, errVaultUnavailable)
	assert.Nil(t, signature)
}
