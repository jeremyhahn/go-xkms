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

//go:build vault

package vault

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigValidate covers every guard clause in Config.Validate,
// including the TransitPath default-fill branch, since a wrong default
// silently points the backend at the wrong secrets engine mount.
func TestConfigValidate(t *testing.T) {
	base := func() *Config {
		return &Config{
			Address:     "http://127.0.0.1:8200",
			Token:       "test-token",
			KeyStorage:  storage.New(),
			CertStorage: storage.New(),
		}
	}

	t.Run("valid config fills default TransitPath", func(t *testing.T) {
		c := base()
		require.NoError(t, c.Validate())
		assert.Equal(t, "transit", c.TransitPath)
	})

	t.Run("explicit TransitPath is preserved", func(t *testing.T) {
		c := base()
		c.TransitPath = "custom-transit"
		require.NoError(t, c.Validate())
		assert.Equal(t, "custom-transit", c.TransitPath)
	})

	t.Run("missing address", func(t *testing.T) {
		c := base()
		c.Address = ""
		assert.Error(t, c.Validate())
	})

	t.Run("missing token", func(t *testing.T) {
		c := base()
		c.Token = ""
		assert.Error(t, c.Validate())
	})

	t.Run("missing key storage", func(t *testing.T) {
		c := base()
		c.KeyStorage = nil
		assert.Error(t, c.Validate())
	})

	t.Run("missing cert storage", func(t *testing.T) {
		c := base()
		c.CertStorage = nil
		assert.Error(t, c.Validate())
	})
}

// TestVaultType verifies Type() reports the Vault store type.
func TestVaultType(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	assert.Equal(t, BackendTypeVault, b.Type())
}

// TestVaultGetKeyLifecycle verifies GetKey's not-found and success paths,
// and that GetSignerByID/GetDecrypterByID correctly reject a key whose
// "private key" (actually Vault's public key stand-in) does not implement
// crypto.Signer/crypto.Decrypter directly -- Vault backend keys are never
// extractable, so these always fail the type assertion once GetKey
// succeeds.
func TestVaultGetKeyLifecycle(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "getkey-lifecycle",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}
	_ = b.DeleteKey(context.Background(), attrs)

	if _, err := b.GetKey(context.Background(), attrs); !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("GetKey() before creation error = %v, want ErrKeyNotFound", err)
	}
	if _, err := b.GetKey(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GetKey(nil) error = %v, want ErrInvalidAttributes", err)
	}

	_, err = b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	if _, err := b.GetKey(context.Background(), attrs); err != nil {
		t.Errorf("GetKey() after creation unexpected error = %v", err)
	}

	if _, err := b.GetSignerByID(context.Background(), "does-not-exist"); err == nil {
		t.Error("GetSignerByID() expected error for unknown key, got nil")
	}
	if _, err := b.GetSignerByID(context.Background(), attrs.CN); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("GetSignerByID() error = %v, want ErrInvalidKeyType", err)
	}
	if _, err := b.GetDecrypterByID(context.Background(), "does-not-exist"); err == nil {
		t.Error("GetDecrypterByID() expected error for unknown key, got nil")
	}
	if _, err := b.GetDecrypterByID(context.Background(), attrs.CN); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("GetDecrypterByID() error = %v, want ErrInvalidKeyType", err)
	}
}

// TestVaultListKeys verifies ListKeys reconstructs KeyAttributes from
// stored metadata -- preserving key type and key algorithm rather than
// silently dropping them, the "silently dropped field" bug class the issue
// calls out for awskms.
func TestVaultListKeys(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	// Both keys use RSA: the in-process Transit double (see
	// transit_double_vault_test.go) only mints real key material for
	// "rsa-*" Transit types, so an "ecdsa-*" GenerateKey call here would
	// fail for a double limitation unrelated to what this test verifies.
	rsaAttrs := &types.KeyAttributes{
		CN:           "list-keys-rsa",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}
	rsaAttrs2 := &types.KeyAttributes{
		CN:           "list-keys-rsa-2",
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}
	_ = b.DeleteKey(context.Background(), rsaAttrs)
	_ = b.DeleteKey(context.Background(), rsaAttrs2)

	_, err = b.GenerateKey(context.Background(), rsaAttrs)
	require.NoError(t, err)
	_, err = b.GenerateKey(context.Background(), rsaAttrs2)
	require.NoError(t, err)

	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)

	found := make(map[string]*types.KeyAttributes, len(keys))
	for _, k := range keys {
		found[b.sanitizeKeyName(k.CN)] = k
	}

	rsaGot, ok := found[b.sanitizeKeyName(rsaAttrs.CN)]
	if !ok {
		t.Fatalf("ListKeys() missing %s (got keys: %v)", rsaAttrs.CN, found)
	}
	if rsaGot.KeyType != backend.KEY_TYPE_SIGNING {
		t.Errorf("ListKeys() %s KeyType = %v, want SIGNING (dropped on read)", rsaAttrs.CN, rsaGot.KeyType)
	}
	if rsaGot.KeyAlgorithm != x509.RSA {
		t.Errorf("ListKeys() %s KeyAlgorithm = %v, want RSA (dropped on read)", rsaAttrs.CN, rsaGot.KeyAlgorithm)
	}
}

// TestVaultSealer_RoundTrip exercises CanSeal, Seal and Unseal end to end
// through the in-process Transit double, and both Marshal/UnmarshalSealedData.
func TestVaultSealer_RoundTrip(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	if !b.CanSeal() {
		t.Fatal("CanSeal() = false, want true once a client is configured")
	}

	attrs := &types.KeyAttributes{
		CN:                 "sealer-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	_ = b.DeleteKey(context.Background(), attrs)
	_, err = b.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)

	plaintext := []byte("seal me")
	sealed, err := b.Seal(context.Background(), plaintext, &types.SealOptions{KeyAttributes: attrs})
	require.NoError(t, err)
	if sealed.Backend != BackendTypeVault {
		t.Errorf("Seal() Backend = %v, want %v", sealed.Backend, BackendTypeVault)
	}

	marshaled, err := MarshalSealedData(sealed)
	require.NoError(t, err)
	roundTripped, err := UnmarshalSealedData(marshaled)
	require.NoError(t, err)

	recovered, err := b.Unseal(context.Background(), roundTripped, &types.UnsealOptions{KeyAttributes: attrs})
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)

	// Guard clauses.
	if _, err := b.Seal(context.Background(), plaintext, nil); err == nil {
		t.Error("Seal(nil opts) expected error, got nil")
	}
	if _, err := b.Unseal(context.Background(), nil, &types.UnsealOptions{KeyAttributes: attrs}); err == nil {
		t.Error("Unseal(nil sealed) expected error, got nil")
	}
}

// TestVaultExportKeyTo verifies ExportKeyTo's guard clauses and its
// unconditional ErrExportToUnsupported result -- Vault never releases
// plaintext key material for re-wrapping under a destination's parameters.
func TestVaultExportKeyTo(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	if _, err := b.ExportKeyTo(context.Background(), nil, &backend.ImportParameters{}); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKeyTo(nil attrs) error = %v, want ErrInvalidAttributes", err)
	}

	attrs := &types.KeyAttributes{CN: "export-to-vault"}
	if _, err := b.ExportKeyTo(context.Background(), attrs, nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKeyTo(nil dstParams) error = %v, want ErrInvalidAttributes", err)
	}
	if _, err := b.ExportKeyTo(context.Background(), attrs, &backend.ImportParameters{}); !errors.Is(err, backend.ErrExportToUnsupported) {
		t.Errorf("ExportKeyTo() error = %v, want ErrExportToUnsupported", err)
	}
}

// TestGetVaultKeyType_AllBranches verifies the key-spec mapping vault uses
// to select a Transit key type, including every supported RSA size and EC
// curve and the unsupported-value rejections, since a wrong mapping here
// would silently create a different (weaker or incompatible) key than the
// caller requested.
func TestGetVaultKeyType_AllBranches(t *testing.T) {
	b := &Backend{}

	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		want    string
		wantErr bool
	}{
		{"RSA default 2048", &types.KeyAttributes{KeyAlgorithm: x509.RSA}, "rsa-2048", false},
		{"RSA 3072", &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 3072}}, "rsa-3072", false},
		{"RSA 4096", &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 4096}}, "rsa-4096", false},
		{"RSA unsupported size", &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 1024}}, "", true},
		{"ECDSA default P256", &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}, "ecdsa-p256", false},
		{"ECDSA P256", &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}}, "ecdsa-p256", false},
		{"ECDSA P384", &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()}}, "ecdsa-p384", false},
		{"ECDSA P521", &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P521()}}, "ecdsa-p521", false},
		{"Ed25519", &types.KeyAttributes{KeyAlgorithm: x509.Ed25519}, "ed25519", false},
		{"unsupported algorithm", &types.KeyAttributes{KeyAlgorithm: x509.DSA}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := b.getVaultKeyType(tt.attrs)
			if tt.wantErr {
				if err == nil {
					t.Error("getVaultKeyType() expected error, got nil")
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestVaultDecrypter_Public verifies Decrypter() resolves the public key
// and exposes it through Public(), covering the guard clause against a
// missing CN.
func TestVaultDecrypter_Public(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "decrypter-public",
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}
	_ = b.DeleteKey(context.Background(), attrs)
	_, err = b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	decrypter, err := b.Decrypter(context.Background(), attrs)
	require.NoError(t, err)
	if decrypter.Public() == nil {
		t.Error("Decrypter().Public() returned nil")
	}

	if _, err := b.Decrypter(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("Decrypter(nil) error = %v, want ErrInvalidAttributes", err)
	}
	if _, err := b.Decrypter(context.Background(), &types.KeyAttributes{CN: "does-not-exist"}); !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Decrypter(unknown key) error = %v, want ErrKeyNotFound", err)
	}
}
