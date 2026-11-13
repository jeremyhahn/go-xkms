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

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validAccountConfig() *AccountConfig {
	return &AccountConfig{
		DirectoryURL: "https://ca.example.com/directory",
		Email:        "admin@example.com",
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
	}
}

func testConfig() *Config {
	return &Config{
		Accounts:     make(map[string]*AccountConfig),
		Certificates: make(map[string]*CertificateSpec),
	}
}

// TestNewAccountManager verifies the constructor returns a non-nil AccountManager
// with an empty configuration.
func TestNewAccountManager(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger())
	require.NotNil(t, am)

	accounts := am.List()
	assert.Empty(t, accounts)
}

// TestAccountManager_Add_Success verifies that adding a valid account succeeds
// and the account can be retrieved afterward.
func TestAccountManager_Add_Success(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger())
	ctx := context.Background()

	acctCfg := validAccountConfig()
	err := am.Add(ctx, "production", acctCfg)
	require.NoError(t, err)

	got, err := am.Get("production")
	require.NoError(t, err)
	assert.Equal(t, acctCfg, got)
}

// TestAccountManager_Add_AlreadyExists verifies that adding an account with
// a duplicate name returns ErrAccountAlreadyExists.
func TestAccountManager_Add_AlreadyExists(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger())
	ctx := context.Background()

	err := am.Add(ctx, "production", validAccountConfig())
	require.NoError(t, err)

	err = am.Add(ctx, "production", validAccountConfig())
	var target ErrAccountAlreadyExists
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "production", target.Name)
}

// TestAccountManager_Add_InvalidConfig_NilConfig verifies that adding a nil
// account config returns ErrInvalidAccountConfig.
func TestAccountManager_Add_InvalidConfig_NilConfig(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger())
	ctx := context.Background()

	err := am.Add(ctx, "nil-account", nil)
	var target ErrInvalidAccountConfig
	require.True(t, errors.As(err, &target))
	assert.Contains(t, target.Reason, "nil")
}

// TestAccountManager_Remove_NotFound verifies that removing a non-existent
// account returns ErrAccountNotFound.
func TestAccountManager_Remove_NotFound(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger())
	ctx := context.Background()

	err := am.Remove(ctx, "nonexistent")
	var target ErrAccountNotFound
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.Name)
}

// TestAccountManager_Remove_ReferencedByCert verifies that an account referenced
// by a certificate spec cannot be removed.
func TestAccountManager_Remove_ReferencedByCert(t *testing.T) {
	cfg := testConfig()
	cfg.Certificates["web-cert"] = &CertificateSpec{
		Account: "production",
	}
	am := NewAccountManager(cfg, testLogger())
	ctx := context.Background()

	err := am.Add(ctx, "production", validAccountConfig())
	require.NoError(t, err)

	err = am.Remove(ctx, "production")
	var target ErrInvalidAccountConfig
	require.True(t, errors.As(err, &target))
	assert.Contains(t, target.Reason, "referenced by certificate specs")
}

// TestAccountManager_Get_NotFound verifies that Get returns ErrAccountNotFound
// for a non-existent account name.
func TestAccountManager_Get_NotFound(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger())

	_, err := am.Get("ghost")
	var target ErrAccountNotFound
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "ghost", target.Name)
}

// TestAccountManager_List_Multiple verifies that List returns all added accounts.
func TestAccountManager_List_Multiple(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger())
	ctx := context.Background()

	err := am.Add(ctx, "alpha", validAccountConfig())
	require.NoError(t, err)

	betaCfg := validAccountConfig()
	betaCfg.Email = "beta@example.com"
	err = am.Add(ctx, "beta", betaCfg)
	require.NoError(t, err)

	accounts := am.List()
	assert.Len(t, accounts, 2)
	assert.Contains(t, accounts, "alpha")
	assert.Contains(t, accounts, "beta")
}

// TestGenerateSigner_ECDSA_P384 verifies that ECDSA with P-384 curve produces
// the correct key type and curve.
func TestGenerateSigner_ECDSA_P384(t *testing.T) {
	keyCfg := &KeyConfig{
		Algorithm: "ECDSA",
		Store:     "software",
		ECC:       &ECCConfig{Curve: "P-384"},
	}
	signer, err := generateSigner(keyCfg)
	require.NoError(t, err)

	key, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected *ecdsa.PrivateKey")
	assert.Equal(t, elliptic.P384(), key.Curve)
}

// TestGenerateSigner_ECDSA_P521 verifies that ECDSA with P-521 curve produces
// the correct key type and curve.
func TestGenerateSigner_ECDSA_P521(t *testing.T) {
	keyCfg := &KeyConfig{
		Algorithm: "ECDSA",
		Store:     "software",
		ECC:       &ECCConfig{Curve: "P-521"},
	}
	signer, err := generateSigner(keyCfg)
	require.NoError(t, err)

	key, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected *ecdsa.PrivateKey")
	assert.Equal(t, elliptic.P521(), key.Curve)
}

// TestGenerateSigner_ECDSA_DefaultCurve verifies that ECDSA with nil ECC config
// defaults to P-256.
func TestGenerateSigner_ECDSA_DefaultCurve(t *testing.T) {
	keyCfg := &KeyConfig{
		Algorithm: "ECDSA",
		Store:     "software",
	}
	signer, err := generateSigner(keyCfg)
	require.NoError(t, err)

	key, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected *ecdsa.PrivateKey")
	assert.Equal(t, elliptic.P256(), key.Curve)
}

// TestGenerateSigner_RSA_Default verifies that RSA without explicit key size
// defaults to 2048 bits.
func TestGenerateSigner_RSA_Default(t *testing.T) {
	keyCfg := &KeyConfig{
		Algorithm: "RSA",
		Store:     "software",
	}
	signer, err := generateSigner(keyCfg)
	require.NoError(t, err)

	key, ok := signer.(*rsa.PrivateKey)
	require.True(t, ok, "expected *rsa.PrivateKey")
	assert.Equal(t, 2048, key.N.BitLen())
}

// TestGenerateSigner_RSA_4096 verifies that RSA with explicit 4096-bit key size
// produces a key of the correct length.
func TestGenerateSigner_RSA_4096(t *testing.T) {
	keyCfg := &KeyConfig{
		Algorithm: "RSA",
		Store:     "software",
		RSA:       &RSAConfig{KeySize: 4096},
	}
	signer, err := generateSigner(keyCfg)
	require.NoError(t, err)

	key, ok := signer.(*rsa.PrivateKey)
	require.True(t, ok, "expected *rsa.PrivateKey")
	assert.Equal(t, 4096, key.N.BitLen())
}

// TestGenerateSigner_RSA_RefusesOversizedKey proves generateSigner refuses
// an RSA key size above the project's RSAKeySize4096 ceiling before
// rsa.GenerateKey ever runs. rsa.GenerateKey cannot be cancelled and its
// cost grows with the cube of the modulus size, so an unvalidated
// account/certificate KeyConfig let a single request pin a CPU core for
// minutes to hours (go-xkms#1260).
func TestGenerateSigner_RSA_RefusesOversizedKey(t *testing.T) {
	keyCfg := &KeyConfig{
		Algorithm: "RSA",
		Store:     "software",
		RSA:       &RSAConfig{KeySize: 65536},
	}
	_, err := generateSigner(keyCfg)
	require.Error(t, err)

	var keyGenErr ErrKeyGeneration
	require.True(t, errors.As(err, &keyGenErr), "expected ErrKeyGeneration, got %T: %v", err, err)

	var sizeErr *types.RSAKeySizeError
	require.True(t, errors.As(err, &sizeErr), "expected *types.RSAKeySizeError, got %T: %v", err, err)
	assert.Equal(t, 65536, sizeErr.Requested)
}

// TestGenerateSigner_Ed25519 verifies that Ed25519 produces a valid
// ed25519.PrivateKey signer.
func TestGenerateSigner_Ed25519(t *testing.T) {
	keyCfg := &KeyConfig{
		Algorithm: "ED25519",
		Store:     "software",
	}
	signer, err := generateSigner(keyCfg)
	require.NoError(t, err)

	_, ok := signer.(ed25519.PrivateKey)
	require.True(t, ok, "expected ed25519.PrivateKey")
}

// TestGenerateSigner_UnsupportedAlgorithm verifies that an unknown algorithm
// returns ErrKeyGeneration.
func TestGenerateSigner_UnsupportedAlgorithm(t *testing.T) {
	keyCfg := &KeyConfig{
		Algorithm: "UNKNOWN",
		Store:     "software",
	}
	_, err := generateSigner(keyCfg)
	var target ErrKeyGeneration
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "UNKNOWN", target.Algorithm)
	assert.Contains(t, target.Error(), "unsupported algorithm")
}

// TestGenerateSigner_CaseInsensitive verifies that algorithm matching is
// case-insensitive (e.g., "ecdsa" works the same as "ECDSA").
func TestGenerateSigner_CaseInsensitive(t *testing.T) {
	keyCfg := &KeyConfig{
		Algorithm: "ecdsa",
		Store:     "software",
		ECC:       &ECCConfig{Curve: "P-256"},
	}
	signer, err := generateSigner(keyCfg)
	require.NoError(t, err)

	key, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected *ecdsa.PrivateKey")
	assert.Equal(t, elliptic.P256(), key.Curve)
}

// TestGenerateSigner_ECDSA_InvalidCurve verifies that an unsupported ECDSA
// curve returns ErrKeyGeneration.
func TestGenerateSigner_ECDSA_InvalidCurve(t *testing.T) {
	keyCfg := &KeyConfig{
		Algorithm: "ECDSA",
		Store:     "software",
		ECC:       &ECCConfig{Curve: "P-999"},
	}
	_, err := generateSigner(keyCfg)
	var target ErrKeyGeneration
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "ECDSA", target.Algorithm)
	assert.Contains(t, target.Error(), "unsupported curve")
}

// TestValidateAccountConfig_MissingFields uses a table-driven approach to
// verify that each required field produces a validation error when absent.
func TestValidateAccountConfig_MissingFields(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(cfg *AccountConfig)
		contains string
	}{
		{
			name: "missing directory URL",
			mutate: func(cfg *AccountConfig) {
				cfg.DirectoryURL = ""
			},
			contains: "directory URL",
		},
		{
			name: "missing email",
			mutate: func(cfg *AccountConfig) {
				cfg.Email = ""
			},
			contains: "email",
		},
		{
			name: "nil key config",
			mutate: func(cfg *AccountConfig) {
				cfg.Key = nil
			},
			contains: "key configuration",
		},
		{
			name: "missing algorithm",
			mutate: func(cfg *AccountConfig) {
				cfg.Key.Algorithm = ""
			},
			contains: "key algorithm",
		},
		{
			name: "missing store",
			mutate: func(cfg *AccountConfig) {
				cfg.Key.Store = ""
			},
			contains: "key store",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validAccountConfig()
			tt.mutate(cfg)

			err := validateAccountConfig("test-account", cfg)
			require.Error(t, err)

			var target ErrInvalidAccountConfig
			require.True(t, errors.As(err, &target))
			assert.Equal(t, "test-account", target.Name)
			assert.Contains(t, target.Reason, tt.contains)
		})
	}
}

// TestCreateStateBackend_FilesystemToLocal verifies that the "filesystem"
// backend string is remapped to the always-available "local" object-storage
// provider before being opened through the storage engine. The error (if any)
// must come from the storage layer, never an "unsupported provider".
func TestCreateStateBackend_FilesystemToLocal(t *testing.T) {
	storageCfg := StorageConfig{
		Backend: "filesystem",
		Options: map[string]interface{}{
			"path": t.TempDir(),
		},
	}
	backend, err := createStateBackend(storageCfg)
	if err != nil {
		assert.NotContains(t, err.Error(), "unsupported provider")
		return
	}
	_ = backend.Close()
}
