// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !awskms && !gcpkms && !azurekv && !pkcs11 && !vault && !frost

package server

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/config"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Backend stub tests - only run when stubs are compiled in
// ============================================================================

// Test backend stub initialization with enabled configs

func TestServer_InitAWSKMSBackend_Stub(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.AWSKMS = &config.AWSKMSConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// AWS KMS stub should be called but not add a backend (since it's a stub)
	// The warning is logged but no error returned
	assert.NotNil(t, server.backends)
}

func TestServer_InitAzureKVBackend_Stub(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.AzureKV = &config.AzureKVConfig{
		Enabled:  true,
		VaultURL: "https://test.vault.azure.net",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Azure KV stub should be called but not add a backend (since it's a stub)
	assert.NotNil(t, server.backends)
}

func TestServer_InitGCPKMSBackend_Stub(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.GCPKMS = &config.GCPKMSConfig{
		Enabled:   true,
		ProjectID: "test-project",
		Location:  "us-east1",
		KeyRing:   "test-ring",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// GCP KMS stub should be called but not add a backend (since it's a stub)
	assert.NotNil(t, server.backends)
}

func TestServer_InitPKCS11Backend_Stub(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.PKCS11 = &config.PKCS11Config{
		Enabled: true,
		Library: "/usr/lib/softhsm/libsofthsm2.so",
		Token:   "test",
		Pin:     "1234",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// PKCS11 stub should be called but not add a backend (since it's a stub)
	assert.NotNil(t, server.backends)
}

func TestServer_InitVaultBackend_Stub(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.Vault = &config.VaultConfig{
		Enabled: true,
		Address: "http://localhost:8200",
		Token:   "test-token",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Vault stub should be called but not add a backend (since it's a stub)
	assert.NotNil(t, server.backends)
}

// Test backend factory stub functions

func TestCreateAWSKMSBackend_Stub(t *testing.T) {
	config := BackendConfig{
		Name:    "awskms",
		Type:    "awskms",
		Enabled: true,
		Config: map[string]interface{}{
			"region": "us-east-1",
		},
	}

	backend, err := createAWSKMSBackend(config)
	// Stub returns nil backend, nil error (gracefully skips)
	assert.NoError(t, err)
	assert.Nil(t, backend)
}

func TestCreateGCPKMSBackend_Stub(t *testing.T) {
	config := BackendConfig{
		Name:    "gcpkms",
		Type:    "gcpkms",
		Enabled: true,
		Config: map[string]interface{}{
			"project_id":  "test-project",
			"location_id": "us-east1",
			"key_ring_id": "test-ring",
		},
	}

	backend, err := createGCPKMSBackend(config)
	// Stub returns nil backend, nil error (gracefully skips)
	assert.NoError(t, err)
	assert.Nil(t, backend)
}

func TestCreateAzureKVBackend_Stub(t *testing.T) {
	config := BackendConfig{
		Name:    "azurekv",
		Type:    "azurekv",
		Enabled: true,
		Config:  map[string]interface{}{},
	}

	backend, err := createAzureKVBackend(config)
	// Stub returns nil backend, nil error (gracefully skips)
	assert.NoError(t, err)
	assert.Nil(t, backend)
}

func TestCreateVaultBackend_Stub(t *testing.T) {
	config := BackendConfig{
		Name:    "vault",
		Type:    "vault",
		Enabled: true,
		Config: map[string]interface{}{
			"address": "http://localhost:8200",
		},
	}

	backend, err := createVaultBackend(config)
	// Stub returns nil backend, nil error (gracefully skips)
	assert.NoError(t, err)
	assert.Nil(t, backend)
}

func TestCreateFrostBackend_Stub(t *testing.T) {
	config := BackendConfig{
		Name:    "frost",
		Type:    "frost",
		Enabled: true,
		Config:  map[string]interface{}{},
	}

	backend, err := createFrostBackend(config)
	// Stub returns nil backend, nil error (gracefully skips)
	assert.NoError(t, err)
	assert.Nil(t, backend)
}

func TestCreateSmartCardHSMBackend_Stub(t *testing.T) {
	config := BackendConfig{
		Name:    "smartcardhsm",
		Type:    "smartcardhsm",
		Enabled: true,
		Config:  map[string]interface{}{},
	}

	backend, err := createSmartCardHSMBackend(config)
	// Stub returns nil backend, nil error (gracefully skips)
	assert.NoError(t, err)
	assert.Nil(t, backend)
}

func TestCreatePKCS11Backend_Stub(t *testing.T) {
	config := BackendConfig{
		Name:    "pkcs11",
		Type:    "pkcs11",
		Enabled: true,
		Config:  map[string]interface{}{},
	}

	backend, err := createPKCS11Backend(config)
	// Stub returns nil backend, nil error (gracefully skips)
	assert.NoError(t, err)
	assert.Nil(t, backend)
}
