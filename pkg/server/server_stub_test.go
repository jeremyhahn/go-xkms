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

//go:build !awskms && !gcpkms && !azurekv && !pkcs11 && !vault && !frost

package server

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Backend stub tests - only run when stubs are compiled in
// ============================================================================

// Test backend stub initialization with enabled configs

func TestServer_InitAWSKMSBackend_Stub(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

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
	xkms.Reset()
	defer xkms.Reset()

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
	xkms.Reset()
	defer xkms.Reset()

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
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.PKCS11 = &config.PKCS11Config{
		Enabled: true,
		Library: "/usr/lib/softhsm/libsofthsm2.so",
		Token:   "test",
		Pin:     types.NewLiteralSecretValue([]byte("1234")),
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// PKCS11 stub should be called but not add a backend (since it's a stub)
	assert.NotNil(t, server.backends)
}

func TestServer_InitVaultBackend_Stub(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.Vault = &config.VaultConfig{
		Enabled: true,
		Address: "http://localhost:8200",
		Token:   types.NewLiteralSecretValue([]byte("test-token")),
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Vault stub should be called but not add a backend (since it's a stub)
	assert.NotNil(t, server.backends)
}
