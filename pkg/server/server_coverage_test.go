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

package server

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Tests — accessor methods
// ============================================================================

func TestServer_Barrier_NilByDefault(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.Barrier())
}

func TestServer_BarrierRegistry_NilByDefault(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.BarrierRegistry())
}

func TestServer_BootstrapService_NilByDefault(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.BootstrapService())
}

func TestServer_PINManager_NilByDefault(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.PINManager())
}

func TestServer_PasswordStore_NotNil(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.PasswordStore())
}

func TestServer_PlatformStore_NilWithoutBarrier(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.PlatformStore())
}

func TestServer_PolicyManager_NilByDefault(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.PolicyManager())
}

// ============================================================================
// Tests — createCompositeAuthenticator
// ============================================================================

func TestServer_CreateCompositeAuthenticator_NilConfig(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "composite"
	cfg.Auth.Composite = nil

	_, err := New(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCompositeMethodsRequired))
}

func TestServer_CreateCompositeAuthenticator_EmptyMethods(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "composite"
	cfg.Auth.Composite = &config.CompositeAuthConfig{
		Methods: []string{},
	}

	_, err := New(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCompositeMethodsRequired))
}

func TestServer_CreateCompositeAuthenticator_UnknownMethod(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "composite"
	cfg.Auth.Composite = &config.CompositeAuthConfig{
		Methods: []string{"biometric"},
	}

	_, err := New(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnknownCompositeMethod))
}

func TestServer_CreateCompositeAuthenticator_JWTMissingConfig(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "composite"
	cfg.Auth.Composite = &config.CompositeAuthConfig{
		Methods: []string{"jwt"},
	}
	cfg.Auth.JWT = nil

	_, err := New(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCompositeJWTRequired))
}

func TestServer_CreateCompositeAuthenticator_MTLSNoTLS(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "composite"
	cfg.Auth.Composite = &config.CompositeAuthConfig{
		Methods: []string{"mtls"},
	}
	cfg.TLS.Enabled = false

	_, err := New(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCompositeMTLSRequiresTLS))
}

func TestServer_CreateCompositeAuthenticator_MTLSSuccess(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "composite"
	cfg.Auth.Composite = &config.CompositeAuthConfig{
		Methods: []string{"mtls"},
	}
	cfg.TLS.Enabled = true

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	assert.Equal(t, "composite", server.authenticator.Name())
}

// ============================================================================
// Tests — initializeAuditLogger
// ============================================================================

func TestServer_InitializeAuditLogger_Enabled(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	tmpDir := t.TempDir()
	cfg := createMinimalConfig(t)
	cfg.Auth.Audit = &config.AuditConfig{
		Enabled: true,
		Path:    filepath.Join(tmpDir, "audit.log"),
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.auditLogger)
}

func TestServer_InitializeAuditLogger_EnabledMissingPath(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Audit = &config.AuditConfig{
		Enabled: true,
		Path:    "",
	}

	_, err := New(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuditPathRequired))
}

// ============================================================================
// Tests — initializeBarrier
// ============================================================================

func TestServer_InitializeBarrier_Enabled(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Barrier.Enabled = true
	cfg.Barrier.RootKeyPath = "barrier/root-key"

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.Barrier())
	assert.NotNil(t, server.BarrierRegistry())
}

func TestServer_InitializeBarrier_WithPreferenceOrder(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Barrier.Enabled = true
	cfg.Barrier.RootKeyPath = ""
	cfg.Barrier.PreferenceOrder = []string{"software"}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.Barrier())
}

// ============================================================================
// Tests — initializeBootstrapService
// ============================================================================

func TestServer_InitializeBootstrapService_Enabled(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.InitBootstrap.Enabled = true
	cfg.InitBootstrap.TokenTTL = 300
	cfg.InitBootstrap.ThresholdMode = true
	cfg.InitBootstrap.AdminThreshold = 2
	cfg.InitBootstrap.AdminTotal = 3

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.BootstrapService())
}

// ============================================================================
// Tests — initializePINManager
// ============================================================================

func TestServer_InitializePINManager_Enabled(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.PIN.Enabled = true
	cfg.PIN.Strategy = "software"

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.PINManager())
}

func TestServer_InitializePINManager_DefaultStrategy(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.PIN.Enabled = true
	cfg.PIN.Strategy = "" // should default to "software"

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.PINManager())
}

func TestServer_InitializePINManager_UnknownStrategy(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.PIN.Enabled = true
	cfg.PIN.Strategy = "biometric"

	_, err := New(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "biometric")
}

// ============================================================================
// Tests — initializeAuthorization
// ============================================================================

func TestServer_InitializeAuthorization_RBACEnabled(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.EnableRBAC = true

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authorizer)
}

// ============================================================================
// Tests — createStorage / createStorageAt
// ============================================================================

func TestServer_CreateStorage_Memory(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Storage.Backend = "memory"

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	store, err := server.createStorage("test")
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestServer_CreateStorage_Pebble(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	tmpDir := t.TempDir()
	cfg := createMinimalConfig(t)
	cfg.Storage.Backend = "pebble"
	cfg.Storage.Path = tmpDir

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	store, err := server.createStorage("testpebble")
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestServer_CreateStorage_Unsupported(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{Backend: "redis"},
	}
	s := newMinimalServer(t, cfg)

	_, err := s.createStorage("test")
	assert.Error(t, err)
	var errUnsupported *ErrUnsupportedStorageBackend
	assert.True(t, errors.As(err, &errUnsupported))
}

func TestServer_CreateStorageAt_Memory(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{Backend: "memory"},
	}
	s := newMinimalServer(t, cfg)

	store, err := s.createStorageAt("/any/path")
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestServer_CreateStorageAt_Pebble(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{
		Storage: config.StorageConfig{Backend: "pebble"},
	}
	s := newMinimalServer(t, cfg)

	store, err := s.createStorageAt(filepath.Join(tmpDir, "pebble-at"))
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestServer_CreateStorageAt_File(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{
		Storage: config.StorageConfig{Backend: "file"},
	}
	s := newMinimalServer(t, cfg)

	store, err := s.createStorageAt(filepath.Join(tmpDir, "file-at"))
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestServer_CreateStorageAt_EmptyBackend(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{
		Storage: config.StorageConfig{Backend: ""},
	}
	s := newMinimalServer(t, cfg)

	store, err := s.createStorageAt(filepath.Join(tmpDir, "empty-at"))
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestServer_CreateStorageAt_Unsupported(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{Backend: "redis"},
	}
	s := newMinimalServer(t, cfg)

	_, err := s.createStorageAt("/any/path")
	assert.Error(t, err)
}

// ============================================================================
// Tests — Initialize (backend factory)
// ============================================================================

func TestInitialize_NilConfig(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	err := Initialize(nil)
	if err != nil {
		assert.Contains(t, err.Error(), "no backends available")
	}
}

func TestInitialize_WithSoftware(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	tmpDir := t.TempDir()
	factoryCfg := &BackendFactoryConfig{
		DefaultBackend: "software",
		Backends: []BackendConfig{
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tmpDir, "software"),
				},
			},
		},
	}

	err := Initialize(factoryCfg)
	assert.NoError(t, err)
}

func TestInitialize_DisabledBackends(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	factoryCfg := &BackendFactoryConfig{
		DefaultBackend: "software",
		Backends: []BackendConfig{
			{
				Name:    "software",
				Type:    "software",
				Enabled: false,
			},
		},
	}

	err := Initialize(factoryCfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backends available")
}

func TestInitialize_DefaultFallback(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	tmpDir := t.TempDir()
	factoryCfg := &BackendFactoryConfig{
		DefaultBackend: "nonexistent",
		Backends: []BackendConfig{
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tmpDir, "software"),
				},
			},
		},
	}

	err := Initialize(factoryCfg)
	assert.NoError(t, err)
}

// ============================================================================
// Tests — createKeyStorage / createCertStorage
// ============================================================================

func TestCreateKeyStorage_Memory(t *testing.T) {
	store, err := createKeyStorage("memory")
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestCreateKeyStorage_Empty(t *testing.T) {
	store, err := createKeyStorage("")
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestCreateKeyStorage_File(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := createKeyStorage(filepath.Join(tmpDir, "keys"))
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestCreateCertStorage_Memory(t *testing.T) {
	store, err := createCertStorage("memory")
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestCreateCertStorage_File(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := createCertStorage(filepath.Join(tmpDir, "certs"))
	require.NoError(t, err)
	assert.NotNil(t, store)
}

// ============================================================================
// Tests — initializePlatformStore
// ============================================================================

func TestServer_InitializePlatformStore_WithBarrier(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Barrier.Enabled = true

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.Barrier())
}

// ============================================================================
// Tests — RegisterPhoneBackend / UnregisterPhoneBackend
// ============================================================================

func TestServer_RegisterPhoneBackend_NilSender(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	err = server.RegisterPhoneBackend(nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilSender))
}

func TestServer_UnregisterPhoneBackend_NotRegistered(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	err = server.UnregisterPhoneBackend()
	assert.NoError(t, err)
}

func TestServer_RegisterPhoneBackend_NilPhoneConfig(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.Phone = nil

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	sender := &mockPhoneSender{}
	err = server.RegisterPhoneBackend(sender)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneConfigNil))
}

// ============================================================================
// Tests — NoiseBootstrapServer accessor
// ============================================================================

func TestServer_NoiseBootstrapServer_NilByDefault(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.NoiseBootstrapServer())
}
