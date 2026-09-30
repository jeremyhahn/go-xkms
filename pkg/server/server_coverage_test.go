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
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
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

func TestServer_PINManager_NilByDefault(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.PINBackend())
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

func TestServer_TPMPolicyService_NilByDefault(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.TPMPolicyService())
}

// ============================================================================
// Tests — createCompositeAuthenticator
// ============================================================================

// An absent composite section DERIVES the session-vehicle chain: with the
// built-in token issuer provisioned (and TLS off in the minimal config), the
// chain resolves to the JWT authenticator. This is the shipped default
// configuration shape.
func TestServer_CreateCompositeAuthenticator_NilConfigDerives(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "composite"
	cfg.Auth.Composite = nil

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()
	assert.Equal(t, "jwt", server.authenticator.Name())
}

// Empty methods behave identically to an absent section: derive.
func TestServer_CreateCompositeAuthenticator_EmptyMethodsDerives(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "composite"
	cfg.Auth.Composite = &config.CompositeAuthConfig{
		Methods: []string{},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()
	assert.Equal(t, "jwt", server.authenticator.Name())
}

// The fail-closed branch: nothing derivable (no issuer, no JWT key, no TLS)
// must refuse rather than serve unauthenticated.
func TestServer_DeriveCompositeAuthenticator_NothingToDerive(t *testing.T) {
	s := &Server{
		config: &config.Config{},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	_, err := s.deriveCompositeAuthenticator()
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
	certFile, keyFile, _ := createTestTLSFiles(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	assert.Equal(t, "composite", server.authenticator.Name())
}

// ============================================================================
// Tests — initializeAuditLogger
// ============================================================================

// TestServer_InitializeAuditLogger_NoQRDBClientUsesChainedFile verifies that
// without a hosted qrdb node (file storage backend => qrdbClient nil) the
// server routes audit to the LOCAL tamper-evident chained file — the same
// record shape as the qrdb-hosted chain — never a silent NoOp.
// TestServer_InitializeAuditLogger_NoQRDBClientUsesChainedFile proves the
// fallback path initializeAuditLogger takes when s.qrdbClient is nil --
// today, only a datastore.mode "remote" deployment (see qrdb_storage.go's
// initializeQRDBStorage: only the "standalone" branch sets s.qrdbClient)
// still routes through here. Exercised directly via newMinimalServer, which
// never sets s.qrdbClient either, rather than a real "remote" New(cfg),
// which would need to dial an actual qrdb cluster to succeed.
func TestServer_InitializeAuditLogger_NoQRDBClientUsesChainedFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createMinimalConfig(t)
	cfg.Datastore.Path = tmpDir
	cfg.Auth.Audit = &config.AuditConfig{
		Enabled: true,
		Path:    filepath.Join(tmpDir, "audit.log"),
	}

	server := newMinimalServer(t, cfg)
	require.NoError(t, server.initializeAuditLogger())

	require.NotNil(t, server.auditLogger)
	_, ok := server.auditLogger.(*audit.ChainedFileLogger)
	assert.True(t, ok, "a server with no qrdb client must audit to the local chained file")
}

// TestServer_InitializeAuditLogger_EnabledMissingPathNoLongerErrors verifies
// that an enabled audit config with an empty path is no longer a fatal error.
// Audit storage moved to the qrdb node: an empty path simply means the node's
// in-memory ring buffer is used instead of the HMAC-chained file logger, so
// server construction succeeds.
func TestServer_InitializeAuditLogger_EnabledMissingPathNoLongerErrors(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Audit = &config.AuditConfig{
		Enabled: true,
		Path:    "",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.auditLogger)
}

// ============================================================================
// Tests — initializeBarrier
// ============================================================================

func TestServer_InitializeBarrier_Enabled(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Barrier.Enabled = true
	// "pkcs11" is not NodeFlipWired, so this deployment keeps xkms's own
	// (non-node) barrier -- initializeBarrier, the function this test
	// exercises -- instead of adopting the qrdb node's barrier, which would
	// skip initializeBarrier entirely and block boot on an operator unseal
	// for the flip-wired default ("passphrase").
	cfg.Barrier.Strategy = "pkcs11"
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
	// See TestServer_InitializeBarrier_Enabled: keeps xkms's own barrier
	// (PreferenceOrder-driven) instead of the node-flip.
	cfg.Barrier.Strategy = "pkcs11"
	cfg.Barrier.RootKeyPath = ""
	cfg.Barrier.PreferenceOrder = []string{"software"}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.Barrier())
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

	assert.NotNil(t, server.PINBackend())
}

func TestServer_InitializePINManager_DefaultStrategy(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.PIN.Enabled = true
	cfg.PIN.Strategy = "" // defaults to auto: software when no TPM is confirmed

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.PINBackend())
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

	// With RBAC enabled, authorization is enforced through the qrdb-backed
	// Authorizer when a qrdb identity plane is hosted; without one it stays
	// permissive (nil) by design.
	if server.qrdbClient != nil {
		require.NotNil(t, server.rbacAuthorizer)
		assert.True(t, server.rbacAuthorizer.Enabled())
	} else {
		assert.Nil(t, server.rbacAuthorizer)
	}
}

// ============================================================================
// Tests — createStorage / createStorageAt
// ============================================================================

func TestServer_CreateStorage_Memory(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Datastore.Engine = "memory"

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
	cfg.Datastore.Engine = "pebble"
	cfg.Datastore.Path = tmpDir

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	store, err := server.createStorage("testpebble")
	require.NoError(t, err)
	assert.NotNil(t, store)
}

// TestServer_CreateStorage_DistinctPrefixesOverOneStore is the regression
// test for go-xkms#1345: createStorage never builds a private, per-subsystem
// storage engine. Every subdir is a key-prefixed view over the SAME shared
// datastore (s.qrdbStorage), so two subsystems' keys coexist in one KV under
// distinct prefixes -- writing under one subdir's view must never be visible
// under another's.
func TestServer_CreateStorage_DistinctPrefixesOverOneStore(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Datastore.Engine = "memory"

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	certs, err := server.createStorage("certs")
	require.NoError(t, err)
	webauthn, err := server.createStorage("webauthn")
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, certs.Put(ctx, "k", []byte("cert-value")))
	require.NoError(t, webauthn.Put(ctx, "k", []byte("webauthn-value")))

	certVal, err := certs.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("cert-value"), certVal)

	webauthnVal, err := webauthn.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("webauthn-value"), webauthnVal)

	// The same key under a different subdir's view is a different entry in
	// the one shared store -- writing to "certs" must not leak into "webauthn".
	assert.NotEqual(t, certVal, webauthnVal)
}

// TestServer_CreateStorageAt_PrefixesOverSharedStore proves createStorageAt
// derives its key namespace from the final path segment, over the one
// shared datastore, regardless of Datastore.Engine (go-xkms#1345:
// createStorageAt no longer builds a private, per-call storage engine, so
// there is nothing left for the engine value to change here).
func TestServer_CreateStorageAt_PrefixesOverSharedStore(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory"},
	}
	s := newMinimalServer(t, cfg)
	var err error
	s.qrdbStorage, err = storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := s.createStorageAt(filepath.Join(tmpDir, "at-test"))
	require.NoError(t, err)
	require.NotNil(t, store)

	ctx := context.Background()
	require.NoError(t, store.Put(ctx, "k", []byte("v")))
	got, err := store.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)
}

// ============================================================================
// Tests — Initialize (backend factory)
// ============================================================================

func TestServer_InitializePlatformStore_WithBarrier(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Barrier.Enabled = true
	// "none" auto-unseals unattended (whichever barrier this resolves to,
	// node-adopted or xkms's own) so this test never blocks on an operator.
	cfg.Barrier.Strategy = "none"

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
