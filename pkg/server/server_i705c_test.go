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

package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	noiseproto "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/escrow"
	_ "github.com/jeremyhahn/go-xkms/pkg/escrow/xkms" // registers the "xkms" escrow agent factory
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ============================================================================
// Tests — retireTLSServerCert: branches TestRetireTLSServerCert_ToleratesAbsence
// (server_extra2_test.go) does not reach.
// ============================================================================

// TestRetireTLSServerCert_BackendNotAvailable proves the backend-lookup
// guard: a keystoreType with no registered backend must fail with a typed
// *ErrBackendNotAvailable rather than silently skipping the backend-side
// retirement.
func TestRetireTLSServerCert_BackendNotAvailable(t *testing.T) {
	s := newMinimalServer(t, tlsServerCertTestConfig("test-cn", false))
	s.ctx = context.Background()
	s.backends = map[string]xkms.Backend{}

	mock := &staleSANCA{store: &recordingCertStore{}}
	err := s.retireTLSServerCert(mock, "test-cn", "software")
	require.Error(t, err)

	var notAvail *ErrBackendNotAvailable
	require.ErrorAs(t, err, &notAvail)
}

// TestRetireTLSServerCert_CertStoreDeleteFailureIsFatal proves that a
// genuine (non-ErrCertNotFound) failure deleting from the CA's certStore
// aborts retirement with a typed *ErrTLSCertOp instead of proceeding to the
// backend delete over a store that may still hold the stale certificate.
func TestRetireTLSServerCert_CertStoreDeleteFailureIsFatal(t *testing.T) {
	s := newMinimalServer(t, tlsServerCertTestConfig("test-cn", false))
	s.ctx = context.Background()
	s.backends = map[string]xkms.Backend{"software": &deletingBackend{}}

	mock := &staleSANCA{store: &recordingCertStore{deleteErr: errors.New("certStore unavailable")}}
	err := s.retireTLSServerCert(mock, "test-cn", "software")
	require.Error(t, err)

	var tlsOp *ErrTLSCertOp
	require.ErrorAs(t, err, &tlsOp)
}

// ============================================================================
// Tests — retainNoiseKey / retainBootstrapKeys
// ============================================================================

// TestRetainNoiseKey_NilIsNoOp proves the nil-key guard: retiring a listener
// that never resolved a key for one suite must not append a nil entry.
func TestRetainNoiseKey_NilIsNoOp(t *testing.T) {
	s := &Server{}
	s.retainNoiseKey(nil)
	assert.Empty(t, s.retainedNoiseKeys)
}

// TestRetainNoiseKey_AppendsKey proves a non-nil key is parked on the
// retention set.
func TestRetainNoiseKey_AppendsKey(t *testing.T) {
	s := &Server{}
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)

	s.retainNoiseKey(key)
	require.Len(t, s.retainedNoiseKeys, 1)
	assert.Same(t, key, s.retainedNoiseKeys[0])
}

// TestRetainBootstrapKeys_NilIsNoOp proves a nil *bootstrapKeys retains
// nothing.
func TestRetainBootstrapKeys_NilIsNoOp(t *testing.T) {
	s := &Server{}
	s.retainBootstrapKeys(nil)
	assert.Empty(t, s.retainedNoiseKeys)
	assert.Empty(t, s.retainedP256Keys)
}

// TestRetainBootstrapKeys_RetainsBothSuites proves both keys of a listener
// that offered both handshake suites are retained.
func TestRetainBootstrapKeys_RetainsBothSuites(t *testing.T) {
	s := &Server{}
	noiseKey, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	p256Key, err := bootstrap.GenerateP256StaticKey()
	require.NoError(t, err)

	s.retainBootstrapKeys(&bootstrapKeys{noise: noiseKey, p256: p256Key})
	assert.Len(t, s.retainedNoiseKeys, 1)
	assert.Len(t, s.retainedP256Keys, 1)
}

// TestRetainBootstrapKeys_NilP256SkipsP256Retention proves a listener that
// offered only the Noise_NK suite (nil p256) retains only that suite's key,
// matching the doc comment's "a build that offered only one suite retains
// only that suite's key".
func TestRetainBootstrapKeys_NilP256SkipsP256Retention(t *testing.T) {
	s := &Server{}
	noiseKey, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)

	s.retainBootstrapKeys(&bootstrapKeys{noise: noiseKey, p256: nil})
	assert.Len(t, s.retainedNoiseKeys, 1)
	assert.Empty(t, s.retainedP256Keys)
}

// ============================================================================
// Tests — initializeEscrow
// ============================================================================

// TestInitializeEscrow_Disabled proves the documented no-op: an explicit
// Enabled: false is a no-op leaving s.escrowRegistry nil, the same as the
// nil-config case every other New(cfg) test exercises implicitly.
func TestInitializeEscrow_Disabled(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Escrow: &escrow.Config{Enabled: false},
	})

	require.NoError(t, s.initializeEscrow())
	assert.Nil(t, s.EscrowRegistry())
}

// TestInitializeEscrow_EnabledWithNoAgentsFailsValidation proves that
// enabling escrow with zero agents surfaces the config's own validation
// error rather than silently building an empty registry.
func TestInitializeEscrow_EnabledWithNoAgentsFailsValidation(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Escrow: &escrow.Config{Enabled: true},
	})

	err := s.initializeEscrow()
	require.Error(t, err)
	assert.Nil(t, s.EscrowRegistry())
}

// TestInitializeEscrow_EnabledWithAgentBuildsRegistry proves the success
// path end to end with a real (lazily-dialing, no network I/O at
// construction) xkms-federation escrow agent: the registry is built,
// retained on s.escrowRegistry, and reachable via EscrowRegistry().
func TestInitializeEscrow_EnabledWithAgentBuildsRegistry(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Escrow: &escrow.Config{
			Enabled: true,
			Agents: []escrow.AgentConfig{
				{Type: "xkms", Endpoint: "https://escrow.example.com:8443"},
			},
		},
	})

	require.NoError(t, s.initializeEscrow())
	require.NotNil(t, s.EscrowRegistry())
	assert.Contains(t, s.EscrowRegistry().Agents(), "xkms")
	t.Cleanup(func() { _ = s.EscrowRegistry().Close() })
}

// ============================================================================
// Tests — initializePKCS11StateStore
// ============================================================================

// TestInitializePKCS11StateStore_Success proves the happy path: the state
// store is built and retained.
func TestInitializePKCS11StateStore_Success(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "memory"},
	})

	require.NoError(t, s.initializePKCS11StateStore())
	assert.NotNil(t, s.pkcs11StateStore)
}

// TestInitializePKCS11StateStore_StorageCreateFails proves that a storage
// backend createStorage cannot build (an unsupported storage.backend) fails
// with a typed *ErrStorageCreate rather than a nil state store silently
// reaching PKCS#11 remote-state callers.
func TestInitializePKCS11StateStore_StorageCreateFails(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "not-a-real-backend"},
	})

	err := s.initializePKCS11StateStore()
	require.Error(t, err)
	assert.Nil(t, s.pkcs11StateStore)

	var storageErr *ErrStorageCreate
	require.ErrorAs(t, err, &storageErr)
}

// TestBootstrapKeys_DestroyNilReceiverIsSafe proves destroy is safe to call
// on a nil *bootstrapKeys (an early-return path before any key was loaded),
// matching its documented "safe on a nil receiver" contract.
func TestBootstrapKeys_DestroyNilReceiverIsSafe(t *testing.T) {
	var k *bootstrapKeys
	assert.NotPanics(t, func() { k.destroy() })
}
