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
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	phonebackend "github.com/jeremyhahn/go-xkms/pkg/backend/phone"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPhoneSender implements phonebackend.Sender for testing.
type mockPhoneSender struct {
	sendFunc func(ctx context.Context, req *pairing.Request) (*pairing.Response, error)
}

func (m *mockPhoneSender) SendRequest(ctx context.Context, req *pairing.Request) (*pairing.Response, error) {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, req)
	}
	return &pairing.Response{
		JSONRPC: "2.0",
		ID:      req.ID,
	}, nil
}

// newTestPhoneConfig returns a valid PhoneConfig for testing.
func newTestPhoneConfig(t testing.TB) *config.PhoneConfig {
	t.Helper()
	return &config.PhoneConfig{
		Enabled:        true,
		Transport:      "tcp",
		DeviceAddress:  "127.0.0.1:9876",
		NoiseStaticKey: secrettest.Literal(t, []byte("aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233")),

		PhoneStaticKey: "11223344556677881122334455667788112233445566778811223344556677aa",
		RequestTimeout: 5 * time.Second,
	}
}

// newTestServerForPhone creates a minimal Server struct for phone backend tests.
// It avoids the full New() constructor which requires filesystem and other setup.
func newTestServerForPhone(t *testing.T, phoneCfg *config.PhoneConfig) *Server {
	t.Helper()
	return &Server{
		ctx: context.Background(),
		config: &config.Config{
			Backends: config.BackendsConfig{
				Phone: phoneCfg,
			},
		},
		backends:     make(map[string]xkms.Backend),
		keyProviders: make(map[string]types.KeyProvider),
		logger:       slog.Default(),
	}
}

// newTestServerForPhoneWithCredentials is newTestServerForPhone plus a
// credential service backed by svc, wiring buildSecretRegistry's
// credential:// resolver the same way a fully booted server would once
// initializeCredentialService has run.
func newTestServerForPhoneWithCredentials(t *testing.T, phoneCfg *config.PhoneConfig, svc *credentialspkg.Service) *Server {
	t.Helper()
	srv := newTestServerForPhone(t, phoneCfg)
	srv.credentialService = svc
	return srv
}

func TestRegisterPhoneBackend_Success(t *testing.T) {
	phoneCfg := newTestPhoneConfig(t)
	srv := newTestServerForPhone(t, phoneCfg)

	sender := &mockPhoneSender{}
	err := srv.RegisterPhoneBackend(sender)
	require.NoError(t, err)

	// Verify the phone backend is registered in the keyProviders map.
	srv.mu.RLock()
	kp, ok := srv.keyProviders["phone"]
	srv.mu.RUnlock()

	assert.True(t, ok, "phone backend should be registered")
	assert.NotNil(t, kp, "phone backend should not be nil")
	assert.Equal(t, types.BackendTypePhone, kp.Type())

	// Clean up: close the backend.
	assert.NoError(t, kp.Close())
}

func TestRegisterPhoneBackend_NilSender(t *testing.T) {
	phoneCfg := newTestPhoneConfig(t)
	srv := newTestServerForPhone(t, phoneCfg)

	err := srv.RegisterPhoneBackend(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilSender)

	// Verify no backend was registered.
	srv.mu.RLock()
	_, ok := srv.keyProviders["phone"]
	srv.mu.RUnlock()
	assert.False(t, ok, "no phone backend should be registered with nil sender")
}

func TestRegisterPhoneBackend_ReplaceExisting(t *testing.T) {
	phoneCfg := newTestPhoneConfig(t)
	srv := newTestServerForPhone(t, phoneCfg)

	// Register the first phone backend.
	firstSender := &mockPhoneSender{}
	err := srv.RegisterPhoneBackend(firstSender)
	require.NoError(t, err)

	// Capture the first backend reference to verify it was closed.
	srv.mu.RLock()
	firstBackend := srv.keyProviders["phone"]
	srv.mu.RUnlock()
	require.NotNil(t, firstBackend)

	// Register a second phone backend, replacing the first.
	secondSender := &mockPhoneSender{}
	err = srv.RegisterPhoneBackend(secondSender)
	require.NoError(t, err)

	// Verify the new backend is registered.
	srv.mu.RLock()
	secondBackend, ok := srv.keyProviders["phone"]
	srv.mu.RUnlock()

	assert.True(t, ok, "phone backend should be registered")
	assert.NotNil(t, secondBackend, "second phone backend should not be nil")

	// The first backend was closed during replacement (via Close()).
	// The phone backend's Close() sets an internal atomic bool, so calling
	// Close again on firstBackend should succeed (idempotent close).
	assert.NoError(t, firstBackend.Close())

	// Clean up second backend.
	assert.NoError(t, secondBackend.Close())
}

func TestRegisterPhoneBackend_NilConfig(t *testing.T) {
	srv := newTestServerForPhone(t, nil)

	sender := &mockPhoneSender{}
	err := srv.RegisterPhoneBackend(sender)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPhoneConfigNil)

	// Verify no backend was registered.
	srv.mu.RLock()
	_, ok := srv.keyProviders["phone"]
	srv.mu.RUnlock()
	assert.False(t, ok, "no phone backend should be registered with nil config")
}

func TestRegisterPhoneBackend_DefaultTimeout(t *testing.T) {
	// Create a phone config with zero RequestTimeout to verify default is applied.
	phoneCfg := newTestPhoneConfig(t)
	phoneCfg.RequestTimeout = 0
	srv := newTestServerForPhone(t, phoneCfg)

	sender := &mockPhoneSender{}
	err := srv.RegisterPhoneBackend(sender)
	require.NoError(t, err)

	// Verify backend was created successfully (default timeout was applied internally).
	srv.mu.RLock()
	backend, ok := srv.keyProviders["phone"]
	srv.mu.RUnlock()

	assert.True(t, ok, "phone backend should be registered")
	assert.NotNil(t, backend)

	// Clean up.
	assert.NoError(t, backend.Close())
}

func TestRegisterPhoneBackend_ConcurrentAccess(t *testing.T) {
	phoneCfg := newTestPhoneConfig(t)
	srv := newTestServerForPhone(t, phoneCfg)

	// Register and unregister concurrently to verify mutex safety.
	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sender := &mockPhoneSender{}
			if err := srv.RegisterPhoneBackend(sender); err != nil {
				errs <- err
			}
		}()
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.UnregisterPhoneBackend(); err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("unexpected error during concurrent access: %v", err)
	}
}

func TestUnregisterPhoneBackend_Success(t *testing.T) {
	phoneCfg := newTestPhoneConfig(t)
	srv := newTestServerForPhone(t, phoneCfg)

	// Register a phone backend first.
	sender := &mockPhoneSender{}
	err := srv.RegisterPhoneBackend(sender)
	require.NoError(t, err)

	// Verify it is registered.
	srv.mu.RLock()
	_, ok := srv.keyProviders["phone"]
	srv.mu.RUnlock()
	require.True(t, ok, "phone backend should be registered before unregister")

	// Unregister the phone backend.
	err = srv.UnregisterPhoneBackend()
	require.NoError(t, err)

	// Verify it is removed.
	srv.mu.RLock()
	_, ok = srv.keyProviders["phone"]
	srv.mu.RUnlock()
	assert.False(t, ok, "phone backend should be removed after unregister")
}

func TestUnregisterPhoneBackend_NotRegistered(t *testing.T) {
	phoneCfg := newTestPhoneConfig(t)
	srv := newTestServerForPhone(t, phoneCfg)

	// Unregister when no phone backend is registered.
	err := srv.UnregisterPhoneBackend()
	assert.NoError(t, err, "unregistering a non-existent backend should not error")

	// Verify map is still empty.
	srv.mu.RLock()
	assert.Empty(t, srv.keyProviders)
	srv.mu.RUnlock()
}

func TestUnregisterPhoneBackend_ClosesBackend(t *testing.T) {
	phoneCfg := newTestPhoneConfig(t)
	srv := newTestServerForPhone(t, phoneCfg)

	sender := &mockPhoneSender{}
	err := srv.RegisterPhoneBackend(sender)
	require.NoError(t, err)

	// Hold a reference to verify close behavior.
	srv.mu.RLock()
	backend := srv.keyProviders["phone"]
	srv.mu.RUnlock()
	require.NotNil(t, backend)

	// Unregister.
	err = srv.UnregisterPhoneBackend()
	require.NoError(t, err)

	// The backend should now be closed. Calling an operation on it should
	// return ErrBackendClosed.
	_, listErr := backend.ListKeys(context.Background())
	assert.ErrorIs(t, listErr, phonebackend.ErrBackendClosed)
}

func TestInitPhoneBackend_Disabled(t *testing.T) {
	phoneCfg := &config.PhoneConfig{
		Enabled: false,
	}
	srv := newTestServerForPhone(t, phoneCfg)

	err := srv.initPhoneBackend()
	assert.NoError(t, err)

	// Verify no backend was registered.
	srv.mu.RLock()
	_, ok := srv.keyProviders["phone"]
	srv.mu.RUnlock()
	assert.False(t, ok, "disabled phone backend should not register")
}

func TestInitPhoneBackend_NilConfig(t *testing.T) {
	srv := newTestServerForPhone(t, nil)

	err := srv.initPhoneBackend()
	assert.NoError(t, err, "nil phone config should be treated as disabled")

	// Verify no backend was registered.
	srv.mu.RLock()
	_, ok := srv.keyProviders["phone"]
	srv.mu.RUnlock()
	assert.False(t, ok)
}

func TestInitPhoneBackend_Enabled(t *testing.T) {
	phoneCfg := newTestPhoneConfig(t)
	srv := newTestServerForPhone(t, phoneCfg)

	err := srv.initPhoneBackend()
	assert.NoError(t, err)

	// initPhoneBackend only logs; the actual registration is deferred.
	// Verify no backend was registered yet.
	srv.mu.RLock()
	_, ok := srv.keyProviders["phone"]
	srv.mu.RUnlock()
	assert.False(t, ok, "initPhoneBackend should not register -- registration is deferred")
}

func TestRegisterPhoneBackend_InvalidConfig(t *testing.T) {
	// PhoneConfig with missing required fields should fail during
	// phonebackend.NewBackend validation.
	phoneCfg := &config.PhoneConfig{
		Enabled:   true,
		Transport: "invalid-transport",
	}
	srv := newTestServerForPhone(t, phoneCfg)

	sender := &mockPhoneSender{}
	err := srv.RegisterPhoneBackend(sender)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPhoneBackendCreate),
		"error should wrap ErrPhoneBackendCreate, got: %v", err)
}

// newManualCredentialService builds a credentialspkg.Service using the
// "manual" seal strategy, which needs no barrier or platform store -- the
// same construction secret_wiring_test.go uses to exercise
// buildSecretRegistry with a real credential-backed resolver.
func newManualCredentialService(t *testing.T) *credentialspkg.Service {
	t.Helper()
	svc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: credentialspkg.StrategyManual},
		nil, nil, nil,
	)
	require.NoError(t, err)
	return svc
}

// TestRegisterPhoneBackend_ResolvableCredentialReference proves the fix for
// go-xkms#610's registry-wiring gap: a "credential://" NoiseStaticKey
// reference is resolved through Server.resolveConfigSecrets -- the same
// whole-config walk Server.New now runs once, right after the credential
// service comes up, for every secret-bearing config field -- and the
// resolved plaintext, not the reference text, reaches the phone backend.
func TestRegisterPhoneBackend_ResolvableCredentialReference(t *testing.T) {
	svc := newManualCredentialService(t)
	const credName = "phone-noise-key"
	const noiseKeyHex = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
	require.NoError(t, svc.StoreCredential(context.Background(), credName, []byte(noiseKeyHex)))

	phoneCfg := newTestPhoneConfig(t)
	phoneCfg.NoiseStaticKey = &types.SecretValue{Raw: "credential://" + credName}

	srv := newTestServerForPhoneWithCredentials(t, phoneCfg, svc)
	// Simulates the resolveConfigSecrets call Server.New makes right after
	// initializeCredentialService, before any phone can connect.
	require.NoError(t, srv.resolveConfigSecrets())

	sender := &mockPhoneSender{}
	require.NoError(t, srv.RegisterPhoneBackend(sender))

	srv.mu.RLock()
	kp, ok := srv.keyProviders["phone"]
	srv.mu.RUnlock()
	require.True(t, ok)
	require.NoError(t, kp.Close())

	// The field now carries the resolved SecretValue (custody transfer),
	// with Raw still naming the reference and real material behind it.
	assert.Equal(t, "credential://"+credName, phoneCfg.NoiseStaticKey.Raw)
	got, err := types.SecretValueBytes(t.Context(), phoneCfg.NoiseStaticKey)
	require.NoError(t, err)
	assert.Equal(t, noiseKeyHex, string(got))
}

// TestResolveConfigSecrets_UnresolvableCredentialReference proves an
// unresolvable reference (the named credential does not exist) fails the
// boot-time resolution pass loudly -- with the typed *ErrConfigSecretResolution
// -- rather than silently registering a backend keyed by the reference text
// once a phone eventually connects.
func TestResolveConfigSecrets_UnresolvableCredentialReference(t *testing.T) {
	svc := newManualCredentialService(t)

	phoneCfg := newTestPhoneConfig(t)
	phoneCfg.NoiseStaticKey = &types.SecretValue{Raw: "credential://does-not-exist"}

	srv := newTestServerForPhoneWithCredentials(t, phoneCfg, svc)
	// The "manual" strategy's RetrieveCredential blocks waiting for an
	// operator to submit the named credential rather than failing fast on a
	// miss (go-qrdb's manual credential strategy) -- exactly right for its
	// real interactive use, but this test wants "no such credential exists
	// and nobody ever will submit one", so it bounds s.ctx instead of
	// hanging for test.timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	srv.ctx = ctx

	err := srv.resolveConfigSecrets()
	require.Error(t, err)
	var resErr *ErrConfigSecretResolution
	require.True(t, errors.As(err, &resErr),
		"error must unwrap to *ErrConfigSecretResolution, got %v", err)

	// A boot that failed to resolve a configured reference must never reach
	// phone registration with the reference text standing in for the key.
	sender := &mockPhoneSender{}
	regErr := srv.RegisterPhoneBackend(sender)
	require.Error(t, regErr, "an unresolved reference must not register a working phone backend")
}

// TestRegisterPhoneBackend_UnresolvedReferenceWithoutCredentialService
// proves that a "credential://" reference with no credential service wired
// (buildSecretRegistry has no resolver to register) fails through
// SecretValueBytes's *types.SecretReferenceUnresolvedError rather than
// silently using the reference text as the Noise key — the exact go-xkms#610
// regression this fix closes.
func TestRegisterPhoneBackend_UnresolvedReferenceWithoutCredentialService(t *testing.T) {
	phoneCfg := newTestPhoneConfig(t)
	phoneCfg.NoiseStaticKey = &types.SecretValue{Raw: "credential://phone-noise-key"}

	// No credential service: srv.credentialService stays nil, so
	// buildSecretRegistry's registry has no CredentialResolver and the
	// registry's own literal fallback would otherwise silently treat the
	// reference text as the Noise key.
	srv := newTestServerForPhone(t, phoneCfg)

	sender := &mockPhoneSender{}
	err := srv.RegisterPhoneBackend(sender)
	require.Error(t, err)

	var refErr *types.SecretReferenceUnresolvedError
	require.True(t, errors.As(err, &refErr),
		"error must unwrap to *types.SecretReferenceUnresolvedError, got %v", err)
	assert.Equal(t, "credential", refErr.Scheme)
}
