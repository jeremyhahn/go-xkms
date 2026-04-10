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

	phonebackend "github.com/jeremyhahn/go-xkms/pkg/backend/phone"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPhoneSender implements phonebackend.Sender for testing.
type mockPhoneSender struct {
	sendFunc func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error)
}

func (m *mockPhoneSender) SendRequest(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, req)
	}
	return &phoneproto.Response{
		JSONRPC: "2.0",
		ID:      req.ID,
	}, nil
}

// newTestPhoneConfig returns a valid PhoneConfig for testing.
func newTestPhoneConfig() *config.PhoneConfig {
	return &config.PhoneConfig{
		Enabled:        true,
		Transport:      "tcp",
		DeviceAddress:  "127.0.0.1:9876",
		NoiseStaticKey: "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
		PhoneStaticKey: "11223344556677881122334455667788112233445566778811223344556677aa",
		RequestTimeout: 5 * time.Second,
	}
}

// newTestServerForPhone creates a minimal Server struct for phone backend tests.
// It avoids the full New() constructor which requires filesystem and other setup.
func newTestServerForPhone(t *testing.T, phoneCfg *config.PhoneConfig) *Server {
	t.Helper()
	return &Server{
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

func TestRegisterPhoneBackend_Success(t *testing.T) {
	phoneCfg := newTestPhoneConfig()
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
	phoneCfg := newTestPhoneConfig()
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
	phoneCfg := newTestPhoneConfig()
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
	phoneCfg := newTestPhoneConfig()
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
	phoneCfg := newTestPhoneConfig()
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
	phoneCfg := newTestPhoneConfig()
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
	phoneCfg := newTestPhoneConfig()
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
	phoneCfg := newTestPhoneConfig()
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
	_, listErr := backend.ListKeys()
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
	phoneCfg := newTestPhoneConfig()
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
