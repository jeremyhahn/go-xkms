package tpm2

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/logging"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// mockTPMForPassword implements TrustedPlatformModule for testing password functions
type mockTPMForPassword struct {
	TrustedPlatformModule
	unsealData   []byte
	unsealErr    error
	sealResponse *tpm2.CreateResponse
	sealErr      error
	randomSource io.Reader
	unsealCount  atomic.Int32 // Track number of Unseal calls for cache testing
}

// UnsealKey implements the legacy unseal method
func (m *mockTPMForPassword) UnsealKey(keyAttrs *types.KeyAttributes, backend store.KeyBackend) ([]byte, error) {
	m.unsealCount.Add(1)
	return m.unsealData, m.unsealErr
}

// SealKey implements the legacy seal method
func (m *mockTPMForPassword) SealKey(keyAttrs *types.KeyAttributes, backend store.KeyBackend, overwrite bool) (*tpm2.CreateResponse, error) {
	return m.sealResponse, m.sealErr
}

// Seal implements types.Sealer interface
func (m *mockTPMForPassword) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	return &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		Ciphertext: data,
	}, nil
}

// Unseal implements types.Sealer interface
func (m *mockTPMForPassword) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	m.unsealCount.Add(1)
	return m.unsealData, m.unsealErr
}

// CanSeal implements types.Sealer interface
func (m *mockTPMForPassword) CanSeal() bool {
	return true
}

func (m *mockTPMForPassword) RandomSource() io.Reader {
	if m.randomSource != nil {
		return m.randomSource
	}
	return rand.Reader
}

// mockKeyBackendForPassword implements store.KeyBackend for testing
type mockKeyBackendForPassword struct {
	store.KeyBackend
}

func TestNewPlatformPassword(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeHMAC,
	}

	password := NewPlatformPassword(logger, tpmMock, keyAttrs, backend)

	if password == nil {
		t.Error("NewPlatformPassword() returned nil")
	}

	pp, ok := password.(*PlatformPassword)
	if !ok {
		t.Error("NewPlatformPassword() did not return PlatformPassword type")
	}

	if pp.logger != logger {
		t.Error("PlatformPassword.logger not set correctly")
	}

	if pp.keyAttrs != keyAttrs {
		t.Error("PlatformPassword.keyAttrs not set correctly")
	}

	if pp.backend != backend {
		t.Error("PlatformPassword.backend not set correctly")
	}
}

func TestPlatformPasswordString(t *testing.T) {
	tests := []struct {
		name       string
		unsealData []byte
		unsealErr  error
		want       string
		wantErr    bool
	}{
		{
			name:       "successful string retrieval",
			unsealData: []byte("secret-password"),
			want:       "secret-password",
		},
		{
			name:       "empty password",
			unsealData: []byte(""),
			want:       "",
		},
		{
			name:       "binary data as string",
			unsealData: []byte{0x01, 0x02, 0x03},
			want:       string([]byte{0x01, 0x02, 0x03}),
		},
		{
			name:      "unseal error propagates",
			unsealErr: errors.New("unseal failed"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			tpmMock := &mockTPMForPassword{
				unsealData: tt.unsealData,
				unsealErr:  tt.unsealErr,
			}
			backend := &mockKeyBackendForPassword{}
			keyAttrs := &types.KeyAttributes{
				CN:      "test-key",
				KeyType: types.KeyTypeHMAC,
				Debug:   false,
			}

			pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend)

			got, err := pp.String()
			if tt.wantErr {
				if err == nil {
					t.Error("PlatformPassword.String() expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("PlatformPassword.String() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("PlatformPassword.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPlatformPasswordBytes(t *testing.T) {
	tests := []struct {
		name       string
		unsealData []byte
		unsealErr  error
		debug      bool
		wantErr    bool
	}{
		{
			name:       "successful bytes retrieval",
			unsealData: []byte("secret-password"),
		},
		{
			name:       "empty bytes",
			unsealData: []byte{},
		},
		{
			name:       "binary data",
			unsealData: []byte{0x00, 0xFF, 0x10, 0xAB},
		},
		{
			name:       "with debug enabled",
			unsealData: []byte("debug-password"),
			debug:      true,
		},
		{
			name:      "unseal error propagates",
			unsealErr: errors.New("unseal failed"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			tpmMock := &mockTPMForPassword{
				unsealData: tt.unsealData,
				unsealErr:  tt.unsealErr,
			}
			backend := &mockKeyBackendForPassword{}
			keyAttrs := &types.KeyAttributes{
				CN:      "test-key",
				KeyType: types.KeyTypeHMAC,
				Debug:   tt.debug,
			}

			pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend)

			got := pp.Bytes()
			if tt.wantErr {
				if got != nil {
					t.Error("PlatformPassword.Bytes() expected nil but got data")
				}
				return
			}

			if got == nil {
				t.Error("PlatformPassword.Bytes() returned nil unexpectedly")
				return
			}

			if len(got) != len(tt.unsealData) {
				t.Errorf("PlatformPassword.Bytes() length = %v, want %v", len(got), len(tt.unsealData))
				return
			}

			for i := range got {
				if got[i] != tt.unsealData[i] {
					t.Errorf("PlatformPassword.Bytes()[%d] = %v, want %v", i, got[i], tt.unsealData[i])
				}
			}
		})
	}
}

func TestPlatformPasswordBytesModifiesKeyType(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeCA, // Start with CA type
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	result := pp.Bytes()
	if result == nil {
		t.Error("PlatformPassword.Bytes() returned nil unexpectedly")
		return
	}

	// The original keyAttrs should not be modified because Bytes() copies it
	if keyAttrs.KeyType != types.KeyTypeCA {
		t.Error("Original keyAttrs.KeyType should not be modified")
	}
}

func TestPlatformPasswordCreate_NilPassword(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		sealErr: nil,
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN:       "test-key",
		Password: nil,
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	err := pp.Create()
	if err != nil {
		t.Errorf("PlatformPassword.Create() with nil password unexpected error: %v", err)
		return
	}

	// When password is nil, it should set to clear password with nil
	if keyAttrs.Password == nil {
		t.Error("PlatformPassword.Create() should set Password to ClearPassword")
	}
}

func TestPlatformPasswordCreate_WithPasswordError(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{}
	backend := &mockKeyBackendForPassword{}

	// Create a password that returns an error
	errPassword := &errorPasswordForPasswordTest{err: errors.New("password error")}
	keyAttrs := &types.KeyAttributes{
		CN:       "test-key",
		Password: errPassword,
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	err := pp.Create()
	if err == nil {
		t.Error("PlatformPassword.Create() expected error but got nil")
	}
}

func TestPlatformPasswordCreate_SealError(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		sealErr: errors.New("seal failed"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN:       "test-key",
		Password: store.NewClearPassword([]byte("test")),
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	err := pp.Create()
	if err == nil {
		t.Error("PlatformPassword.Create() expected seal error but got nil")
	}
}

// errorPasswordForPasswordTest is a mock password that returns an error
type errorPasswordForPasswordTest struct {
	types.Password
	err error
}

func (p *errorPasswordForPasswordTest) Bytes() []byte {
	return nil
}

func (p *errorPasswordForPasswordTest) String() (string, error) {
	return "", p.err
}

func (p *errorPasswordForPasswordTest) Clear() {
	// No-op
}

func TestPlatformPasswordIntegration(t *testing.T) {
	// Test that multiple calls to Bytes() work correctly
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("consistent-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeHMAC,
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend)

	// First call
	bytes1 := pp.Bytes()
	if bytes1 == nil {
		t.Error("First Bytes() call returned nil unexpectedly")
		return
	}

	// Second call
	bytes2 := pp.Bytes()
	if bytes2 == nil {
		t.Error("Second Bytes() call returned nil unexpectedly")
		return
	}

	// Both should return same data
	if string(bytes1) != string(bytes2) {
		t.Errorf("Inconsistent Bytes() results: %v vs %v", string(bytes1), string(bytes2))
	}

	// String should match bytes
	str, err := pp.String()
	if err != nil {
		t.Errorf("String() call unexpected error: %v", err)
		return
	}

	if str != string(bytes1) {
		t.Errorf("String() = %v, want %v", str, string(bytes1))
	}
}

func TestPlatformPasswordImplementsInterface(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{}

	// Verify that NewPlatformPassword returns types.Password interface
	password := NewPlatformPassword(logger, tpmMock, keyAttrs, backend)

	if password == nil {
		t.Error("NewPlatformPassword() should implement types.Password")
	}
}

func TestPlatformPasswordCreate_DefaultPassword(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		sealResponse: &tpm2.CreateResponse{},
		sealErr:      nil,
	}
	backend := &mockKeyBackendForPassword{}

	// Use the default password which should trigger key generation
	keyAttrs := &types.KeyAttributes{
		CN:       "test-key",
		Password: store.NewClearPassword([]byte(store.DEFAULT_PASSWORD)),
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	err := pp.Create()
	if err != nil {
		t.Errorf("PlatformPassword.Create() with default password unexpected error: %v", err)
		return
	}

	// After Create, keyAttrs.Password should be updated (either PlatformPassword or RequiredPassword)
	if keyAttrs.Password == nil {
		t.Error("keyAttrs.Password should not be nil after Create()")
	}
}

func TestPlatformPasswordCreate_WithPlatformPolicy(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		sealResponse: &tpm2.CreateResponse{},
		sealErr:      nil,
	}
	backend := &mockKeyBackendForPassword{}

	keyAttrs := &types.KeyAttributes{
		CN:             "test-key",
		Password:       store.NewClearPassword([]byte("test-pass")),
		PlatformPolicy: true,
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	err := pp.Create()
	if err != nil {
		t.Errorf("PlatformPassword.Create() with platform policy unexpected error: %v", err)
		return
	}

	// When PlatformPolicy is true, password should be set to PlatformPassword
	_, ok := keyAttrs.Password.(*PlatformPassword)
	if !ok {
		t.Error("keyAttrs.Password should be *PlatformPassword when PlatformPolicy is true")
	}
}

func TestPlatformPasswordCreate_WithoutPlatformPolicy(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		sealResponse: &tpm2.CreateResponse{},
		sealErr:      nil,
	}
	backend := &mockKeyBackendForPassword{}

	keyAttrs := &types.KeyAttributes{
		CN:             "test-key",
		Password:       store.NewClearPassword([]byte("test-pass")),
		PlatformPolicy: false,
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	err := pp.Create()
	if err != nil {
		t.Errorf("PlatformPassword.Create() without platform policy unexpected error: %v", err)
		return
	}

	// When PlatformPolicy is false, password should be set to RequiredPassword
	// (which returns ErrPasswordRequired when invoked)
	if keyAttrs.Password == nil {
		t.Error("keyAttrs.Password should not be nil")
	}
}

// ========== Password Caching Tests ==========

func TestPlatformPassword_CacheDisabled(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("test-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN:            "test-key",
		PasswordCache: nil, // Cache disabled (nil)
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend)

	// Call Bytes() multiple times
	for i := 0; i < 3; i++ {
		result := pp.Bytes()
		if string(result) != "test-password" {
			t.Errorf("Bytes() call %d returned unexpected value", i+1)
		}
	}

	// With cache disabled, Unseal should be called every time
	if tpmMock.unsealCount.Load() != 3 {
		t.Errorf("Expected 3 Unseal calls with cache disabled, got %d", tpmMock.unsealCount.Load())
	}
}

func TestPlatformPassword_CacheDisabledExplicit(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("test-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
		PasswordCache: &types.PasswordCacheConfig{
			Enabled: false, // Cache explicitly disabled
			TTL:     300,
		},
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend)

	// Call Bytes() multiple times
	for i := 0; i < 3; i++ {
		result := pp.Bytes()
		if string(result) != "test-password" {
			t.Errorf("Bytes() call %d returned unexpected value", i+1)
		}
	}

	// With cache disabled, Unseal should be called every time
	if tpmMock.unsealCount.Load() != 3 {
		t.Errorf("Expected 3 Unseal calls with cache disabled, got %d", tpmMock.unsealCount.Load())
	}
}

func TestPlatformPassword_CacheEnabled(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("test-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
		PasswordCache: &types.PasswordCacheConfig{
			Enabled: true,
			TTL:     300, // 5 minutes
		},
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend)

	// Call Bytes() multiple times
	for i := 0; i < 5; i++ {
		result := pp.Bytes()
		if string(result) != "test-password" {
			t.Errorf("Bytes() call %d returned unexpected value", i+1)
		}
	}

	// With cache enabled, Unseal should only be called once
	if tpmMock.unsealCount.Load() != 1 {
		t.Errorf("Expected 1 Unseal call with cache enabled, got %d", tpmMock.unsealCount.Load())
	}
}

func TestPlatformPassword_CacheDefaultTTL(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("test-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
		PasswordCache: &types.PasswordCacheConfig{
			Enabled: true,
			TTL:     0, // Should use default TTL
		},
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	// Trigger cache
	pp.Bytes()

	// Verify default TTL is used
	expectedTTL := time.Duration(DefaultCacheTTLSeconds) * time.Second
	if pp.cacheTTL() != expectedTTL {
		t.Errorf("Expected default TTL %v, got %v", expectedTTL, pp.cacheTTL())
	}
}

func TestPlatformPassword_CacheExpiry(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("test-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
		PasswordCache: &types.PasswordCacheConfig{
			Enabled: true,
			TTL:     1, // 1 second TTL for testing
		},
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend)

	// First call - unseals from TPM
	result1 := pp.Bytes()
	if string(result1) != "test-password" {
		t.Error("First Bytes() returned unexpected value")
	}

	// Second call immediately - should use cache
	result2 := pp.Bytes()
	if string(result2) != "test-password" {
		t.Error("Second Bytes() returned unexpected value")
	}

	if tpmMock.unsealCount.Load() != 1 {
		t.Errorf("Expected 1 Unseal call before expiry, got %d", tpmMock.unsealCount.Load())
	}

	// Wait for cache to expire
	time.Sleep(1100 * time.Millisecond)

	// Third call - cache expired, should unseal again
	result3 := pp.Bytes()
	if string(result3) != "test-password" {
		t.Error("Third Bytes() returned unexpected value")
	}

	if tpmMock.unsealCount.Load() != 2 {
		t.Errorf("Expected 2 Unseal calls after expiry, got %d", tpmMock.unsealCount.Load())
	}
}

func TestPlatformPassword_IsCached(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("test-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
		PasswordCache: &types.PasswordCacheConfig{
			Enabled: true,
			TTL:     300,
		},
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	// Before Bytes() - not cached
	if pp.IsCached() {
		t.Error("IsCached() should return false before Bytes() is called")
	}

	// After Bytes() - should be cached
	pp.Bytes()
	if !pp.IsCached() {
		t.Error("IsCached() should return true after Bytes() is called")
	}
}

func TestPlatformPassword_IsCached_Disabled(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("test-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN:            "test-key",
		PasswordCache: nil, // Cache disabled
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	// Call Bytes()
	pp.Bytes()

	// With cache disabled, IsCached should always return false
	if pp.IsCached() {
		t.Error("IsCached() should return false when cache is disabled")
	}
}

func TestPlatformPassword_Clear(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("test-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
		PasswordCache: &types.PasswordCacheConfig{
			Enabled: true,
			TTL:     300,
		},
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	// Populate cache
	pp.Bytes()
	if !pp.IsCached() {
		t.Error("Cache should be populated after Bytes()")
	}

	// Clear cache
	pp.Clear()
	if pp.IsCached() {
		t.Error("IsCached() should return false after Clear()")
	}

	// Next Bytes() should unseal again
	pp.Bytes()
	if tpmMock.unsealCount.Load() != 2 {
		t.Errorf("Expected 2 Unseal calls after Clear(), got %d", tpmMock.unsealCount.Load())
	}
}

func TestPlatformPassword_CacheExpiry_Time(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("test-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
		PasswordCache: &types.PasswordCacheConfig{
			Enabled: true,
			TTL:     60, // 60 seconds
		},
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	// Before cache - should return zero time
	expiry := pp.CacheExpiry()
	if !expiry.IsZero() {
		t.Error("CacheExpiry() should return zero time before cache is populated")
	}

	// Populate cache
	beforeBytes := time.Now()
	pp.Bytes()
	afterBytes := time.Now()

	// Check expiry is in the future
	expiry = pp.CacheExpiry()
	if expiry.IsZero() {
		t.Error("CacheExpiry() should return non-zero time after cache is populated")
	}

	expectedExpiry := beforeBytes.Add(60 * time.Second)
	maxExpiry := afterBytes.Add(60 * time.Second)

	if expiry.Before(expectedExpiry) || expiry.After(maxExpiry) {
		t.Errorf("CacheExpiry() = %v, expected between %v and %v", expiry, expectedExpiry, maxExpiry)
	}
}

func TestPlatformPassword_CacheExpiry_Disabled(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("test-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN:            "test-key",
		PasswordCache: nil, // Cache disabled
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	pp.Bytes()

	// With cache disabled, should return zero time
	expiry := pp.CacheExpiry()
	if !expiry.IsZero() {
		t.Error("CacheExpiry() should return zero time when cache is disabled")
	}
}

func TestPlatformPassword_RefreshCache(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("password-v1"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
		PasswordCache: &types.PasswordCacheConfig{
			Enabled: true,
			TTL:     300,
		},
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	// Populate cache
	result1 := pp.Bytes()
	if string(result1) != "password-v1" {
		t.Error("First Bytes() returned unexpected value")
	}

	// Change the mock's password (simulating TPM data change)
	tpmMock.unsealData = []byte("password-v2")

	// Regular Bytes() should still return cached value
	result2 := pp.Bytes()
	if string(result2) != "password-v1" {
		t.Error("Cached Bytes() should return old value")
	}

	// RefreshCache should get the new value
	result3 := pp.RefreshCache()
	if string(result3) != "password-v2" {
		t.Error("RefreshCache() should return new value")
	}

	// Verify Unseal was called for refresh
	if tpmMock.unsealCount.Load() != 2 {
		t.Errorf("Expected 2 Unseal calls (initial + refresh), got %d", tpmMock.unsealCount.Load())
	}
}

func TestPlatformPassword_CacheConcurrency(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("concurrent-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
		PasswordCache: &types.PasswordCacheConfig{
			Enabled: true,
			TTL:     300,
		},
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend)

	// Launch concurrent goroutines
	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			result := pp.Bytes()
			if string(result) != "concurrent-password" {
				t.Error("Concurrent Bytes() returned unexpected value")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// With caching, Unseal should only be called a small number of times
	// (ideally 1, but race conditions might cause a few more)
	if tpmMock.unsealCount.Load() > 5 {
		t.Errorf("Expected minimal Unseal calls with caching, got %d", tpmMock.unsealCount.Load())
	}
}

func TestPlatformPassword_CacheSecureMemory(t *testing.T) {
	logger := logging.DefaultLogger()
	tpmMock := &mockTPMForPassword{
		unsealData: []byte("sensitive-password"),
	}
	backend := &mockKeyBackendForPassword{}
	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
		PasswordCache: &types.PasswordCacheConfig{
			Enabled: true,
			TTL:     300,
		},
	}

	pp := NewPlatformPassword(logger, tpmMock, keyAttrs, backend).(*PlatformPassword)

	// Populate cache
	pp.Bytes()

	// Get reference to cached data before clear
	pp.mu.RLock()
	cachedRef := pp.cachedData
	pp.mu.RUnlock()

	// Clear cache
	pp.Clear()

	// Verify cached data was zeroed (not just set to nil)
	for i, b := range cachedRef {
		if b != 0 {
			t.Errorf("Cached data byte %d not zeroed after Clear(): %d", i, b)
		}
	}
}
