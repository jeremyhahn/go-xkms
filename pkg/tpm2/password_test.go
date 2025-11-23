package tpm2

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/internal/tpm/logging"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
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
}

func (m *mockTPMForPassword) Unseal(keyAttrs *types.KeyAttributes, backend store.KeyBackend) ([]byte, error) {
	return m.unsealData, m.unsealErr
}

func (m *mockTPMForPassword) Seal(keyAttrs *types.KeyAttributes, backend store.KeyBackend, overwrite bool) (*tpm2.CreateResponse, error) {
	return m.sealResponse, m.sealErr
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
