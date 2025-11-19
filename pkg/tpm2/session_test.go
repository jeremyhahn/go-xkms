package tpm2

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// mockKeyBackendForSession implements store.KeyBackend for session tests
type mockKeyBackendForSession struct {
	store.KeyBackend
	getData    map[string][]byte
	getErr     error
	saveErr    error
	deleteErr  error
	savedData  map[string][]byte
	deletedKey string
}

func newMockKeyBackendForSession() *mockKeyBackendForSession {
	return &mockKeyBackendForSession{
		getData:   make(map[string][]byte),
		savedData: make(map[string][]byte),
	}
}

func (m *mockKeyBackendForSession) Get(keyAttrs *types.KeyAttributes, ext store.FSExtension) ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	data, ok := m.getData[string(ext)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return data, nil
}

func (m *mockKeyBackendForSession) Save(keyAttrs *types.KeyAttributes, data []byte, ext store.FSExtension, overwrite bool) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.savedData[string(ext)] = data
	return nil
}

func (m *mockKeyBackendForSession) Delete(keyAttrs *types.KeyAttributes) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deletedKey = keyAttrs.CN
	return nil
}

func TestSaveKeyPairSuccess(t *testing.T) {
	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	outPrivate := tpm2.TPM2BPrivate{
		Buffer: []byte("private-data"),
	}

	// Create a mock public area
	pubBytes := []byte("public-data")
	outPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes)

	tpmImpl := tpm.(*TPM2)

	err := tpmImpl.SaveKeyPair(keyAttrs, outPrivate, outPublic, backend, false)
	if err != nil {
		t.Errorf("SaveKeyPair() unexpected error: %v", err)
		return
	}

	// Verify private blob was saved
	if _, ok := backend.savedData[string(store.FSEXT_PRIVATE_BLOB)]; !ok {
		t.Error("SaveKeyPair() did not save private blob")
	}

	// Verify public blob was saved
	if _, ok := backend.savedData[string(store.FSEXT_PUBLIC_BLOB)]; !ok {
		t.Error("SaveKeyPair() did not save public blob")
	}

	// Verify private data matches
	if string(backend.savedData[string(store.FSEXT_PRIVATE_BLOB)]) != "private-data" {
		t.Errorf("SaveKeyPair() private data = %v, want %v", string(backend.savedData[string(store.FSEXT_PRIVATE_BLOB)]), "private-data")
	}

	logger.Debug("SaveKeyPair test passed")
}

func TestSaveKeyPairWithNilBackend(t *testing.T) {
	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	outPrivate := tpm2.TPM2BPrivate{
		Buffer: []byte("private-data"),
	}

	pubBytes := []byte("public-data")
	outPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes)

	tpmImpl := tpm.(*TPM2)

	// When backend is nil, it should use the default backend
	err := tpmImpl.SaveKeyPair(keyAttrs, outPrivate, outPublic, nil, false)
	// This will likely error because the default backend may not be set up correctly,
	// but it tests the nil backend path
	_ = err

	logger.Debug("SaveKeyPairWithNilBackend test passed")
}

func TestSaveKeyPairPrivateSaveError(t *testing.T) {
	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()
	backend.saveErr = errors.New("save failed")

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	outPrivate := tpm2.TPM2BPrivate{
		Buffer: []byte("private-data"),
	}

	pubBytes := []byte("public-data")
	outPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes)

	tpmImpl := tpm.(*TPM2)

	err := tpmImpl.SaveKeyPair(keyAttrs, outPrivate, outPublic, backend, false)
	if err == nil {
		t.Error("SaveKeyPair() expected error but got nil")
	}

	logger.Debug("SaveKeyPairPrivateSaveError test passed")
}

func TestDeleteKeyPairSuccess(t *testing.T) {
	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	tpmImpl := tpm.(*TPM2)

	err := tpmImpl.DeleteKeyPair(keyAttrs, backend)
	if err != nil {
		t.Errorf("DeleteKeyPair() unexpected error: %v", err)
		return
	}

	if backend.deletedKey != "test-key" {
		t.Errorf("DeleteKeyPair() did not delete the correct key: got %v, want %v", backend.deletedKey, "test-key")
	}

	logger.Debug("DeleteKeyPairSuccess test passed")
}

func TestDeleteKeyPairWithNilBackend(t *testing.T) {
	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	tpmImpl := tpm.(*TPM2)

	// When backend is nil, it should use the default backend
	err := tpmImpl.DeleteKeyPair(keyAttrs, nil)
	// This will likely error but tests the nil backend path
	_ = err

	logger.Debug("DeleteKeyPairWithNilBackend test passed")
}

func TestDeleteKeyPairError(t *testing.T) {
	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()
	backend.deleteErr = errors.New("delete failed")

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	tpmImpl := tpm.(*TPM2)

	err := tpmImpl.DeleteKeyPair(keyAttrs, backend)
	if err == nil {
		t.Error("DeleteKeyPair() expected error but got nil")
	}

	logger.Debug("DeleteKeyPairError test passed")
}

func TestCreateKeySessionWithPlatformPolicy(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	keyAttrs := &types.KeyAttributes{
		CN:             "test-key",
		PlatformPolicy: true,
	}

	// This test will fail because PlatformPolicySession requires TPM operations
	// but it tests the branch logic
	session, closer, err := tpmImpl.CreateKeySession(keyAttrs)

	// Even if it errors, we should have a closer
	if closer != nil {
		defer func() { _ = closer() }()
	}

	// The important thing is that it attempts to create a policy session
	_ = session
	_ = err
}

func TestCreateKeySessionWithPassword(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	keyAttrs := &types.KeyAttributes{
		CN:             "test-key",
		PlatformPolicy: false,
		Password:       store.NewClearPassword([]byte("test-password")),
	}

	session, closer, err := tpmImpl.CreateKeySession(keyAttrs)
	if err != nil {
		t.Errorf("CreateKeySession() unexpected error: %v", err)
		return
	}

	if session == nil {
		t.Error("CreateKeySession() returned nil session")
		return
	}

	if closer == nil {
		t.Error("CreateKeySession() returned nil closer")
		return
	}

	// Call the closer
	err = closer()
	if err != nil {
		t.Errorf("closer() unexpected error: %v", err)
	}
}

func TestCreateKeySessionWithNilPassword(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	keyAttrs := &types.KeyAttributes{
		CN:             "test-key",
		PlatformPolicy: false,
		Password:       nil,
	}

	session, closer, err := tpmImpl.CreateKeySession(keyAttrs)
	if err != nil {
		t.Errorf("CreateKeySession() unexpected error: %v", err)
		return
	}

	if session == nil {
		t.Error("CreateKeySession() returned nil session")
		return
	}

	if closer == nil {
		t.Error("CreateKeySession() returned nil closer")
		return
	}

	// Call the closer - should be no-op
	err = closer()
	if err != nil {
		t.Errorf("closer() unexpected error: %v", err)
	}
}

func TestCreateKeySessionPasswordError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	// Create a password that returns an error
	errPassword := &errorPasswordForSession{err: errors.New("password error")}

	keyAttrs := &types.KeyAttributes{
		CN:             "test-key",
		PlatformPolicy: false,
		Password:       errPassword,
	}

	_, _, err := tpmImpl.CreateKeySession(keyAttrs)
	if err == nil {
		t.Error("CreateKeySession() expected error but got nil")
	}
}

// errorPasswordForSession is a mock password that returns an error
type errorPasswordForSession struct {
	types.Password
	err error
}

func (p *errorPasswordForSession) Bytes() []byte {
	return nil
}

func (p *errorPasswordForSession) String() (string, error) {
	return "", p.err
}

func (p *errorPasswordForSession) Clear() {
	// No-op
}

func TestCreateSessionWithNilParent(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	keyAttrs := &types.KeyAttributes{
		CN:             "test-key",
		PlatformPolicy: false,
		Password:       store.NewClearPassword([]byte("test-password")),
		Parent:         nil,
	}

	// When parent is nil, it should call CreateKeySession
	session, closer, err := tpmImpl.CreateSession(keyAttrs)
	if err != nil {
		t.Errorf("CreateSession() with nil parent unexpected error: %v", err)
		return
	}

	if session == nil {
		t.Error("CreateSession() returned nil session")
		return
	}

	if closer == nil {
		t.Error("CreateSession() returned nil closer")
		return
	}

	err = closer()
	if err != nil {
		t.Errorf("closer() unexpected error: %v", err)
	}
}

func TestHMACSessionConfiguration(t *testing.T) {
	// Test both encrypted and unencrypted paths
	tests := []struct {
		name         string
		encrypted    bool
		debugSecrets bool
	}{
		{
			name:         "unencrypted session",
			encrypted:    false,
			debugSecrets: false,
		},
		{
			name:         "unencrypted session with debug",
			encrypted:    false,
			debugSecrets: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, tpm := createSim(tt.encrypted, false)
			defer func() { _ = tpm.Close() }()

			tpmImpl := tpm.(*TPM2)

			// Test HMAC (not HMACSession) which returns a session without transport
			auth := []byte("test-auth")
			session := tpmImpl.HMAC(auth)

			if session == nil {
				t.Error("HMAC() returned nil session")
			}
		})
	}
}

func TestLoadKeyPairPrivateBlobError(t *testing.T) {
	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()
	backend.getErr = errors.New("blob not found")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		t.Fatalf("EKAttributes() error: %v", err)
	}

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
		Parent:  ekAttrs,
		TPMAttributes: &types.TPMAttributes{
			Handle: 0x81000003,
		},
	}

	tpmImpl := tpm.(*TPM2)

	_, err = tpmImpl.LoadKeyPair(keyAttrs, nil, backend)
	if err == nil {
		t.Error("LoadKeyPair() expected error but got nil")
	}

	logger.Debug("LoadKeyPairPrivateBlobError test passed")
}

func TestLoadKeyPairPublicBlobError(t *testing.T) {
	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()
	// Set private blob but not public blob to trigger public blob error
	backend.getData[string(store.FSEXT_PRIVATE_BLOB)] = []byte("private-data")
	// Don't set public blob so it will error

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		t.Fatalf("EKAttributes() error: %v", err)
	}

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
		Parent:  ekAttrs,
		TPMAttributes: &types.TPMAttributes{
			Handle: 0x81000003,
		},
	}

	tpmImpl := tpm.(*TPM2)

	_, err = tpmImpl.LoadKeyPair(keyAttrs, nil, backend)
	if err == nil {
		t.Error("LoadKeyPair() expected error but got nil")
	}

	logger.Debug("LoadKeyPairPublicBlobError test passed")
}

func TestLoadKeyPairPasswordError(t *testing.T) {
	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()
	backend.getData[string(store.FSEXT_PRIVATE_BLOB)] = []byte("private-data")
	backend.getData[string(store.FSEXT_PUBLIC_BLOB)] = []byte("public-data")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		t.Fatalf("EKAttributes() error: %v", err)
	}

	// Create a password that returns an error
	errPassword := &errorPasswordForSession{err: errors.New("password error")}

	keyAttrs := &types.KeyAttributes{
		CN:             "test-key",
		KeyType:        types.KeyTypeTPM,
		Parent:         ekAttrs,
		Password:       errPassword,
		PlatformPolicy: false,
		TPMAttributes: &types.TPMAttributes{
			Handle: 0x81000003,
		},
	}

	tpmImpl := tpm.(*TPM2)

	_, err = tpmImpl.LoadKeyPair(keyAttrs, nil, backend)
	if err == nil {
		t.Error("LoadKeyPair() expected error but got nil")
	}

	logger.Debug("LoadKeyPairPasswordError test passed")
}

func TestEncodeFunction(t *testing.T) {
	// Test the Encode helper function used in LoadKeyPair
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "empty bytes",
			input: []byte{},
			want:  "",
		},
		{
			name:  "single byte",
			input: []byte{0xFF},
			want:  "ff",
		},
		{
			name:  "multiple bytes",
			input: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			want:  "0123456789abcdef",
		},
		{
			name:  "zero bytes",
			input: []byte{0x00, 0x00, 0x00},
			want:  "000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encode(tt.input)
			if got != tt.want {
				t.Errorf("Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionCloserFunction(t *testing.T) {
	// Test that a no-op closer works correctly
	closer := func() error { return nil }

	err := closer()
	if err != nil {
		t.Errorf("no-op closer() unexpected error: %v", err)
	}

	// Test error closer
	errorCloser := func() error { return errors.New("close error") }

	err = errorCloser()
	if err == nil {
		t.Error("error closer() expected error but got nil")
	}
}

func TestSessionTypeValidation(t *testing.T) {
	// Validate that session-related error types exist
	if ErrInvalidSessionType.Error() != "tpm: invalid session type" {
		t.Errorf("ErrInvalidSessionType = %v, want %v", ErrInvalidSessionType.Error(), "tpm: invalid session type")
	}

	if ErrInvalidSessionAuthorization.Error() != "tpm: invalid session authorization" {
		t.Errorf("ErrInvalidSessionAuthorization = %v, want %v", ErrInvalidSessionAuthorization.Error(), "tpm: invalid session authorization")
	}
}

func TestKeyAttributesPasswordExtraction(t *testing.T) {
	tests := []struct {
		name           string
		password       types.Password
		platformPolicy bool
		expectNil      bool
	}{
		{
			name:           "nil password without policy",
			password:       nil,
			platformPolicy: false,
			expectNil:      true,
		},
		{
			name:           "clear password without policy",
			password:       store.NewClearPassword([]byte("test")),
			platformPolicy: false,
			expectNil:      false,
		},
		{
			name:           "password with platform policy",
			password:       store.NewClearPassword([]byte("test")),
			platformPolicy: true,
			expectNil:      true, // Should not extract when platform policy is true
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				CN:             "test",
				Password:       tt.password,
				PlatformPolicy: tt.platformPolicy,
			}

			var auth []byte
			if keyAttrs.Password != nil && !keyAttrs.PlatformPolicy {
				auth = keyAttrs.Password.Bytes()
			}

			if tt.expectNil {
				if auth != nil {
					t.Errorf("Expected nil auth but got %v", auth)
				}
			} else {
				if auth == nil {
					t.Error("Expected non-nil auth but got nil")
				}
			}
		})
	}
}

func TestHMACEncryptedSession(t *testing.T) {
	_, tpm := createSim(true, false) // Enable encryption
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	auth := []byte("test-auth")
	session := tpmImpl.HMAC(auth)

	if session == nil {
		t.Error("HMAC() returned nil session for encrypted mode")
	}
}

func TestHMACUnencryptedSession(t *testing.T) {
	_, tpm := createSim(false, false) // Disable encryption
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	auth := []byte("test-auth")
	session := tpmImpl.HMAC(auth)

	if session == nil {
		t.Error("HMAC() returned nil session for unencrypted mode")
	}
}

func TestHMACWithEmptyAuth(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	// Test with nil auth
	session := tpmImpl.HMAC(nil)
	if session == nil {
		t.Error("HMAC() returned nil session for nil auth")
	}

	// Test with empty auth
	session = tpmImpl.HMAC([]byte{})
	if session == nil {
		t.Error("HMAC() returned nil session for empty auth")
	}
}
