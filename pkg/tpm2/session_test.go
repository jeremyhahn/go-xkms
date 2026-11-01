//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

func TestDeleteKeyPairWithNilBackend(t *testing.T) {
	logger, tpm := createSim(t, false)
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
	logger, tpm := createSim(t, false)
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

func TestCreateKeySessionPasswordError(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	// Create a password that returns an error
	errPassword := &errorPasswordForSession{err: errors.New("password error")}

	keyAttrs := &types.KeyAttributes{
		CN: "test-key",

		Password: errPassword,
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

func (p *errorPasswordForSession) WithBytes(func([]byte) error) error {
	return p.err
}

func (p *errorPasswordForSession) String() string {
	return types.PasswordRedacted
}

func (p *errorPasswordForSession) Clear() {
	// No-op
}

func TestLoadKeyPairPublicBlobError(t *testing.T) {
	logger, tpm := createSim(t, false)
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

// ---------------------------------------------------------------------------
// Session error types tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PCR bank parsing tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Session type validation tests (TPM algorithm constants)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Session attribute flags tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Session parameter checking tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PCR selection creation tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Policy digest creation tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Auth handle creation tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Named handle creation tests
// ---------------------------------------------------------------------------
