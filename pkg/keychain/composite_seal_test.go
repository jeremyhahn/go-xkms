// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package keychain

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSealerBackendForComposite is a mock backend that implements types.Backend and types.Sealer
type mockSealerBackendForComposite struct {
	backendType types.BackendType
	canSeal     bool
	sealErr     error
	unsealErr   error
	sealedData  map[string][]byte
}

func newMockSealerBackendForComposite() *mockSealerBackendForComposite {
	return &mockSealerBackendForComposite{
		backendType: types.BackendTypeSoftware,
		canSeal:     true,
		sealedData:  make(map[string][]byte),
	}
}

// Backend interface implementation
func (m *mockSealerBackendForComposite) Type() types.BackendType { return m.backendType }
func (m *mockSealerBackendForComposite) Capabilities() types.Capabilities {
	return types.Capabilities{}
}
func (m *mockSealerBackendForComposite) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}
func (m *mockSealerBackendForComposite) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}
func (m *mockSealerBackendForComposite) DeleteKey(attrs *types.KeyAttributes) error { return nil }
func (m *mockSealerBackendForComposite) ListKeys() ([]*types.KeyAttributes, error)  { return nil, nil }
func (m *mockSealerBackendForComposite) RotateKey(attrs *types.KeyAttributes) error {
	return errors.New("not implemented")
}
func (m *mockSealerBackendForComposite) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}
func (m *mockSealerBackendForComposite) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not implemented")
}
func (m *mockSealerBackendForComposite) Close() error { return nil }

// Sealer interface implementation
func (m *mockSealerBackendForComposite) CanSeal() bool { return m.canSeal }

func (m *mockSealerBackendForComposite) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}

	keyID := "default"
	if opts != nil && opts.KeyAttributes != nil {
		keyID = opts.KeyAttributes.ID()
	}

	m.sealedData[keyID] = data

	return &types.SealedData{
		Backend:    m.backendType,
		Ciphertext: []byte("mock-encrypted-" + string(data)),
		KeyID:      keyID,
		Metadata:   make(map[string][]byte),
	}, nil
}

func (m *mockSealerBackendForComposite) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}

	keyID := "default"
	if opts != nil && opts.KeyAttributes != nil {
		keyID = opts.KeyAttributes.ID()
	}

	data, ok := m.sealedData[keyID]
	if !ok {
		return nil, errors.New("sealed data not found")
	}

	return data, nil
}

// mockNonSealerBackend is a mock backend that does NOT implement types.Sealer
type mockNonSealerBackend struct {
	backendType types.BackendType
}

func (m *mockNonSealerBackend) Type() types.BackendType { return m.backendType }
func (m *mockNonSealerBackend) Capabilities() types.Capabilities {
	return types.Capabilities{}
}
func (m *mockNonSealerBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}
func (m *mockNonSealerBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}
func (m *mockNonSealerBackend) DeleteKey(attrs *types.KeyAttributes) error { return nil }
func (m *mockNonSealerBackend) ListKeys() ([]*types.KeyAttributes, error)  { return nil, nil }
func (m *mockNonSealerBackend) RotateKey(attrs *types.KeyAttributes) error {
	return errors.New("not implemented")
}
func (m *mockNonSealerBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}
func (m *mockNonSealerBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not implemented")
}
func (m *mockNonSealerBackend) Close() error { return nil }

func TestCompositeKeyStore_CanSeal_WithSealer(t *testing.T) {
	backend := newMockSealerBackendForComposite()
	backend.canSeal = true

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	assert.True(t, ks.CanSeal())
}

func TestCompositeKeyStore_CanSeal_SealerDisabled(t *testing.T) {
	backend := newMockSealerBackendForComposite()
	backend.canSeal = false

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	assert.False(t, ks.CanSeal())
}

func TestCompositeKeyStore_CanSeal_NonSealer(t *testing.T) {
	backend := &mockNonSealerBackend{backendType: types.BackendTypeSoftware}

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	assert.False(t, ks.CanSeal())
}

func TestCompositeKeyStore_Seal_Success(t *testing.T) {
	backend := newMockSealerBackendForComposite()

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	data := []byte("secret data")
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test-key"},
	}

	sealed, err := ks.Seal(ctx, data, opts)
	assert.NoError(t, err)
	assert.NotNil(t, sealed)
	assert.Equal(t, types.BackendTypeSoftware, sealed.Backend)
}

func TestCompositeKeyStore_Seal_NonSealer(t *testing.T) {
	backend := &mockNonSealerBackend{backendType: types.BackendTypeSoftware}

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = ks.Seal(ctx, []byte("data"), &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test"},
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSealingNotSupported)
}

func TestCompositeKeyStore_Seal_CannotSeal(t *testing.T) {
	backend := newMockSealerBackendForComposite()
	backend.canSeal = false

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = ks.Seal(ctx, []byte("data"), &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test"},
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSealingNotSupported)
}

func TestCompositeKeyStore_Seal_BackendError(t *testing.T) {
	backend := newMockSealerBackendForComposite()
	backend.sealErr = errors.New("seal failed")

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = ks.Seal(ctx, []byte("data"), &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "seal failed")
}

func TestCompositeKeyStore_Unseal_Success(t *testing.T) {
	backend := newMockSealerBackendForComposite()

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	originalData := []byte("secret data")
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test-key"},
	}

	// First seal
	sealed, err := ks.Seal(ctx, originalData, opts)
	require.NoError(t, err)

	// Then unseal
	unsealOpts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test-key"},
	}
	plaintext, err := ks.Unseal(ctx, sealed, unsealOpts)
	assert.NoError(t, err)
	assert.Equal(t, originalData, plaintext)
}

func TestCompositeKeyStore_Unseal_NilSealedData(t *testing.T) {
	backend := newMockSealerBackendForComposite()

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = ks.Unseal(ctx, nil, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test"},
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSealedData)
}

func TestCompositeKeyStore_Unseal_NonSealer(t *testing.T) {
	backend := &mockNonSealerBackend{backendType: types.BackendTypeSoftware}

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	sealed := &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: []byte("encrypted"),
	}

	ctx := context.Background()
	_, err = ks.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test"},
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSealingNotSupported)
}

func TestCompositeKeyStore_Unseal_BackendMismatch(t *testing.T) {
	backend := newMockSealerBackendForComposite()
	backend.backendType = types.BackendTypeSoftware

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	// Sealed data from a different backend
	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11, // Different from our backend
		Ciphertext: []byte("encrypted"),
	}

	ctx := context.Background()
	_, err = ks.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test"},
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendMismatch)
}

func TestCompositeKeyStore_Unseal_BackendError(t *testing.T) {
	backend := newMockSealerBackendForComposite()
	backend.unsealErr = errors.New("unseal failed")

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	sealed := &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: []byte("encrypted"),
	}

	ctx := context.Background()
	_, err = ks.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unseal failed")
}

func TestCompositeKeyStore_SealUnseal_RoundTrip(t *testing.T) {
	backend := newMockSealerBackendForComposite()

	ks, err := New(&Config{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	testCases := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"small data", []byte("hello")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}},
		{"large data", make([]byte, 1024*1024)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{CN: "roundtrip-" + tc.name}

			// Seal
			sealed, err := ks.Seal(ctx, tc.data, &types.SealOptions{
				KeyAttributes: keyAttrs,
			})
			require.NoError(t, err)

			// Unseal
			plaintext, err := ks.Unseal(ctx, sealed, &types.UnsealOptions{
				KeyAttributes: keyAttrs,
			})
			require.NoError(t, err)

			assert.Equal(t, tc.data, plaintext)
		})
	}
}
