package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mockSealerKeyProvider implements types.KeyProvider and types.Sealer
// for testing seal/unseal field round-tripping. It includes a simple
// in-memory key store so auto-generated sealing keys can be created
// and retrieved.
type mockSealerKeyProvider struct {
	backendType types.BackendType
	sealErr     error
	unsealErr   error
	generateErr error

	// In-memory key store for auto-generated sealing keys.
	keys map[string]crypto.PrivateKey

	// Captured seal options for verification.
	lastSealOpts *types.SealOptions

	// Captured sealed data from unseal for verification.
	lastUnsealData *types.SealedData
	lastUnsealOpts *types.UnsealOptions
}

// newMockSealerKeyProvider creates a mockSealerKeyProvider with an initialized
// in-memory key map.
func newMockSealerKeyProvider(bt types.BackendType) *mockSealerKeyProvider {
	return &mockSealerKeyProvider{
		backendType: bt,
		keys:        make(map[string]crypto.PrivateKey),
	}
}

// KeyProvider interface methods.

func (m *mockSealerKeyProvider) Type() types.BackendType {
	return m.backendType
}

func (m *mockSealerKeyProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Sealing: true}
}

func (m *mockSealerKeyProvider) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if m.generateErr != nil {
		return nil, m.generateErr
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	m.keys[attrs.CN] = key
	return key, nil
}

func (m *mockSealerKeyProvider) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, &ErrMockKeyNotFound{KeyID: attrs.CN}
	}
	return key, nil
}

func (m *mockSealerKeyProvider) DeleteKey(_ *types.KeyAttributes) error {
	return errors.New("not implemented")
}

func (m *mockSealerKeyProvider) ListKeys() ([]*types.KeyAttributes, error) {
	return nil, errors.New("not implemented")
}

func (m *mockSealerKeyProvider) Signer(_ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}

func (m *mockSealerKeyProvider) Decrypter(_ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not implemented")
}

func (m *mockSealerKeyProvider) RotateKey(_ *types.KeyAttributes) error {
	return errors.New("not implemented")
}

func (m *mockSealerKeyProvider) Close() error {
	return nil
}

// Sealer interface methods.

func (m *mockSealerKeyProvider) Seal(
	_ context.Context, data []byte, opts *types.SealOptions,
) (*types.SealedData, error) {
	m.lastSealOpts = opts
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	return &types.SealedData{
		Backend:    m.backendType,
		Ciphertext: append([]byte("encrypted:"), data...),
		Nonce:      []byte("test-nonce"),
		Tag:        []byte("test-tag"),
		TPMPublic:  []byte("tpm-pub-area"),
		TPMPrivate: []byte("tpm-priv-area"),
		WrappedDEK: []byte("wrapped-dek-bytes"),
		KeyID:      "test-key-id",
		Metadata: map[string][]byte{
			"tpm:creation_ticket": []byte("ticket"),
		},
	}, nil
}

func (m *mockSealerKeyProvider) Unseal(
	_ context.Context, sealed *types.SealedData, opts *types.UnsealOptions,
) ([]byte, error) {
	m.lastUnsealData = sealed
	m.lastUnsealOpts = opts
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	return []byte("decrypted-data"), nil
}

func (m *mockSealerKeyProvider) CanSeal() bool {
	return true
}

// setupSealableService configures the XKMSService singleton with a mock backend
// that supports sealing, returning the mock sealer for assertion.
func setupSealableService(t *testing.T) *mockSealerKeyProvider {
	t.Helper()
	Reset()

	sealer := newMockSealerKeyProvider(types.BackendType("software"))

	software := newMockKeyStore("software")
	software.backend = sealer

	config := &ServiceConfig{
		Backends: map[string]Backend{
			"software": software,
		},
		DefaultBackend: "software",
	}

	err := Initialize(config)
	require.NoError(t, err)

	return sealer
}

// setupSealableServiceWithBackendType configures the service with a specific
// backend type, useful for testing TPM2 vs software auto-key behavior.
func setupSealableServiceWithBackendType(t *testing.T, name string, bt types.BackendType) *mockSealerKeyProvider {
	t.Helper()
	Reset()

	sealer := newMockSealerKeyProvider(bt)

	backend := newMockKeyStore(name)
	backend.backend = sealer

	config := &ServiceConfig{
		Backends: map[string]Backend{
			name: backend,
		},
		DefaultBackend: name,
	}

	err := Initialize(config)
	require.NoError(t, err)

	return sealer
}

// --- Seal ---

func TestSeal_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestSeal_EmptyData(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    nil,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilData))
}

func TestSeal_EmptyDataSlice(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte{},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilData))
}

func TestSeal_BackendNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "nonexistent",
		Data:    []byte("seal me"),
	})
	require.Error(t, err)
}

// --- Unseal ---

func TestUnseal_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestUnseal_EmptyCiphertext(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// No ciphertext, no TPM blobs -- should fail validation.
	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: nil,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSealedData))
}

func TestServicerUnseal_BackendNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "nonexistent",
		Ciphertext: []byte("sealed"),
	})
	require.Error(t, err)
}

// --- CanSeal ---

func TestCanSeal_DefaultBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.CanSeal(context.Background(), "")
	require.NoError(t, err)
	// Mock backend has no sealer, so CanSeal should be false
	assert.False(t, resp.CanSeal)
	assert.Equal(t, "software", resp.Backend)
}

func TestCanSeal_SpecificBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.CanSeal(context.Background(), "pkcs11")
	require.NoError(t, err)
	assert.False(t, resp.CanSeal)
	assert.Equal(t, "pkcs11", resp.Backend)
}

func TestCanSeal_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CanSeal(context.Background(), "nonexistent")
	require.Error(t, err)
}

// --- Additional seal coverage ---

func TestSeal_DefaultBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Data: []byte("seal me"),
	})
	// Mock backend doesn't support sealing
	require.Error(t, err)
}

func TestSeal_WithKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("seal me"),
		KeyID:   "software:signing:ecdsa:P-256:my-key",
	})
	// Mock backend doesn't support sealing
	require.Error(t, err)
}

func TestSeal_InvalidKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("seal me"),
		KeyID:   "invalid:::",
	})
	require.Error(t, err)
}

func TestUnseal_EmptyCiphertextSlice(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// Empty ciphertext slice and no TPM blobs -- should fail validation.
	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte{},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSealedData))
}

func TestCanSeal_DefaultBackendEmpty(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.CanSeal(context.Background(), "")
	require.NoError(t, err)
	assert.False(t, resp.CanSeal)
	assert.Equal(t, "software", resp.Backend)
}

func TestUnseal_InvalidKeyID_TPM2_ReturnsError(t *testing.T) {
	setupSealableServiceWithBackendType(t, "tpm2", types.BackendTypeTPM2)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "tpm2",
		Ciphertext: []byte("sealed"),
		KeyID:      "invalid:::",
	})
	require.Error(t, err)
	var keyIDErr *ErrKeyIDParse
	assert.True(t, errors.As(err, &keyIDErr))
}

func TestUnseal_LegacyKeyID_SoftwareBackend_FallsBackToDefaults(t *testing.T) {
	setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	// A legacy ID() format KeyID that ParseKeyID can't parse — software backend
	// should fall back to default sealing key attributes rather than returning error.
	resp, err := svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("sealed"),
		KeyID:      "software:encryption:xkms-sealing-key-software:ecdsa",
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("decrypted-data"), resp.Plaintext)
}

func TestSeal_WithAAD(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("seal me"),
		AAD:     []byte("additional-data"),
	})
	// Mock backend doesn't support sealing, but AAD is passed through
	require.Error(t, err)
}

// --- Seal/Unseal field round-trip tests ---

func TestSeal_AllFieldsPreservedInResponse(t *testing.T) {
	setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret"),
	})
	require.NoError(t, err)

	assert.Equal(t, "software", resp.Backend)
	assert.Equal(t, []byte("encrypted:secret"), resp.Ciphertext)
	assert.Equal(t, []byte("test-nonce"), resp.Nonce)
	assert.Equal(t, []byte("test-tag"), resp.Tag)
	assert.Equal(t, []byte("tpm-pub-area"), resp.TPMPublic)
	assert.Equal(t, []byte("tpm-priv-area"), resp.TPMPrivate)
	assert.Equal(t, []byte("wrapped-dek-bytes"), resp.WrappedDEK)
	assert.Equal(t, "test-key-id", resp.KeyID)
	assert.Equal(t, map[string][]byte{
		"tpm:creation_ticket": []byte("ticket"),
	}, resp.Metadata)
}

func TestSeal_SealOperationError(t *testing.T) {
	sealer := setupSealableService(t)
	sealer.sealErr = errors.New("seal failed")
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret"),
	})
	require.Error(t, err)
	var sealErr *ErrSealOperation
	assert.True(t, errors.As(err, &sealErr))
	assert.Equal(t, "seal", sealErr.Operation)
}

func TestUnseal_AllFieldsPassedToSealedData(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	metadata := map[string][]byte{
		"aws:encryption_context": []byte("ctx-val"),
	}

	resp, err := svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("encrypted"),
		Nonce:      []byte("nonce"),
		Tag:        []byte("tag"),
		TPMPublic:  []byte("pub"),
		TPMPrivate: []byte("priv"),
		WrappedDEK: []byte("dek"),
		Metadata:   metadata,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("decrypted-data"), resp.Plaintext)

	// Verify all fields were passed through to the backend.
	require.NotNil(t, sealer.lastUnsealData)
	assert.Equal(t, types.BackendType("software"), sealer.lastUnsealData.Backend)
	assert.Equal(t, []byte("encrypted"), sealer.lastUnsealData.Ciphertext)
	assert.Equal(t, []byte("nonce"), sealer.lastUnsealData.Nonce)
	assert.Equal(t, []byte("tag"), sealer.lastUnsealData.Tag)
	assert.Equal(t, []byte("pub"), sealer.lastUnsealData.TPMPublic)
	assert.Equal(t, []byte("priv"), sealer.lastUnsealData.TPMPrivate)
	assert.Equal(t, []byte("dek"), sealer.lastUnsealData.WrappedDEK)
	assert.Equal(t, metadata, sealer.lastUnsealData.Metadata)
}

func TestUnseal_OperationError(t *testing.T) {
	sealer := setupSealableService(t)
	sealer.unsealErr = errors.New("unseal failed")
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("encrypted"),
	})
	require.Error(t, err)
	var sealErr *ErrSealOperation
	assert.True(t, errors.As(err, &sealErr))
	assert.Equal(t, "unseal", sealErr.Operation)
}

func TestUnseal_WithPassword(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("encrypted"),
		Password:   "my-tpm-auth",
	})
	require.NoError(t, err)

	require.NotNil(t, sealer.lastUnsealOpts)
	require.NotNil(t, sealer.lastUnsealOpts.Password)
	assert.Equal(t, []byte("my-tpm-auth"), sealer.lastUnsealOpts.Password.Bytes())
}

func TestUnseal_WithoutPassword(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("encrypted"),
	})
	require.NoError(t, err)

	require.NotNil(t, sealer.lastUnsealOpts)
	assert.Nil(t, sealer.lastUnsealOpts.Password)
}

func TestUnseal_WithKeyID(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("encrypted"),
		KeyID:      "software:signing:ecdsa-p256:my-key",
	})
	require.NoError(t, err)

	require.NotNil(t, sealer.lastUnsealOpts)
	require.NotNil(t, sealer.lastUnsealOpts.KeyAttributes)
	assert.Equal(t, "my-key", sealer.lastUnsealOpts.KeyAttributes.CN)
}

func TestUnseal_WithAAD(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("encrypted"),
		AAD:        []byte("extra-auth"),
	})
	require.NoError(t, err)

	require.NotNil(t, sealer.lastUnsealOpts)
	assert.Equal(t, []byte("extra-auth"), sealer.lastUnsealOpts.AAD)
}

// --- Unseal TPM2 blob validation tests ---

func TestUnseal_TPMBlobsOnly_NoCiphertext(t *testing.T) {
	// TPM2 sealing stores data in TPMPublic/TPMPrivate blobs, not Ciphertext.
	// Unseal must accept requests with TPM blobs and empty Ciphertext.
	sealer := setupSealableServiceWithBackendType(t, "tpm2", types.BackendTypeTPM2)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "tpm2",
		TPMPublic:  []byte("tpm-public-blob"),
		TPMPrivate: []byte("tpm-private-blob"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, []byte("decrypted-data"), resp.Plaintext)

	// Verify the TPM blobs were forwarded to the backend.
	require.NotNil(t, sealer.lastUnsealData)
	assert.Equal(t, []byte("tpm-public-blob"), sealer.lastUnsealData.TPMPublic)
	assert.Equal(t, []byte("tpm-private-blob"), sealer.lastUnsealData.TPMPrivate)
	assert.Empty(t, sealer.lastUnsealData.Ciphertext)
}

func TestUnseal_AllFieldsEmpty_ReturnsErrInvalidSealedData(t *testing.T) {
	// When Ciphertext, TPMPublic, and TPMPrivate are all empty,
	// the request contains no sealed data and must be rejected.
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend: "software",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSealedData))
}

func TestUnseal_TPMPublicOnly_MissingPrivate_ReturnsError(t *testing.T) {
	// TPM blobs require both public and private. Having only TPMPublic
	// with empty Ciphertext is invalid.
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:   "software",
		TPMPublic: []byte("tpm-public-only"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSealedData))
}

func TestUnseal_TPMPrivateOnly_MissingPublic_ReturnsError(t *testing.T) {
	// TPM blobs require both public and private. Having only TPMPrivate
	// with empty Ciphertext is invalid.
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		TPMPrivate: []byte("tpm-private-only"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSealedData))
}

func TestUnseal_CiphertextWithTPMBlobs_Succeeds(t *testing.T) {
	// When both ciphertext and TPM blobs are present, validation passes.
	// This covers hybrid scenarios where both forms coexist.
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("encrypted"),
		TPMPublic:  []byte("pub"),
		TPMPrivate: []byte("priv"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, []byte("decrypted-data"), resp.Plaintext)

	// All three fields should be forwarded.
	require.NotNil(t, sealer.lastUnsealData)
	assert.Equal(t, []byte("encrypted"), sealer.lastUnsealData.Ciphertext)
	assert.Equal(t, []byte("pub"), sealer.lastUnsealData.TPMPublic)
	assert.Equal(t, []byte("priv"), sealer.lastUnsealData.TPMPrivate)
}

// --- PCR mapping tests ---

func TestSeal_PCRMapping_DefaultHashAlg(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret"),
		PCRs:    []int{0, 7},
	})
	require.NoError(t, err)

	require.NotNil(t, sealer.lastSealOpts)
	require.NotNil(t, sealer.lastSealOpts.TPMPolicy)
	assert.Equal(t, tpm2.TPMAlgSHA256, sealer.lastSealOpts.TPMPolicy.HashAlg)
	assert.Len(t, sealer.lastSealOpts.TPMPolicy.PCRSelection.PCRSelections, 1)
	assert.Equal(t, tpm2.TPMAlgSHA256,
		sealer.lastSealOpts.TPMPolicy.PCRSelection.PCRSelections[0].Hash)
}

func TestSeal_PCRMapping_SHA384(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend:    "software",
		Data:       []byte("secret"),
		PCRs:       []int{7},
		PCRHashAlg: "sha384",
	})
	require.NoError(t, err)

	require.NotNil(t, sealer.lastSealOpts)
	require.NotNil(t, sealer.lastSealOpts.TPMPolicy)
	assert.Equal(t, tpm2.TPMAlgSHA384, sealer.lastSealOpts.TPMPolicy.HashAlg)
}

func TestSeal_PCRMapping_InvalidHashAlg(t *testing.T) {
	setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend:    "software",
		Data:       []byte("secret"),
		PCRs:       []int{0},
		PCRHashAlg: "md5",
	})
	require.Error(t, err)
	var hashErr *ErrPCRHashAlgParse
	assert.True(t, errors.As(err, &hashErr))
	assert.Equal(t, "md5", hashErr.Algorithm)
}

func TestSeal_PCRMapping_NoPCRs_NoPolicySet(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret"),
	})
	require.NoError(t, err)

	require.NotNil(t, sealer.lastSealOpts)
	assert.Nil(t, sealer.lastSealOpts.TPMPolicy)
}

func TestSeal_PCRMapping_InvalidPCRIndex_Negative(t *testing.T) {
	setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret"),
		PCRs:    []int{-1},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPCRIndex))
}

func TestSeal_PCRMapping_InvalidPCRIndex_TooHigh(t *testing.T) {
	setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret"),
		PCRs:    []int{24},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPCRIndex))
}

// --- Password mapping tests ---

func TestSeal_PasswordMapping(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend:  "software",
		Data:     []byte("secret"),
		Password: "my-seal-password",
	})
	require.NoError(t, err)

	require.NotNil(t, sealer.lastSealOpts)
	require.NotNil(t, sealer.lastSealOpts.Password)
	assert.Equal(t, []byte("my-seal-password"), sealer.lastSealOpts.Password.Bytes())
}

func TestSeal_NoPassword_NilInOpts(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret"),
	})
	require.NoError(t, err)

	require.NotNil(t, sealer.lastSealOpts)
	assert.Nil(t, sealer.lastSealOpts.Password)
}

// --- CanSeal with sealable backend ---

func TestCanSeal_SealableBackend(t *testing.T) {
	setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.CanSeal(context.Background(), "software")
	require.NoError(t, err)
	assert.True(t, resp.CanSeal)
	assert.Equal(t, "software", resp.Backend)
}

// --- parsePCRHashAlg unit tests ---

func TestParsePCRHashAlg_EmptyDefaultsSHA256(t *testing.T) {
	alg, err := parsePCRHashAlg("")
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgSHA256, alg)
}

func TestParsePCRHashAlg_AllValid(t *testing.T) {
	tests := []struct {
		input    string
		expected tpm2.TPMIAlgHash
	}{
		{"sha1", tpm2.TPMAlgSHA1},
		{"SHA1", tpm2.TPMAlgSHA1},
		{"sha256", tpm2.TPMAlgSHA256},
		{"SHA256", tpm2.TPMAlgSHA256},
		{"sha384", tpm2.TPMAlgSHA384},
		{"SHA384", tpm2.TPMAlgSHA384},
		{"sha512", tpm2.TPMAlgSHA512},
		{"SHA512", tpm2.TPMAlgSHA512},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			alg, err := parsePCRHashAlg(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, alg)
		})
	}
}

func TestParsePCRHashAlg_Invalid(t *testing.T) {
	tests := []string{"md5", "blake2b", "unknown", "SHA-256"}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := parsePCRHashAlg(input)
			require.Error(t, err)
			var hashErr *ErrPCRHashAlgParse
			assert.True(t, errors.As(err, &hashErr))
			assert.Equal(t, input, hashErr.Algorithm)
			assert.True(t, errors.Is(err, ErrInvalidHashFunction))
		})
	}
}

// --- buildPCRSelection unit tests ---

func TestBuildPCRSelection_ValidPCRs(t *testing.T) {
	sel, err := buildPCRSelection([]int{0, 7, 14}, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	assert.Len(t, sel.PCRSelections, 1)
	assert.Equal(t, tpm2.TPMAlgSHA256, sel.PCRSelections[0].Hash)
	assert.NotEmpty(t, sel.PCRSelections[0].PCRSelect)
}

func TestBuildPCRSelection_SinglePCR(t *testing.T) {
	sel, err := buildPCRSelection([]int{23}, tpm2.TPMAlgSHA384)
	require.NoError(t, err)
	assert.Len(t, sel.PCRSelections, 1)
	assert.Equal(t, tpm2.TPMAlgSHA384, sel.PCRSelections[0].Hash)
}

func TestBuildPCRSelection_InvalidNegative(t *testing.T) {
	_, err := buildPCRSelection([]int{-1}, tpm2.TPMAlgSHA256)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPCRIndex))
}

func TestBuildPCRSelection_InvalidTooHigh(t *testing.T) {
	_, err := buildPCRSelection([]int{24}, tpm2.TPMAlgSHA256)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPCRIndex))
}

func TestBuildPCRSelection_BoundaryValid(t *testing.T) {
	// PCR 0 and 23 are the boundary valid values.
	sel, err := buildPCRSelection([]int{0, 23}, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	assert.Len(t, sel.PCRSelections, 1)
}

// --- ErrPCRHashAlgParse tests ---

func TestErrPCRHashAlgParse_ErrorMessage(t *testing.T) {
	err := &ErrPCRHashAlgParse{
		Algorithm: "md5",
		Err:       ErrInvalidHashFunction,
	}
	assert.Contains(t, err.Error(), "md5")
	assert.Contains(t, err.Error(), "invalid PCR hash algorithm")
}

func TestErrPCRHashAlgParse_Unwrap(t *testing.T) {
	inner := ErrInvalidHashFunction
	err := &ErrPCRHashAlgParse{
		Algorithm: "md5",
		Err:       inner,
	}
	assert.True(t, errors.Is(err, inner))
}

// --- Auto-generate sealing key tests ---

func TestSeal_SoftwareBackend_AutoGeneratesKey(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	// Seal without providing a KeyID; the servicer should auto-generate
	// a sealing key and populate opts.KeyAttributes.
	resp, err := svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret payload"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Ciphertext)

	// Verify KeyAttributes were auto-populated with the well-known CN.
	require.NotNil(t, sealer.lastSealOpts)
	require.NotNil(t, sealer.lastSealOpts.KeyAttributes)

	expectedCN := "xkms-sealing-key-software"
	assert.Equal(t, expectedCN, sealer.lastSealOpts.KeyAttributes.CN)
	assert.Equal(t, x509.ECDSA, sealer.lastSealOpts.KeyAttributes.KeyAlgorithm)
	assert.Equal(t, elliptic.P256(), sealer.lastSealOpts.KeyAttributes.ECCAttributes.Curve)
	assert.Equal(t, types.KeyTypeEncryption, sealer.lastSealOpts.KeyAttributes.KeyType)
	assert.Equal(t, types.StoreSoftware, sealer.lastSealOpts.KeyAttributes.StoreType)

	// Verify the sealing key was persisted in the mock key provider.
	_, keyErr := sealer.GetKey(&types.KeyAttributes{CN: expectedCN})
	assert.NoError(t, keyErr)
}

func TestSeal_SoftwareBackend_AutoKeyReusedOnSecondCall(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	// First seal creates the auto-generated key.
	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("first"),
	})
	require.NoError(t, err)

	// Record the key count after first seal.
	keyCountAfterFirst := len(sealer.keys)

	// Second seal should reuse the existing key (GetKey succeeds).
	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("second"),
	})
	require.NoError(t, err)

	// Key count should not have changed.
	assert.Equal(t, keyCountAfterFirst, len(sealer.keys))
}

func TestSeal_SoftwareBackend_AutoGenerateKeyFailure(t *testing.T) {
	sealer := setupSealableService(t)
	sealer.generateErr = errors.New("key generation hardware failure")
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret"),
	})
	require.Error(t, err)
	var sealErr *ErrSealOperation
	assert.True(t, errors.As(err, &sealErr))
	assert.Equal(t, "auto-generate sealing key", sealErr.Operation)
}

func TestSeal_WithExplicitKeyID_SkipsAutoGenerate(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret"),
		KeyID:   "software:signing:ecdsa-p256:my-explicit-key",
	})
	require.NoError(t, err)

	// Verify the explicit key's CN was used, not the auto-generated one.
	require.NotNil(t, sealer.lastSealOpts)
	require.NotNil(t, sealer.lastSealOpts.KeyAttributes)
	assert.Equal(t, "my-explicit-key", sealer.lastSealOpts.KeyAttributes.CN)

	// Verify no auto-generated key was created.
	_, keyErr := sealer.GetKey(&types.KeyAttributes{CN: "xkms-sealing-key-software"})
	assert.Error(t, keyErr)
}

func TestUnseal_SoftwareBackend_AutoResolvesKey(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	// Unseal without a KeyID; the servicer should auto-resolve the
	// well-known sealing key CN.
	resp, err := svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("encrypted-payload"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, []byte("decrypted-data"), resp.Plaintext)

	// Verify KeyAttributes were auto-populated.
	require.NotNil(t, sealer.lastUnsealOpts)
	require.NotNil(t, sealer.lastUnsealOpts.KeyAttributes)

	expectedCN := "xkms-sealing-key-software"
	assert.Equal(t, expectedCN, sealer.lastUnsealOpts.KeyAttributes.CN)
	assert.Equal(t, x509.ECDSA, sealer.lastUnsealOpts.KeyAttributes.KeyAlgorithm)
	assert.Equal(t, types.StoreSoftware, sealer.lastUnsealOpts.KeyAttributes.StoreType)
}

func TestUnseal_WithExplicitKeyID_SkipsAutoResolve(t *testing.T) {
	sealer := setupSealableService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("encrypted"),
		KeyID:      "software:signing:ecdsa-p256:my-unseal-key",
	})
	require.NoError(t, err)

	// Verify the explicit key's CN was used.
	require.NotNil(t, sealer.lastUnsealOpts)
	require.NotNil(t, sealer.lastUnsealOpts.KeyAttributes)
	assert.Equal(t, "my-unseal-key", sealer.lastUnsealOpts.KeyAttributes.CN)
}

func TestSeal_TPM2Backend_NoAutoGenerate(t *testing.T) {
	sealer := setupSealableServiceWithBackendType(t, "tpm2", types.BackendTypeTPM2)
	svc, err := Get()
	require.NoError(t, err)

	// Seal without KeyID on TPM2 backend -- auto-generation should NOT happen.
	// TPM2 handles sealing keys internally via the SRK.
	_, err = svc.Seal(context.Background(), &transport.SealRequest{
		Backend: "tpm2",
		Data:    []byte("secret"),
	})
	require.NoError(t, err)

	// Verify no KeyAttributes were auto-generated for TPM2.
	require.NotNil(t, sealer.lastSealOpts)
	assert.Nil(t, sealer.lastSealOpts.KeyAttributes)
}

func TestUnseal_TPM2Backend_NoAutoResolve(t *testing.T) {
	sealer := setupSealableServiceWithBackendType(t, "tpm2", types.BackendTypeTPM2)
	svc, err := Get()
	require.NoError(t, err)

	// Unseal without KeyID on TPM2 backend -- auto-resolution should NOT happen.
	_, err = svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "tpm2",
		Ciphertext: []byte("encrypted"),
	})
	require.NoError(t, err)

	// Verify no KeyAttributes were auto-generated for TPM2.
	require.NotNil(t, sealer.lastUnsealOpts)
	assert.Nil(t, sealer.lastUnsealOpts.KeyAttributes)
}

// --- defaultSealingKeyAttributes unit tests ---

func TestDefaultSealingKeyAttributes_Software(t *testing.T) {
	attrs := defaultSealingKeyAttributes(types.BackendTypeSoftware)

	assert.Equal(t, "xkms-sealing-key-software", attrs.CN)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.ECCAttributes)
	assert.Equal(t, elliptic.P256(), attrs.ECCAttributes.Curve)
	assert.Equal(t, types.KeyTypeEncryption, attrs.KeyType)
	assert.Equal(t, types.StoreSoftware, attrs.StoreType)
}

func TestDefaultSealingKeyAttributes_PKCS11(t *testing.T) {
	attrs := defaultSealingKeyAttributes(types.BackendTypePKCS11)

	assert.Equal(t, "xkms-sealing-key-pkcs11", attrs.CN)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.ECCAttributes)
	assert.Equal(t, elliptic.P256(), attrs.ECCAttributes.Curve)
	assert.Equal(t, types.KeyTypeEncryption, attrs.KeyType)
	assert.Equal(t, types.StorePKCS11, attrs.StoreType)
}

// --- ensureSealingKey unit tests ---

func TestEnsureSealingKey_KeyAlreadyExists(t *testing.T) {
	provider := newMockSealerKeyProvider(types.BackendTypeSoftware)
	attrs := defaultSealingKeyAttributes(types.BackendTypeSoftware)

	// Pre-populate the key.
	_, err := provider.GenerateKey(attrs)
	require.NoError(t, err)

	keyCountBefore := len(provider.keys)

	// ensureSealingKey should succeed without generating a new key.
	err = ensureSealingKey(provider, attrs)
	require.NoError(t, err)
	assert.Equal(t, keyCountBefore, len(provider.keys))
}

func TestEnsureSealingKey_GeneratesNewKey(t *testing.T) {
	provider := newMockSealerKeyProvider(types.BackendTypeSoftware)
	attrs := defaultSealingKeyAttributes(types.BackendTypeSoftware)

	err := ensureSealingKey(provider, attrs)
	require.NoError(t, err)

	// Verify the key was generated.
	_, keyErr := provider.GetKey(attrs)
	assert.NoError(t, keyErr)
}

func TestEnsureSealingKey_GenerateFailure(t *testing.T) {
	provider := newMockSealerKeyProvider(types.BackendTypeSoftware)
	provider.generateErr = errors.New("hardware not available")
	attrs := defaultSealingKeyAttributes(types.BackendTypeSoftware)

	err := ensureSealingKey(provider, attrs)
	require.Error(t, err)

	var sealErr *ErrSealOperation
	assert.True(t, errors.As(err, &sealErr))
	assert.Equal(t, "auto-generate sealing key", sealErr.Operation)
}
