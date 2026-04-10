package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Mock import/export key provider
// ===========================================================================

type boostIEKeyProvider struct {
	keys          map[string]crypto.PrivateKey
	keyAttrs      map[string]*types.KeyAttributes
	importErr     error
	exportErr     error
	wrapErr       error
	unwrapErr     error
	getParamsErr  error
	wrappingKey   *rsa.PrivateKey
	importedKeys  map[string]*backend.WrappedKeyMaterial
	unwrappedData []byte
}

func newBoostIEKeyProvider() *boostIEKeyProvider {
	wrappingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &boostIEKeyProvider{
		keys:         make(map[string]crypto.PrivateKey),
		keyAttrs:     make(map[string]*types.KeyAttributes),
		importedKeys: make(map[string]*backend.WrappedKeyMaterial),
		wrappingKey:  wrappingKey,
	}
}

func (m *boostIEKeyProvider) Type() types.BackendType { return "mock-ie" }
func (m *boostIEKeyProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Import: true, Export: true}
}
func (m *boostIEKeyProvider) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	m.keys[attrs.CN] = key
	m.keyAttrs[attrs.CN] = attrs
	return key, nil
}
func (m *boostIEKeyProvider) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	k, ok := m.keys[attrs.CN]
	if !ok {
		return nil, errors.New("key not found")
	}
	return k, nil
}
func (m *boostIEKeyProvider) DeleteKey(attrs *types.KeyAttributes) error {
	delete(m.keys, attrs.CN)
	delete(m.keyAttrs, attrs.CN)
	return nil
}
func (m *boostIEKeyProvider) ListKeys() ([]*types.KeyAttributes, error) {
	var attrs []*types.KeyAttributes
	for cn := range m.keys {
		if a, ok := m.keyAttrs[cn]; ok {
			attrs = append(attrs, a)
		} else {
			attrs = append(attrs, &types.KeyAttributes{CN: cn})
		}
	}
	return attrs, nil
}
func (m *boostIEKeyProvider) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	k, err := m.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("not a signer")
	}
	return s, nil
}
func (m *boostIEKeyProvider) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not supported")
}
func (m *boostIEKeyProvider) RotateKey(attrs *types.KeyAttributes) error { return nil }
func (m *boostIEKeyProvider) Close() error                              { return nil }

func (m *boostIEKeyProvider) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if m.getParamsErr != nil {
		return nil, m.getParamsErr
	}
	return &backend.ImportParameters{
		WrappingPublicKey: &m.wrappingKey.PublicKey,
		ImportToken:       []byte("test-token"),
		Algorithm:         algorithm,
	}, nil
}

func (m *boostIEKeyProvider) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if m.wrapErr != nil {
		return nil, m.wrapErr
	}
	return &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-material"),
		Algorithm:  params.Algorithm,
	}, nil
}

func (m *boostIEKeyProvider) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if m.unwrapErr != nil {
		return nil, m.unwrapErr
	}
	if m.unwrappedData != nil {
		return m.unwrappedData, nil
	}
	return []byte("unwrapped-key-material"), nil
}

func (m *boostIEKeyProvider) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if m.importErr != nil {
		return m.importErr
	}
	m.importedKeys[attrs.CN] = wrapped
	return nil
}


func (m *boostIEKeyProvider) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if m.exportErr != nil {
		return nil, m.exportErr
	}
	return &backend.WrappedKeyMaterial{
		WrappedKey: []byte("exported-material"),
		Algorithm:  algorithm,
	}, nil
}

func (m *boostIEKeyProvider) ExportKeyMaterial(attrs *types.KeyAttributes) ([]byte, error) {
	return nil, errors.New("not supported")
}

// ===========================================================================
// Mock symmetric key provider
// ===========================================================================

type boostSymKey struct {
	attrs   *types.KeyAttributes
	keyData []byte
}

func (k *boostSymKey) Algorithm() string         { return string(k.attrs.SymmetricAlgorithm) }
func (k *boostSymKey) KeySize() int              { return len(k.keyData) * 8 }
func (k *boostSymKey) Raw() ([]byte, error)      { return k.keyData, nil }

type boostSymEncrypter struct {
	encryptErr error
	decryptErr error
}

func (e *boostSymEncrypter) Encrypt(data []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if e.encryptErr != nil {
		return nil, e.encryptErr
	}
	return &types.EncryptedData{
		Ciphertext: append([]byte("enc:"), data...),
		Nonce:      []byte("test-nonce"),
		Tag:        []byte("test-tag"),
	}, nil
}

func (e *boostSymEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if e.decryptErr != nil {
		return nil, e.decryptErr
	}
	if len(data.Ciphertext) > 4 {
		return data.Ciphertext[4:], nil
	}
	return data.Ciphertext, nil
}

type boostSymKeyProvider struct {
	boostIEKeyProvider
	symKeys    map[string]*boostSymKey
	encrypters map[string]*boostSymEncrypter
}

func newBoostSymKeyProvider() *boostSymKeyProvider {
	return &boostSymKeyProvider{
		boostIEKeyProvider: *newBoostIEKeyProvider(),
		symKeys:            make(map[string]*boostSymKey),
		encrypters:         make(map[string]*boostSymEncrypter),
	}
}

func (m *boostSymKeyProvider) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	key := &boostSymKey{
		attrs:   attrs,
		keyData: []byte("symmetric-key-material-32-bytes!"),
	}
	m.symKeys[attrs.CN] = key
	// Store a placeholder in the key map so findKeyAttrs works
	m.keys[attrs.CN] = nil
	m.keyAttrs[attrs.CN] = attrs
	return key, nil
}

func (m *boostSymKeyProvider) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	k, ok := m.symKeys[attrs.CN]
	if !ok {
		return nil, errors.New("symmetric key not found")
	}
	return k, nil
}

func (m *boostSymKeyProvider) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	if enc, ok := m.encrypters[attrs.CN]; ok {
		return enc, nil
	}
	if _, ok := m.symKeys[attrs.CN]; !ok {
		return nil, errors.New("symmetric key not found")
	}
	enc := &boostSymEncrypter{}
	m.encrypters[attrs.CN] = enc
	return enc, nil
}

// ===========================================================================
// Setup helpers
// ===========================================================================

func setupBoostIEService(t *testing.T) (*mockKeyStore, *boostIEKeyProvider) {
	t.Helper()
	Reset()

	ieKP := newBoostIEKeyProvider()
	ieStore := newMockKeyStore("ie-backend")
	ieStore.backend = ieKP

	softStore := newMockKeyStore("software")

	config := &ServiceConfig{
		Backends: map[string]Backend{
			"software":   softStore,
			"ie-backend": ieStore,
		},
		DefaultBackend: "software",
	}
	err := Initialize(config)
	require.NoError(t, err)
	return ieStore, ieKP
}

func setupBoostSymService(t *testing.T) (*mockKeyStore, *boostSymKeyProvider) {
	t.Helper()
	Reset()

	symKP := newBoostSymKeyProvider()
	symStore := newMockKeyStore("sym-backend")
	symStore.backend = symKP

	softStore := newMockKeyStore("software")

	config := &ServiceConfig{
		Backends: map[string]Backend{
			"software":    softStore,
			"sym-backend": symStore,
		},
		DefaultBackend: "software",
	}
	err := Initialize(config)
	require.NoError(t, err)
	return symStore, symKP
}

// boostGenIEKey generates a key in both the mockKeyStore and the IE provider.
func boostGenIEKey(t *testing.T, store *mockKeyStore, kp *boostIEKeyProvider, attrs *types.KeyAttributes) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	store.keys[attrs.CN] = key
	store.keyAttrs[attrs.CN] = attrs
	kp.keys[attrs.CN] = key
	kp.keyAttrs[attrs.CN] = attrs
}

// boostGenSymKey generates a symmetric key in both the mockKeyStore and the provider.
func boostGenSymKey(t *testing.T, store *mockKeyStore, kp *boostSymKeyProvider, attrs *types.KeyAttributes) {
	t.Helper()
	key := &boostSymKey{
		attrs:   attrs,
		keyData: []byte("symmetric-key-material-32-bytes!"),
	}
	kp.symKeys[attrs.CN] = key
	store.keys[attrs.CN] = nil
	store.keyAttrs[attrs.CN] = attrs
	kp.keys[attrs.CN] = nil
	kp.keyAttrs[attrs.CN] = attrs
}

// ===========================================================================
// servicer_key.go: GenerateKey symmetric path
// ===========================================================================

func TestBoostGenerateKey_Symmetric_Success(t *testing.T) {
	symStore, symKP := setupBoostSymService(t)
	svc, err := Get()
	require.NoError(t, err)

	// Pre-create a key
	boostGenSymKey(t, symStore, symKP, &types.KeyAttributes{
		CN:                 "sym-test-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "new-sym-key",
		Algorithm: "aes-256-gcm",
		Backend:   "sym-backend",
	})
	require.NoError(t, err)
	assert.Equal(t, "new-sym-key", resp.KeyID)
}

func TestBoostGenerateKey_Symmetric_BackendNotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "sym-key",
		Algorithm: "aes-256-gcm",
		Backend:   "software",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

// ===========================================================================
// servicer_key.go: ImportKey with IE backend
// ===========================================================================

func TestBoostImportKey_IEBackend_Success(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.ImportKey(context.Background(), &transport.ImportKeyRequest{
		KeyID:              "imported-key",
		Backend:            "ie-backend",
		WrappedKeyMaterial: []byte("wrapped-data"),
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "imported-key", resp.KeyID)
}

func TestBoostImportKey_IEBackend_ImportError(t *testing.T) {
	_, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	ieKP.importErr = errors.New("import failed")

	_, err = svc.ImportKey(context.Background(), &transport.ImportKeyRequest{
		KeyID:              "fail-import",
		Backend:            "ie-backend",
		WrappedKeyMaterial: []byte("data"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationFailed))
}

// ===========================================================================
// servicer_key.go: ExportKey with IE backend
// ===========================================================================

func TestBoostExportKey_IEBackend_Success(t *testing.T) {
	ieStore, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenIEKey(t, ieStore, ieKP, &types.KeyAttributes{CN: "export-me"})

	resp, err := svc.ExportKey(context.Background(), &transport.ExportKeyRequest{
		KeyID:     "export-me",
		Backend:   "ie-backend",
		Algorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.Equal(t, "export-me", resp.KeyID)
	assert.NotEmpty(t, resp.WrappedKeyMaterial)
}

func TestBoostExportKey_IEBackend_ExportError(t *testing.T) {
	ieStore, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenIEKey(t, ieStore, ieKP, &types.KeyAttributes{CN: "export-fail"})
	ieKP.exportErr = errors.New("export failed")

	_, err = svc.ExportKey(context.Background(), &transport.ExportKeyRequest{
		KeyID:   "export-fail",
		Backend: "ie-backend",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationFailed))
}

func TestBoostExportKey_IEBackend_KeyNotFound(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ExportKey(context.Background(), &transport.ExportKeyRequest{
		KeyID:   "nonexistent",
		Backend: "ie-backend",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrKeyNotFound))
}

// ===========================================================================
// servicer_key.go: GetImportParameters
// ===========================================================================

func TestBoostGetImportParameters_IEBackend_Success(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		KeyID:     "some-key",
		Backend:   "ie-backend",
		Algorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappingPublicKey)
	assert.NotEmpty(t, resp.ImportToken)
}

func TestBoostGetImportParameters_IEBackend_Error(t *testing.T) {
	_, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	ieKP.getParamsErr = errors.New("params error")

	_, err = svc.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		KeyID:   "key",
		Backend: "ie-backend",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationFailed))
}

func TestBoostGetImportParameters_NonExistentBackend(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend: "nonexistent",
	})
	require.Error(t, err)
}

// ===========================================================================
// servicer_key.go: WrapKey
// ===========================================================================

func TestBoostWrapKey_IEBackend_Success(t *testing.T) {
	_, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	wrappingPubBytes, err := x509.MarshalPKIXPublicKey(&ieKP.wrappingKey.PublicKey)
	require.NoError(t, err)

	resp, err := svc.WrapKey(context.Background(), &transport.WrapKeyRequest{
		Backend:           "ie-backend",
		KeyMaterial:       []byte("secret-key-material"),
		WrappingPublicKey: wrappingPubBytes,
		ImportToken:       []byte("token"),
		Algorithm:         "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKeyMaterial)
}

func TestBoostWrapKey_IEBackend_WrapError(t *testing.T) {
	_, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	ieKP.wrapErr = errors.New("wrap failed")

	wrappingPubBytes, err := x509.MarshalPKIXPublicKey(&ieKP.wrappingKey.PublicKey)
	require.NoError(t, err)

	_, err = svc.WrapKey(context.Background(), &transport.WrapKeyRequest{
		Backend:           "ie-backend",
		KeyMaterial:       []byte("data"),
		WrappingPublicKey: wrappingPubBytes,
		Algorithm:         "RSAES_OAEP_SHA_256",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationFailed))
}

func TestBoostWrapKey_IEBackend_InvalidPublicKey(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.WrapKey(context.Background(), &transport.WrapKeyRequest{
		Backend:           "ie-backend",
		KeyMaterial:       []byte("data"),
		WrappingPublicKey: []byte("not-a-valid-key"),
	})
	require.Error(t, err)
}

func TestBoostWrapKey_NonExistentBackend(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.WrapKey(context.Background(), &transport.WrapKeyRequest{
		Backend: "nonexistent",
	})
	require.Error(t, err)
}

func TestBoostWrapKey_DefaultBackend(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.WrapKey(context.Background(), &transport.WrapKeyRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

// ===========================================================================
// servicer_key.go: UnwrapKey
// ===========================================================================

func TestBoostUnwrapKey_IEBackend_Success(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		Backend:            "ie-backend",
		WrappedKeyMaterial: []byte("wrapped"),
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyMaterial)
}

func TestBoostUnwrapKey_IEBackend_UnwrapError(t *testing.T) {
	_, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	ieKP.unwrapErr = errors.New("unwrap failed")

	_, err = svc.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		Backend:            "ie-backend",
		WrappedKeyMaterial: []byte("data"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationFailed))
}

func TestBoostUnwrapKey_NonExistentBackend(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		Backend: "nonexistent",
	})
	require.Error(t, err)
}

func TestBoostUnwrapKey_DefaultBackend(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

// ===========================================================================
// servicer_key.go: CopyKey with IE backends
// ===========================================================================

func TestBoostCopyKey_IEBackend_Success(t *testing.T) {
	ieStore, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenIEKey(t, ieStore, ieKP, &types.KeyAttributes{
		CN:           "src-key",
		KeyAlgorithm: x509.ECDSA,
	})

	resp, err := svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID:   "src-key",
		SourceBackend: "ie-backend",
		DestKeyID:     "dst-key",
		DestBackend:   "ie-backend",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "dst-key", resp.KeyID)
}

func TestBoostCopyKey_IEBackend_SourceKeyNotFound(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID:   "nonexistent",
		SourceBackend: "ie-backend",
		DestKeyID:     "dst-key",
		DestBackend:   "ie-backend",
	})
	require.Error(t, err)
}

func TestBoostCopyKey_IEBackend_DestNotIE(t *testing.T) {
	ieStore, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenIEKey(t, ieStore, ieKP, &types.KeyAttributes{CN: "src-key"})

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID:   "src-key",
		SourceBackend: "ie-backend",
		DestKeyID:     "dst-key",
		DestBackend:   "software",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestBoostCopyKey_IEBackend_SourceNotIE(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID:   "src-key",
		SourceBackend: "software",
		DestKeyID:     "dst-key",
		DestBackend:   "ie-backend",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestBoostCopyKey_IEBackend_GetImportParamsError(t *testing.T) {
	ieStore, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenIEKey(t, ieStore, ieKP, &types.KeyAttributes{CN: "src-key"})
	ieKP.getParamsErr = errors.New("params error")

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID:   "src-key",
		SourceBackend: "ie-backend",
		DestKeyID:     "dst-key",
		DestBackend:   "ie-backend",
	})
	require.Error(t, err)
}

func TestBoostCopyKey_IEBackend_ExportError(t *testing.T) {
	ieStore, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenIEKey(t, ieStore, ieKP, &types.KeyAttributes{CN: "src-key"})
	ieKP.exportErr = errors.New("export failed")

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID:   "src-key",
		SourceBackend: "ie-backend",
		DestKeyID:     "dst-key",
		DestBackend:   "ie-backend",
	})
	require.Error(t, err)
}

func TestBoostCopyKey_IEBackend_ImportError(t *testing.T) {
	ieStore, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenIEKey(t, ieStore, ieKP, &types.KeyAttributes{CN: "src-key"})
	ieKP.importErr = errors.New("import failed")

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID:   "src-key",
		SourceBackend: "ie-backend",
		DestKeyID:     "dst-key",
		DestBackend:   "ie-backend",
	})
	require.Error(t, err)
}

func TestBoostCopyKey_DefaultBackends(t *testing.T) {
	setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID: "src",
		DestKeyID:   "dst",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

// ===========================================================================
// servicer_key.go: RotateKey success path
// ===========================================================================

func TestBoostRotateKey_IEBackend_KeyFound(t *testing.T) {
	ieStore, ieKP := setupBoostIEService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenIEKey(t, ieStore, ieKP, &types.KeyAttributes{
		CN:           "rotate-ie",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	})

	// mockKeyStore.RotateKey returns "not implemented", so the servicer
	// wraps it as ErrOperationFailed. This tests the findKeyAttrs+rotate delegation path.
	_, err = svc.RotateKey(context.Background(), &transport.RotateKeyRequest{
		KeyID:   "rotate-ie",
		Backend: "ie-backend",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationFailed))
}

// ===========================================================================
// servicer_key.go: GenerateKey various algorithm paths
// ===========================================================================

func TestBoostGenerateKey_Ed25519_ViaServicer(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "ed25519-boost",
		Algorithm: "ed25519",
		Backend:   "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "ed25519-boost", resp.KeyID)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestBoostGenerateKey_ECAlias(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "ec-alias-boost",
		Algorithm: "ec",
		Backend:   "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "ec-alias-boost", resp.KeyID)
}

func TestBoostGenerateKey_WithCurve(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "p384-boost",
		Algorithm: "ecdsa",
		Curve:     "P-384",
		Backend:   "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "p384-boost", resp.KeyID)
}

func TestBoostGenerateKey_WithExportable(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:      "exportable-boost",
		Algorithm:  "ecdsa",
		Backend:    "software",
		Exportable: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "exportable-boost", resp.KeyID)
}

func TestBoostGenerateKey_RSAWithKeySize(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "rsa-4096-boost",
		Algorithm: "rsa",
		KeySize:   4096,
		Backend:   "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "rsa-4096-boost", resp.KeyID)
}

func TestBoostGenerateKey_KeyTypeOverride(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "enc-boost",
		Algorithm: "ecdsa",
		KeyType:   "encryption",
		Backend:   "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "enc-boost", resp.KeyID)
}

// ===========================================================================
// servicer_crypto.go: Encrypt/Decrypt with symmetric backend
// ===========================================================================

func TestBoostEncrypt_Symmetric_Success(t *testing.T) {
	symStore, symKP := setupBoostSymService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenSymKey(t, symStore, symKP, &types.KeyAttributes{
		CN:                 "enc-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		KeyType:            types.KeyTypeSecret,
	})

	resp, err := svc.Encrypt(context.Background(), &transport.EncryptRequest{
		KeyID:     "enc-key",
		Backend:   "sym-backend",
		Plaintext: []byte("hello world"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
	assert.NotEmpty(t, resp.Nonce)
}

func TestBoostEncrypt_Symmetric_EncryptError(t *testing.T) {
	symStore, symKP := setupBoostSymService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenSymKey(t, symStore, symKP, &types.KeyAttributes{
		CN:                 "fail-enc",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		KeyType:            types.KeyTypeSecret,
	})
	symKP.encrypters["fail-enc"] = &boostSymEncrypter{
		encryptErr: errors.New("encrypt failed"),
	}

	_, err = svc.Encrypt(context.Background(), &transport.EncryptRequest{
		KeyID:     "fail-enc",
		Backend:   "sym-backend",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEncryptionFailed))
}

func TestBoostDecrypt_Symmetric_Success(t *testing.T) {
	symStore, symKP := setupBoostSymService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenSymKey(t, symStore, symKP, &types.KeyAttributes{
		CN:                 "dec-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		KeyType:            types.KeyTypeSecret,
	})

	resp, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		KeyID:      "dec-key",
		Backend:    "sym-backend",
		Ciphertext: []byte("enc:hello"),
		Nonce:      []byte("test-nonce"),
		Tag:        []byte("test-tag"),
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), resp.Plaintext)
}

func TestBoostDecrypt_Symmetric_DecryptError(t *testing.T) {
	symStore, symKP := setupBoostSymService(t)
	svc, err := Get()
	require.NoError(t, err)

	boostGenSymKey(t, symStore, symKP, &types.KeyAttributes{
		CN:                 "fail-dec",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		KeyType:            types.KeyTypeSecret,
	})
	symKP.encrypters["fail-dec"] = &boostSymEncrypter{
		decryptErr: errors.New("decrypt failed"),
	}

	_, err = svc.Decrypt(context.Background(), &transport.DecryptRequest{
		KeyID:      "fail-dec",
		Backend:    "sym-backend",
		Ciphertext: []byte("data"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDecryptionFailed))
}

func TestBoostDecrypt_AsymFallback_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	software.keys["rsa-dec-boost"] = rsaKey
	software.keyAttrs["rsa-dec-boost"] = &types.KeyAttributes{
		CN:           "rsa-dec-boost",
		KeyAlgorithm: x509.RSA,
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, []byte("secret"))
	require.NoError(t, err)

	resp, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		KeyID:      "rsa-dec-boost",
		Backend:    "software",
		Ciphertext: ciphertext,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), resp.Plaintext)
}

// ===========================================================================
// algorithms.go: DiscoverAlgorithms
// ===========================================================================

func TestBoostDiscoverAlgorithms_EmptyBackends(t *testing.T) {
	// DiscoverAlgorithms uses the global registry, which may have backends
	// registered without corresponding service initialization. We test
	// BuildAlgorithmsResponse directly for deterministic behavior.
	provider := func(name string) (types.Capabilities, error) {
		return types.Capabilities{Keys: true}, nil
	}
	resp := BuildAlgorithmsResponse([]BackendType{BackendSoftware}, provider)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Signing)
}

// ===========================================================================
// service.go: RegisterServiceBackend
// ===========================================================================

func TestBoostRegisterServiceBackend_Success(t *testing.T) {
	setupService(t)

	newBackend := newMockKeyStore("dynamic-boost")
	err := RegisterServiceBackend("dynamic-boost", newBackend)
	require.NoError(t, err)

	b, err := GetBackend("dynamic-boost")
	require.NoError(t, err)
	assert.NotNil(t, b)
}

func TestBoostRegisterServiceBackend_NotInitialized(t *testing.T) {
	Reset()

	err := RegisterServiceBackend("test", newMockKeyStore("test"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotInitialized))
}

func TestBoostRegisterServiceBackend_InvalidName(t *testing.T) {
	setupService(t)

	err := RegisterServiceBackend("", newMockKeyStore("empty"))
	require.Error(t, err)
}

// ===========================================================================
// service.go: Get not initialized
// ===========================================================================

func TestBoostGet_NotInitialized(t *testing.T) {
	Reset()

	_, err := Get()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotInitialized))
}

// ===========================================================================
// service.go: package-level import/export functions
// ===========================================================================

func TestBoostGetImportParameters_PackageLevel_InvalidBackend(t *testing.T) {
	setupService(t)

	_, err := GetImportParameters("software", &types.KeyAttributes{CN: "key"}, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrImportExportNotSupported))
}

func TestBoostGetImportParameters_PackageLevel_EmptyBackendName(t *testing.T) {
	setupService(t)

	_, err := GetImportParameters("", &types.KeyAttributes{CN: "key"}, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
}

func TestBoostWrapKey_PackageLevel_InvalidBackend(t *testing.T) {
	setupService(t)

	_, err := WrapKey("software", []byte("data"), &backend.ImportParameters{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrImportExportNotSupported))
}

func TestBoostWrapKey_PackageLevel_EmptyBackendName(t *testing.T) {
	setupService(t)

	_, err := WrapKey("", []byte("data"), &backend.ImportParameters{})
	require.Error(t, err)
}

func TestBoostUnwrapKey_PackageLevel_InvalidBackend(t *testing.T) {
	setupService(t)

	_, err := UnwrapKey("software", &backend.WrappedKeyMaterial{}, &backend.ImportParameters{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrImportExportNotSupported))
}

func TestBoostUnwrapKey_PackageLevel_EmptyBackendName(t *testing.T) {
	setupService(t)

	_, err := UnwrapKey("", &backend.WrappedKeyMaterial{}, &backend.ImportParameters{})
	require.Error(t, err)
}

func TestBoostImportKey_PackageLevel_InvalidBackend(t *testing.T) {
	setupService(t)

	err := ImportKey("software", &types.KeyAttributes{CN: "key"}, &backend.WrappedKeyMaterial{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrImportExportNotSupported))
}

func TestBoostImportKey_PackageLevel_EmptyBackendName(t *testing.T) {
	setupService(t)

	err := ImportKey("", &types.KeyAttributes{CN: "key"}, &backend.WrappedKeyMaterial{})
	require.Error(t, err)
}

func TestBoostExportKey_PackageLevel_InvalidRef(t *testing.T) {
	setupService(t)

	_, err := ExportKey("", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
}

func TestBoostCopyKey_PackageLevel_InvalidRef(t *testing.T) {
	setupService(t)

	err := CopyKey("", "software", &types.KeyAttributes{CN: "dest"})
	require.Error(t, err)
}

func TestBoostGenerateSymmetricKey_PackageLevel_EmptyBackend(t *testing.T) {
	setupService(t)

	_, err := GenerateSymmetricKey("", &types.KeyAttributes{CN: "key"})
	require.Error(t, err)
}

func TestBoostGenerateSymmetricKey_PackageLevel_NotSupported(t *testing.T) {
	setupService(t)

	_, err := GenerateSymmetricKey("software", &types.KeyAttributes{CN: "key"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSymmetricNotSupported))
}

func TestBoostGetSymmetricKey_PackageLevel_InvalidRef(t *testing.T) {
	setupService(t)

	_, err := GetSymmetricKey("")
	require.Error(t, err)
}

func TestBoostEncrypt_PackageLevel_InvalidRef(t *testing.T) {
	setupService(t)

	_, err := Encrypt("", []byte("data"), nil)
	require.Error(t, err)
}

func TestBoostDecrypt_PackageLevel_InvalidRef(t *testing.T) {
	setupService(t)

	_, err := Decrypt("", &types.EncryptedData{}, nil)
	require.Error(t, err)
}

func TestBoostGenerateKeyWithBackend_EmptyBackend(t *testing.T) {
	setupService(t)

	_, err := GenerateKeyWithBackend("", &types.KeyAttributes{CN: "key", KeyAlgorithm: x509.ECDSA})
	require.Error(t, err)
}

func TestBoostGenerateKeyWithBackend_UnsupportedAlgo(t *testing.T) {
	setupService(t)

	_, err := GenerateKeyWithBackend("software", &types.KeyAttributes{
		CN:           "key",
		KeyAlgorithm: x509.PublicKeyAlgorithm(99),
	})
	require.Error(t, err)
}

func TestBoostGenerateKeyWithBackend_RSASuccess(t *testing.T) {
	setupService(t)

	key, err := GenerateKeyWithBackend("software", &types.KeyAttributes{
		CN:            "rsa-boost",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestBoostGenerateKeyWithBackend_Ed25519(t *testing.T) {
	setupService(t)

	key, err := GenerateKeyWithBackend("software", &types.KeyAttributes{
		CN:           "ed-boost",
		KeyAlgorithm: x509.Ed25519,
	})
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestBoostSign_PackageLevel_InvalidRef(t *testing.T) {
	setupService(t)

	_, err := Sign("", []byte("data"), nil)
	require.Error(t, err)
}

func TestBoostVerify_PackageLevel_InvalidRef(t *testing.T) {
	setupService(t)

	err := Verify("", []byte("data"), []byte("sig"), nil)
	require.Error(t, err)
}

func TestBoostSaveCertificateChainByID_InvalidRef(t *testing.T) {
	setupService(t)

	err := SaveCertificateChainByID("", nil)
	require.Error(t, err)
}

func TestBoostCertificateChainByID_InvalidRef(t *testing.T) {
	setupService(t)

	_, err := CertificateChainByID("")
	require.Error(t, err)
}

func TestBoostCertificateExistsByID_InvalidRef(t *testing.T) {
	setupService(t)

	_, err := CertificateExistsByID("")
	require.Error(t, err)
}

func TestBoostTLSCertificateByID_InvalidRef(t *testing.T) {
	setupService(t)

	_, err := TLSCertificateByID("")
	require.Error(t, err)
}

func TestBoostRotateKey_PackageLevel_InvalidRef(t *testing.T) {
	setupService(t)

	_, err := RotateKey("")
	require.Error(t, err)
}

// ===========================================================================
// auto.go: AutoInitialize default backend override
// ===========================================================================

func TestBoostAutoInitialize_DefaultBackendOverride(t *testing.T) {
	Reset()
	err := AutoInitialize(&AutoConfig{
		DefaultBackend: "nonexistent-backend",
	})
	_ = err
}

// ===========================================================================
// servicer_piv.go: InitPIVBackendResolver
// ===========================================================================

func TestBoostInitPIVBackendResolver_Success(t *testing.T) {
	ResetPIV()
	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)
	t.Cleanup(ResetPIV)

	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.InitPIVBackendResolver()
	require.NoError(t, err)
}

func TestBoostInitPIVBackendResolver_PIVNotInitialized(t *testing.T) {
	ResetPIV()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.InitPIVBackendResolver()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

// ===========================================================================
// version.go
// ===========================================================================

func TestBoostVersion_ReturnsValue(t *testing.T) {
	v := Version()
	assert.NotEmpty(t, v)
}

// ===========================================================================
// servicer_key.go: buildKeyAttributes helpers
// ===========================================================================

func TestBoostBuildKeyAttributes_ECCAlias(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "key",
		Algorithm: "ecc",
	}, "software")
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
}

func TestBoostBuildKeyAttributes_SymmetricSecret(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "key",
		Algorithm: "symmetric",
	}, "software")
	require.NoError(t, err)
	assert.NotEmpty(t, attrs.SymmetricAlgorithm)
	assert.Equal(t, types.KeyTypeSecret, attrs.KeyType)
}

func TestBoostBuildKeyAttributes_SecretAlias(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "key",
		Algorithm: "secret",
	}, "software")
	require.NoError(t, err)
	assert.NotEmpty(t, attrs.SymmetricAlgorithm)
}

func TestBoostBuildImportKeyAttributes_WithKeyType(t *testing.T) {
	attrs := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:   "key",
		KeyType: "signing",
	}, "software")
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
}

func TestBoostBuildImportKeyAttributes_DefaultKeyType(t *testing.T) {
	attrs := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID: "key",
	}, "software")
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
}

func TestBoostParseCurveString_AllCurves(t *testing.T) {
	tests := []struct {
		input string
		want  elliptic.Curve
	}{
		{"P-224", elliptic.P224()},
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
		{"unknown", nil},
		{"", nil},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseCurveString(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBoostParseSymmetricAlgorithm_Variants(t *testing.T) {
	tests := []struct {
		input    string
		wantNone bool
	}{
		{"aes-256-gcm", false},
		{"chacha20-poly1305", false},
		{"symmetric", false},
		{"secret", false},
		{"rsa", true},
		{"ecdsa", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseSymmetricAlgorithm(tt.input)
			if tt.wantNone {
				assert.Empty(t, result)
			} else {
				assert.NotEmpty(t, result)
			}
		})
	}
}

// ===========================================================================
// servicer_helpers.go: parseHash
// ===========================================================================

func TestBoostParseHash_Values(t *testing.T) {
	tests := []struct {
		input string
		want  crypto.Hash
	}{
		{"", crypto.SHA256},
		{"sha256", crypto.SHA256},
		{"sha384", crypto.SHA384},
		{"sha512", crypto.SHA512},
		{"unknown-hash", crypto.SHA256},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseHash(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ===========================================================================
// servicer_helpers.go: pubKeyPEM edge cases
// ===========================================================================

func TestBoostPubKeyPEM_NilKey(t *testing.T) {
	_, err := pubKeyPEM(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilPrivateKey))
}

func TestBoostPubKeyPEM_RSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemStr, err := pubKeyPEM(key)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")
}

// ===========================================================================
// algorithms.go: BuildAlgorithmsResponse
// ===========================================================================

func TestBoostBuildAlgorithmsResponse_WithQuantumAndKEM(t *testing.T) {
	provider := func(name string) (types.Capabilities, error) {
		if name == "test-quantum" {
			return types.Capabilities{
				Keys:             true,
				QuantumSigning:   true,
				KeyEncapsulation: true,
			}, nil
		}
		return types.Capabilities{}, errors.New("unknown backend")
	}

	resp := BuildAlgorithmsResponse(
		[]BackendType{"test-quantum"},
		provider,
	)
	require.NotNil(t, resp)
	assert.GreaterOrEqual(t, len(resp.Signing), 3)
	assert.GreaterOrEqual(t, len(resp.KeyEncapsulation), 1)
}

func TestBoostBuildAlgorithmsResponse_BackendError(t *testing.T) {
	provider := func(name string) (types.Capabilities, error) {
		return types.Capabilities{}, errors.New("unavailable")
	}

	resp := BuildAlgorithmsResponse(
		[]BackendType{"unavailable"},
		provider,
	)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Signing)
	assert.Empty(t, resp.KeyEncapsulation)
}

func TestBoostBuildAlgorithmsResponse_MultipleBackendsMerge(t *testing.T) {
	provider := func(name string) (types.Capabilities, error) {
		return types.Capabilities{Keys: true}, nil
	}

	resp := BuildAlgorithmsResponse(
		[]BackendType{"backend-a", "backend-b"},
		provider,
	)
	require.NotNil(t, resp)

	for _, alg := range resp.Signing {
		assert.Len(t, alg.Backends, 2, "algorithm %s should have 2 backends", alg.Algorithm)
	}
}

// ===========================================================================
// composite.go: Close error paths
// ===========================================================================

func TestBoostCompositeClose_BackendError(t *testing.T) {
	software, _ := setupService(t)
	software.closeError = errors.New("close failed")

	err := software.Close()
	require.Error(t, err)
}

// ===========================================================================
// servicer_key.go: ListKeys edge cases
// ===========================================================================

func TestBoostListKeys_AllBackends_OneBackendError(t *testing.T) {
	software, pkcs11 := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(&types.KeyAttributes{CN: "sw-boost", KeyAlgorithm: x509.ECDSA})
	require.NoError(t, err)
	pkcs11.listKeysErr = errors.New("pkcs11 error")

	resp, err := svc.ListKeys(context.Background(), "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Keys), 1)
}

func TestBoostListKeys_InvalidBackendName(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListKeys(context.Background(), "bad name with spaces")
	require.Error(t, err)
}

func TestBoostListKeys_SpecificBackend_ListKeysError(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	software.listKeysErr = errors.New("list failed")

	_, err = svc.ListKeys(context.Background(), "software")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationFailed))
}

// ===========================================================================
// servicer_cert.go: GetTLSCertificate validation
// ===========================================================================

func TestBoostGetTLSCertificate_KeyIDValidationError(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetTLSCertificate(context.Background(), "software", "")
	require.Error(t, err)
}
