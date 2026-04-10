package xkms

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- GenerateKey ---

func TestGenerateKey_ECDSA_Success(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "ecdsa-key",
		Algorithm: "ecdsa",
		Backend:   "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "ecdsa-key", resp.KeyID)
	assert.NotEmpty(t, resp.PublicKeyPEM)
	assert.Contains(t, resp.PublicKeyPEM, "BEGIN PUBLIC KEY")
}

func TestGenerateKey_RSA_Success(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "rsa-key",
		Algorithm: "rsa",
		Backend:   "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "rsa-key", resp.KeyID)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestGenerateKey_DefaultAlgorithm(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// Empty algorithm defaults to ECDSA P-256
	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:   "default-key",
		Backend: "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "default-key", resp.KeyID)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestGenerateKey_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestGenerateKey_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		Algorithm: "ecdsa",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyID))
}

func TestGenerateKey_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "test",
		Algorithm: "ecdsa",
		Backend:   "nonexistent",
	})
	require.Error(t, err)
}

func TestServicerGenerateKey_UnsupportedAlgorithm(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "test",
		Algorithm: "quantum-lattice",
		Backend:   "software",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnsupportedKeyAlgorithm))
}

func TestGenerateKey_DefaultBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// Empty backend uses default ("software")
	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "default-backend-key",
		Algorithm: "ecdsa",
	})
	require.NoError(t, err)
	assert.Equal(t, "default-backend-key", resp.KeyID)
}

// --- ListKeys ---

func TestServicerListKeys_AllBackends(t *testing.T) {
	software, pkcs11 := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// Generate keys in both backends
	_, err = software.GenerateECDSA(&types.KeyAttributes{CN: "sw-key", KeyAlgorithm: x509.ECDSA})
	require.NoError(t, err)
	_, err = pkcs11.GenerateECDSA(&types.KeyAttributes{CN: "p11-key", KeyAlgorithm: x509.ECDSA})
	require.NoError(t, err)

	resp, err := svc.ListKeys(context.Background(), "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Keys), 2)
}

func TestServicerListKeys_SpecificBackend(t *testing.T) {
	software, pkcs11 := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(&types.KeyAttributes{CN: "sw-only", KeyAlgorithm: x509.ECDSA})
	require.NoError(t, err)
	_, err = pkcs11.GenerateECDSA(&types.KeyAttributes{CN: "p11-only", KeyAlgorithm: x509.ECDSA})
	require.NoError(t, err)

	resp, err := svc.ListKeys(context.Background(), "software")
	require.NoError(t, err)
	for _, k := range resp.Keys {
		assert.Equal(t, "software", k.Backend)
	}
}

func TestListKeys_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListKeys(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendNotFound))
}

func TestListKeys_EmptyResult(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.ListKeys(context.Background(), "software")
	require.NoError(t, err)
	assert.Empty(t, resp.Keys)
}

// --- GetKey ---

func TestGetKey_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(&types.KeyAttributes{
		CN:           "get-me",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	})
	require.NoError(t, err)

	resp, err := svc.GetKey(context.Background(), "software", "get-me")
	require.NoError(t, err)
	assert.Equal(t, "get-me", resp.KeyID)
	assert.Equal(t, "software", resp.Backend)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestGetKey_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetKey(context.Background(), "software", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyID))
}

func TestGetKey_KeyNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetKey(context.Background(), "software", "does-not-exist")
	require.Error(t, err)
}

// --- DeleteKey ---

func TestDeleteKey_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(&types.KeyAttributes{CN: "delete-me", KeyAlgorithm: x509.ECDSA})
	require.NoError(t, err)

	err = svc.DeleteKey(context.Background(), "software", "delete-me")
	require.NoError(t, err)

	// Verify it's gone
	_, err = software.GetKey(&types.KeyAttributes{CN: "delete-me"})
	require.Error(t, err)
}

func TestDeleteKey_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeleteKey(context.Background(), "software", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyID))
}

func TestDeleteKey_KeyNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeleteKey(context.Background(), "software", "ghost-key")
	require.Error(t, err)
}

// --- RotateKey ---

func TestRotateKey_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.RotateKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestRotateKey_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.RotateKey(context.Background(), &transport.RotateKeyRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyID))
}

func TestExportKeyMaterial_NotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestWrapKeyByID_NotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestUnwrapKeyByID_NotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

// --- ImportKey / ExportKey validation ---

func TestImportKey_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestImportKey_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), &transport.ImportKeyRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyID))
}

func TestExportKey_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ExportKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestExportKey_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ExportKey(context.Background(), &transport.ExportKeyRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyID))
}

func TestCopyKey_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CopyKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestCopyKey_EmptySourceKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		DestKeyID: "dest",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyID))
}

func TestGetImportParameters_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetImportParameters(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestWrapKey_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.WrapKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestUnwrapKey_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.UnwrapKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

// --- Import/Export/Wrap/Unwrap backend not supported ---

func TestImportKey_BackendNotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), &transport.ImportKeyRequest{
		KeyID:   "import-key",
		Backend: "software",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestImportKey_DefaultBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), &transport.ImportKeyRequest{
		KeyID: "import-key",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestExportKey_BackendNotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ExportKey(context.Background(), &transport.ExportKeyRequest{
		KeyID:   "export-key",
		Backend: "software",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestExportKey_DefaultBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ExportKey(context.Background(), &transport.ExportKeyRequest{
		KeyID: "export-key",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestExportKey_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ExportKey(context.Background(), &transport.ExportKeyRequest{
		KeyID:   "key",
		Backend: "nonexistent",
	})
	require.Error(t, err)
}

func TestServicerRotateKey_MockNotImplemented(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(&types.KeyAttributes{
		CN:            "rotate-me",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)

	resp, err := svc.RotateKey(context.Background(), &transport.RotateKeyRequest{
		KeyID:   "rotate-me",
		Backend: "software",
	})
	require.Error(t, err) // mockKeyStore.RotateKey returns "not implemented"
	_ = resp
}

func TestRotateKey_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.RotateKey(context.Background(), &transport.RotateKeyRequest{
		KeyID:   "key",
		Backend: "nonexistent",
	})
	require.Error(t, err)
}

func TestServicerRotateKey_KeyNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.RotateKey(context.Background(), &transport.RotateKeyRequest{
		KeyID:   "ghost-key",
		Backend: "software",
	})
	require.Error(t, err)
}

func TestRotateKey_DefaultBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.RotateKey(context.Background(), &transport.RotateKeyRequest{
		KeyID: "ghost-key",
	})
	require.Error(t, err) // key not found
}

func TestGetImportParameters_BackendNotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend: "software",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestGetImportParameters_DefaultBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestWrapKey_BackendNotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.WrapKey(context.Background(), &transport.WrapKeyRequest{
		Backend: "software",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestUnwrapKey_BackendNotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		Backend: "software",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestCopyKey_EmptyDestKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID: "src",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyID))
}

func TestCopyKey_BackendNotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID:   "src",
		DestKeyID:     "dst",
		SourceBackend: "software",
		DestBackend:   "pkcs11",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestCopyKey_NonExistentSourceBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID:   "src",
		DestKeyID:     "dst",
		SourceBackend: "nonexistent",
	})
	require.Error(t, err)
}

func TestCopyKey_NonExistentDestBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceKeyID: "src",
		DestKeyID:   "dst",
		DestBackend: "nonexistent",
	})
	require.Error(t, err)
}
