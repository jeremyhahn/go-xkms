package xkms

import (
	"context"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
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

// TestGenerateKey_RSA_RefusesUndersizedModulus proves the RPC surface itself
// refuses an RSA request under types.RSAKeySize2048: buildKeyAttributes now
// runs KeyAttributes.Validate before any backend is asked to generate a key.
// Before that call existed, this request reached the backend unchecked and,
// on PKCS#11 or TPM, produced a real 1024-bit key (go-xkms#1204).
func TestGenerateKey_RSA_RefusesUndersizedModulus(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "undersized-rsa-key",
		Algorithm: "rsa",
		Backend:   "software",
		KeySize:   1024,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "RSA key size must be at least 2048")
}

// TestGenerateKey_RSA_AcceptsDocumentedSizes proves the go-xkms#1204 floor is
// a floor and not an accidental rejection of every RSA request: 2048, 3072
// and 4096 -- the three sizes this project documents as supported -- must
// all still succeed.
func TestGenerateKey_RSA_AcceptsDocumentedSizes(t *testing.T) {
	for _, keySize := range []int{types.RSAKeySize2048, types.RSAKeySize3072, types.RSAKeySize4096} {
		t.Run(fmt.Sprintf("%d", keySize), func(t *testing.T) {
			setupService(t)
			svc, err := Get()
			require.NoError(t, err)

			resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
				KeyID:     fmt.Sprintf("rsa-%d-key", keySize),
				Algorithm: "rsa",
				Backend:   "software",
				KeySize:   keySize,
			})
			require.NoError(t, err)
			assert.NotEmpty(t, resp.PublicKeyPEM)
		})
	}
}

// TestGenerateKey_MissingAlgorithm verifies Algorithm is required: it no
// longer defaults to ECDSA P-256 nor falls back to KeyType (owner rule
// 2026-09-22, PR 2).
func TestGenerateKey_MissingAlgorithm(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:   "default-key",
		Backend: "software",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingAlgorithm)
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
	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{CN: "sw-key", KeyAlgorithm: x509.ECDSA})
	require.NoError(t, err)
	_, err = pkcs11.GenerateECDSA(context.Background(), &types.KeyAttributes{CN: "p11-key", KeyAlgorithm: x509.ECDSA})
	require.NoError(t, err)

	resp, err := svc.ListKeys(context.Background(), "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Keys), 2)
}

func TestServicerListKeys_SpecificBackend(t *testing.T) {
	software, pkcs11 := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{CN: "sw-only", KeyAlgorithm: x509.ECDSA})
	require.NoError(t, err)
	_, err = pkcs11.GenerateECDSA(context.Background(), &types.KeyAttributes{CN: "p11-only", KeyAlgorithm: x509.ECDSA})
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

	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{CN: "delete-me", KeyAlgorithm: x509.ECDSA})
	require.NoError(t, err)

	err = svc.DeleteKey(context.Background(), "software", "delete-me")
	require.NoError(t, err)

	// Verify it's gone
	_, err = software.GetKey(context.Background(), &types.KeyAttributes{CN: "delete-me"})
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

func TestExportKeyMaterial_BackendWithoutImportExport(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		KeyID:   "some-key",
		Backend: "software",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestWrapKeyByID_BackendWithoutImportExport(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// The target-backend capability check runs before the wrapping key is
	// even resolved, so this fails immediately regardless of Algorithm.
	_, err = svc.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyID:        "target",
		TargetKeyBackend:   "software",
		Algorithm:          string(types.WrapAESKW),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

// TestUnwrapKeyByID_BackendWithoutImportExport proves the target backend's
// ImportExportBackend requirement (needed for ImportKey) still holds even
// though the unwrapping key itself no longer needs that capability -- it is
// used directly via crypto.Decrypter (see servicer_wrapkey.go), so the
// request must genuinely unwrap before the target-capability check is ever
// reached. The wrapped blob is a real RSA-PKCS1v15 ciphertext under a real
// key so the flow gets past unwrapKeyMaterial and into the target-backend
// check this test is actually about.
func TestUnwrapKeyByID_BackendWithoutImportExport(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	privKey, err := software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "kek",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	require.True(t, ok)

	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, []byte("target-key-material-bytes")) //nolint:staticcheck // SA1019: builds a CKM_RSA_PKCS-wrapped blob for the unwrap path
	if fips140.Enforced() {
		// GODEBUG=fips140=only refuses PKCS#1 v1.5 encryption outright, so
		// this test's fixture blob cannot be built in that mode -- there is
		// no wrapped blob to drive the unwrap path this test targets.
		require.Error(t, err)
		return
	}
	require.NoError(t, err)

	_, err = svc.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{
		WrappedKey:           wrapped,
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "software",
		Algorithm:            string(types.WrapRSAPKCS1v15),
		TargetKeyID:          "imported",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})
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

	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{
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
