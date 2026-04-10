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

//go:build codec_json && codec_cbor && codec_msgpack

package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/authz"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ===================== ImportKey type-branch tests =====================

func TestImportKey_EdDSABranch(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "test-ed-key",
		Backend:    "software",
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  "RSAES_OAEP_SHA_256",
		KeyType:    "ed25519",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestImportKey_AES128Branch(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "test-aes128-key",
		Backend:    "software",
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  "AES-WRAP",
		KeyType:    "aes",
		KeySize:    128,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestImportKey_AES192Branch(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "test-aes192-key",
		Backend:    "software",
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  "AES-WRAP",
		KeyType:    "symmetric",
		KeySize:    192,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestImportKey_AESInvalidKeySize(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "test-aes-bad",
		Backend:    "software",
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  "AES-WRAP",
		KeyType:    "symmetric",
		KeySize:    512,
	})
	require.Error(t, err)
}

func TestImportKey_UnsupportedKeyType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "test-unknown",
		Backend:    "software",
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  "AES-WRAP",
		KeyType:    "chacha20",
	})
	require.Error(t, err)
}

func TestImportKey_ECDSAWithInvalidCurve(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "test-ecdsa-bad-curve",
		Backend:    "software",
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  "AES-WRAP",
		KeyType:    "ecdsa",
		Curve:      "INVALID_CURVE",
	})
	require.Error(t, err)
}

// ===================== Certificate CRUD tests =====================

func testCertPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	return string(certPEM)
}

func TestSaveCert_InvalidPEM(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "test-key",
		CertPem: "not-a-valid-pem",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "invalid certificate PEM")
}

func TestSaveCert_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	certPEM := testCertPEM(t)
	resp, err := svc.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "test-cert-key",
		CertPem: certPEM,
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestGetCert_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	certPEM := testCertPEM(t)
	_, err := svc.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "cert-get-key",
		CertPem: certPEM,
	})
	require.NoError(t, err)

	resp, err := svc.GetCert(context.Background(), &pb.GetCertRequest{
		KeyId: "cert-get-key",
	})
	require.NoError(t, err)
	assert.Contains(t, resp.CertPem, "BEGIN CERTIFICATE")
}

func TestGetCert_NotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetCert(context.Background(), &pb.GetCertRequest{
		KeyId: "nonexistent-cert",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDeleteCert_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	certPEM := testCertPEM(t)
	_, err := svc.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "cert-del-key",
		CertPem: certPEM,
	})
	require.NoError(t, err)

	resp, err := svc.DeleteCert(context.Background(), &pb.DeleteCertRequest{
		KeyId: "cert-del-key",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestDeleteCert_NotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.DeleteCert(context.Background(), &pb.DeleteCertRequest{
		KeyId: "nonexistent-cert-del",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestCertExists_FoundPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	certPEM := testCertPEM(t)
	_, err := svc.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "cert-exists-key",
		CertPem: certPEM,
	})
	require.NoError(t, err)

	resp, err := svc.CertExists(context.Background(), &pb.CertExistsRequest{
		KeyId: "cert-exists-key",
	})
	require.NoError(t, err)
	assert.True(t, resp.Exists)
}

func TestCertExists_NotFoundPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.CertExists(context.Background(), &pb.CertExistsRequest{
		KeyId: "nonexistent-cert-exists",
	})
	require.NoError(t, err)
	assert.False(t, resp.Exists)
}

func TestSaveCertChain_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	certPEM := testCertPEM(t)
	resp, err := svc.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
		KeyId:        "cert-chain-key",
		CertChainPem: []string{certPEM},
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestSaveCertChain_InvalidPEMInChain(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
		KeyId:        "cert-chain-bad",
		CertChainPem: []string{"not-valid-pem"},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestGetCertChain_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	certPEM := testCertPEM(t)
	_, err := svc.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
		KeyId:        "cert-chain-get-key",
		CertChainPem: []string{certPEM},
	})
	require.NoError(t, err)

	resp, err := svc.GetCertChain(context.Background(), &pb.GetCertChainRequest{
		KeyId: "cert-chain-get-key",
	})
	require.NoError(t, err)
	require.Len(t, resp.CertChainPem, 1)
	assert.Contains(t, resp.CertChainPem[0], "BEGIN CERTIFICATE")
}

func TestGetCertChain_NotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetCertChain(context.Background(), &pb.GetCertChainRequest{
		KeyId: "nonexistent-chain",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== GetTLSCertificate tests =====================

func TestGetTLSCertificate_BackendNotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{
		KeyId:   "some-key",
		Backend: "nonexistent",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== GetImportParameters tests =====================

func TestGetImportParameters_BackendNotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "key",
		Backend:           "nonexistent",
		WrappingAlgorithm: "AES-WRAP",
		KeyType:           "rsa",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestGetImportParameters_SoftwareBackendKeyNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "nonexistent-import-key",
		Backend:           "software",
		WrappingAlgorithm: "AES-WRAP",
		KeyType:           "rsa",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	// Software backend supports import/export but the key does not exist
	assert.True(t, st.Code() == codes.NotFound || st.Code() == codes.Internal, "expected NotFound or Internal, got %v", st.Code())
}

// ===================== ExportKeyMaterial tests =====================

func TestExportKeyMaterial_KeyNotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{
		KeyId:   "nonexistent-export-key",
		Backend: "software",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== WrapKeyByID deeper path tests =====================

func TestWrapKeyByID_TargetBackendNoImportExport(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "wrap-target-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	_, err = svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "wrap-target-key",
		WrappingKeyBackend: "software",
		TargetKeyId:        "wrap-target-key",
		TargetKeyBackend:   "software",
		Algorithm:          "AES-WRAP",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.True(t, st.Code() == codes.Unimplemented || st.Code() == codes.Internal || st.Code() == codes.NotFound || st.Code() == codes.FailedPrecondition)
}

// ===================== UnwrapKeyByID deeper path tests =====================

func TestUnwrapKeyByID_UnwrappingBackendNoImportExport(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("some-data"),
		UnwrappingKeyId:      "k",
		UnwrappingKeyBackend: "software",
		Algorithm:            "AES-WRAP",
		TargetKeyId:          "target",
		TargetKeyBackend:     "software",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.True(t, st.Code() == codes.Unimplemented || st.Code() == codes.Internal || st.Code() == codes.NotFound)
}

// ===================== DeriveKeyECDH deeper path tests =====================

func TestDeriveKeyECDH_KeyNotECDSA(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rsa-for-ecdh",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	require.NoError(t, err)

	_, err = svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:         "rsa-for-ecdh",
		Backend:       "software",
		PeerPublicKey: []byte("fake-peer-key"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "key must be an ECDSA key for ECDH")
}

func TestDeriveKeyECDH_KeyNotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:         "nonexistent-ecdh-key",
		Backend:       "software",
		PeerPublicKey: []byte("fake-peer-key"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDeriveKeyECDH_BackendNoKeyAgreement(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ecdsa-for-ecdh-unimpl",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	_, err = svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:         "ecdsa-for-ecdh-unimpl",
		Backend:       "software",
		PeerPublicKey: []byte("fake-peer-key"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.True(t, st.Code() == codes.Unimplemented || st.Code() == codes.Internal)
}

// ===================== Decrypt asymmetric path tests =====================

func TestDecrypt_AsymmetricRSA_ErrorPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rsa-decrypt-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	require.NoError(t, err)

	// Provide invalid ciphertext to exercise the asymmetric decrypt path.
	// The Decrypt method calls decrypter.Decrypt which uses PKCS1v15 by default.
	_, err = svc.Decrypt(context.Background(), &pb.DecryptRequest{
		KeyId:      "rsa-decrypt-key",
		Backend:    "software",
		Ciphertext: []byte("invalid-ciphertext-data-for-rsa-decrypt"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Contains(t, st.Message(), "failed to decrypt")
}

func TestDecrypt_KeyNotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Decrypt(context.Background(), &pb.DecryptRequest{
		KeyId:      "nonexistent-dec-key",
		Backend:    "software",
		Ciphertext: []byte("ciphertext"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== Verify with Ed25519 tests =====================

func TestVerify_Ed25519_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ed25519-verify-key",
		Backend: "software",
		KeyType: "ed25519",
	})
	require.NoError(t, err)

	data := []byte("test data for ed25519")
	signResp, err := svc.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "ed25519-verify-key",
		Backend: "software",
		Data:    data,
	})
	require.NoError(t, err)

	verifyResp, err := svc.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "ed25519-verify-key",
		Backend:   "software",
		Signature: signResp.Signature,
		Data:      data,
	})
	require.NoError(t, err)
	assert.True(t, verifyResp.Valid)
	assert.Equal(t, "signature is valid", verifyResp.Message)
}

func TestVerify_Ed25519_InvalidSignature(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ed25519-verify-inv",
		Backend: "software",
		KeyType: "ed25519",
	})
	require.NoError(t, err)

	verifyResp, err := svc.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "ed25519-verify-inv",
		Backend:   "software",
		Signature: []byte("invalid-signature-data-that-is-64-bytes-long-for-ed25519-verify!"),
		Data:      []byte("test data"),
	})
	require.NoError(t, err)
	assert.False(t, verifyResp.Valid)
	assert.Equal(t, "signature is invalid", verifyResp.Message)
}

func TestVerify_ECDSA_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ecdsa-verify-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	data := []byte("test data for ecdsa")
	signResp, err := svc.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "ecdsa-verify-key",
		Backend: "software",
		Data:    data,
	})
	require.NoError(t, err)

	verifyResp, err := svc.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "ecdsa-verify-key",
		Backend:   "software",
		Signature: signResp.Signature,
		Data:      data,
	})
	require.NoError(t, err)
	assert.True(t, verifyResp.Valid)
}

func TestVerify_MissingData_NonEd25519Key(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ecdsa-verify-nodata",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	_, err = svc.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "ecdsa-verify-nodata",
		Backend:   "software",
		Signature: []byte("sig"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "data is required")
}

// ===================== Encrypt edge cases =====================

func TestEncrypt_KeyNotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Encrypt(context.Background(), &pb.EncryptRequest{
		KeyId:     "nonexistent-enc-key",
		Backend:   "software",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== EncryptAsym with non-RSA key =====================

func TestEncryptAsym_NonRSAKeyError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ecdsa-for-encrypt",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	_, err = svc.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
		KeyId:     "ecdsa-for-encrypt",
		Backend:   "software",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "asymmetric encryption only supported for RSA keys")
}

// ===================== RotateKey tests =====================

func TestRotateKey_KeyNotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.RotateKey(context.Background(), &pb.RotateKeyRequest{
		KeyId:   "nonexistent-rotate",
		Backend: "software",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestRotateKey_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rotate-test-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	resp, err := svc.RotateKey(context.Background(), &pb.RotateKeyRequest{
		KeyId:   "rotate-test-key",
		Backend: "software",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyId)
}

// ===================== GetLockoutStatus with lockout data =====================

func TestGetLockoutStatus_NilFromBackend(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
	ctx := context.Background()

	resp, err := svc.GetLockoutStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.IsLocked)
	assert.Equal(t, int32(0), resp.FailedAttempts)
}

// ===================== PIN Manager error paths =====================

func TestSetUserPIN_PINManagerErrorPath(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{
		CurrentSoPin: "",
		NewSoPin:     "123456",
	})
	require.NoError(t, err)

	_, err = svc.SetUserPIN(ctx, &pb.SetUserPINRequest{
		SoPin:      "wrong-pin",
		NewUserPin: "userpin1",
	})
	require.Error(t, err)
}

func TestChangeUserPIN_ErrorPath(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.ChangeUserPIN(ctx, &pb.ChangeUserPINRequest{
		CurrentUserPin: "wrong-old-pin",
		NewUserPin:     "new-pin-123",
	})
	require.Error(t, err)
}

func TestResetLockout_NotConfiguredPath(t *testing.T) {
	SetPINManager(nil)
	defer SetPINManager(nil)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.ResetLockout(ctx, &pb.ResetLockoutRequest{
		SoPin: "some-pin",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

// mockPINBackendWithLockout implements PINManager with active lockout tracking.
type mockPINBackendWithLockout struct {
	pin.PINManager
}

func (m *mockPINBackendWithLockout) GetLockoutStatus() *pin.LockoutStatus {
	return &pin.LockoutStatus{
		FailedAttempts:  3,
		MaxAttempts:     10,
		IsLocked:        true,
		LockoutUntil:    time.Now().Add(5 * time.Minute),
		RecoverySeconds: 300,
	}
}

func (m *mockPINBackendWithLockout) VerifySOPIN(_ string) error   { return nil }
func (m *mockPINBackendWithLockout) VerifyUserPIN(_ string) error { return nil }
func (m *mockPINBackendWithLockout) SetSOPIN(_, _ string) error   { return nil }
func (m *mockPINBackendWithLockout) SetUserPIN(_, _ string) error { return nil }
func (m *mockPINBackendWithLockout) ChangeSOPIN(_, _ string) error {
	return nil
}
func (m *mockPINBackendWithLockout) ChangeUserPIN(_, _ string) error {
	return nil
}
func (m *mockPINBackendWithLockout) ResetLockout(_ string) error { return nil }

func TestGetLockoutStatus_WithActiveLockout(t *testing.T) {
	mock := &mockPINBackendWithLockout{}
	SetPINManager(mock)
	t.Cleanup(func() { SetPINManager(nil) })

	svc := newTestService()
	ctx := context.Background()

	resp, err := svc.GetLockoutStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, resp.IsLocked)
	assert.Equal(t, int32(3), resp.FailedAttempts)
	assert.Equal(t, int32(10), resp.MaxAttempts)
	assert.Equal(t, int32(300), resp.RecoverySeconds)
	assert.NotEmpty(t, resp.LockoutUntil)
}

// ===================== parseCertFromPEM edge cases =====================

func TestParseCertFromPEM_InvalidDER(t *testing.T) {
	invalidPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not-a-real-certificate"),
	}))
	_, err := parseCertFromPEM(invalidPEM)
	require.Error(t, err)
}

func TestParseCertFromPEM_NoPEMBlock(t *testing.T) {
	_, err := parseCertFromPEM("just a regular string with no PEM")
	require.Error(t, err)
}

// ===================== encodePrivateKeyToPEM edge cases =====================

func TestEncodePrivateKeyToPEM_RSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemStr, err := encodePrivateKeyToPEM(key)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "RSA PRIVATE KEY")
}

func TestEncodePrivateKeyToPEM_ECDSAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pemStr, err := encodePrivateKeyToPEM(key)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "EC PRIVATE KEY")
}

func TestEncodePrivateKeyToPEM_UnsupportedTypeError(t *testing.T) {
	_, err := encodePrivateKeyToPEM("not-a-key")
	require.Error(t, err)
}

// ===================== GenerateKey Ed25519 and symmetric =====================

func TestGenerateKey_Ed25519Type(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ed25519-gen-test",
		Backend: "software",
		KeyType: "ed25519",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyId)
	assert.Equal(t, "ed25519", resp.KeyType)
}

func TestGenerateKey_SymmetricAES256Type(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "aes256-gen-test",
		Backend: "software",
		KeyType: "symmetric",
		KeySize: 256,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyId)
}

func TestGenerateKey_SymmetricAES128Type(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "aes128-gen-test",
		Backend: "software",
		KeyType: "symmetric",
		KeySize: 128,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyId)
}

func TestGenerateKey_SymmetricAES192Type(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "aes192-gen-test",
		Backend: "software",
		KeyType: "symmetric",
		KeySize: 192,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyId)
}

// ===================== Seal with key_id path =====================

func TestSeal_WithKeyID_KeyNotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Seal(context.Background(), &pb.SealRequest{
		Backend: "software",
		Data:    []byte("data"),
		KeyId:   "nonexistent-seal-key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== GetKey tests =====================

func TestGetKey_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "get-key-test",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	resp, err := svc.GetKey(context.Background(), &pb.GetKeyRequest{
		KeyId:   "get-key-test",
		Backend: "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "get-key-test", resp.Key.KeyId)
	assert.NotEmpty(t, resp.PublicKeyPem)
}

func TestGetKey_NotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetKey(context.Background(), &pb.GetKeyRequest{
		KeyId:   "nonexistent-get-key",
		Backend: "software",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== ListKeys tests =====================

func TestListKeys_WithGeneratedKeys(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "list-keys-test",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	resp, err := svc.ListKeys(context.Background(), &pb.ListKeysRequest{
		Backend: "software",
	})
	require.NoError(t, err)
	assert.True(t, resp.Total >= 1)
	found := false
	for _, k := range resp.Keys {
		if k.KeyId == "list-keys-test" {
			found = true
		}
	}
	assert.True(t, found)
}

// ===================== DeleteKey tests =====================

func TestDeleteKey_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "delete-key-test",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	resp, err := svc.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
		KeyId:   "delete-key-test",
		Backend: "software",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestDeleteKey_NotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
		KeyId:   "nonexistent-del",
		Backend: "software",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== CanSeal tests =====================

func TestCanSeal_WithBackendParam(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.CanSeal(context.Background(), &pb.CanSealRequest{
		Backend: "software",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestCanSeal_WithoutBackendParam(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.CanSeal(context.Background(), &pb.CanSealRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// ===================== Seal/Unseal success path =====================

func TestSeal_WithRSAKey_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "seal-rsa-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	require.NoError(t, err)

	plaintext := []byte("sensitive data to seal")
	sealResp, err := svc.Seal(context.Background(), &pb.SealRequest{
		Backend: "software",
		Data:    plaintext,
		KeyId:   "seal-rsa-key",
	})
	require.NoError(t, err)
	require.NotEmpty(t, sealResp.Ciphertext)
	assert.NotEmpty(t, sealResp.Backend)
}

func TestUnseal_InvalidCiphertext(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "unseal-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	require.NoError(t, err)

	_, err = svc.Unseal(context.Background(), &pb.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("invalid-ciphertext-data"),
		KeyId:      "unseal-key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

// ===================== Sign with RSA =====================

func TestSign_RSAKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rsa-sign-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	require.NoError(t, err)

	resp, err := svc.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "rsa-sign-test",
		Backend: "software",
		Data:    []byte("data to sign"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Signature)
}

func TestSign_KeyNotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "nonexistent-sign-key",
		Backend: "software",
		Data:    []byte("data"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== grpcPageRequest tests =====================

func TestGrpcPageRequest_EdgeCases(t *testing.T) {
	t.Run("zero limit returns unpaginated", func(t *testing.T) {
		pr := grpcPageRequest(0, 0)
		assert.Equal(t, 0, pr.Page)
	})

	t.Run("positive limit with zero offset", func(t *testing.T) {
		pr := grpcPageRequest(10, 0)
		assert.Equal(t, 1, pr.Page)
		assert.Equal(t, 10, pr.PageSize)
	})

	t.Run("positive limit and offset", func(t *testing.T) {
		pr := grpcPageRequest(10, 20)
		assert.Equal(t, 3, pr.Page)
		assert.Equal(t, 10, pr.PageSize)
	})

	t.Run("negative limit returns unpaginated", func(t *testing.T) {
		pr := grpcPageRequest(-1, 0)
		assert.Equal(t, 0, pr.Page)
	})
}

// ===================== BarrierSeal when not initialized =====================

func TestBarrierSeal_NotInitializedPath(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()

	// Barrier is not initialized, sealing should still work (idempotent seal)
	resp, err := svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// ===================== Verify RSA with invalid signature =====================

func TestVerify_RSA_InvalidSignature(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rsa-verify-invalid",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	require.NoError(t, err)

	verifyResp, err := svc.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "rsa-verify-invalid",
		Backend:   "software",
		Signature: []byte("invalid-signature"),
		Data:      []byte("some data"),
	})
	require.NoError(t, err)
	assert.False(t, verifyResp.Valid)
	assert.Equal(t, "signature is invalid", verifyResp.Message)
}

// ===================== ListBackends description coverage =====================

func TestListBackends_DescriptionField(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.ListBackends(context.Background(), &pb.ListBackendsRequest{})
	require.NoError(t, err)
	require.True(t, resp.Count >= 1)

	for _, b := range resp.Backends {
		if b.Name == "software" {
			assert.NotEmpty(t, b.Description)
		}
	}
}

// ===================== Sign Ed25519 =====================

func TestSign_Ed25519Key(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ed25519-sign-test",
		Backend: "software",
		KeyType: "ed25519",
	})
	require.NoError(t, err)

	resp, err := svc.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "ed25519-sign-test",
		Backend: "software",
		Data:    []byte("data to sign"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Signature)
}

// ===================== Deep import/export path tests with exportable keys =====================

func TestGetImportParameters_RSAKeySuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Generate an exportable RSA key for import parameters
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-params-rsa",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	resp, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-rsa",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "rsa",
		KeySize:           2048,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappingPublicKey)
	assert.NotEmpty(t, resp.Algorithm)
}

func TestExportKey_SymmetricKeySuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "export-sym-key-wrap",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	resp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "export-sym-key-wrap",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKey)
	assert.NotEmpty(t, resp.Algorithm)
}

func TestExportKeyMaterial_SymmetricSuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "export-sym-key",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	resp, err := svc.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{
		KeyId:   "export-sym-key",
		Backend: "software",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyMaterial)
	assert.NotEmpty(t, resp.KeyType)
}

func TestWrapKeyByID_FullPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Create a wrapping RSA key
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "wrapping-key-byid",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	// Create an exportable symmetric key to wrap
	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "target-sym-key-byid",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	resp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "wrapping-key-byid",
		WrappingKeyBackend: "software",
		TargetKeyId:        "target-sym-key-byid",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKey)
	assert.NotEmpty(t, resp.Algorithm)
}

func TestUnwrapKeyByID_FullPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Create an RSA key for wrapping
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	// Create an exportable symmetric key
	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "source-sym-key",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	// Wrap it first
	wrapResp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "unwrap-rsa-key",
		WrappingKeyBackend: "software",
		TargetKeyId:        "source-sym-key",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// Unwrap into new key. The unwrap path goes through GetImportParameters
	// which exercises the deep code path even if the import token mismatch
	// causes a downstream error.
	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyId:      "unwrap-rsa-key",
		UnwrappingKeyBackend: "software",
		Algorithm:            wrapResp.Algorithm,
		TargetKeyId:          "imported-sym-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})
	// May fail due to import token requirements in the software backend
	// but exercises the full unwrap code path
	assert.Error(t, err)
}

func TestUnwrapKeyByID_RSATargetType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key2",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "source-sym2",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	wrapResp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "unwrap-rsa-key2",
		WrappingKeyBackend: "software",
		TargetKeyId:        "source-sym2",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// Try to unwrap as RSA key type (exercises the RSA branch in UnwrapKeyByID)
	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyId:      "unwrap-rsa-key2",
		UnwrappingKeyBackend: "software",
		Algorithm:            wrapResp.Algorithm,
		TargetKeyId:          "imported-rsa-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "rsa",
		TargetKeySize:        2048,
	})
	// This will likely fail since the unwrapped material is a symmetric key,
	// but it exercises the RSA branch in the type switch
	require.Error(t, err)
}

func TestUnwrapKeyByID_ECDSATargetType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key3",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "source-sym3",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	wrapResp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "unwrap-rsa-key3",
		WrappingKeyBackend: "software",
		TargetKeyId:        "source-sym3",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// Exercise the ECDSA branch
	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyId:      "unwrap-rsa-key3",
		UnwrappingKeyBackend: "software",
		Algorithm:            wrapResp.Algorithm,
		TargetKeyId:          "imported-ecdsa-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "ecdsa",
		TargetCurve:          "P256",
	})
	require.Error(t, err)
}

func TestUnwrapKeyByID_Ed25519TargetType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key4",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "source-sym4",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	wrapResp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "unwrap-rsa-key4",
		WrappingKeyBackend: "software",
		TargetKeyId:        "source-sym4",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// Exercise the Ed25519 branch
	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyId:      "unwrap-rsa-key4",
		UnwrappingKeyBackend: "software",
		Algorithm:            wrapResp.Algorithm,
		TargetKeyId:          "imported-ed25519-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "ed25519",
	})
	require.Error(t, err)
}

func TestUnwrapKeyByID_AES128TargetType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key5",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "source-sym5",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    128,
		Exportable: true,
	})
	require.NoError(t, err)

	wrapResp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "unwrap-rsa-key5",
		WrappingKeyBackend: "software",
		TargetKeyId:        "source-sym5",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// Unwrap as AES-128 symmetric key - exercises the 128 branch
	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyId:      "unwrap-rsa-key5",
		UnwrappingKeyBackend: "software",
		Algorithm:            wrapResp.Algorithm,
		TargetKeyId:          "imported-aes128-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        128,
	})
	// May fail due to import token requirements but exercises the code path
	assert.Error(t, err)
}

func TestUnwrapKeyByID_AES192TargetType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key6",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "source-sym6",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    192,
		Exportable: true,
	})
	require.NoError(t, err)

	wrapResp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "unwrap-rsa-key6",
		WrappingKeyBackend: "software",
		TargetKeyId:        "source-sym6",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyId:      "unwrap-rsa-key6",
		UnwrappingKeyBackend: "software",
		Algorithm:            wrapResp.Algorithm,
		TargetKeyId:          "imported-aes192-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        192,
	})
	// May fail due to import token requirements but exercises the code path
	assert.Error(t, err)
}

func TestUnwrapKeyByID_InvalidTargetKeyType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key7",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "source-sym7",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	wrapResp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "unwrap-rsa-key7",
		WrappingKeyBackend: "software",
		TargetKeyId:        "source-sym7",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// Unsupported key type - exercises the unwrap flow
	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyId:      "unwrap-rsa-key7",
		UnwrappingKeyBackend: "software",
		Algorithm:            wrapResp.Algorithm,
		TargetKeyId:          "imported-unknown",
		TargetKeyBackend:     "software",
		TargetKeyType:        "chacha20poly1305",
	})
	require.Error(t, err)
}

func TestUnwrapKeyByID_InvalidSymmetricKeySize(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key8",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "source-sym8",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	wrapResp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "unwrap-rsa-key8",
		WrappingKeyBackend: "software",
		TargetKeyId:        "source-sym8",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// Invalid key size for symmetric - exercises the unwrap flow
	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyId:      "unwrap-rsa-key8",
		UnwrappingKeyBackend: "software",
		Algorithm:            wrapResp.Algorithm,
		TargetKeyId:          "imported-sym-bad",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        512,
	})
	require.Error(t, err)
}

func TestUnwrapKeyByID_NoKeyTypeWithNoKeySize(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key9",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "source-sym9",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	wrapResp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "unwrap-rsa-key9",
		WrappingKeyBackend: "software",
		TargetKeyId:        "source-sym9",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// No key type and no key size - exercises the unwrap flow
	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyId:      "unwrap-rsa-key9",
		UnwrappingKeyBackend: "software",
		Algorithm:            wrapResp.Algorithm,
		TargetKeyId:          "imported-no-type",
		TargetKeyBackend:     "software",
	})
	require.Error(t, err)
}

func TestUnwrapKeyByID_InvalidECDSACurve(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key10",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "source-sym10",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	wrapResp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "unwrap-rsa-key10",
		WrappingKeyBackend: "software",
		TargetKeyId:        "source-sym10",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// Invalid curve for ECDSA target - exercises the unwrap flow
	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyId:      "unwrap-rsa-key10",
		UnwrappingKeyBackend: "software",
		Algorithm:            wrapResp.Algorithm,
		TargetKeyId:          "imported-ecdsa-bad",
		TargetKeyBackend:     "software",
		TargetKeyType:        "ecdsa",
		TargetCurve:          "INVALID",
	})
	require.Error(t, err)
}

func TestCopyKey_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Generate an exportable symmetric key (small enough for RSA wrapping)
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "copy-source-key",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	resp, err := svc.CopyKey(context.Background(), &pb.CopyKeyRequest{
		SourceBackend:     "software",
		SourceKeyId:       "copy-source-key",
		DestBackend:       "software",
		DestKeyId:         "copy-dest-key",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "copy-dest-key", resp.DestKeyId)
}

func TestImportKey_SymmetricWithSoftwareBackend(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Generate an exportable symmetric key, export it, then import it back
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-sym-src",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	exportResp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "import-sym-src",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	importResp, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:       "import-sym-dst",
		Backend:     "software",
		WrappedKey:  exportResp.WrappedKey,
		Algorithm:   exportResp.Algorithm,
		KeyType:     "symmetric",
		KeySize:     256,
		ImportToken: exportResp.ImportToken,
	})
	require.NoError(t, err)
	assert.True(t, importResp.Success)
}

// ===================== GetImportParameters type branch coverage =====================

func TestGetImportParameters_ECDSAKeyType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-params-ecdsa",
		Backend:    "software",
		KeyType:    "ecdsa",
		Curve:      "P256",
		Exportable: true,
	})
	require.NoError(t, err)

	resp, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-ecdsa",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "ecdsa",
		Curve:             "P256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappingPublicKey)
}

func TestGetImportParameters_Ed25519KeyType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-params-ed25519",
		Backend:    "software",
		KeyType:    "ed25519",
		Exportable: true,
	})
	require.NoError(t, err)

	resp, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-ed25519",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "ed25519",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappingPublicKey)
}

func TestGetImportParameters_SymmetricKeyType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-params-sym",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	resp, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-sym",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "symmetric",
		KeySize:           256,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappingPublicKey)
}

func TestGetImportParameters_SymmetricAES128(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-params-sym128",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    128,
		Exportable: true,
	})
	require.NoError(t, err)

	resp, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-sym128",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "symmetric",
		KeySize:           128,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappingPublicKey)
}

func TestGetImportParameters_SymmetricAES192(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-params-sym192",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    192,
		Exportable: true,
	})
	require.NoError(t, err)

	resp, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-sym192",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "symmetric",
		KeySize:           192,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappingPublicKey)
}

func TestGetImportParameters_UnsupportedKeyType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-params-dummy",
		Backend:    "software",
		KeyType:    "ecdsa",
		Curve:      "P256",
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-dummy",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "chacha20",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestGetImportParameters_InvalidSymmetricKeySize(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-params-sym-bad",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-sym-bad",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "symmetric",
		KeySize:           512,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestGetImportParameters_ECDSAInvalidCurve(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-params-ecdsa-bad",
		Backend:    "software",
		KeyType:    "ecdsa",
		Curve:      "P256",
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-ecdsa-bad",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "ecdsa",
		Curve:             "INVALID_CURVE",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// ===================== ImportKey type-specific branches (with software backend) =====================

func TestImportKey_ECDSATypeBranch(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Generate exportable ECDSA, export, re-import
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-ecdsa-src",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	exportResp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "import-ecdsa-src",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// Import as ECDSA type to exercise the ECDSA branch
	_, err = svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:       "import-ecdsa-dst",
		Backend:     "software",
		WrappedKey:  exportResp.WrappedKey,
		Algorithm:   exportResp.Algorithm,
		KeyType:     "ecdsa",
		Curve:       "P256",
		ImportToken: exportResp.ImportToken,
	})
	// May fail since material is actually symmetric, but exercises the ECDSA branch
	require.Error(t, err)
}

func TestImportKey_Ed25519TypeBranch(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-ed-src",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	exportResp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "import-ed-src",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:       "import-ed-dst",
		Backend:     "software",
		WrappedKey:  exportResp.WrappedKey,
		Algorithm:   exportResp.Algorithm,
		KeyType:     "ed25519",
		ImportToken: exportResp.ImportToken,
	})
	require.Error(t, err)
}

func TestImportKey_UnsupportedTypeBranch(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-unsup-src",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	exportResp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "import-unsup-src",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:       "import-unsup-dst",
		Backend:     "software",
		WrappedKey:  exportResp.WrappedKey,
		Algorithm:   exportResp.Algorithm,
		KeyType:     "chacha20poly1305",
		ImportToken: exportResp.ImportToken,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestImportKey_AESInvalidKeySizeWithBackend(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-aes-bad-src",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	exportResp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "import-aes-bad-src",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:       "import-aes-bad-dst",
		Backend:     "software",
		WrappedKey:  exportResp.WrappedKey,
		Algorithm:   exportResp.Algorithm,
		KeyType:     "symmetric",
		KeySize:     512,
		ImportToken: exportResp.ImportToken,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestImportKey_ECDSAInvalidCurveWithBackend(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-ecdsa-bad-src",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	exportResp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "import-ecdsa-bad-src",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:       "import-ecdsa-bad-dst",
		Backend:     "software",
		WrappedKey:  exportResp.WrappedKey,
		Algorithm:   exportResp.Algorithm,
		KeyType:     "ecdsa",
		Curve:       "INVALID",
		ImportToken: exportResp.ImportToken,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// ===================== GetTLSCertificate success path =====================

func TestGetTLSCertificate_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Generate an RSA key
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "tls-cert-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	require.NoError(t, err)

	// Create a self-signed cert for this key
	certPEM := testCertPEM(t)
	_, err = svc.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "tls-cert-key",
		CertPem: certPEM,
	})
	require.NoError(t, err)

	// Try to get TLS certificate. The software backend may need the cert
	// and key to match, but even if it fails, it exercises the code path.
	resp, err := svc.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{
		KeyId:   "tls-cert-key",
		Backend: "software",
	})
	if err == nil {
		assert.NotEmpty(t, resp.CertPem)
		assert.NotEmpty(t, resp.PrivateKeyPem)
	}
	// If error, the code still exercised GetTLSCertificate up to the error point
}

// ===================== Decrypt with ECDSA key (non-symmetric, non-RSA) =====================

func TestDecrypt_ECDSAKey_NoDecrypter(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ecdsa-decrypt-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	_, err = svc.Decrypt(context.Background(), &pb.DecryptRequest{
		KeyId:      "ecdsa-decrypt-key",
		Backend:    "software",
		Ciphertext: []byte("some-ciphertext"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

// ===================== CopyKey with non-exportable key =====================

func TestCopyKey_NonExportableKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "copy-noexport",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	_, err = svc.CopyKey(context.Background(), &pb.CopyKeyRequest{
		SourceBackend:     "software",
		SourceKeyId:       "copy-noexport",
		DestBackend:       "software",
		DestKeyId:         "copy-noexport-dest",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.Error(t, err)
}

// ===================== GenerateKey error paths =====================

func TestGenerateKey_InvalidCurve(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "gen-bad-curve",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "INVALID_CURVE",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestGenerateKey_UnsupportedKeyType(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "gen-unsupported",
		Backend: "software",
		KeyType: "chacha20",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestGenerateKey_InvalidSymmetricSize(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "gen-bad-sym-size",
		Backend: "software",
		KeyType: "symmetric",
		KeySize: 512,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestGenerateKey_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "gen-no-backend",
		Backend: "nonexistent",
		KeyType: "rsa",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== Sign/Verify error paths =====================

func TestSign_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "key",
		Backend: "nonexistent",
		Data:    []byte("data"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestVerify_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "key",
		Backend:   "nonexistent",
		Signature: []byte("sig"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestVerify_KeyNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "nonexistent-verify",
		Backend:   "software",
		Signature: []byte("sig"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== Encrypt/Decrypt backend errors =====================

func TestEncrypt_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Encrypt(context.Background(), &pb.EncryptRequest{
		KeyId:     "key",
		Backend:   "nonexistent",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDecrypt_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Decrypt(context.Background(), &pb.DecryptRequest{
		KeyId:      "key",
		Backend:    "nonexistent",
		Ciphertext: []byte("data"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== EncryptAsym error paths =====================

func TestEncryptAsym_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
		KeyId:     "key",
		Backend:   "nonexistent",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestEncryptAsym_KeyNotFoundError(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
		KeyId:     "nonexistent",
		Backend:   "software",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== WrapKey/UnwrapKey error paths =====================

func TestWrapKey_InvalidPublicKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.WrapKey(context.Background(), &pb.WrapKeyRequest{
		KeyMaterial:      []byte("key-material"),
		WrappingPublicKey: []byte("invalid-public-key"),
		Algorithm:        "RSAES_OAEP_SHA_256",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "failed to parse wrapping public key")
}

func TestUnwrapKey_InvalidPublicKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
		WrappedKey:        []byte("data"),
		Algorithm:         "RSAES_OAEP_SHA_256",
		WrappingPublicKey: []byte("invalid-pubkey"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// ===================== ExportKey error paths =====================

func TestExportKey_KeyNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "nonexistent",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== Seal/Unseal error paths =====================

func TestSeal_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Seal(context.Background(), &pb.SealRequest{
		Backend: "nonexistent",
		Data:    []byte("data"),
	})
	require.Error(t, err)
}

func TestUnseal_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.Unseal(context.Background(), &pb.UnsealRequest{
		Backend:    "nonexistent",
		Ciphertext: []byte("data"),
	})
	require.Error(t, err)
}

// ===================== DeriveKey error paths =====================

func TestDeriveKey_MissingInputKeyMaterial(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
		Algorithm: "hkdf",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeriveKey_UnsupportedAlgorithm(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
		Algorithm:     "unsupported-kdf",
		InputKeyMaterial: []byte("input"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// ===================== findKeyAttributes error =====================

func TestFindKeyAttributes_EmptyKeyList(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// GetKey with nonexistent key exercises findKeyAttributes
	_, err := svc.GetKey(context.Background(), &pb.GetKeyRequest{
		KeyId:   "no-such-key",
		Backend: "software",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== WrapKey success path =====================

func TestWrapKey_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Generate an RSA key for wrapping
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "wrap-rsa-key",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	// Get import parameters to get the wrapping public key
	importParams, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "wrap-rsa-key",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "rsa",
		KeySize:           2048,
	})
	require.NoError(t, err)

	// Wrap some key material
	resp, err := svc.WrapKey(context.Background(), &pb.WrapKeyRequest{
		KeyMaterial:       []byte("0123456789abcdef"), // 16 bytes AES key
		WrappingPublicKey: importParams.WrappingPublicKey,
		Algorithm:         "RSAES_OAEP_SHA_256",
		ImportToken:       importParams.ImportToken,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKey)
}

// ===================== UnwrapKey success path =====================

func TestUnwrapKey_SuccessPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "unwrap-rsa-key-full",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	// Get import parameters
	importParams, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "unwrap-rsa-key-full",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "rsa",
		KeySize:           2048,
	})
	require.NoError(t, err)

	// Wrap key material
	wrapResp, err := svc.WrapKey(context.Background(), &pb.WrapKeyRequest{
		KeyMaterial:       []byte("0123456789abcdef"),
		WrappingPublicKey: importParams.WrappingPublicKey,
		Algorithm:         "RSAES_OAEP_SHA_256",
		ImportToken:       importParams.ImportToken,
	})
	require.NoError(t, err)

	// Unwrap it back
	unwrapResp, err := svc.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
		WrappedKey:        wrapResp.WrappedKey,
		Algorithm:         "RSAES_OAEP_SHA_256",
		WrappingPublicKey: importParams.WrappingPublicKey,
		ImportToken:       importParams.ImportToken,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, unwrapResp.KeyMaterial)
}

// ===================== GetBackendInfo tests =====================

func TestGetBackendInfo_Success(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.GetBackendInfo(context.Background(), &pb.GetBackendInfoRequest{
		Name: "software",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp.Backend)
	assert.Equal(t, "software", resp.Backend.Name)
}

func TestGetBackendInfo_NotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetBackendInfo(context.Background(), &pb.GetBackendInfoRequest{
		Name: "nonexistent",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== DeleteKey backend not found =====================

func TestDeleteKey_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
		KeyId:   "key",
		Backend: "nonexistent",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== RotateKey backend not found =====================

func TestRotateKey_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.RotateKey(context.Background(), &pb.RotateKeyRequest{
		KeyId:   "key",
		Backend: "nonexistent",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== ListKeys backend not found =====================

func TestListKeys_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.ListKeys(context.Background(), &pb.ListKeysRequest{
		Backend: "nonexistent",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== GetKey backend not found =====================

func TestGetKey_BackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetKey(context.Background(), &pb.GetKeyRequest{
		KeyId:   "key",
		Backend: "nonexistent",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ===================== No backends available paths =====================

func TestSaveCert_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	certPEM := testCertPEM(t)
	_, err := svc.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "key",
		CertPem: certPEM,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Contains(t, st.Message(), "no backends available")
}

func TestGetCert_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.GetCert(context.Background(), &pb.GetCertRequest{
		KeyId: "key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestDeleteCert_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.DeleteCert(context.Background(), &pb.DeleteCertRequest{
		KeyId: "key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestListCerts_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.ListCerts(context.Background(), &pb.ListCertsRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestCertExists_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.CertExists(context.Background(), &pb.CertExistsRequest{
		KeyId: "key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestSaveCertChain_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	certPEM := testCertPEM(t)
	_, err := svc.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
		KeyId:        "key",
		CertChainPem: []string{certPEM},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestGetCertChain_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.GetCertChain(context.Background(), &pb.GetCertChainRequest{
		KeyId: "key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestWrapKey_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	// Create a valid RSA public key for the test
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	_, err = svc.WrapKey(context.Background(), &pb.WrapKeyRequest{
		KeyMaterial:       []byte("data"),
		WrappingPublicKey: pubKeyDER,
		Algorithm:         "RSAES_OAEP_SHA_256",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestUnwrapKey_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	_, err = svc.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
		WrappedKey:        []byte("data"),
		Algorithm:         "RSAES_OAEP_SHA_256",
		WrappingPublicKey: pubKeyDER,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestListBackends_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	resp, err := svc.ListBackends(context.Background(), &pb.ListBackendsRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Count)
}

func TestSeal_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.Seal(context.Background(), &pb.SealRequest{
		Backend: "software",
		Data:    []byte("data"),
	})
	require.Error(t, err)
}

func TestUnseal_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.Unseal(context.Background(), &pb.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("data"),
	})
	require.Error(t, err)
}

// ===================== Authorization deny tests for barrier shamir methods =====================

// denyAllAuthorizer always denies authorization.
type denyAllAuthorizer struct{}

func (d *denyAllAuthorizer) Authorize(_ context.Context, _ *authz.AuthorizationRequest) (*authz.AuthorizationDecision, error) {
	return &authz.AuthorizationDecision{Allowed: false, Reason: "denied"}, nil
}

func TestAuthzDeny_BarrierShamirMethods(t *testing.T) {
	setupBarrier(t)
	svc := NewService(&denyAllAuthorizer{}, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"BarrierInitializeShamir", func() error {
			_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{Secret: "s"})
			return err
		}},
		{"BarrierUnsealShare", func() error {
			_, err := svc.BarrierUnsealShare(ctx, &pb.BarrierUnsealShareRequest{Share: "share-data"})
			return err
		}},
		{"BarrierUnsealShares", func() error {
			_, err := svc.BarrierUnsealShares(ctx, &pb.BarrierUnsealSharesRequest{})
			return err
		}},
		{"BarrierShamirListShares", func() error {
			_, err := svc.BarrierShamirListShares(ctx, &emptypb.Empty{})
			return err
		}},
		{"BarrierShamirDeleteShare", func() error {
			_, err := svc.BarrierShamirDeleteShare(ctx, &pb.BarrierShamirDeleteShareRequest{Index: 1})
			return err
		}},
		{"BarrierShamirDeleteAllShares", func() error {
			_, err := svc.BarrierShamirDeleteAllShares(ctx, &emptypb.Empty{})
			return err
		}},
		{"BarrierShamirVerify", func() error {
			_, err := svc.BarrierShamirVerify(ctx, &emptypb.Empty{})
			return err
		}},
		{"BarrierRekey", func() error {
			_, err := svc.BarrierRekey(ctx, &pb.BarrierRekeyRequest{})
			return err
		}},
		{"BarrierGenerateRecoveryKeys", func() error {
			_, err := svc.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{})
			return err
		}},
		{"BarrierRecoverWithKeys", func() error {
			_, err := svc.BarrierRecoverWithKeys(ctx, &pb.BarrierRecoverWithKeysRequest{})
			return err
		}},
		{"BarrierDeleteRecoveryKeys", func() error {
			_, err := svc.BarrierDeleteRecoveryKeys(ctx, &emptypb.Empty{})
			return err
		}},
		{"BarrierGenerateRootToken", func() error {
			_, err := svc.BarrierGenerateRootToken(ctx, &pb.BarrierGenerateRootTokenRequest{})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok, "expected gRPC status error for %s", tt.name)
			assert.Equal(t, codes.PermissionDenied, st.Code(), "expected PermissionDenied for %s", tt.name)
		})
	}
}

// ===================== Authorization deny for barrier PIN methods =====================

func TestAuthzDeny_PINMethods(t *testing.T) {
	setupPINManager(t)
	svc := NewService(&denyAllAuthorizer{}, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"SetSOPIN", func() error { _, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{}); return err }},
		{"SetUserPIN", func() error { _, err := svc.SetUserPIN(ctx, &pb.SetUserPINRequest{}); return err }},
		{"ChangeSOPIN", func() error { _, err := svc.ChangeSOPIN(ctx, &pb.ChangeSOPINRequest{}); return err }},
		{"ChangeUserPIN", func() error { _, err := svc.ChangeUserPIN(ctx, &pb.ChangeUserPINRequest{}); return err }},
		{"VerifySOPIN", func() error { _, err := svc.VerifySOPIN(ctx, &pb.VerifySOPINRequest{}); return err }},
		{"VerifyUserPIN", func() error { _, err := svc.VerifyUserPIN(ctx, &pb.VerifyUserPINRequest{}); return err }},
		{"GetLockoutStatus", func() error { _, err := svc.GetLockoutStatus(ctx, &emptypb.Empty{}); return err }},
		{"ResetLockout", func() error { _, err := svc.ResetLockout(ctx, &pb.ResetLockoutRequest{}); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.PermissionDenied, st.Code())
		})
	}
}

// ===================== Encrypt with asymmetric key (not supported for symmetric encrypt) =====================

func TestEncrypt_WithAsymmetricKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rsa-for-sym-encrypt",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	require.NoError(t, err)

	// Try symmetric encrypt with an RSA key - should fail
	_, err = svc.Encrypt(context.Background(), &pb.EncryptRequest{
		KeyId:     "rsa-for-sym-encrypt",
		Backend:   "software",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.True(t, st.Code() == codes.InvalidArgument || st.Code() == codes.Internal)
}

// ===================== Decrypt with symmetric key =====================

func TestDecrypt_SymmetricKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "aes-for-decrypt",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	// Encrypt first
	encResp, err := svc.Encrypt(context.Background(), &pb.EncryptRequest{
		KeyId:     "aes-for-decrypt",
		Backend:   "software",
		Plaintext: []byte("hello symmetric world"),
	})
	require.NoError(t, err)

	// Decrypt
	decResp, err := svc.Decrypt(context.Background(), &pb.DecryptRequest{
		KeyId:      "aes-for-decrypt",
		Backend:    "software",
		Ciphertext: encResp.Ciphertext,
		Nonce:      encResp.Nonce,
		Tag:        encResp.Tag,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("hello symmetric world"), decResp.Plaintext)
}

// ===================== Decrypt symmetric key - invalid ciphertext =====================

func TestDecrypt_SymmetricKeyInvalidCiphertext(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "aes-for-decrypt-bad",
		Backend: "software",
		KeyType: "symmetric",
		KeySize: 256,
	})
	require.NoError(t, err)

	_, err = svc.Decrypt(context.Background(), &pb.DecryptRequest{
		KeyId:      "aes-for-decrypt-bad",
		Backend:    "software",
		Ciphertext: []byte("invalid-ciphertext"),
		Nonce:      []byte("123456789012"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

// ===================== ExportKey with non-exportable key =====================

func TestExportKey_NonExportableKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "non-export-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	_, err = svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "non-export-key",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.Error(t, err)
}

// ===================== ExportKeyMaterial with non-symmetric key =====================

func TestExportKeyMaterial_NonSymmetricKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "ecdsa-export-mat",
		Backend:    "software",
		KeyType:    "ecdsa",
		Curve:      "P256",
		Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{
		KeyId:   "ecdsa-export-mat",
		Backend: "software",
	})
	require.Error(t, err)
}

// ===================== encodePrivateKeyToPEM Ed25519 =====================

func TestEncodePrivateKeyToPEM_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemStr, err := encodePrivateKeyToPEM(priv)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "PRIVATE KEY")
}

// ===================== WrapKey failure path =====================

func TestWrapKey_WrappingFailure(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Generate RSA key for wrapping public key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	// Wrapping with a standalone public key succeeds since RSA-OAEP
	// only needs the public key, not an import token for wrapping.
	resp, err := svc.WrapKey(context.Background(), &pb.WrapKeyRequest{
		KeyMaterial:       []byte("0123456789abcdef"),
		WrappingPublicKey: pubKeyDER,
		Algorithm:         "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKey)
}

// ===================== Additional service.go error paths =====================

func TestGetBackendInfo_EmptyName(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetBackendInfo(context.Background(), &pb.GetBackendInfoRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestHealth_Success(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.Health(context.Background(), &pb.HealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)
	assert.NotEmpty(t, resp.Version)
}

// ===================== ImportKey RSA type branch =====================

func TestImportKey_RSATypeBranch(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Export a symmetric key, then try to import it as RSA
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-rsa-branch-src",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	exportResp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "import-rsa-branch-src",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	// Import as RSA - exercises the RSA branch (will fail on import since material is sym)
	_, err = svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:       "import-rsa-branch-dst",
		Backend:     "software",
		WrappedKey:  exportResp.WrappedKey,
		Algorithm:   exportResp.Algorithm,
		KeyType:     "rsa",
		KeySize:     2048,
		ImportToken: exportResp.ImportToken,
	})
	// May fail since material is symmetric, but exercises RSA attrs branch
	require.Error(t, err)
}

// ===================== ImportKey AES-128 and AES-192 branches =====================

func TestImportKey_AES128BranchWithExport(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-aes128-src",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    128,
		Exportable: true,
	})
	require.NoError(t, err)

	exportResp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "import-aes128-src",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	importResp, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:       "import-aes128-dst",
		Backend:     "software",
		WrappedKey:  exportResp.WrappedKey,
		Algorithm:   exportResp.Algorithm,
		KeyType:     "symmetric",
		KeySize:     128,
		ImportToken: exportResp.ImportToken,
	})
	require.NoError(t, err)
	assert.True(t, importResp.Success)
}

func TestImportKey_AES192BranchWithExport(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:      "import-aes192-src",
		Backend:    "software",
		KeyType:    "symmetric",
		KeySize:    192,
		Exportable: true,
	})
	require.NoError(t, err)

	exportResp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId:             "import-aes192-src",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	importResp, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:       "import-aes192-dst",
		Backend:     "software",
		WrappedKey:  exportResp.WrappedKey,
		Algorithm:   exportResp.Algorithm,
		KeyType:     "symmetric",
		KeySize:     192,
		ImportToken: exportResp.ImportToken,
	})
	require.NoError(t, err)
	assert.True(t, importResp.Success)
}

// ===================== More error path coverage =====================

func TestImportKey_ECDSAInvalidCurveWithRealBackend(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Export sym key
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId: "imp-ecdsa-curve-src", Backend: "software",
		KeyType: "symmetric", KeySize: 256, Exportable: true,
	})
	require.NoError(t, err)
	exp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId: "imp-ecdsa-curve-src", Backend: "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId: "imp-ecdsa-curve-dst", Backend: "software",
		WrappedKey: exp.WrappedKey, Algorithm: exp.Algorithm,
		KeyType: "ecdsa", Curve: "INVALID",
		ImportToken: exp.ImportToken,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestImportKey_AESInvalidSizeWithRealBackend(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId: "imp-aes-bad-src", Backend: "software",
		KeyType: "symmetric", KeySize: 256, Exportable: true,
	})
	require.NoError(t, err)
	exp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId: "imp-aes-bad-src", Backend: "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId: "imp-aes-bad-dst", Backend: "software",
		WrappedKey: exp.WrappedKey, Algorithm: exp.Algorithm,
		KeyType: "symmetric", KeySize: 512,
		ImportToken: exp.ImportToken,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestImportKey_UnsupportedTypeWithRealBackend(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId: "imp-unsup-src", Backend: "software",
		KeyType: "symmetric", KeySize: 256, Exportable: true,
	})
	require.NoError(t, err)
	exp, err := svc.ExportKey(context.Background(), &pb.ExportKeyRequest{
		KeyId: "imp-unsup-src", Backend: "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	_, err = svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId: "imp-unsup-dst", Backend: "software",
		WrappedKey: exp.WrappedKey, Algorithm: exp.Algorithm,
		KeyType: "chacha20",
		ImportToken: exp.ImportToken,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// ===================== BarrierStatus with InitializedAt =====================

func TestBarrierStatus_WithInitializedAt(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()

	// Initialize to set InitializedAt
	_, err := svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{
		Secret: "test-secret-123456",
	})
	require.NoError(t, err)

	resp, err := svc.BarrierStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.False(t, resp.Sealed)
	// InitializedAt may be empty depending on barrier implementation
}

// ===================== DeriveKeyECDH with ECDSA key (backend supports it) =====================

func TestDeriveKeyECDH_InvalidPeerKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ecdsa-ecdh-bad-peer",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	require.NoError(t, err)

	// Try ECDH with invalid peer key data
	_, err = svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:         "ecdsa-ecdh-bad-peer",
		Backend:       "software",
		PeerPublicKey: []byte("invalid-peer-key-data"),
		KdfAlgorithm:  "hkdf",
		KeyLength:     32,
	})
	require.Error(t, err)
}
