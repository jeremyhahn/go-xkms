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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ===================== ImportKey type-branch tests =====================

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

// ===================== GetTLSCertificate tests =====================

// ===================== GetImportParameters tests =====================

// ===================== ExportKeyMaterial tests =====================

// ===================== WrapKeyByID deeper path tests =====================

// ===================== UnwrapKeyByID deeper path tests =====================

// ===================== DeriveKeyECDH deeper path tests =====================

// ===================== Decrypt asymmetric path tests =====================

// TestDecrypt_PKCS1v15RefusedByDefault is the gRPC refusal test for
// go-xkms#1283: Decrypt's asymmetric fallback must refuse PKCS#1 v1.5 --
// named explicitly or left unnamed -- unless crypto.allow_legacy_key_wrap is
// set. Before this fix it performed PKCS#1 v1.5 unconditionally, the one
// construction of its kind in the service not gated by this policy.
func TestDecrypt_PKCS1v15RefusedByDefault(t *testing.T) {
	previous := types.AllowLegacyKeyWrap()
	types.SetAllowLegacyKeyWrap(false)
	t.Cleanup(func() { types.SetAllowLegacyKeyWrap(previous) })

	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rsa-decrypt-refused",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	})
	require.NoError(t, err)

	for _, padding := range []string{"", "pkcs1v15"} {
		_, err = svc.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:      "rsa-decrypt-refused",
			Backend:    "software",
			Ciphertext: []byte("irrelevant"),
			Padding:    padding,
		})
		require.Error(t, err, "padding %q", padding)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code(), "padding %q", padding)
		assert.Contains(t, st.Message(), "allow_legacy_key_wrap", "padding %q", padding)
	}
}

// ===================== Verify with Ed25519 tests =====================

func TestVerify_Ed25519_InvalidSignature(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ed25519-verify-inv",
		Backend: "software",
		KeyType: "ed25519", Algorithm: "ed25519",
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

// ===================== Encrypt edge cases =====================

// ===================== EncryptAsym with non-RSA key =====================

// ===================== RotateKey tests =====================

// ===================== GetLockoutStatus with lockout data =====================

// ===================== GenerateKey Ed25519 and symmetric =====================

// ===================== Seal with key_id path =====================

// ===================== GetKey tests =====================

// ===================== ListKeys tests =====================

// ===================== DeleteKey tests =====================

// ===================== CanSeal tests =====================

// ===================== Seal/Unseal success path =====================

// ===================== Sign with RSA =====================

// ===================== grpcPageRequest tests =====================

// ===================== BarrierSeal when not initialized =====================

// ===================== Verify RSA with invalid signature =====================

func TestVerify_RSA_InvalidSignature(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rsa-verify-invalid",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
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

// ===================== Sign Ed25519 =====================

// ===================== Deep import/export path tests with exportable keys =====================

func TestUnwrapKeyByID_FullPath(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Create an RSA key for wrapping
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "unwrap-rsa-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize:    2048,
		Exportable: true,
	})
	require.NoError(t, err)

	// Create an exportable symmetric key
	_, err = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "source-sym-key",
		Backend: "software",
		KeyType: "symmetric", Algorithm: "symmetric",
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

	// Unwrap into a new key. A wrap immediately followed by an unwrap of the
	// same blob is the round trip the import ceremony is built on, so it must
	// succeed and land a usable key under the target id.
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
	require.NoError(t, err)

	_, err = svc.GetKey(context.Background(), &pb.GetKeyRequest{
		KeyId:   "imported-sym-key",
		Backend: "software",
	})
	require.NoError(t, err, "the unwrapped key must exist under the target id")
}

// ===================== GetImportParameters type branch coverage =====================

// ===================== ImportKey type-specific branches (with software backend) =====================

// ===================== GetTLSCertificate success path =====================

// ===================== Decrypt with ECDSA key (non-symmetric, non-RSA) =====================

// ===================== CopyKey with non-exportable key =====================

func TestCopyKey_NonExportableKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "copy-noexport",
		Backend: "software",
		KeyType: "ecdsa", Algorithm: "ecdsa",
		Curve: "P256",
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

// ===================== Sign/Verify error paths =====================

// ===================== Encrypt/Decrypt backend errors =====================

// ===================== EncryptAsym error paths =====================

// ===================== WrapKey/UnwrapKey error paths =====================

func TestWrapKey_InvalidPublicKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.WrapKey(context.Background(), &pb.WrapKeyRequest{
		KeyMaterial:       []byte("key-material"),
		WrappingPublicKey: []byte("invalid-public-key"),
		Algorithm:         "RSAES_OAEP_SHA_256",
		Backend:           "software",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "failed to parse wrapping public key")
}

// ===================== ExportKey error paths =====================

// ===================== Seal/Unseal error paths =====================

// ===================== DeriveKey error paths =====================

// ===================== findKeyAttributes error =====================

// ===================== WrapKey success path =====================

// ===================== UnwrapKey success path =====================

// ===================== GetBackendInfo tests =====================

// ===================== DeleteKey backend not found =====================

// ===================== RotateKey backend not found =====================

// ===================== ListKeys backend not found =====================

// ===================== GetKey backend not found =====================

// ===================== No backends available paths =====================

// The certificate RPCs are adapters over the xkms service; without one they
// report Unavailable, as every other service-backed RPC does.

func TestSaveCert_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	certPEM := testCertPEM(t)
	_, err := svc.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "key",
		CertPem: certPEM,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Contains(t, st.Message(), xkms.ErrNotInitialized.Error())
}

func TestGetCert_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	_, err := svc.GetCert(context.Background(), &pb.GetCertRequest{
		KeyId: "key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestDeleteCert_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	_, err := svc.DeleteCert(context.Background(), &pb.DeleteCertRequest{
		KeyId: "key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestListCerts_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	_, err := svc.ListCerts(context.Background(), &pb.ListCertsRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestCertExists_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	_, err := svc.CertExists(context.Background(), &pb.CertExistsRequest{
		KeyId: "key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestSaveCertChain_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	certPEM := testCertPEM(t)
	_, err := svc.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
		KeyId:        "key",
		CertChainPem: []string{certPEM},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestGetCertChain_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	_, err := svc.GetCertChain(context.Background(), &pb.GetCertChainRequest{
		KeyId: "key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestWrapKey_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	// Create a valid RSA public key for the test
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	// The backend is named so the call is rejected for the condition under
	// test — no backends configured — rather than for a missing field. An
	// unresolvable backend is NotFound: the caller named something that does
	// not exist, which is not a server fault.
	_, err = svc.WrapKey(context.Background(), &pb.WrapKeyRequest{
		KeyMaterial:       []byte("data"),
		WrappingPublicKey: pubKeyDER,
		Algorithm:         "RSAES_OAEP_SHA_256",
		Backend:           "software",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestUnwrapKey_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	// The backend is named so the call is rejected for the condition under
	// test — no backends configured — rather than for a missing field. An
	// unresolvable backend is NotFound: the caller named something that does
	// not exist, which is not a server fault.
	_, err = svc.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
		WrappedKey:        []byte("data"),
		Algorithm:         "RSAES_OAEP_SHA_256",
		WrappingPublicKey: pubKeyDER,
		Backend:           "software",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestListBackends_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	resp, err := svc.ListBackends(context.Background(), &pb.ListBackendsRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Count)
}

func TestSeal_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	_, err := svc.Seal(context.Background(), &pb.SealRequest{
		Backend: "software",
		Data:    []byte("data"),
	})
	require.Error(t, err)
}

func TestUnseal_NoBackendsAvailable(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	_, err := svc.Unseal(context.Background(), &pb.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("data"),
	})
	require.Error(t, err)
}

// ===================== Authorization deny tests for barrier shamir methods =====================

// ===================== Authorization deny for barrier PIN methods =====================

func TestAuthzDeny_PINMethods(t *testing.T) {
	setupPINManager(t)
	svc := newDeniedService()
	ctx := deniedCtx()

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

// ===================== Encrypt dispatches on key type =====================

// ===================== Decrypt with symmetric key =====================

// ===================== Decrypt symmetric key - invalid ciphertext =====================

// ===================== ExportKey with non-exportable key =====================

func TestExportKey_NonExportableKey(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "non-export-key",
		Backend: "software",
		KeyType: "ecdsa", Algorithm: "ecdsa",
		Curve: "P256",
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

// ===================== WrapKey failure path =====================

// ===================== Additional service.go error paths =====================

// ===================== ImportKey RSA type branch =====================

// ===================== ImportKey AES-128 and AES-192 branches =====================

// ===================== More error path coverage =====================

// ===================== BarrierStatus with InitializedAt =====================

// ===================== DeriveKeyECDH with ECDSA key (backend supports it) =====================
