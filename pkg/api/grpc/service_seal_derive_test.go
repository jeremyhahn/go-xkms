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

package grpc

import (
	"context"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSeal_KeyNotFoundInBackend(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Seal with key_id pointing to a nonexistent key in a valid backend
	_, err := svc.Seal(context.Background(), &pb.SealRequest{
		Backend: "software",
		Data:    []byte("secret data"),
		KeyId:   "nonexistent-key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestUnseal_KeyNotFoundInBackend(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Unseal with key_id pointing to a nonexistent key
	_, err := svc.Unseal(context.Background(), &pb.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("encrypted"),
		KeyId:      "nonexistent-key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDeriveKeyECDH_KeyNotFoundInBackend(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Try to derive key with a nonexistent key ID
	_, err := svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:         "nonexistent-key",
		Backend:       "software",
		PeerPublicKey: []byte("fake-key"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	// Will be NotFound because the key doesn't exist
	assert.Contains(t, st.Message(), "not found")
}

func TestAttestKey_SoftwareBackendDoesNotSupportAttestation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Generate a key first
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:     "attest-test-key",
		Backend:   "software",
		Algorithm: "ECDSA",
		KeyType:   "signing",
	})
	require.NoError(t, err)

	// Try to attest - software backend doesn't support attestation
	_, err = svc.AttestKey(context.Background(), &pb.AttestKeyRequest{
		Backend: "software",
		KeyId:   "attest-test-key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestListCerts_WithDefaultBackend(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.ListCerts(context.Background(), &pb.ListCertsRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	// Initially no certs
	assert.Equal(t, int32(0), resp.Total)
}

func TestGetImportParameters_BackendDoesNotSupportImportExport(t *testing.T) {
	// Use the server test setup which uses pkcs8 (no import/export support)
	setupXKMSForTest(t)
	defer xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "k",
		Backend:           "test",
		WrappingAlgorithm: "RSA_AES_KEY_WRAP_SHA_256",
		KeyType:           "RSA",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestExportKeyMaterial_BackendDoesNotSupportImportExport(t *testing.T) {
	// Use pkcs8 backend which doesn't support import/export
	setupXKMSForTest(t)
	defer xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{
		KeyId:   "k",
		Backend: "test",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestWrapKeyByID_BackendDoesNotSupportImportExport(t *testing.T) {
	// Use pkcs8 backend
	setupXKMSForTest(t)
	defer xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "k",
		WrappingKeyBackend: "test",
		TargetKeyId:        "k2",
		TargetKeyBackend:   "test",
		Algorithm:          "AES-WRAP",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestUnwrapKeyByID_BackendDoesNotSupportImportExport(t *testing.T) {
	// Use pkcs8 backend
	setupXKMSForTest(t)
	defer xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped"),
		UnwrappingKeyId:      "k",
		UnwrappingKeyBackend: "test",
		Algorithm:            "AES-WRAP",
		TargetKeyId:          "k2",
		TargetKeyBackend:     "test",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestCopyKey_DestBackendNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.CopyKey(context.Background(), &pb.CopyKeyRequest{
		SourceBackend:    "software",
		SourceKeyId:      "k",
		DestBackend:      "nonexistent",
		DestKeyId:        "k2",
		WrappingAlgorithm: "AES-WRAP",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Contains(t, st.Message(), "destination backend not found")
}

func TestImportKey_BackendDoesNotSupportImportExport(t *testing.T) {
	// Use pkcs8 backend
	setupXKMSForTest(t)
	defer xkms.Reset()
	svc := NewService(nil, nil)

	_, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "k",
		Backend:    "test",
		WrappedKey: []byte("key-data"),
		Algorithm:  "AES-WRAP",
		KeyType:    "RSA",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestEncryptAsym_KeyNotFound(t *testing.T) {
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

func TestGetTLSCertificate_KeyNotFound(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{
		KeyId:   "nonexistent",
		Backend: "software",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	// Key not found
	assert.Contains(t, st.Message(), "not found")
}
