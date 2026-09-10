// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package grpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// grpcImportSymmetric runs the BYOK ceremony over the gRPC service and imports
// 32 bytes of material under keyID with the given exportability choice.
func grpcImportSymmetric(t *testing.T, service *Service, keyID string, exportable *bool, sensitive bool) []byte {
	t.Helper()
	ctx := context.Background()
	material := make([]byte, 32)
	_, err := rand.Read(material)
	require.NoError(t, err)

	params, err := service.GetImportParameters(ctx, &pb.GetImportParametersRequest{
		Backend: "software", KeyId: keyID, WrappingAlgorithm: "RSAES_OAEP_SHA_256", KeyType: "symmetric", KeySize: 256,
	})
	require.NoError(t, err)
	parsed, err := x509.ParsePKIXPublicKey(params.WrappingPublicKey)
	require.NoError(t, err)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, parsed.(*rsa.PublicKey), material, nil)
	require.NoError(t, err)

	resp, err := service.ImportKey(ctx, &pb.ImportKeyRequest{
		KeyId: keyID, Backend: "software", WrappedKey: wrapped, Algorithm: params.Algorithm,
		ImportToken: params.ImportToken, KeyType: "symmetric", KeySize: 256,
		Exportable: exportable, Sensitive: sensitive,
	})
	require.NoError(t, err)
	require.True(t, resp.Success)
	return material
}

// TestImportKeySymmetricNonExportableRefusesMaterialExport proves the gRPC
// import honours exportable=false: the key imports, and ExportKeyMaterial is
// refused as a failed precondition instead of returning the plaintext.
func TestImportKeySymmetricNonExportableRefusesMaterialExport(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer xkms.Reset()
	ctx := context.Background()

	exportable := false
	grpcImportSymmetric(t, service, "grpc-non-exportable", &exportable, false)
	_, err := service.ExportKeyMaterial(ctx, &pb.ExportKeyMaterialRequest{Backend: "software", KeyId: "grpc-non-exportable"})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "got %v", err)

	// A request that says nothing keeps the write-once exportable default.
	material := grpcImportSymmetric(t, service, "grpc-default", nil, false)
	exported, err := service.ExportKeyMaterial(ctx, &pb.ExportKeyMaterialRequest{Backend: "software", KeyId: "grpc-default"})
	require.NoError(t, err)
	assert.Equal(t, material, exported.KeyMaterial)
}

// TestImportKeySymmetricSensitiveRefusesMaterialExport proves the sensitive
// flag reaches the record over gRPC.
func TestImportKeySymmetricSensitiveRefusesMaterialExport(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer xkms.Reset()

	grpcImportSymmetric(t, service, "grpc-sensitive", nil, true)
	_, err := service.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{Backend: "software", KeyId: "grpc-sensitive"})
	require.Error(t, err)
}
