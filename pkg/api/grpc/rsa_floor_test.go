// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// TestGenerateKey_RSAFloor proves that a gRPC caller asking for an RSA key
// below the 2048-bit floor (go-xkms#1204) is refused by the service layer's
// own validation. GenerateKey now calls XKMSService.GenerateKey directly
// (go-xkms#1214), so this is the service's floor, not a copy kept in this
// transport.
func TestGenerateKey_RSAFloor(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rsa-1024",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 1024,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "2048")
}

// TestImportKey_RSAFloor proves the gRPC import ceremony refuses an
// RSA-1024 import with the same floor GenerateKey enforces. Before
// go-xkms#1214 this path built its key attributes and handed them straight
// to the backend's ImportKey without ever calling
// types.KeyAttributes.Validate.
func TestImportKey_RSAFloor(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "rsa-1024-import",
		Backend:    "software",
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  "RSAES_OAEP_SHA_256",
		KeyType:    "rsa",
		KeySize:    1024,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "2048")
}

// TestGetImportParameters_RSAFloor proves the import-parameter negotiation
// step refuses an RSA-1024 request rather than handing back working
// wrapping parameters for a key ImportKey will refuse anyway.
func TestGetImportParameters_RSAFloor(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "rsa-1024-params",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "rsa",
		KeySize:           1024,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "2048")
}

// TestGenerateKey_UnknownBackendRefusal pins the status code a caller sees
// when GenerateKey is routed, unconverted from #1214's evidence, through the
// service layer for a backend that was never registered.
func TestGenerateKey_UnknownBackendRefusal(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "gen-key",
		Backend: "nonexistent",
		KeyType: "rsa", Algorithm: "rsa",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}
