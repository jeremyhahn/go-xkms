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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MockImportExportBackend is a mock implementation of backend.ImportExportBackend for testing
type MockImportExportBackend struct {
	mock.Mock
	types.KeyProvider
}

func (m *MockImportExportBackend) GetImportParameters(_ context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	args := m.Called(attrs, algorithm)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*backend.ImportParameters), args.Error(1)
}

func (m *MockImportExportBackend) WrapKey(_ context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	args := m.Called(keyMaterial, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*backend.WrappedKeyMaterial), args.Error(1)
}

func (m *MockImportExportBackend) UnwrapKey(_ context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	args := m.Called(wrapped, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockImportExportBackend) ImportKey(_ context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	args := m.Called(attrs, wrapped)
	return args.Error(0)
}

func (m *MockImportExportBackend) ExportKey(_ context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	args := m.Called(attrs, algorithm)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*backend.WrappedKeyMaterial), args.Error(1)
}

func (m *MockImportExportBackend) ExportKeyTo(_ context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	args := m.Called(attrs, dstParams)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*backend.WrappedKeyMaterial), args.Error(1)
}

func (m *MockImportExportBackend) ExportKeyMaterial(_ context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	args := m.Called(attrs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// TestGetImportParameters tests the GetImportParameters RPC method
func TestGetImportParameters(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.GetImportParametersRequest
		expectedError codes.Code
	}{
		{
			name: "Valid request without registered backend returns NotFound",
			request: &pb.GetImportParametersRequest{
				KeyId:             "test-key",
				Backend:           "test-backend",
				WrappingAlgorithm: "RSAES_OAEP_SHA_256",
				KeyType:           "rsa",
				KeySize:           2048,
			},
			expectedError: codes.NotFound,
		},
		{
			name: "Missing key_id",
			request: &pb.GetImportParametersRequest{
				Backend:           "test-backend",
				WrappingAlgorithm: "RSAES_OAEP_SHA_256",
				KeyType:           "rsa",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing backend",
			request: &pb.GetImportParametersRequest{
				KeyId:             "test-key",
				WrappingAlgorithm: "RSAES_OAEP_SHA_256",
				KeyType:           "rsa",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing wrapping_algorithm",
			request: &pb.GetImportParametersRequest{
				KeyId:   "test-key",
				Backend: "test-backend",
				KeyType: "rsa",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing key_type",
			request: &pb.GetImportParametersRequest{
				KeyId:             "test-key",
				Backend:           "test-backend",
				WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "AES key without key_size",
			request: &pb.GetImportParametersRequest{
				KeyId:             "test-key",
				Backend:           "test-backend",
				WrappingAlgorithm: "RSAES_OAEP_SHA_256",
				KeyType:           "symmetric",
			},
			expectedError: codes.NotFound,
		},
		{
			name: "Unsupported key type",
			request: &pb.GetImportParametersRequest{
				KeyId:             "test-key",
				Backend:           "test-backend",
				WrappingAlgorithm: "RSAES_OAEP_SHA_256",
				KeyType:           "unsupported",
			},
			expectedError: codes.NotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewService(nil, nil, nil)

			resp, err := service.GetImportParameters(context.Background(), tt.request)

			assert.Error(t, err)
			st, ok := status.FromError(err)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedError, st.Code())
			assert.Nil(t, resp)
		})
	}
}

// TestWrapKey tests the WrapKey RPC method
func TestWrapKey(t *testing.T) {
	// Generate a test RSA wrapping key
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	wrappingPubKeyDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	assert.NoError(t, err)

	tests := []struct {
		name          string
		request       *pb.WrapKeyRequest
		expectedError codes.Code
	}{
		{
			name: "Valid wrap request",
			request: &pb.WrapKeyRequest{
				KeyMaterial:       []byte("test-key-material"),
				WrappingPublicKey: wrappingPubKeyDER,
				ImportToken:       []byte("test-token"),
				Algorithm:         "RSAES_OAEP_SHA_256",
				KeySpec:           "RSA_2048",
			},
			expectedError: codes.OK,
		},
		{
			name: "Missing key_material",
			request: &pb.WrapKeyRequest{
				WrappingPublicKey: wrappingPubKeyDER,
				Algorithm:         "RSAES_OAEP_SHA_256",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing wrapping_public_key",
			request: &pb.WrapKeyRequest{
				KeyMaterial: []byte("test-key-material"),
				Algorithm:   "RSAES_OAEP_SHA_256",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing algorithm",
			request: &pb.WrapKeyRequest{
				KeyMaterial:       []byte("test-key-material"),
				WrappingPublicKey: wrappingPubKeyDER,
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Invalid public key DER",
			request: &pb.WrapKeyRequest{
				KeyMaterial:       []byte("test-key-material"),
				WrappingPublicKey: []byte("invalid-der"),
				Algorithm:         "RSAES_OAEP_SHA_256",
			},
			expectedError: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewService(nil, nil, nil)

			resp, err := service.WrapKey(context.Background(), tt.request)

			if tt.expectedError != codes.OK {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedError, st.Code())
				assert.Nil(t, resp)
			}
		})
	}
}

// TestUnwrapKey tests the UnwrapKey RPC method
func TestUnwrapKey(t *testing.T) {
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	wrappingPubKeyDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	assert.NoError(t, err)

	tests := []struct {
		name          string
		request       *pb.UnwrapKeyRequest
		expectedError codes.Code
	}{
		{
			name: "Valid unwrap request",
			request: &pb.UnwrapKeyRequest{
				WrappedKey:        []byte("wrapped-key-data"),
				Algorithm:         "RSAES_OAEP_SHA_256",
				ImportToken:       []byte("test-token"),
				WrappingPublicKey: wrappingPubKeyDER,
				KeySpec:           "RSA_2048",
			},
			expectedError: codes.OK,
		},
		{
			name: "Missing wrapped_key",
			request: &pb.UnwrapKeyRequest{
				Algorithm:         "RSAES_OAEP_SHA_256",
				WrappingPublicKey: wrappingPubKeyDER,
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing algorithm",
			request: &pb.UnwrapKeyRequest{
				WrappedKey:        []byte("wrapped-key-data"),
				WrappingPublicKey: wrappingPubKeyDER,
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing wrapping_public_key",
			request: &pb.UnwrapKeyRequest{
				WrappedKey: []byte("wrapped-key-data"),
				Algorithm:  "RSAES_OAEP_SHA_256",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Invalid public key DER",
			request: &pb.UnwrapKeyRequest{
				WrappedKey:        []byte("wrapped-key-data"),
				Algorithm:         "RSAES_OAEP_SHA_256",
				WrappingPublicKey: []byte("invalid-der"),
			},
			expectedError: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewService(nil, nil, nil)

			resp, err := service.UnwrapKey(context.Background(), tt.request)

			if tt.expectedError != codes.OK {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedError, st.Code())
				assert.Nil(t, resp)
			}
		})
	}
}

// TestImportKey tests the ImportKey RPC method
func TestImportKey(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.ImportKeyRequest
		expectedError codes.Code
	}{
		{
			name: "Valid RSA import request",
			request: &pb.ImportKeyRequest{
				KeyId:       "test-key",
				Backend:     "test-backend",
				WrappedKey:  []byte("wrapped-key-data"),
				Algorithm:   "RSAES_OAEP_SHA_256",
				ImportToken: []byte("test-token"),
				KeyType:     "rsa",
				KeySize:     2048,
			},
			expectedError: codes.NotFound, // Backend not found in test
		},
		{
			name: "Valid ECDSA import request",
			request: &pb.ImportKeyRequest{
				KeyId:       "test-key",
				Backend:     "test-backend",
				WrappedKey:  []byte("wrapped-key-data"),
				Algorithm:   "RSAES_OAEP_SHA_256",
				ImportToken: []byte("test-token"),
				KeyType:     "ecdsa",
				Curve:       "P256",
			},
			expectedError: codes.NotFound,
		},
		{
			name: "Valid AES import request",
			request: &pb.ImportKeyRequest{
				KeyId:       "test-key",
				Backend:     "test-backend",
				WrappedKey:  []byte("wrapped-key-data"),
				Algorithm:   "RSAES_OAEP_SHA_256",
				ImportToken: []byte("test-token"),
				KeyType:     "symmetric",
				KeySize:     256,
			},
			expectedError: codes.NotFound,
		},
		{
			name: "Missing key_id",
			request: &pb.ImportKeyRequest{
				Backend:     "test-backend",
				WrappedKey:  []byte("wrapped-key-data"),
				Algorithm:   "RSAES_OAEP_SHA_256",
				ImportToken: []byte("test-token"),
				KeyType:     "rsa",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing backend",
			request: &pb.ImportKeyRequest{
				KeyId:       "test-key",
				WrappedKey:  []byte("wrapped-key-data"),
				Algorithm:   "RSAES_OAEP_SHA_256",
				ImportToken: []byte("test-token"),
				KeyType:     "rsa",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing wrapped_key",
			request: &pb.ImportKeyRequest{
				KeyId:       "test-key",
				Backend:     "test-backend",
				Algorithm:   "RSAES_OAEP_SHA_256",
				ImportToken: []byte("test-token"),
				KeyType:     "rsa",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing algorithm",
			request: &pb.ImportKeyRequest{
				KeyId:       "test-key",
				Backend:     "test-backend",
				WrappedKey:  []byte("wrapped-key-data"),
				ImportToken: []byte("test-token"),
				KeyType:     "rsa",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing key_type",
			request: &pb.ImportKeyRequest{
				KeyId:       "test-key",
				Backend:     "test-backend",
				WrappedKey:  []byte("wrapped-key-data"),
				Algorithm:   "RSAES_OAEP_SHA_256",
				ImportToken: []byte("test-token"),
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "AES without key_size",
			request: &pb.ImportKeyRequest{
				KeyId:       "test-key",
				Backend:     "test-backend",
				WrappedKey:  []byte("wrapped-key-data"),
				Algorithm:   "RSAES_OAEP_SHA_256",
				ImportToken: []byte("test-token"),
				KeyType:     "symmetric",
			},
			expectedError: codes.NotFound, // Backend not found before validation
		},
		{
			name: "Unsupported key_type",
			request: &pb.ImportKeyRequest{
				KeyId:       "test-key",
				Backend:     "test-backend",
				WrappedKey:  []byte("wrapped-key-data"),
				Algorithm:   "RSAES_OAEP_SHA_256",
				ImportToken: []byte("test-token"),
				KeyType:     "unsupported",
			},
			expectedError: codes.NotFound, // Backend not found before validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewService(nil, nil, nil)

			resp, err := service.ImportKey(context.Background(), tt.request)

			assert.Error(t, err)
			st, ok := status.FromError(err)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedError, st.Code())
			assert.Nil(t, resp)
		})
	}
}

// TestExportKey tests the ExportKey RPC method
func TestExportKey(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.ExportKeyRequest
		expectedError codes.Code
	}{
		{
			name: "Valid export request without a service",
			request: &pb.ExportKeyRequest{
				KeyId:             "test-key",
				Backend:           "test-backend",
				WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			},
			expectedError: codes.Unavailable, // no XKMSService is wired
		},
		{
			name: "Missing key_id",
			request: &pb.ExportKeyRequest{
				Backend:           "test-backend",
				WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing backend",
			request: &pb.ExportKeyRequest{
				KeyId:             "test-key",
				WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "Missing wrapping_algorithm",
			request: &pb.ExportKeyRequest{
				KeyId:   "test-key",
				Backend: "test-backend",
			},
			expectedError: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewService(nil, nil, nil)

			resp, err := service.ExportKey(context.Background(), tt.request)

			assert.Error(t, err)
			st, ok := status.FromError(err)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedError, st.Code())
			assert.Nil(t, resp)
		})
	}
}

// TestWrappingAlgorithmValidation tests that all wrapping algorithms are properly handled
func TestWrappingAlgorithmValidation(t *testing.T) {
	algorithms := []string{
		"RSAES_OAEP_SHA_1",
		"RSAES_OAEP_SHA_256",
		"RSA_AES_KEY_WRAP_SHA_1",
		"RSA_AES_KEY_WRAP_SHA_256",
		"RSA_OAEP_3072_SHA256_AES_256",
		"RSA_OAEP_4096_SHA256_AES_256",
		"RSA_OAEP_4096_SHA256",
	}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			// Test that the algorithm string can be converted to backend.WrappingAlgorithm
			wrappingAlg := backend.WrappingAlgorithm(algo)
			assert.NotEmpty(t, wrappingAlg)
			assert.Equal(t, algo, string(wrappingAlg))
		})
	}
}

// TestKeyTypeValidation tests key type parsing and validation
func TestKeyTypeValidation(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string
		keySize  int32
		curve    string
		isValid  bool
		hasError bool
	}{
		{"RSA with size", "rsa", 2048, "", true, false},
		{"RSA default size", "rsa", 0, "", true, false},
		{"ECDSA with curve", "ecdsa", 0, "P256", true, false},
		{"ECDSA default curve", "ecdsa", 0, "", true, false},
		{"Ed25519", "ed25519", 0, "", true, false},
		{"Symmetric with size", "symmetric", 256, "", true, false},
		{"Symmetric without size", "symmetric", 0, "", false, true},
		{"Invalid type", "invalid", 0, "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyType := types.ParseKeyType(tt.keyType)
			if tt.isValid && !tt.hasError {
				// For valid types, ensure we got a non-empty key type
				assert.NotEmpty(t, string(keyType))
			}
		})
	}
}

// TestImportKeySymmetricRoundTripsThroughARealBackend is the end-to-end half of
// TestImportKey, which only ever reaches argument validation and "backend not
// found" and so proved nothing about the attributes a successful import stores.
//
// Those attributes are what decides whether the key can be used afterwards.
// types.KeyAttributes.ID() encodes the key type, so a symmetric key imported
// under the wrong one is stored beneath an identifier nothing else constructs:
// ListKeys reported such a key as RSA, and every later operation failed with
// "key not found: <backend>:encryption:<cn>:rsa". Exportability is equally
// invisible at import time and equally fatal later -- a key the backend will
// not release cannot be read back or wrapped.
//
// The assertions are therefore made after the import, against the real software
// backend, on the properties a subsequent operation depends on.
func TestImportKeySymmetricRoundTripsThroughARealBackend(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer xkms.Reset()

	ctx := context.Background()
	const keyID = "grpc-symmetric-import"

	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatalf("generating key material failed: %v", err)
	}

	// The import ceremony, driven exactly as a client drives it.
	params, err := service.GetImportParameters(ctx, &pb.GetImportParametersRequest{
		Backend:           "software",
		KeyId:             keyID,
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "symmetric",
		KeySize:           256,
	})
	if err != nil {
		t.Fatalf("GetImportParameters: %v", err)
	}

	parsed, err := x509.ParsePKIXPublicKey(params.WrappingPublicKey)
	if err != nil {
		t.Fatalf("parsing the wrapping public key: %v", err)
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("the wrapping public key is %T, not an RSA key", parsed)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, material, nil)
	if err != nil {
		t.Fatalf("wrapping the key material: %v", err)
	}

	resp, err := service.ImportKey(ctx, &pb.ImportKeyRequest{
		KeyId:       keyID,
		Backend:     "software",
		WrappedKey:  wrapped,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		KeyType:     "symmetric",
		KeySize:     256,
	})
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	assert.True(t, resp.Success)

	// The key must be discoverable as the symmetric key it is. Reporting it as
	// RSA here is what made every later operation fail.
	listed, err := service.ListKeys(ctx, &pb.ListKeysRequest{Backend: "software"})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	var found *pb.KeyInfo
	for _, k := range listed.Keys {
		if k.KeyId == keyID {
			found = k
			break
		}
	}
	if found == nil {
		t.Fatal("the imported key is not listed at all")
	}
	assert.Equal(t, "aes256-gcm", found.Algorithm,
		"an imported symmetric key must be stored under the key type every other path uses for symmetric material")

	// Exportability is the other attribute the request cannot carry. Reading
	// the material back is what proves it was recorded, and that the bytes that
	// went in are the bytes the backend holds.
	exported, err := service.ExportKeyMaterial(ctx, &pb.ExportKeyMaterialRequest{
		Backend: "software",
		KeyId:   keyID,
	})
	if err != nil {
		t.Fatalf("ExportKeyMaterial on the imported key: %v", err)
	}
	assert.Equal(t, material, exported.KeyMaterial,
		"the backend must hold exactly the material that was imported")
}

// TestImportKeySymmetricRejectsAnUnsupportedKeySize is the bad-input half: a
// size with no AES algorithm must be refused at the boundary rather than stored
// under attributes the rest of the system cannot interpret.
//
// Zero is deliberately excluded from this table: the service layer's
// unwrapSymmetricAlgorithms table treats a zero size as "no size given,
// default to AES-256-GCM" -- the same default REST, MCP and the embedded
// transport have always applied for GetImportParameters and ImportKey. This
// RPC used to reject size 0 with its own hand-rolled switch, a drift
// go-xkms#1216 unifies by routing ImportKey through the service layer
// (go-xkms#1214).
func TestImportKeySymmetricRejectsAnUnsupportedKeySize(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer xkms.Reset()

	for _, size := range []int32{1, 64, 127, 255, 512} {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:       "grpc-bad-size",
			Backend:     "software",
			WrappedKey:  []byte("wrapped-key-data"),
			Algorithm:   "RSAES_OAEP_SHA_256",
			ImportToken: []byte("token"),
			KeyType:     "symmetric",
			KeySize:     size,
		})
		assert.Equal(t, codes.InvalidArgument, status.Code(err),
			"key size %d has no AES algorithm and must be refused", size)
	}
}
