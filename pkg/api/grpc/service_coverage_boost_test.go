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

// ===================== WrapKeyByID validation tests =====================

func TestWrapKeyByID_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	tests := []struct {
		name     string
		req      *pb.WrapKeyByIDRequest
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "missing wrapping_key_id",
			req:      &pb.WrapKeyByIDRequest{WrappingKeyBackend: "b", TargetKeyId: "k", TargetKeyBackend: "b", Algorithm: "a"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "wrapping_key_id is required",
		},
		{
			name:     "missing wrapping_key_backend",
			req:      &pb.WrapKeyByIDRequest{WrappingKeyId: "k", TargetKeyId: "k", TargetKeyBackend: "b", Algorithm: "a"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "wrapping_key_backend is required",
		},
		{
			name:     "missing target_key_id",
			req:      &pb.WrapKeyByIDRequest{WrappingKeyId: "k", WrappingKeyBackend: "b", TargetKeyBackend: "b", Algorithm: "a"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "target_key_id is required",
		},
		{
			name:     "missing target_key_backend",
			req:      &pb.WrapKeyByIDRequest{WrappingKeyId: "k", WrappingKeyBackend: "b", TargetKeyId: "k", Algorithm: "a"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "target_key_backend is required",
		},
		{
			name:     "missing algorithm",
			req:      &pb.WrapKeyByIDRequest{WrappingKeyId: "k", WrappingKeyBackend: "b", TargetKeyId: "k", TargetKeyBackend: "b"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "algorithm is required",
		},
		{
			name:     "target backend not found",
			req:      &pb.WrapKeyByIDRequest{WrappingKeyId: "k", WrappingKeyBackend: "b", TargetKeyId: "k", TargetKeyBackend: "nonexistent", Algorithm: "AES-WRAP"},
			wantCode: codes.NotFound,
			wantMsg:  "target key backend not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.WrapKeyByID(context.Background(), tt.req)
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
			assert.Contains(t, st.Message(), tt.wantMsg)
		})
	}
}

// ===================== UnwrapKeyByID validation tests =====================

func TestUnwrapKeyByID_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	tests := []struct {
		name     string
		req      *pb.UnwrapKeyByIDRequest
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "missing wrapped_key",
			req:      &pb.UnwrapKeyByIDRequest{UnwrappingKeyId: "k", UnwrappingKeyBackend: "b", Algorithm: "a", TargetKeyId: "k", TargetKeyBackend: "b"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "wrapped_key is required",
		},
		{
			name:     "missing unwrapping_key_id",
			req:      &pb.UnwrapKeyByIDRequest{WrappedKey: []byte("data"), UnwrappingKeyBackend: "b", Algorithm: "a", TargetKeyId: "k", TargetKeyBackend: "b"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "unwrapping_key_id is required",
		},
		{
			name:     "missing unwrapping_key_backend",
			req:      &pb.UnwrapKeyByIDRequest{WrappedKey: []byte("data"), UnwrappingKeyId: "k", Algorithm: "a", TargetKeyId: "k", TargetKeyBackend: "b"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "unwrapping_key_backend is required",
		},
		{
			name:     "missing algorithm",
			req:      &pb.UnwrapKeyByIDRequest{WrappedKey: []byte("data"), UnwrappingKeyId: "k", UnwrappingKeyBackend: "b", TargetKeyId: "k", TargetKeyBackend: "b"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "algorithm is required",
		},
		{
			name:     "missing target_key_id",
			req:      &pb.UnwrapKeyByIDRequest{WrappedKey: []byte("data"), UnwrappingKeyId: "k", UnwrappingKeyBackend: "b", Algorithm: "a", TargetKeyBackend: "b"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "target_key_id is required",
		},
		{
			name:     "missing target_key_backend",
			req:      &pb.UnwrapKeyByIDRequest{WrappedKey: []byte("data"), UnwrappingKeyId: "k", UnwrappingKeyBackend: "b", Algorithm: "a", TargetKeyId: "k"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "target_key_backend is required",
		},
		{
			name: "unwrapping backend not found",
			req: &pb.UnwrapKeyByIDRequest{
				WrappedKey: []byte("data"), UnwrappingKeyId: "k", UnwrappingKeyBackend: "nonexistent",
				Algorithm: "a", TargetKeyId: "k", TargetKeyBackend: "b",
			},
			wantCode: codes.NotFound,
			wantMsg:  "unwrapping key backend not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.UnwrapKeyByID(context.Background(), tt.req)
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
			assert.Contains(t, st.Message(), tt.wantMsg)
		})
	}
}

// ===================== ImportKey validation tests =====================

func TestImportKey_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	tests := []struct {
		name     string
		req      *pb.ImportKeyRequest
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "missing key_id",
			req:      &pb.ImportKeyRequest{Backend: "b", WrappedKey: []byte("d"), Algorithm: "a", KeyType: "RSA"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "key_id is required",
		},
		{
			name:     "missing backend",
			req:      &pb.ImportKeyRequest{KeyId: "k", WrappedKey: []byte("d"), Algorithm: "a", KeyType: "RSA"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "backend is required",
		},
		{
			name:     "missing wrapped_key",
			req:      &pb.ImportKeyRequest{KeyId: "k", Backend: "b", Algorithm: "a", KeyType: "RSA"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "wrapped_key is required",
		},
		{
			name:     "missing algorithm",
			req:      &pb.ImportKeyRequest{KeyId: "k", Backend: "b", WrappedKey: []byte("d"), KeyType: "RSA"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "algorithm is required",
		},
		{
			name:     "missing key_type",
			req:      &pb.ImportKeyRequest{KeyId: "k", Backend: "b", WrappedKey: []byte("d"), Algorithm: "a"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "key_type is required",
		},
		{
			name:     "backend not found",
			req:      &pb.ImportKeyRequest{KeyId: "k", Backend: "nonexistent", WrappedKey: []byte("d"), Algorithm: "a", KeyType: "RSA"},
			wantCode: codes.NotFound,
			wantMsg:  "backend not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ImportKey(context.Background(), tt.req)
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
			assert.Contains(t, st.Message(), tt.wantMsg)
		})
	}
}

// ===================== ExportKeyMaterial validation tests =====================

func TestExportKeyMaterial_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{Backend: "b"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{KeyId: "k"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := svc.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{KeyId: "k", Backend: "nonexistent"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// ===================== CopyKey validation tests =====================

func TestCopyKey_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	tests := []struct {
		name     string
		req      *pb.CopyKeyRequest
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "missing source_backend",
			req:      &pb.CopyKeyRequest{SourceKeyId: "k", DestBackend: "b", DestKeyId: "k", WrappingAlgorithm: "a"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "source_backend is required",
		},
		{
			name:     "missing source_key_id",
			req:      &pb.CopyKeyRequest{SourceBackend: "b", DestBackend: "b", DestKeyId: "k", WrappingAlgorithm: "a"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "source_key_id is required",
		},
		{
			name:     "missing dest_backend",
			req:      &pb.CopyKeyRequest{SourceBackend: "b", SourceKeyId: "k", DestKeyId: "k", WrappingAlgorithm: "a"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "dest_backend is required",
		},
		{
			name:     "missing dest_key_id",
			req:      &pb.CopyKeyRequest{SourceBackend: "b", SourceKeyId: "k", DestBackend: "b", WrappingAlgorithm: "a"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "dest_key_id is required",
		},
		{
			name:     "missing wrapping_algorithm",
			req:      &pb.CopyKeyRequest{SourceBackend: "b", SourceKeyId: "k", DestBackend: "b", DestKeyId: "k"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "wrapping_algorithm is required",
		},
		{
			name:     "source backend not found",
			req:      &pb.CopyKeyRequest{SourceBackend: "nonexistent", SourceKeyId: "k", DestBackend: "software", DestKeyId: "k", WrappingAlgorithm: "a"},
			wantCode: codes.NotFound,
			wantMsg:  "source backend not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CopyKey(context.Background(), tt.req)
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
			assert.Contains(t, st.Message(), tt.wantMsg)
		})
	}
}

// ===================== AttestKey validation tests =====================

func TestAttestKey_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.AttestKey(context.Background(), &pb.AttestKeyRequest{KeyId: "k"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.AttestKey(context.Background(), &pb.AttestKeyRequest{Backend: "b"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := svc.AttestKey(context.Background(), &pb.AttestKeyRequest{Backend: "nonexistent", KeyId: "k"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("backend does not support attestation", func(t *testing.T) {
		_, err := svc.AttestKey(context.Background(), &pb.AttestKeyRequest{Backend: "software", KeyId: "k"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})
}

// ===================== Seal validation tests =====================

func TestSeal_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.Seal(context.Background(), &pb.SealRequest{Data: []byte("data")})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing data", func(t *testing.T) {
		_, err := svc.Seal(context.Background(), &pb.SealRequest{Backend: "software"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("backend not found for key lookup", func(t *testing.T) {
		_, err := svc.Seal(context.Background(), &pb.SealRequest{
			Backend: "nonexistent", Data: []byte("data"), KeyId: "some-key",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// ===================== Unseal validation tests =====================

func TestUnseal_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.Unseal(context.Background(), &pb.UnsealRequest{Ciphertext: []byte("data")})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing ciphertext", func(t *testing.T) {
		_, err := svc.Unseal(context.Background(), &pb.UnsealRequest{Backend: "software"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := svc.Unseal(context.Background(), &pb.UnsealRequest{
			Backend: "nonexistent", Ciphertext: []byte("data"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// ===================== DeriveKeyECDH validation tests =====================

func TestDeriveKeyECDH_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
			Backend:      "software",
			PeerPublicKey: []byte("key"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing peer_public_key", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
			KeyId:   "k",
			Backend: "software",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
			KeyId:        "k",
			Backend:      "nonexistent",
			PeerPublicKey: []byte("key"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// ===================== Password validation tests =====================

func TestPasswordAdd_InputValidation(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("nil request", func(t *testing.T) {
		_, err := svc.PasswordAdd(context.Background(), nil)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("empty name", func(t *testing.T) {
		_, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{Password: "secret"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("empty password", func(t *testing.T) {
		_, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{Name: "test"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestPasswordGet_InputValidation(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("nil request", func(t *testing.T) {
		_, err := svc.PasswordGet(context.Background(), nil)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("empty id", func(t *testing.T) {
		_, err := svc.PasswordGet(context.Background(), &pb.PasswordGetRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestPasswordUpdate_InputValidation(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("nil request", func(t *testing.T) {
		_, err := svc.PasswordUpdate(context.Background(), nil)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("empty id", func(t *testing.T) {
		_, err := svc.PasswordUpdate(context.Background(), &pb.PasswordUpdateRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestPasswordDelete_InputValidation(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("nil request", func(t *testing.T) {
		_, err := svc.PasswordDelete(context.Background(), nil)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("empty id", func(t *testing.T) {
		_, err := svc.PasswordDelete(context.Background(), &pb.PasswordDeleteRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// ===================== PIV additional validation tests =====================

func TestGetPIVCertificate_FieldValidation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.GetPIVCertificate(context.Background(), &pb.GetPIVCertificateRequest{Slot: "9a"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing slot", func(t *testing.T) {
		_, err := svc.GetPIVCertificate(context.Background(), &pb.GetPIVCertificateRequest{Backend: "software"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestStorePIVCertificate_FieldValidation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.StorePIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{Slot: "9a", Certificate: []byte("cert")})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing slot", func(t *testing.T) {
		_, err := svc.StorePIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{Backend: "software", Certificate: []byte("cert")})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing certificate_data", func(t *testing.T) {
		_, err := svc.StorePIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{Backend: "software", Slot: "9a"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestImportPIVCertificate_FieldValidation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.ImportPIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
			Slot: "9a", Certificate: []byte("cert"), Format: "PEM",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing slot", func(t *testing.T) {
		_, err := svc.ImportPIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
			Backend: "software", Certificate: []byte("cert"), Format: "PEM",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing certificate_data", func(t *testing.T) {
		_, err := svc.ImportPIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
			Backend: "software", Slot: "9a", Format: "PEM",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing format", func(t *testing.T) {
		_, err := svc.ImportPIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
			Backend: "software", Slot: "9a", Certificate: []byte("cert"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// ===================== GetTLSCertificate validation =====================

func TestGetTLSCertificate_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{Backend: "software"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{KeyId: "k"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := svc.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{KeyId: "k", Backend: "nonexistent"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// ===================== GetImportParameters validation =====================

func TestGetImportParameters_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{Backend: "software"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{KeyId: "k"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := svc.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId: "k", Backend: "nonexistent", WrappingAlgorithm: "AES-WRAP", KeyType: "RSA",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// ===================== Cert operations validation =====================

func TestSaveCert_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.SaveCert(context.Background(), &pb.SaveCertRequest{CertPem: "cert"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing cert_pem", func(t *testing.T) {
		_, err := svc.SaveCert(context.Background(), &pb.SaveCertRequest{KeyId: "c"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestGetCert_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.GetCert(context.Background(), &pb.GetCertRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestDeleteCert_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.DeleteCert(context.Background(), &pb.DeleteCertRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestListCerts_Success(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// ListCerts uses the first available backend, should succeed
	resp, err := svc.ListCerts(context.Background(), &pb.ListCertsRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestCertExists_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.CertExists(context.Background(), &pb.CertExistsRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestSaveCertChain_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{CertChainPem: []string{"cert"}})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("empty certs_pem", func(t *testing.T) {
		_, err := svc.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{KeyId: "c"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestGetCertChain_Validation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := svc.GetCertChain(context.Background(), &pb.GetCertChainRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// ===================== Barrier PIN additional tests =====================

