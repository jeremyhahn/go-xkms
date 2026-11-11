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

// ===================== UnwrapKeyByID validation tests =====================

// ===================== ImportKey validation tests =====================

// ===================== ExportKeyMaterial validation tests =====================

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
			wantMsg:  "source backend: " + xkms.ErrBackendNotFound.Error(),
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

// ===================== Seal validation tests =====================

// ===================== Unseal validation tests =====================

// ===================== DeriveKeyECDH validation tests =====================

// ===================== Password validation tests =====================

// ===================== PIV additional validation tests =====================

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

// ===================== Cert operations validation =====================

// ===================== Barrier PIN additional tests =====================
