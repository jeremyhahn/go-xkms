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
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Test Setup
// =============================================================================

func setupExportWrapTest(t *testing.T) *Service {
	t.Helper()
	xkms.Reset()

	keyStorage := storage.New()
	certStorage := storage.New()

	backend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     backend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	config := &xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	}
	if err := xkms.Initialize(config); err != nil {
		t.Fatalf("Failed to initialize xkms: %v", err)
	}
	t.Cleanup(xkms.Reset)

	return NewService(nil, nil)
}

// =============================================================================
// ExportKeyMaterial Tests
// =============================================================================

func TestService_ExportKeyMaterial_MissingKeyID(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{
		Backend: "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "key_id is required" {
		t.Errorf("Expected message 'key_id is required', got %q", st.Message())
	}
}

func TestService_ExportKeyMaterial_MissingBackend(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{
		KeyId: "test-key",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "backend is required" {
		t.Errorf("Expected message 'backend is required', got %q", st.Message())
	}
}

func TestService_ExportKeyMaterial_BackendNotFound(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{
		KeyId:   "test-key",
		Backend: "nonexistent",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got: %v", st.Code())
	}
}

func TestService_ExportKeyMaterial_KeyNotFound(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{
		KeyId:   "nonexistent-key",
		Backend: "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got: %v", st.Code())
	}
}

// =============================================================================
// WrapKeyByID Tests
// =============================================================================

func TestService_WrapKeyByID_MissingWrappingKeyID(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyBackend: "software",
		TargetKeyId:        "target-key",
		TargetKeyBackend:   "software",
		Algorithm:          "AES-256-GCM",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "wrapping_key_id is required" {
		t.Errorf("Expected message 'wrapping_key_id is required', got %q", st.Message())
	}
}

func TestService_WrapKeyByID_MissingWrappingKeyBackend(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:    "wrapper-key",
		TargetKeyId:      "target-key",
		TargetKeyBackend: "software",
		Algorithm:        "AES-256-GCM",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "wrapping_key_backend is required" {
		t.Errorf("Expected message 'wrapping_key_backend is required', got %q", st.Message())
	}
}

func TestService_WrapKeyByID_MissingTargetKeyID(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "wrapper-key",
		WrappingKeyBackend: "software",
		TargetKeyBackend:   "software",
		Algorithm:          "AES-256-GCM",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "target_key_id is required" {
		t.Errorf("Expected message 'target_key_id is required', got %q", st.Message())
	}
}

func TestService_WrapKeyByID_MissingTargetKeyBackend(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "wrapper-key",
		WrappingKeyBackend: "software",
		TargetKeyId:        "target-key",
		Algorithm:          "AES-256-GCM",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "target_key_backend is required" {
		t.Errorf("Expected message 'target_key_backend is required', got %q", st.Message())
	}
}

func TestService_WrapKeyByID_MissingAlgorithm(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "wrapper-key",
		WrappingKeyBackend: "software",
		TargetKeyId:        "target-key",
		TargetKeyBackend:   "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "algorithm is required" {
		t.Errorf("Expected message 'algorithm is required', got %q", st.Message())
	}
}

func TestService_WrapKeyByID_TargetBackendNotFound(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "wrapper-key",
		WrappingKeyBackend: "software",
		TargetKeyId:        "target-key",
		TargetKeyBackend:   "nonexistent",
		Algorithm:          "AES-256-GCM",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got: %v", st.Code())
	}
}

func TestService_WrapKeyByID_TargetKeyNotFound(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "wrapper-key",
		WrappingKeyBackend: "software",
		TargetKeyId:        "nonexistent-target",
		TargetKeyBackend:   "software",
		Algorithm:          "AES-256-GCM",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got: %v", st.Code())
	}
}

// =============================================================================
// UnwrapKeyByID Tests
// =============================================================================

func TestService_UnwrapKeyByID_MissingWrappedKey(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		UnwrappingKeyId:      "unwrapper-key",
		UnwrappingKeyBackend: "software",
		Algorithm:            "AES-256-GCM",
		TargetKeyId:          "new-key",
		TargetKeyBackend:     "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "wrapped_key is required" {
		t.Errorf("Expected message 'wrapped_key is required', got %q", st.Message())
	}
}

func TestService_UnwrapKeyByID_MissingUnwrappingKeyID(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-key-data"),
		UnwrappingKeyBackend: "software",
		Algorithm:            "AES-256-GCM",
		TargetKeyId:          "new-key",
		TargetKeyBackend:     "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "unwrapping_key_id is required" {
		t.Errorf("Expected message 'unwrapping_key_id is required', got %q", st.Message())
	}
}

func TestService_UnwrapKeyByID_MissingUnwrappingKeyBackend(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:       []byte("wrapped-key-data"),
		UnwrappingKeyId:  "unwrapper-key",
		Algorithm:        "AES-256-GCM",
		TargetKeyId:      "new-key",
		TargetKeyBackend: "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "unwrapping_key_backend is required" {
		t.Errorf("Expected message 'unwrapping_key_backend is required', got %q", st.Message())
	}
}

func TestService_UnwrapKeyByID_MissingAlgorithm(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-key-data"),
		UnwrappingKeyId:      "unwrapper-key",
		UnwrappingKeyBackend: "software",
		TargetKeyId:          "new-key",
		TargetKeyBackend:     "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "algorithm is required" {
		t.Errorf("Expected message 'algorithm is required', got %q", st.Message())
	}
}

func TestService_UnwrapKeyByID_MissingTargetKeyID(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-key-data"),
		UnwrappingKeyId:      "unwrapper-key",
		UnwrappingKeyBackend: "software",
		Algorithm:            "AES-256-GCM",
		TargetKeyBackend:     "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "target_key_id is required" {
		t.Errorf("Expected message 'target_key_id is required', got %q", st.Message())
	}
}

func TestService_UnwrapKeyByID_MissingTargetKeyBackend(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-key-data"),
		UnwrappingKeyId:      "unwrapper-key",
		UnwrappingKeyBackend: "software",
		Algorithm:            "AES-256-GCM",
		TargetKeyId:          "new-key",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "target_key_backend is required" {
		t.Errorf("Expected message 'target_key_backend is required', got %q", st.Message())
	}
}

func TestService_UnwrapKeyByID_UnwrappingBackendNotFound(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-key-data"),
		UnwrappingKeyId:      "unwrapper-key",
		UnwrappingKeyBackend: "nonexistent",
		Algorithm:            "AES-256-GCM",
		TargetKeyId:          "new-key",
		TargetKeyBackend:     "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got: %v", st.Code())
	}
}

func TestService_UnwrapKeyByID_UnwrappingKeyNotFound(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-key-data"),
		UnwrappingKeyId:      "nonexistent-unwrapper",
		UnwrappingKeyBackend: "software",
		Algorithm:            "AES-256-GCM",
		TargetKeyId:          "new-key",
		TargetKeyBackend:     "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got: %v", st.Code())
	}
}

// =============================================================================
// DeriveKeyECDH Tests
// =============================================================================

func TestService_DeriveKeyECDH_MissingKeyID(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		Backend:       "software",
		PeerPublicKey: []byte("peer-public-key"),
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "key_id is required" {
		t.Errorf("Expected message 'key_id is required', got %q", st.Message())
	}
}

func TestService_DeriveKeyECDH_MissingBackend(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:         "ecdsa-key",
		PeerPublicKey: []byte("peer-public-key"),
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "backend is required" {
		t.Errorf("Expected message 'backend is required', got %q", st.Message())
	}
}

func TestService_DeriveKeyECDH_MissingPeerPublicKey(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:   "ecdsa-key",
		Backend: "software",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", st.Code())
	}
	if st.Message() != "peer_public_key is required" {
		t.Errorf("Expected message 'peer_public_key is required', got %q", st.Message())
	}
}

func TestService_DeriveKeyECDH_BackendNotFound(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:         "ecdsa-key",
		Backend:       "nonexistent",
		PeerPublicKey: []byte("peer-public-key"),
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got: %v", st.Code())
	}
}

func TestService_DeriveKeyECDH_KeyNotFound(t *testing.T) {
	service := setupExportWrapTest(t)

	_, err := service.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:         "nonexistent-key",
		Backend:       "software",
		PeerPublicKey: []byte("peer-public-key"),
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got: %v", st.Code())
	}
}
