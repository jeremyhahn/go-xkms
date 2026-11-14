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

	svc, err := xkms.Get()
	if err != nil {
		t.Fatalf("Failed to get xkms service: %v", err)
	}
	return NewService(nil, nil, svc)
}

// =============================================================================
// ExportKeyMaterial Tests
// =============================================================================

// =============================================================================
// WrapKeyByID Tests
// =============================================================================

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

// =============================================================================
// UnwrapKeyByID Tests
// =============================================================================

// =============================================================================
// DeriveKeyECDH Tests
// =============================================================================

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
