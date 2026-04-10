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
	"errors"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivfile "github.com/jeremyhahn/go-xkms/pkg/pivcert/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setupPIVTest initializes the PIV manager with a memory-backed file store
// and returns a cleanup function.
func setupPIVTest(t *testing.T) func() {
	t.Helper()

	xkms.ResetPIV()

	memBackend := storage.NewMemory()
	store, err := pivfile.NewFileBackend(&pivcert.FileStorageConfig{
		Backend:    memBackend,
		DEREnabled: true,
		PEMEnabled: true,
	})
	if err != nil {
		t.Fatalf("failed to create PIV file backend: %v", err)
	}

	err = xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	if err != nil {
		t.Fatalf("failed to initialize PIV: %v", err)
	}

	return func() {
		xkms.ResetPIV()
	}
}

func TestListPIVSlots_Success(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()

	svc := NewService(nil, nil)
	resp, err := svc.ListPIVSlots(context.Background(), &pb.ListPIVSlotsRequest{
		Backend: "software",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Slots) == 0 {
		t.Fatal("expected at least one slot in response")
	}
}

func TestListPIVSlots_MissingBackend(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.ListPIVSlots(context.Background(), &pb.ListPIVSlotsRequest{
		Backend: "",
	})
	if err == nil {
		t.Fatal("expected error for missing backend")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestListPIVSlots_BackendNotFound(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()

	svc := NewService(nil, nil)
	_, err := svc.ListPIVSlots(context.Background(), &pb.ListPIVSlotsRequest{
		Backend: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent backend")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Fatalf("expected NotFound, got: %v", st.Code())
	}
}

func TestGetPIVCertificate_MissingBackend(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.GetPIVCertificate(context.Background(), &pb.GetPIVCertificateRequest{
		Backend: "",
		Slot:    "9a",
		Format:  "pem",
	})
	if err == nil {
		t.Fatal("expected error for missing backend")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestGetPIVCertificate_MissingSlot(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.GetPIVCertificate(context.Background(), &pb.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "",
		Format:  "pem",
	})
	if err == nil {
		t.Fatal("expected error for missing slot")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestGetPIVCertificate_MissingFormat(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.GetPIVCertificate(context.Background(), &pb.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		Format:  "",
	})
	if err == nil {
		t.Fatal("expected error for missing format")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestStorePIVCertificate_MissingBackend(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.StorePIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
		Backend:     "",
		Slot:        "9a",
		Format:      "pem",
		Certificate: []byte("cert-data"),
	})
	if err == nil {
		t.Fatal("expected error for missing backend")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestStorePIVCertificate_MissingSlot(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.StorePIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
		Backend:     "software",
		Slot:        "",
		Format:      "pem",
		Certificate: []byte("cert-data"),
	})
	if err == nil {
		t.Fatal("expected error for missing slot")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestStorePIVCertificate_MissingFormat(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.StorePIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
		Backend:     "software",
		Slot:        "9a",
		Format:      "",
		Certificate: []byte("cert-data"),
	})
	if err == nil {
		t.Fatal("expected error for missing format")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestStorePIVCertificate_MissingCertificate(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.StorePIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
		Backend:     "software",
		Slot:        "9a",
		Format:      "pem",
		Certificate: nil,
	})
	if err == nil {
		t.Fatal("expected error for missing certificate")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestDeletePIVCertificate_MissingBackend(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.DeletePIVCertificate(context.Background(), &pb.DeletePIVCertificateRequest{
		Backend: "",
		Slot:    "9a",
	})
	if err == nil {
		t.Fatal("expected error for missing backend")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestDeletePIVCertificate_MissingSlot(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.DeletePIVCertificate(context.Background(), &pb.DeletePIVCertificateRequest{
		Backend: "software",
		Slot:    "",
	})
	if err == nil {
		t.Fatal("expected error for missing slot")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestGeneratePIVKey_Success(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()

	svc := NewService(nil, nil)
	resp, err := svc.GeneratePIVKey(context.Background(), &pb.GeneratePIVKeyRequest{
		Backend: "software",
		Slot:    "9a",
		Subject: "Test Key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Slot != "9a" {
		t.Fatalf("expected slot 9a, got: %s", resp.Slot)
	}
	if len(resp.Certificate) == 0 {
		t.Fatal("expected non-empty certificate")
	}
	if len(resp.PublicKey) == 0 {
		t.Fatal("expected non-empty public key")
	}
}

func TestGeneratePIVKey_MissingBackend(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.GeneratePIVKey(context.Background(), &pb.GeneratePIVKeyRequest{
		Backend: "",
		Slot:    "9a",
	})
	if err == nil {
		t.Fatal("expected error for missing backend")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestGeneratePIVKey_MissingSlot(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.GeneratePIVKey(context.Background(), &pb.GeneratePIVKeyRequest{
		Backend: "software",
		Slot:    "",
	})
	if err == nil {
		t.Fatal("expected error for missing slot")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestGeneratePIVKey_InvalidSlot(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()

	svc := NewService(nil, nil)
	_, err := svc.GeneratePIVKey(context.Background(), &pb.GeneratePIVKeyRequest{
		Backend: "software",
		Slot:    "invalid-slot",
	})
	if err == nil {
		t.Fatal("expected error for invalid slot")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestImportPIVCertificate_MissingBackend(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.ImportPIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
		Backend:     "",
		Slot:        "9a",
		Format:      "pem",
		Certificate: []byte("cert-data"),
	})
	if err == nil {
		t.Fatal("expected error for missing backend")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestImportPIVCertificate_MissingSlot(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.ImportPIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
		Backend:     "software",
		Slot:        "",
		Format:      "pem",
		Certificate: []byte("cert-data"),
	})
	if err == nil {
		t.Fatal("expected error for missing slot")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestImportPIVCertificate_MissingFormat(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.ImportPIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
		Backend:     "software",
		Slot:        "9a",
		Format:      "",
		Certificate: []byte("cert-data"),
	})
	if err == nil {
		t.Fatal("expected error for missing format")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestImportPIVCertificate_MissingCertificate(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.ImportPIVCertificate(context.Background(), &pb.StorePIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		Format:  "pem",
	})
	if err == nil {
		t.Fatal("expected error for missing certificate data")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestExportPIVCertificate_MissingBackend(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.ExportPIVCertificate(context.Background(), &pb.GetPIVCertificateRequest{
		Backend: "",
		Slot:    "9a",
		Format:  "pem",
	})
	if err == nil {
		t.Fatal("expected error for missing backend")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestExportPIVCertificate_MissingSlot(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.ExportPIVCertificate(context.Background(), &pb.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "",
		Format:  "pem",
	})
	if err == nil {
		t.Fatal("expected error for missing slot")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestExportPIVCertificate_MissingFormat(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.ExportPIVCertificate(context.Background(), &pb.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		Format:  "",
	})
	if err == nil {
		t.Fatal("expected error for missing format")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestGeneratePIVCSR_Success(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()

	svc := NewService(nil, nil)

	// A key must exist in the slot before a CSR can be generated.
	_, err := svc.GeneratePIVKey(context.Background(), &pb.GeneratePIVKeyRequest{
		Backend: "software",
		Slot:    "9a",
		Subject: "CSR Key",
	})
	if err != nil {
		t.Fatalf("GeneratePIVKey prerequisite failed: %v", err)
	}

	resp, err := svc.GeneratePIVCSR(context.Background(), &pb.GeneratePIVCSRRequest{
		Backend: "software",
		Slot:    "9a",
		Subject: "Test CSR Subject",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Slot != "9a" {
		t.Fatalf("expected slot 9a, got: %s", resp.Slot)
	}
	if len(resp.Csr) == 0 {
		t.Fatal("expected non-empty CSR")
	}
}

func TestGeneratePIVCSR_MissingBackend(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.GeneratePIVCSR(context.Background(), &pb.GeneratePIVCSRRequest{
		Backend: "",
		Slot:    "9a",
	})
	if err == nil {
		t.Fatal("expected error for missing backend")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestGeneratePIVCSR_MissingSlot(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.GeneratePIVCSR(context.Background(), &pb.GeneratePIVCSRRequest{
		Backend: "software",
		Slot:    "",
	})
	if err == nil {
		t.Fatal("expected error for missing slot")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got: %v", st.Code())
	}
}

func TestGeneratePIVCSR_BackendNotFound(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()

	svc := NewService(nil, nil)
	_, err := svc.GeneratePIVCSR(context.Background(), &pb.GeneratePIVCSRRequest{
		Backend: "nonexistent",
		Slot:    "9a",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent backend")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Fatalf("expected NotFound, got: %v", st.Code())
	}
}

func TestGeneratePIVKey_GenerateAndExport(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()

	svc := NewService(nil, nil)

	// Generate a key in slot 9a
	genResp, err := svc.GeneratePIVKey(context.Background(), &pb.GeneratePIVKeyRequest{
		Backend: "software",
		Slot:    "9a",
		Subject: "Integration Test Key",
	})
	if err != nil {
		t.Fatalf("GeneratePIVKey failed: %v", err)
	}
	if genResp.Slot != "9a" {
		t.Fatalf("expected slot 9a, got: %s", genResp.Slot)
	}

	// Export the certificate from the same slot
	exportResp, err := svc.ExportPIVCertificate(context.Background(), &pb.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		Format:  "pem",
	})
	if err != nil {
		t.Fatalf("ExportPIVCertificate failed: %v", err)
	}
	if len(exportResp.Certificate) == 0 {
		t.Fatal("expected non-empty exported certificate")
	}
	if exportResp.Slot != "9a" {
		t.Fatalf("expected slot 9a in export response, got: %s", exportResp.Slot)
	}
}

func TestDeletePIVCertificate_Success(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()

	svc := NewService(nil, nil)

	// Generate a key first
	_, err := svc.GeneratePIVKey(context.Background(), &pb.GeneratePIVKeyRequest{
		Backend: "software",
		Slot:    "9a",
		Subject: "Delete Test Key",
	})
	if err != nil {
		t.Fatalf("GeneratePIVKey failed: %v", err)
	}

	// Delete the certificate
	_, err = svc.DeletePIVCertificate(context.Background(), &pb.DeletePIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
	})
	if err != nil {
		t.Fatalf("DeletePIVCertificate failed: %v", err)
	}
}

func TestDeletePIVCertificate_NotFound(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()

	svc := NewService(nil, nil)

	// Try to delete from an empty slot
	_, err := svc.DeletePIVCertificate(context.Background(), &pb.DeletePIVCertificateRequest{
		Backend: "software",
		Slot:    "9c",
	})
	// The error may be NotFound or Internal depending on the storage implementation
	if err == nil {
		t.Fatal("expected error when deleting from empty slot")
	}
}

func TestMapPIVError_NilError(t *testing.T) {
	result := mapPIVError(nil, "test")
	if result != nil {
		t.Fatalf("expected nil, got: %v", result)
	}
}

func TestMapPIVError_KnownErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{
			name:     "not initialized",
			err:      xkms.ErrPIVNotInitialized,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "backend not found",
			err:      xkms.ErrPIVBackendNotFound,
			wantCode: codes.NotFound,
		},
		{
			name:     "invalid algorithm",
			err:      xkms.ErrPIVInvalidAlgorithm,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "invalid slot",
			err:      xkms.ErrPIVInvalidSlot,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "invalid format",
			err:      xkms.ErrPIVInvalidFormat,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "key not found",
			err:      xkms.ErrPIVKeyNotFound,
			wantCode: codes.NotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapPIVError(tt.err, "test operation")
			if result == nil {
				t.Fatal("expected non-nil error")
			}

			st, ok := status.FromError(result)
			if !ok {
				t.Fatalf("expected gRPC status error, got: %v", result)
			}
			if st.Code() != tt.wantCode {
				t.Fatalf("expected code %v, got: %v", tt.wantCode, st.Code())
			}
		})
	}
}

func TestMapPIVError_UnknownError(t *testing.T) {
	unknownErr := errors.New("some unexpected error")
	result := mapPIVError(unknownErr, "test operation")
	if result == nil {
		t.Fatal("expected non-nil error")
	}

	st, ok := status.FromError(result)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", result)
	}
	if st.Code() != codes.Internal {
		t.Fatalf("expected Internal, got: %v", st.Code())
	}
}

func TestPIVNotInitialized(t *testing.T) {
	// Ensure PIV manager is reset (not initialized)
	xkms.ResetPIV()

	svc := NewService(nil, nil)

	_, err := svc.ListPIVSlots(context.Background(), &pb.ListPIVSlotsRequest{
		Backend: "software",
	})
	if err == nil {
		t.Fatal("expected error when PIV not initialized")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got: %v", st.Code())
	}
}
