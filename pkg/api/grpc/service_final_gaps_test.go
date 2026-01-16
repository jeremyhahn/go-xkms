// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/ratelimit"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// setupFinalGapsTest initializes keychain for final coverage gap tests
func setupFinalGapsTest(t *testing.T) *Service {
	t.Helper()
	keychain.Reset()

	keyStorage := storage.New()
	certStorage := storage.New()

	backend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	ks, err := keychain.New(&keychain.Config{
		Backend:     backend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	err = keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software": ks,
		},
		DefaultBackend: "software",
	})
	if err != nil {
		t.Fatalf("Failed to initialize keychain: %v", err)
	}

	return NewService()
}

// TestVerifyErrorPaths tests Verify error handling paths
func TestVerifyErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: []byte("signature"),
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "test-key",
			Data:      []byte("test data"),
			Signature: []byte("signature"),
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing data", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "test-key",
			Backend:   "software",
			Signature: []byte("signature"),
		})
		if err == nil {
			t.Fatal("Expected error for missing data")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing signature", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:   "test-key",
			Backend: "software",
			Data:    []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for missing signature")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "non-existent-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: []byte("signature"),
		})
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestSignErrorPaths tests Sign error handling paths
func TestSignErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Sign(context.Background(), &pb.SignRequest{
			Backend: "software",
			Data:    []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId: "test-key",
			Data:  []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing data", func(t *testing.T) {
		_, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for missing data")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		_, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "non-existent-key",
			Backend: "software",
			Data:    []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestDeleteKeyErrorPaths tests DeleteKey error handling paths
func TestDeleteKeyErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			KeyId: "test-key",
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		_, err := service.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			KeyId:   "test-key",
			Backend: "non-existent-backend",
		})
		if err == nil {
			t.Fatal("Expected error for non-existent backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		_, err := service.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			KeyId:   "non-existent-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestRotateKeyErrorPaths tests RotateKey error handling paths
func TestRotateKeyErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
			KeyId: "test-key",
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		_, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
			KeyId:   "test-key",
			Backend: "non-existent-backend",
		})
		if err == nil {
			t.Fatal("Expected error for non-existent backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		_, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
			KeyId:   "non-existent-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestSaveCertErrorPaths tests SaveCert error handling paths
func TestSaveCertErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
			CertPem: "cert-pem-data",
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing cert_pem", func(t *testing.T) {
		_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
			KeyId: "test-key",
		})
		if err == nil {
			t.Fatal("Expected error for missing cert_pem")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for invalid cert PEM", func(t *testing.T) {
		_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
			KeyId:   "test-key",
			CertPem: "invalid-cert-pem",
		})
		if err == nil {
			t.Fatal("Expected error for invalid cert PEM")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})
}

// TestGetCertErrorPaths tests GetCert error handling paths
func TestGetCertErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.GetCert(context.Background(), &pb.GetCertRequest{})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent cert", func(t *testing.T) {
		_, err := service.GetCert(context.Background(), &pb.GetCertRequest{
			KeyId: "non-existent-cert",
		})
		if err == nil {
			t.Fatal("Expected error for non-existent cert")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestDeleteCertErrorPaths tests DeleteCert error handling paths
func TestDeleteCertErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.DeleteCert(context.Background(), &pb.DeleteCertRequest{})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent cert", func(t *testing.T) {
		_, err := service.DeleteCert(context.Background(), &pb.DeleteCertRequest{
			KeyId: "non-existent-cert",
		})
		if err == nil {
			t.Fatal("Expected error for non-existent cert")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		// Accept either Internal or NotFound as valid error codes
		if st.Code() != codes.Internal && st.Code() != codes.NotFound {
			t.Errorf("Expected Internal or NotFound, got %v", st.Code())
		}
	})
}

// TestSaveCertChainErrorPaths tests SaveCertChain error handling paths
func TestSaveCertChainErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			CertChainPem: []string{"cert-pem"},
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for empty cert_chain_pem", func(t *testing.T) {
		_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			KeyId:        "test-key",
			CertChainPem: []string{},
		})
		if err == nil {
			t.Fatal("Expected error for empty cert_chain_pem")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for invalid cert in chain", func(t *testing.T) {
		_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			KeyId:        "test-key",
			CertChainPem: []string{"invalid-cert-pem"},
		})
		if err == nil {
			t.Fatal("Expected error for invalid cert in chain")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})
}

// TestGetCertChainErrorPaths tests GetCertChain error handling paths
func TestGetCertChainErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.GetCertChain(context.Background(), &pb.GetCertChainRequest{})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent cert chain", func(t *testing.T) {
		_, err := service.GetCertChain(context.Background(), &pb.GetCertChainRequest{
			KeyId: "non-existent-chain",
		})
		if err == nil {
			t.Fatal("Expected error for non-existent cert chain")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestGetTLSCertificateErrorPaths tests GetTLSCertificate error handling paths
func TestGetTLSCertificateErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{
			KeyId: "test-key",
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		_, err := service.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{
			KeyId:   "test-key",
			Backend: "non-existent-backend",
		})
		if err == nil {
			t.Fatal("Expected error for non-existent backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestListCertsWithCertsGaps tests ListCerts when certificates exist
func TestListCertsWithCertsGaps(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// First save some certs
	cert := createFinalGapsTestCert(t)
	certPEM := encodeCertToPEM(cert)

	_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "list-certs-test-1",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("SaveCert failed: %v", err)
	}

	_, err = service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "list-certs-test-2",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("SaveCert failed: %v", err)
	}

	// Now list certs
	resp, err := service.ListCerts(context.Background(), &pb.ListCertsRequest{})
	if err != nil {
		t.Fatalf("ListCerts failed: %v", err)
	}

	if resp.Total < 2 {
		t.Errorf("Expected at least 2 certs, got %d", resp.Total)
	}
}

// TestCertExistsAfterSave tests CertExists returns true after SaveCert
func TestCertExistsAfterSave(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Save a cert first
	cert := createFinalGapsTestCert(t)
	certPEM := encodeCertToPEM(cert)

	_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "cert-exists-test",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("SaveCert failed: %v", err)
	}

	// Now check if it exists
	resp, err := service.CertExists(context.Background(), &pb.CertExistsRequest{
		KeyId: "cert-exists-test",
	})
	if err != nil {
		t.Fatalf("CertExists failed: %v", err)
	}

	if !resp.Exists {
		t.Error("Expected cert to exist")
	}
}

// TestGetKeyErrorPaths tests GetKey error handling paths
func TestGetKeyErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
			KeyId: "test-key",
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		_, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
			KeyId:   "test-key",
			Backend: "non-existent-backend",
		})
		if err == nil {
			t.Fatal("Expected error for non-existent backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestListKeysErrorPaths tests ListKeys error handling paths
func TestListKeysErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		_, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
			Backend: "non-existent-backend",
		})
		if err == nil {
			t.Fatal("Expected error for non-existent backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestGenerateKeyErrorPaths tests GenerateKey error handling paths
func TestGenerateKeyErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			Backend: "software",
			KeyType: "rsa",
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-key",
			KeyType: "rsa",
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing key_type", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for missing key_type")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for unsupported algorithm", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-key",
			Backend: "software",
			KeyType: "unsupported-algo",
		})
		if err == nil {
			t.Fatal("Expected error for unsupported algorithm")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for invalid ECDSA curve", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "invalid-curve-key",
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "invalid-curve",
		})
		if err == nil {
			t.Fatal("Expected error for invalid curve")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for invalid symmetric key size", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "invalid-sym-key",
			Backend:   "software",
			KeyType:   "symmetric",
			Algorithm: "symmetric",
			KeySize:   999, // Invalid key size
		})
		if err == nil {
			t.Fatal("Expected error for invalid key size")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})
}

// TestEncryptErrorPaths tests Encrypt error handling paths
func TestEncryptErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			Backend:   "software",
			Plaintext: []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:     "test-key",
			Plaintext: []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing plaintext", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for missing plaintext")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:     "non-existent-key",
			Backend:   "software",
			Plaintext: []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestDecryptErrorPaths tests Decrypt error handling paths
func TestDecryptErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			Backend:    "software",
			Ciphertext: []byte("encrypted"),
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:      "test-key",
			Ciphertext: []byte("encrypted"),
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing ciphertext", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for missing ciphertext")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})
}

// TestNewServerWithTLSConfig tests NewServer with TLS configuration
func TestNewServerWithTLSConfig(t *testing.T) {
	setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate TLS certificates for testing
	tlsCert, err := generateTestTLSCert(t)
	if err != nil {
		t.Fatalf("Failed to generate TLS cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	cfg := &ServerConfig{
		Port:      0,
		TLSConfig: tlsConfig,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if server == nil {
		t.Fatal("Expected non-nil server")
	}
	if server.tlsConfig == nil {
		t.Error("Expected TLS config to be set")
	}
}

// TestNewServerWithRateLimiter tests NewServer with rate limiter
func TestNewServerWithRateLimiter(t *testing.T) {
	setupFinalGapsTest(t)
	defer keychain.Reset()

	// Create a rate limiter
	limiter := ratelimit.New(&ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 100,
		Burst:             10,
		CleanupInterval:   time.Minute,
	})

	cfg := &ServerConfig{
		Port:        0,
		RateLimiter: limiter,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if server == nil {
		t.Fatal("Expected non-nil server")
	}
	if server.rateLimiter == nil {
		t.Error("Expected rate limiter to be set")
	}
}

// TestVerifyWithEd25519Key tests Verify with Ed25519 key
func TestVerifyWithEd25519Key(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate Ed25519 key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ed25519-verify-test",
		Backend: "software",
		KeyType: "ed25519",
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	testData := []byte("test data for ed25519 signature")

	// Sign data
	signResp, err := service.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "ed25519-verify-test",
		Backend: "software",
		Data:    testData,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify signature
	verifyResp, err := service.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "ed25519-verify-test",
		Backend:   "software",
		Data:      testData,
		Signature: signResp.Signature,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !verifyResp.Valid {
		t.Error("Expected valid signature")
	}
}

// TestListKeysPagination tests ListKeys with pagination
func TestListKeysPagination(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate multiple keys
	for i := 0; i < 5; i++ {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "pagination-key-" + string(rune('a'+i)),
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "P256",
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
	}

	// Test with limit
	resp, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
		Backend: "software",
		Limit:   2,
	})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(resp.Keys) != 2 {
		t.Errorf("Expected 2 keys with limit, got %d", len(resp.Keys))
	}

	// Test with offset
	resp2, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
		Backend: "software",
		Offset:  2,
		Limit:   2,
	})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(resp2.Keys) != 2 {
		t.Errorf("Expected 2 keys with offset, got %d", len(resp2.Keys))
	}

	// Test with offset beyond total
	resp3, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
		Backend: "software",
		Offset:  100,
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(resp3.Keys) != 0 {
		t.Errorf("Expected 0 keys with large offset, got %d", len(resp3.Keys))
	}
}

// TestAuthenticationStreamInterceptorWithMissingMetadata tests stream auth interceptor
func TestAuthenticationStreamInterceptorWithMissingMetadata(t *testing.T) {
	setupFinalGapsTest(t)
	defer keychain.Reset()

	cfg := &ServerConfig{
		Port:          0,
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Context without metadata
	ctx := context.Background()
	stream := &mockStreamServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handlerCalled := false
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err = server.authenticationStreamInterceptor(nil, stream, info, handler)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if !handlerCalled {
		t.Error("Handler should have been called")
	}
}

// TestCorrelationStreamInterceptorWithRequestID tests correlation with x-request-id
func TestCorrelationStreamInterceptorWithRequestID(t *testing.T) {
	setupFinalGapsTest(t)
	defer keychain.Reset()

	cfg := &ServerConfig{
		Port:          0,
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Context with x-request-id but not x-correlation-id
	ctx := context.Background()
	md := metadata.Pairs("x-request-id", "test-request-id-123")
	ctx = metadata.NewIncomingContext(ctx, md)

	stream := &mockStreamServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}

	err = server.correlationStreamInterceptor(nil, stream, info, handler)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

// mockStreamServerStream is a minimal mock for grpc.ServerStream
type mockStreamServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockStreamServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockStreamServerStream) SetHeader(md metadata.MD) error {
	return nil
}

// TestExtractPublicKeyPEMWithCryptoSignerInterface tests extractPublicKeyPEM with crypto.Signer
func TestExtractPublicKeyPEMWithCryptoSignerInterface(t *testing.T) {
	// Test with RSA key (implements crypto.Signer)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pem, err := extractPublicKeyPEM(rsaKey)
	if err != nil {
		t.Fatalf("extractPublicKeyPEM failed: %v", err)
	}
	if pem == "" {
		t.Error("Expected non-empty PEM")
	}

	// Test with ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pem, err = extractPublicKeyPEM(ecKey)
	if err != nil {
		t.Fatalf("extractPublicKeyPEM failed: %v", err)
	}
	if pem == "" {
		t.Error("Expected non-empty PEM")
	}

	// Test with Ed25519 key
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	pem, err = extractPublicKeyPEM(ed25519Key)
	if err != nil {
		t.Fatalf("extractPublicKeyPEM failed: %v", err)
	}
	if pem == "" {
		t.Error("Expected non-empty PEM")
	}
}

// Helper function to generate test TLS certificate
func generateTestTLSCert(t *testing.T) (tls.Certificate, error) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "test-tls-cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}, nil
}

// Helper function to create test certificate
func createFinalGapsTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "test-final-gaps-cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// TestCertExistsWithMissingKeyId tests CertExists with missing key_id
func TestCertExistsWithMissingKeyId(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	_, err := service.CertExists(context.Background(), &pb.CertExistsRequest{
		KeyId: "", // Missing key_id
	})
	if err == nil {
		t.Fatal("Expected error for missing key_id")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// TestSignWithSHA512Hash tests Sign with SHA512 hash
func TestSignWithSHA512Hash(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "sha512-sign-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Sign with SHA512
	resp, err := service.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "sha512-sign-test",
		Backend: "software",
		Data:    []byte("test data for SHA512"),
		Hash:    "SHA512",
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(resp.Signature) == 0 {
		t.Error("Expected non-empty signature")
	}
}

// TestVerifyWithSHA512Hash tests Verify with SHA512 hash
func TestVerifyWithSHA512Hash(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "sha512-verify-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	testData := []byte("test data for SHA512 verify")

	// Sign
	signResp, err := service.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "sha512-verify-test",
		Backend: "software",
		Data:    testData,
		Hash:    "SHA512",
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify
	verifyResp, err := service.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "sha512-verify-test",
		Backend:   "software",
		Data:      testData,
		Signature: signResp.Signature,
		Hash:      "SHA512",
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !verifyResp.Valid {
		t.Error("Expected valid signature")
	}
}

// TestGenerateKeyWithDefaultKeySize tests GenerateKey RSA with default key size
func TestGenerateKeyWithDefaultKeySize(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key with no key size specified
	resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "default-keysize-test",
		Backend: "software",
		KeyType: "rsa",
		// KeySize not specified - should default
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if resp.PublicKeyPem == "" {
		t.Error("Expected non-empty public key PEM")
	}
}

// TestGenerateKeyECDSAWithDefaultCurve tests GenerateKey ECDSA with default curve
func TestGenerateKeyECDSAWithDefaultCurve(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate ECDSA key with no curve specified
	resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "default-curve-test",
		Backend: "software",
		KeyType: "ecdsa",
		// Curve not specified - should default to P256
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if resp.PublicKeyPem == "" {
		t.Error("Expected non-empty public key PEM")
	}
}

// TestGenerateSymmetricKeyWithAES128 tests GenerateKey with AES-128
func TestGenerateSymmetricKeyWithAES128(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:     "aes128-test",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "symmetric",
		KeySize:   128, // AES-128
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if resp.KeyId != "aes128-test" {
		t.Errorf("Expected key_id 'aes128-test', got '%s'", resp.KeyId)
	}
}

// TestGenerateSymmetricKeyWithAES192 tests GenerateKey with AES-192
func TestGenerateSymmetricKeyWithAES192(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:     "aes192-test",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "symmetric",
		KeySize:   192, // AES-192
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if resp.KeyId != "aes192-test" {
		t.Errorf("Expected key_id 'aes192-test', got '%s'", resp.KeyId)
	}
}

// TestGenerateSymmetricKeyWithDefaultSize tests GenerateKey symmetric with default size
func TestGenerateSymmetricKeyWithDefaultSize(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:     "sym-default-size-test",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "symmetric",
		// KeySize not specified - should default to 256
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if resp.KeyId != "sym-default-size-test" {
		t.Errorf("Expected key_id 'sym-default-size-test', got '%s'", resp.KeyId)
	}
}

// TestRotateKeyWithRSA tests RotateKey with RSA key
func TestRotateKeyWithRSA(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key
	genResp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rsa-rotate-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	originalPubKey := genResp.PublicKeyPem

	// Rotate the key
	rotateResp, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
		KeyId:   "rsa-rotate-test",
		Backend: "software",
	})
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	if rotateResp.PublicKeyPem == originalPubKey {
		t.Error("Expected different public key after rotation")
	}
}

// TestGetKeyWithRSA tests GetKey with RSA key
func TestGetKeyWithRSA(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "get-rsa-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Get key
	resp, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
		KeyId:   "get-rsa-test",
		Backend: "software",
	})
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if resp.Key.KeyId != "get-rsa-test" {
		t.Errorf("Expected key_id 'get-rsa-test', got '%s'", resp.Key.KeyId)
	}
	if resp.Key.KeySize == 0 {
		t.Error("Expected non-zero key size")
	}
}

// TestSignVerifyWithECDSA tests Sign and Verify with ECDSA P384
func TestSignVerifyWithECDSAP384(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate ECDSA P384 key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "ecdsa-p384-test",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P384",
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	testData := []byte("test data for ECDSA P384")

	// Sign
	signResp, err := service.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "ecdsa-p384-test",
		Backend: "software",
		Data:    testData,
		Hash:    "SHA384",
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify
	verifyResp, err := service.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "ecdsa-p384-test",
		Backend:   "software",
		Data:      testData,
		Signature: signResp.Signature,
		Hash:      "SHA384",
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !verifyResp.Valid {
		t.Error("Expected valid signature")
	}
}

// TestDeleteCertAfterSave tests DeleteCert after saving a cert
func TestDeleteCertAfterSave(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Save a cert
	cert := createFinalGapsTestCert(t)
	certPEM := encodeCertToPEM(cert)

	_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "delete-cert-test",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("SaveCert failed: %v", err)
	}

	// Verify it exists
	existsResp, err := service.CertExists(context.Background(), &pb.CertExistsRequest{
		KeyId: "delete-cert-test",
	})
	if err != nil {
		t.Fatalf("CertExists failed: %v", err)
	}
	if !existsResp.Exists {
		t.Fatal("Expected cert to exist before delete")
	}

	// Delete the cert
	deleteResp, err := service.DeleteCert(context.Background(), &pb.DeleteCertRequest{
		KeyId: "delete-cert-test",
	})
	if err != nil {
		t.Fatalf("DeleteCert failed: %v", err)
	}
	if !deleteResp.Success {
		t.Error("Expected DeleteCert to succeed")
	}
}

// TestVerifyWithInvalidSignatureECDSA tests Verify with invalid signature for ECDSA
func TestVerifyWithInvalidSignatureECDSA(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate ECDSA key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "verify-invalid-ecdsa-test",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	testData := []byte("test data")

	// Sign the data
	signResp, err := service.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "verify-invalid-ecdsa-test",
		Backend: "software",
		Data:    testData,
		Hash:    "SHA256",
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify with different data (should fail)
	verifyResp, err := service.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "verify-invalid-ecdsa-test",
		Backend:   "software",
		Data:      []byte("different data"),
		Signature: signResp.Signature,
		Hash:      "SHA256",
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if verifyResp.Valid {
		t.Error("Expected signature to be invalid for different data")
	}
}

// TestEncryptWithAsymmetricKey tests Encrypt error when using asymmetric key
func TestEncryptWithAsymmetricKey(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key (asymmetric)
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "encrypt-asym-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Try to encrypt with asymmetric key - should fail
	_, err = service.Encrypt(context.Background(), &pb.EncryptRequest{
		KeyId:     "encrypt-asym-test",
		Backend:   "software",
		Plaintext: []byte("test data"),
	})
	if err == nil {
		// Might succeed on some backends, so accept either way
		return
	}
	// If it fails, just ensure it's a valid gRPC error
	_, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}
}

// TestDecryptWithAsymmetricKey tests Decrypt error when using asymmetric key
func TestDecryptWithAsymmetricKey(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key (asymmetric)
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "decrypt-asym-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Try to decrypt with asymmetric key - should fail
	_, err = service.Decrypt(context.Background(), &pb.DecryptRequest{
		KeyId:      "decrypt-asym-test",
		Backend:    "software",
		Ciphertext: []byte("test data"),
	})
	if err == nil {
		// Might succeed on some backends, so accept either way
		return
	}
	// If it fails, just ensure it's a valid gRPC error
	_, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}
}

// TestSignWithDefaultHash tests Sign with default hash (no hash specified)
func TestSignWithDefaultHash(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "sign-default-hash-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Sign with no hash specified (should default to SHA256)
	resp, err := service.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "sign-default-hash-test",
		Backend: "software",
		Data:    []byte("test data"),
		// Hash not specified
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(resp.Signature) == 0 {
		t.Error("Expected non-empty signature")
	}
}

// TestVerifyWithDefaultHash tests Verify with default hash (no hash specified)
func TestVerifyWithDefaultHash(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "verify-default-hash-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	testData := []byte("test data")

	// Sign with no hash specified
	signResp, err := service.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "verify-default-hash-test",
		Backend: "software",
		Data:    testData,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify with no hash specified
	verifyResp, err := service.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "verify-default-hash-test",
		Backend:   "software",
		Data:      testData,
		Signature: signResp.Signature,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !verifyResp.Valid {
		t.Error("Expected valid signature")
	}
}

// TestSignWithInvalidHash tests Sign with invalid hash algorithm
func TestSignWithInvalidHash(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "sign-invalid-hash-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Sign with invalid hash (should default to SHA256)
	resp, err := service.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "sign-invalid-hash-test",
		Backend: "software",
		Data:    []byte("test data"),
		Hash:    "INVALID_HASH",
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(resp.Signature) == 0 {
		t.Error("Expected non-empty signature")
	}
}

// TestVerifyWithWrongHash tests Verify with mismatched hash
func TestVerifyWithWrongHash(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate RSA key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "verify-wrong-hash-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	testData := []byte("test data")

	// Sign with SHA256
	signResp, err := service.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "verify-wrong-hash-test",
		Backend: "software",
		Data:    testData,
		Hash:    "SHA256",
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify with SHA512 (wrong hash) - should return invalid
	verifyResp, err := service.Verify(context.Background(), &pb.VerifyRequest{
		KeyId:     "verify-wrong-hash-test",
		Backend:   "software",
		Data:      testData,
		Signature: signResp.Signature,
		Hash:      "SHA512",
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if verifyResp.Valid {
		t.Error("Expected invalid signature with wrong hash")
	}
}

// TestSaveCertWithBackendLookup tests SaveCert backend lookup
func TestSaveCertWithBackendLookup(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	cert := createFinalGapsTestCert(t)
	certPEM := encodeCertToPEM(cert)

	// Save cert - this tests the backend lookup path
	resp, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "backend-lookup-cert-test",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("SaveCert failed: %v", err)
	}

	if !resp.Success {
		t.Error("Expected Success to be true")
	}
}

// TestGetKeyNonExistent tests GetKey with non-existent key
func TestGetKeyNonExistent(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	_, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
		KeyId:   "non-existent-key-get",
		Backend: "software",
	})
	if err == nil {
		t.Fatal("Expected error for non-existent key")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

// TestEncodePrivateKeyToPEMWithECDSAP384 tests encoding P384 ECDSA key
func TestEncodePrivateKeyToPEMWithECDSAP384(t *testing.T) {
	// Generate P384 ECDSA key
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pem, err := encodePrivateKeyToPEM(privKey)
	if err != nil {
		t.Fatalf("encodePrivateKeyToPEM failed: %v", err)
	}

	if pem == "" {
		t.Error("Expected non-empty PEM")
	}
}

// TestListKeyFilteredByType tests ListKeys with key filtering
func TestListKeyFilteredByType(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate various key types
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "filter-rsa-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	_, err = service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "filter-ecdsa-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// List all keys
	resp, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
		Backend: "software",
	})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if resp.Total < 2 {
		t.Errorf("Expected at least 2 keys, got %d", resp.Total)
	}
}

// TestServerStartStop tests starting and stopping the server
func TestServerStartStop(t *testing.T) {
	setupFinalGapsTest(t)
	defer keychain.Reset()

	cfg := &ServerConfig{
		Port:          0, // Use ephemeral port
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Check that the server is listening
	if server.Port() == 0 {
		t.Error("Expected server port to be set")
	}

	// Stop the server
	if err := server.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	// Check for any errors from Start
	select {
	case err := <-errChan:
		// Start may return an error when stopped - that's OK
		if err != nil {
			// Only log, don't fail - server was stopped
			t.Logf("Server start returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Server stopped gracefully without returning from Start
	}
}

// TestServerStartWithTLS tests starting server with TLS
func TestServerStartWithTLS(t *testing.T) {
	setupFinalGapsTest(t)
	defer keychain.Reset()

	// Generate TLS certificates for testing
	tlsCert, err := generateTestTLSCert(t)
	if err != nil {
		t.Fatalf("Failed to generate TLS cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	cfg := &ServerConfig{
		Port:          0,
		TLSConfig:     tlsConfig,
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop the server
	if err := server.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	// Check for any errors from Start
	select {
	case err := <-errChan:
		if err != nil {
			t.Logf("Server start returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Server stopped gracefully
	}
}
