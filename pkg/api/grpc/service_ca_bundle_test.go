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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockCABundler implements CABundler for testing.
type mockCABundler struct {
	bundle []byte
	cert   *x509.Certificate
	err    error
}

func (m *mockCABundler) CABundle() ([]byte, error) {
	return m.bundle, m.err
}

func (m *mockCABundler) CACertificate() (*x509.Certificate, error) {
	return m.cert, m.err
}

// createTestRootCACert creates a self-signed RSA root CA certificate for testing.
func createTestRootCACert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, privKey
}

// createTestIntermediateCACert creates an ECDSA intermediate CA certificate for testing.
func createTestIntermediateCACert(t *testing.T, parent *x509.Certificate, parentKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &privKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, privKey
}

// createTestLeafCert creates an Ed25519 leaf certificate for testing.
func createTestLeafCert(t *testing.T, parent *x509.Certificate, parentKey interface{}) *x509.Certificate {
	t.Helper()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	_ = privKey

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "Test Leaf",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, parentKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// encodeCertsToPEM encodes a slice of certificates to PEM format.
func encodeCertsToPEM(certs []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		buf.Write(pem.EncodeToMemory(block))
	}
	return buf.Bytes()
}

// TestGRPCSetGetCABundler tests setting and getting the CA bundler.
func TestGRPCSetGetCABundler(t *testing.T) {
	// Clean up after test
	defer SetCABundler(nil)

	t.Run("returns nil when not configured", func(t *testing.T) {
		SetCABundler(nil)
		bundler := GetCABundler()
		if bundler != nil {
			t.Error("Expected nil bundler when not configured")
		}
	})

	t.Run("returns bundler after setting", func(t *testing.T) {
		mockBundler := &mockCABundler{
			bundle: []byte("test bundle"),
		}
		SetCABundler(mockBundler)

		bundler := GetCABundler()
		if bundler == nil {
			t.Fatal("Expected non-nil bundler")
		}
		if bundler != mockBundler {
			t.Error("Expected same bundler instance")
		}
	})

	t.Run("replaces existing bundler", func(t *testing.T) {
		firstBundler := &mockCABundler{bundle: []byte("first")}
		secondBundler := &mockCABundler{bundle: []byte("second")}

		SetCABundler(firstBundler)
		SetCABundler(secondBundler)

		bundler := GetCABundler()
		if bundler != secondBundler {
			t.Error("Expected second bundler to replace first")
		}
	})
}

// TestGetCABundle_NoBundlerConfigured tests GetCABundle when no bundler is configured.
func TestGetCABundle_NoBundlerConfigured(t *testing.T) {
	// Ensure bundler is not configured
	SetCABundler(nil)
	defer SetCABundler(nil)

	service := NewService(nil, nil)

	_, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{})
	if err == nil {
		t.Fatal("Expected error when bundler not configured")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
	if st.Message() != ErrCABundlerNotConfigured.Error() {
		t.Errorf("Expected error message '%s', got '%s'", ErrCABundlerNotConfigured.Error(), st.Message())
	}
}

// TestGetCABundle_EmptyBundle tests GetCABundle when bundler returns empty bundle.
func TestGetCABundle_EmptyBundle(t *testing.T) {
	defer SetCABundler(nil)

	mockBundler := &mockCABundler{
		bundle: []byte{},
	}
	SetCABundler(mockBundler)

	service := NewService(nil, nil)

	_, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{})
	if err == nil {
		t.Fatal("Expected error when bundle is empty")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
	if st.Message() != ErrCABundleEmpty.Error() {
		t.Errorf("Expected error message '%s', got '%s'", ErrCABundleEmpty.Error(), st.Message())
	}
}

// TestGetCABundle_BundlerError tests GetCABundle when bundler returns an error.
func TestGetCABundle_BundlerError(t *testing.T) {
	defer SetCABundler(nil)

	expectedErr := errors.New("bundler error")
	mockBundler := &mockCABundler{
		err: expectedErr,
	}
	SetCABundler(mockBundler)

	service := NewService(nil, nil)

	_, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{})
	if err == nil {
		t.Fatal("Expected error when bundler returns error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

// TestGetCABundle_Success tests successful CA bundle retrieval.
func TestGetCABundle_Success(t *testing.T) {
	defer SetCABundler(nil)

	rootCA, _ := createTestRootCACert(t)
	bundlePEM := encodeCertsToPEM([]*x509.Certificate{rootCA})

	mockBundler := &mockCABundler{
		bundle: bundlePEM,
		cert:   rootCA,
	}
	SetCABundler(mockBundler)

	service := NewService(nil, nil)

	resp, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{})
	if err != nil {
		t.Fatalf("GetCABundle failed: %v", err)
	}

	// Verify response fields
	if len(resp.BundlePem) == 0 {
		t.Error("Expected non-empty bundle_pem")
	}
	if len(resp.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(resp.Certificates))
	}
	if resp.ContentType != ContentTypePEMCertificateChain {
		t.Errorf("Expected content type '%s', got '%s'", ContentTypePEMCertificateChain, resp.ContentType)
	}

	// Verify DER certificate matches
	if !bytes.Equal(resp.Certificates[0], rootCA.Raw) {
		t.Error("DER certificate does not match original")
	}
}

// TestGetCABundle_MultipleCertificates tests bundle with multiple certificates.
func TestGetCABundle_MultipleCertificates(t *testing.T) {
	defer SetCABundler(nil)

	rootCA, rootKey := createTestRootCACert(t)
	intermediateCA, intermediateKey := createTestIntermediateCACert(t, rootCA, rootKey)
	leafCert := createTestLeafCert(t, intermediateCA, intermediateKey)

	certs := []*x509.Certificate{leafCert, intermediateCA, rootCA}
	bundlePEM := encodeCertsToPEM(certs)

	mockBundler := &mockCABundler{
		bundle: bundlePEM,
	}
	SetCABundler(mockBundler)

	service := NewService(nil, nil)

	resp, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{})
	if err != nil {
		t.Fatalf("GetCABundle failed: %v", err)
	}

	if len(resp.Certificates) != 3 {
		t.Errorf("Expected 3 certificates, got %d", len(resp.Certificates))
	}
}

// TestGetCABundle_WithStoreTypeFilter tests filtering by store type.
func TestGetCABundle_WithStoreTypeFilter(t *testing.T) {
	defer SetCABundler(nil)

	rootCA, rootKey := createTestRootCACert(t)
	intermediateCA, intermediateKey := createTestIntermediateCACert(t, rootCA, rootKey)
	leafCert := createTestLeafCert(t, intermediateCA, intermediateKey)

	certs := []*x509.Certificate{leafCert, intermediateCA, rootCA}
	bundlePEM := encodeCertsToPEM(certs)

	mockBundler := &mockCABundler{
		bundle: bundlePEM,
	}
	SetCABundler(mockBundler)

	service := NewService(nil, nil)

	testCases := []struct {
		name          string
		storeType     string
		expectedCount int
	}{
		{
			name:          "filter root returns only root CA",
			storeType:     "root",
			expectedCount: 1,
		},
		{
			name:          "filter intermediate returns only intermediate CA",
			storeType:     "intermediate",
			expectedCount: 1,
		},
		{
			name:          "filter leaf returns only leaf certificate",
			storeType:     "leaf",
			expectedCount: 1,
		},
		{
			name:          "filter end-entity returns only leaf certificate",
			storeType:     "end-entity",
			expectedCount: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{
				StoreType: tc.storeType,
			})
			if err != nil {
				t.Fatalf("GetCABundle failed: %v", err)
			}

			if len(resp.Certificates) != tc.expectedCount {
				t.Errorf("Expected %d certificates, got %d", tc.expectedCount, len(resp.Certificates))
			}
		})
	}
}

// TestGetCABundle_WithAlgorithmFilter tests filtering by algorithm.
func TestGetCABundle_WithAlgorithmFilter(t *testing.T) {
	defer SetCABundler(nil)

	rootCA, rootKey := createTestRootCACert(t)
	intermediateCA, intermediateKey := createTestIntermediateCACert(t, rootCA, rootKey)
	leafCert := createTestLeafCert(t, intermediateCA, intermediateKey)

	certs := []*x509.Certificate{leafCert, intermediateCA, rootCA}
	bundlePEM := encodeCertsToPEM(certs)

	mockBundler := &mockCABundler{
		bundle: bundlePEM,
	}
	SetCABundler(mockBundler)

	service := NewService(nil, nil)

	testCases := []struct {
		name          string
		algorithm     string
		expectedCount int
	}{
		{
			name:          "filter RSA returns RSA certificates",
			algorithm:     "RSA",
			expectedCount: 1, // root CA
		},
		{
			name:          "filter ECDSA returns ECDSA certificates",
			algorithm:     "ECDSA",
			expectedCount: 1, // intermediate CA
		},
		{
			name:          "filter Ed25519 returns Ed25519 certificates",
			algorithm:     "Ed25519",
			expectedCount: 1, // leaf cert
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{
				Algorithm: tc.algorithm,
			})
			if err != nil {
				t.Fatalf("GetCABundle failed: %v", err)
			}

			if len(resp.Certificates) != tc.expectedCount {
				t.Errorf("Expected %d certificates, got %d", tc.expectedCount, len(resp.Certificates))
			}
		})
	}
}

// TestGetCABundle_FilterNoMatch tests filtering when no certificates match.
func TestGetCABundle_FilterNoMatch(t *testing.T) {
	defer SetCABundler(nil)

	rootCA, _ := createTestRootCACert(t)
	bundlePEM := encodeCertsToPEM([]*x509.Certificate{rootCA})

	mockBundler := &mockCABundler{
		bundle: bundlePEM,
	}
	SetCABundler(mockBundler)

	service := NewService(nil, nil)

	t.Run("unknown store type returns empty", func(t *testing.T) {
		_, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{
			StoreType: "unknown-type",
		})
		if err == nil {
			t.Fatal("Expected error when filter matches nothing")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})

	t.Run("unknown algorithm returns empty", func(t *testing.T) {
		_, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{
			Algorithm: "unknown-algo",
		})
		if err == nil {
			t.Fatal("Expected error when filter matches nothing")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})

	t.Run("filter for non-existent algorithm returns empty", func(t *testing.T) {
		// rootCA is RSA, filter for Ed25519
		_, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{
			Algorithm: "Ed25519",
		})
		if err == nil {
			t.Fatal("Expected error when filter matches nothing")
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

// TestGetCABundle_CombinedFilters tests using both store type and algorithm filters.
func TestGetCABundle_CombinedFilters(t *testing.T) {
	defer SetCABundler(nil)

	rootCA, rootKey := createTestRootCACert(t)
	intermediateCA, intermediateKey := createTestIntermediateCACert(t, rootCA, rootKey)
	leafCert := createTestLeafCert(t, intermediateCA, intermediateKey)

	certs := []*x509.Certificate{leafCert, intermediateCA, rootCA}
	bundlePEM := encodeCertsToPEM(certs)

	mockBundler := &mockCABundler{
		bundle: bundlePEM,
	}
	SetCABundler(mockBundler)

	service := NewService(nil, nil)

	t.Run("filter root + RSA returns RSA root", func(t *testing.T) {
		resp, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{
			StoreType: "root",
			Algorithm: "RSA",
		})
		if err != nil {
			t.Fatalf("GetCABundle failed: %v", err)
		}

		if len(resp.Certificates) != 1 {
			t.Errorf("Expected 1 certificate, got %d", len(resp.Certificates))
		}
	})

	t.Run("filter intermediate + ECDSA returns ECDSA intermediate", func(t *testing.T) {
		resp, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{
			StoreType: "intermediate",
			Algorithm: "ECDSA",
		})
		if err != nil {
			t.Fatalf("GetCABundle failed: %v", err)
		}

		if len(resp.Certificates) != 1 {
			t.Errorf("Expected 1 certificate, got %d", len(resp.Certificates))
		}
	})

	t.Run("conflicting filters return empty", func(t *testing.T) {
		// Root is RSA, not ECDSA
		_, err := service.GetCABundle(context.Background(), &pb.GetCABundleRequest{
			StoreType: "root",
			Algorithm: "ECDSA",
		})
		if err == nil {
			t.Fatal("Expected error when conflicting filters match nothing")
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

// TestParsePEMCertificatesFromBundle tests PEM certificate parsing.
func TestParsePEMCertificatesFromBundle(t *testing.T) {
	t.Run("parses single certificate", func(t *testing.T) {
		cert, _ := createTestRootCACert(t)
		pemData := encodeCertsToPEM([]*x509.Certificate{cert})

		certs, err := parsePEMCertificatesFromBundle(pemData)
		if err != nil {
			t.Fatalf("Failed to parse PEM: %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("Expected 1 certificate, got %d", len(certs))
		}
	})

	t.Run("parses multiple certificates", func(t *testing.T) {
		rootCA, rootKey := createTestRootCACert(t)
		intermediateCA, _ := createTestIntermediateCACert(t, rootCA, rootKey)
		pemData := encodeCertsToPEM([]*x509.Certificate{intermediateCA, rootCA})

		certs, err := parsePEMCertificatesFromBundle(pemData)
		if err != nil {
			t.Fatalf("Failed to parse PEM: %v", err)
		}

		if len(certs) != 2 {
			t.Errorf("Expected 2 certificates, got %d", len(certs))
		}
	})

	t.Run("skips non-certificate blocks", func(t *testing.T) {
		cert, _ := createTestRootCACert(t)
		pemData := encodeCertsToPEM([]*x509.Certificate{cert})

		// Add a non-certificate block
		privateKeyBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: []byte("fake key data"),
		}
		pemData = append(pemData, pem.EncodeToMemory(privateKeyBlock)...)

		certs, err := parsePEMCertificatesFromBundle(pemData)
		if err != nil {
			t.Fatalf("Failed to parse PEM: %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("Expected 1 certificate (skipping non-cert), got %d", len(certs))
		}
	})

	t.Run("returns empty slice for empty input", func(t *testing.T) {
		certs, err := parsePEMCertificatesFromBundle([]byte{})
		if err != nil {
			t.Fatalf("Failed to parse empty PEM: %v", err)
		}

		if len(certs) != 0 {
			t.Errorf("Expected 0 certificates for empty input, got %d", len(certs))
		}
	})

	t.Run("returns empty slice for non-PEM data", func(t *testing.T) {
		certs, err := parsePEMCertificatesFromBundle([]byte("not pem data"))
		if err != nil {
			t.Fatalf("Failed to parse non-PEM data: %v", err)
		}

		if len(certs) != 0 {
			t.Errorf("Expected 0 certificates for non-PEM input, got %d", len(certs))
		}
	})

	t.Run("returns error for invalid certificate DER", func(t *testing.T) {
		invalidBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid DER data"),
		}
		pemData := pem.EncodeToMemory(invalidBlock)

		_, err := parsePEMCertificatesFromBundle(pemData)
		if err == nil {
			t.Fatal("Expected error for invalid DER")
		}
	})
}

// TestEncodeCertificatesToPEM tests PEM certificate encoding.
func TestEncodeCertificatesToPEM(t *testing.T) {
	t.Run("encodes single certificate", func(t *testing.T) {
		cert, _ := createTestRootCACert(t)
		certs := []*x509.Certificate{cert}

		pemData, err := encodeCertificatesToPEM(certs)
		if err != nil {
			t.Fatalf("Failed to encode PEM: %v", err)
		}

		if len(pemData) == 0 {
			t.Error("Expected non-empty PEM data")
		}

		// Verify it can be parsed back
		block, _ := pem.Decode(pemData)
		if block == nil {
			t.Fatal("Failed to decode PEM block")
		}
		if block.Type != "CERTIFICATE" {
			t.Errorf("Expected block type 'CERTIFICATE', got '%s'", block.Type)
		}
	})

	t.Run("encodes multiple certificates", func(t *testing.T) {
		rootCA, rootKey := createTestRootCACert(t)
		intermediateCA, _ := createTestIntermediateCACert(t, rootCA, rootKey)
		certs := []*x509.Certificate{intermediateCA, rootCA}

		pemData, err := encodeCertificatesToPEM(certs)
		if err != nil {
			t.Fatalf("Failed to encode PEM: %v", err)
		}

		// Verify both can be parsed back
		parsedCerts, err := parsePEMCertificatesFromBundle(pemData)
		if err != nil {
			t.Fatalf("Failed to parse encoded PEM: %v", err)
		}

		if len(parsedCerts) != 2 {
			t.Errorf("Expected 2 certificates, got %d", len(parsedCerts))
		}
	})

	t.Run("encodes empty slice", func(t *testing.T) {
		pemData, err := encodeCertificatesToPEM([]*x509.Certificate{})
		if err != nil {
			t.Fatalf("Failed to encode empty slice: %v", err)
		}

		if len(pemData) != 0 {
			t.Errorf("Expected empty PEM data for empty slice, got %d bytes", len(pemData))
		}
	})

	t.Run("preserves certificate data", func(t *testing.T) {
		cert, _ := createTestRootCACert(t)
		certs := []*x509.Certificate{cert}

		pemData, err := encodeCertificatesToPEM(certs)
		if err != nil {
			t.Fatalf("Failed to encode PEM: %v", err)
		}

		parsedCerts, err := parsePEMCertificatesFromBundle(pemData)
		if err != nil {
			t.Fatalf("Failed to parse encoded PEM: %v", err)
		}

		if !bytes.Equal(parsedCerts[0].Raw, cert.Raw) {
			t.Error("Encoded and parsed certificate DER do not match")
		}
	})
}

// TestFilterCertificates tests the certificate filtering logic.
func TestFilterCertificates(t *testing.T) {
	rootCA, rootKey := createTestRootCACert(t)
	intermediateCA, intermediateKey := createTestIntermediateCACert(t, rootCA, rootKey)
	leafCert := createTestLeafCert(t, intermediateCA, intermediateKey)
	allCerts := []*x509.Certificate{leafCert, intermediateCA, rootCA}

	t.Run("nil filter returns all certificates", func(t *testing.T) {
		filtered := filterCertificates(allCerts, nil)
		if len(filtered) != len(allCerts) {
			t.Errorf("Expected %d certificates, got %d", len(allCerts), len(filtered))
		}
	})

	t.Run("empty filter returns all certificates", func(t *testing.T) {
		filtered := filterCertificates(allCerts, &CABundleFilter{})
		if len(filtered) != len(allCerts) {
			t.Errorf("Expected %d certificates, got %d", len(allCerts), len(filtered))
		}
	})

	t.Run("filters by store type only", func(t *testing.T) {
		filtered := filterCertificates(allCerts, &CABundleFilter{StoreType: "root"})
		if len(filtered) != 1 {
			t.Errorf("Expected 1 certificate, got %d", len(filtered))
		}
	})

	t.Run("filters by algorithm only", func(t *testing.T) {
		filtered := filterCertificates(allCerts, &CABundleFilter{Algorithm: "RSA"})
		if len(filtered) != 1 {
			t.Errorf("Expected 1 certificate, got %d", len(filtered))
		}
	})

	t.Run("filters by both store type and algorithm", func(t *testing.T) {
		filtered := filterCertificates(allCerts, &CABundleFilter{
			StoreType: "intermediate",
			Algorithm: "ECDSA",
		})
		if len(filtered) != 1 {
			t.Errorf("Expected 1 certificate, got %d", len(filtered))
		}
	})

	t.Run("returns empty when no match", func(t *testing.T) {
		filtered := filterCertificates(allCerts, &CABundleFilter{
			StoreType: "root",
			Algorithm: "ECDSA",
		})
		if len(filtered) != 0 {
			t.Errorf("Expected 0 certificates, got %d", len(filtered))
		}
	})

	t.Run("handles empty input slice", func(t *testing.T) {
		filtered := filterCertificates([]*x509.Certificate{}, &CABundleFilter{StoreType: "root"})
		if len(filtered) != 0 {
			t.Errorf("Expected 0 certificates, got %d", len(filtered))
		}
	})
}

// TestMatchesStoreType tests the store type matching function.
func TestMatchesStoreType(t *testing.T) {
	rootCA, rootKey := createTestRootCACert(t)
	intermediateCA, intermediateKey := createTestIntermediateCACert(t, rootCA, rootKey)
	leafCert := createTestLeafCert(t, intermediateCA, intermediateKey)

	testCases := []struct {
		name      string
		cert      *x509.Certificate
		storeType string
		expected  bool
	}{
		// Root CA tests
		{
			name:      "root CA matches root",
			cert:      rootCA,
			storeType: "root",
			expected:  true,
		},
		{
			name:      "root CA does not match intermediate",
			cert:      rootCA,
			storeType: "intermediate",
			expected:  false,
		},
		{
			name:      "root CA does not match leaf",
			cert:      rootCA,
			storeType: "leaf",
			expected:  false,
		},
		{
			name:      "root CA does not match end-entity",
			cert:      rootCA,
			storeType: "end-entity",
			expected:  false,
		},

		// Intermediate CA tests
		{
			name:      "intermediate CA does not match root",
			cert:      intermediateCA,
			storeType: "root",
			expected:  false,
		},
		{
			name:      "intermediate CA matches intermediate",
			cert:      intermediateCA,
			storeType: "intermediate",
			expected:  true,
		},
		{
			name:      "intermediate CA does not match leaf",
			cert:      intermediateCA,
			storeType: "leaf",
			expected:  false,
		},
		{
			name:      "intermediate CA does not match end-entity",
			cert:      intermediateCA,
			storeType: "end-entity",
			expected:  false,
		},

		// Leaf certificate tests
		{
			name:      "leaf cert does not match root",
			cert:      leafCert,
			storeType: "root",
			expected:  false,
		},
		{
			name:      "leaf cert does not match intermediate",
			cert:      leafCert,
			storeType: "intermediate",
			expected:  false,
		},
		{
			name:      "leaf cert matches leaf",
			cert:      leafCert,
			storeType: "leaf",
			expected:  true,
		},
		{
			name:      "leaf cert matches end-entity",
			cert:      leafCert,
			storeType: "end-entity",
			expected:  true,
		},

		// Unknown store type
		{
			name:      "unknown store type returns false",
			cert:      rootCA,
			storeType: "unknown",
			expected:  false,
		},
		{
			name:      "empty store type returns false",
			cert:      rootCA,
			storeType: "",
			expected:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := matchesStoreType(tc.cert, tc.storeType)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

// TestMatchesAlgorithm tests the algorithm matching function.
func TestMatchesAlgorithm(t *testing.T) {
	rootCA, rootKey := createTestRootCACert(t)
	intermediateCA, intermediateKey := createTestIntermediateCACert(t, rootCA, rootKey)
	leafCert := createTestLeafCert(t, intermediateCA, intermediateKey)

	testCases := []struct {
		name      string
		cert      *x509.Certificate
		algorithm string
		expected  bool
	}{
		// RSA tests
		{
			name:      "RSA cert matches RSA",
			cert:      rootCA,
			algorithm: "RSA",
			expected:  true,
		},
		{
			name:      "RSA cert does not match ECDSA",
			cert:      rootCA,
			algorithm: "ECDSA",
			expected:  false,
		},
		{
			name:      "RSA cert does not match Ed25519",
			cert:      rootCA,
			algorithm: "Ed25519",
			expected:  false,
		},
		{
			name:      "RSA cert does not match DSA",
			cert:      rootCA,
			algorithm: "DSA",
			expected:  false,
		},

		// ECDSA tests
		{
			name:      "ECDSA cert matches ECDSA",
			cert:      intermediateCA,
			algorithm: "ECDSA",
			expected:  true,
		},
		{
			name:      "ECDSA cert does not match RSA",
			cert:      intermediateCA,
			algorithm: "RSA",
			expected:  false,
		},
		{
			name:      "ECDSA cert does not match Ed25519",
			cert:      intermediateCA,
			algorithm: "Ed25519",
			expected:  false,
		},

		// Ed25519 tests
		{
			name:      "Ed25519 cert matches Ed25519",
			cert:      leafCert,
			algorithm: "Ed25519",
			expected:  true,
		},
		{
			name:      "Ed25519 cert does not match RSA",
			cert:      leafCert,
			algorithm: "RSA",
			expected:  false,
		},
		{
			name:      "Ed25519 cert does not match ECDSA",
			cert:      leafCert,
			algorithm: "ECDSA",
			expected:  false,
		},

		// Unknown algorithm
		{
			name:      "unknown algorithm returns false",
			cert:      rootCA,
			algorithm: "unknown",
			expected:  false,
		},
		{
			name:      "empty algorithm returns false",
			cert:      rootCA,
			algorithm: "",
			expected:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := matchesAlgorithm(tc.cert, tc.algorithm)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

// TestGetPublicKeyAlgorithmName tests the algorithm name lookup function.
func TestGetPublicKeyAlgorithmName(t *testing.T) {
	rootCA, rootKey := createTestRootCACert(t)
	intermediateCA, intermediateKey := createTestIntermediateCACert(t, rootCA, rootKey)
	leafCert := createTestLeafCert(t, intermediateCA, intermediateKey)

	testCases := []struct {
		name     string
		cert     *x509.Certificate
		expected string
	}{
		{
			name:     "RSA certificate returns RSA",
			cert:     rootCA,
			expected: "RSA",
		},
		{
			name:     "ECDSA certificate returns ECDSA",
			cert:     intermediateCA,
			expected: "ECDSA",
		},
		{
			name:     "Ed25519 certificate returns Ed25519",
			cert:     leafCert,
			expected: "Ed25519",
		},
		{
			name: "DSA certificate returns DSA",
			cert: &x509.Certificate{
				PublicKeyAlgorithm: x509.DSA,
			},
			expected: "DSA",
		},
		{
			name: "Unknown algorithm returns Unknown",
			cert: &x509.Certificate{
				PublicKeyAlgorithm: x509.PublicKeyAlgorithm(999),
			},
			expected: "Unknown",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getPublicKeyAlgorithmName(tc.cert)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

// TestGetFilteredCABundle tests the internal getFilteredCABundle function.
func TestGetFilteredCABundle(t *testing.T) {
	rootCA, rootKey := createTestRootCACert(t)
	intermediateCA, _ := createTestIntermediateCACert(t, rootCA, rootKey)
	bundlePEM := encodeCertsToPEM([]*x509.Certificate{intermediateCA, rootCA})

	t.Run("returns all certs with empty filter", func(t *testing.T) {
		bundler := &mockCABundler{bundle: bundlePEM}
		filter := &CABundleFilter{}

		resultPEM, certs, err := getFilteredCABundle(bundler, filter)
		if err != nil {
			t.Fatalf("getFilteredCABundle failed: %v", err)
		}

		if len(certs) != 2 {
			t.Errorf("Expected 2 certificates, got %d", len(certs))
		}
		if len(resultPEM) == 0 {
			t.Error("Expected non-empty PEM")
		}
	})

	t.Run("returns filtered certs", func(t *testing.T) {
		bundler := &mockCABundler{bundle: bundlePEM}
		filter := &CABundleFilter{StoreType: "root"}

		resultPEM, certs, err := getFilteredCABundle(bundler, filter)
		if err != nil {
			t.Fatalf("getFilteredCABundle failed: %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("Expected 1 certificate, got %d", len(certs))
		}
		if len(resultPEM) == 0 {
			t.Error("Expected non-empty PEM")
		}
	})

	t.Run("returns error when bundler fails", func(t *testing.T) {
		expectedErr := errors.New("bundler error")
		bundler := &mockCABundler{err: expectedErr}
		filter := &CABundleFilter{}

		_, _, err := getFilteredCABundle(bundler, filter)
		if err == nil {
			t.Fatal("Expected error")
		}
		if err != expectedErr {
			t.Errorf("Expected '%v', got '%v'", expectedErr, err)
		}
	})

	t.Run("returns error when PEM parse fails", func(t *testing.T) {
		invalidPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid DER"),
		})
		bundler := &mockCABundler{bundle: invalidPEM}
		filter := &CABundleFilter{}

		_, _, err := getFilteredCABundle(bundler, filter)
		if err == nil {
			t.Fatal("Expected error for invalid PEM")
		}
	})
}

// TestCABundleFilter tests the CABundleFilter struct.
func TestCABundleFilter(t *testing.T) {
	t.Run("zero value has empty fields", func(t *testing.T) {
		filter := CABundleFilter{}
		if filter.StoreType != "" {
			t.Errorf("Expected empty StoreType, got '%s'", filter.StoreType)
		}
		if filter.Algorithm != "" {
			t.Errorf("Expected empty Algorithm, got '%s'", filter.Algorithm)
		}
	})

	t.Run("fields can be set", func(t *testing.T) {
		filter := CABundleFilter{
			StoreType: "root",
			Algorithm: "RSA",
		}
		if filter.StoreType != "root" {
			t.Errorf("Expected StoreType 'root', got '%s'", filter.StoreType)
		}
		if filter.Algorithm != "RSA" {
			t.Errorf("Expected Algorithm 'RSA', got '%s'", filter.Algorithm)
		}
	})
}

// TestContentTypePEMCertificateChain tests the content type constant.
func TestContentTypePEMCertificateChain(t *testing.T) {
	expected := "application/pem-certificate-chain"
	if ContentTypePEMCertificateChain != expected {
		t.Errorf("Expected '%s', got '%s'", expected, ContentTypePEMCertificateChain)
	}
}

// TestTypedErrors tests the typed error variables.
func TestTypedErrors(t *testing.T) {
	t.Run("ErrCABundlerNotConfigured has expected message", func(t *testing.T) {
		expected := "grpc: CA bundler not configured"
		if ErrCABundlerNotConfigured.Error() != expected {
			t.Errorf("Expected '%s', got '%s'", expected, ErrCABundlerNotConfigured.Error())
		}
	})

	t.Run("ErrCABundleEmpty has expected message", func(t *testing.T) {
		expected := "grpc: CA bundle is empty"
		if ErrCABundleEmpty.Error() != expected {
			t.Errorf("Expected '%s', got '%s'", expected, ErrCABundleEmpty.Error())
		}
	})

	t.Run("ErrCertificateEncodeFailed has expected message", func(t *testing.T) {
		expected := "grpc: failed to encode certificate"
		if ErrCertificateEncodeFailed.Error() != expected {
			t.Errorf("Expected '%s', got '%s'", expected, ErrCertificateEncodeFailed.Error())
		}
	})
}
