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

// TestServiceSetGetCABundler tests setting and getting the CA bundler on a
// Service instance.
func TestServiceSetGetCABundler(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns nil when not configured", func(t *testing.T) {
		svc.SetCABundler(nil)
		bundler := svc.CABundler()
		if bundler != nil {
			t.Error("Expected nil bundler when not configured")
		}
	})

	t.Run("returns bundler after setting", func(t *testing.T) {
		mockBundler := &mockCABundler{
			bundle: []byte("test bundle"),
		}
		svc.SetCABundler(mockBundler)

		bundler := svc.CABundler()
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

		svc.SetCABundler(firstBundler)
		svc.SetCABundler(secondBundler)

		bundler := svc.CABundler()
		if bundler != secondBundler {
			t.Error("Expected second bundler to replace first")
		}
	})
}

// TestGetCABundle_NoBundlerConfigured tests GetCABundle when no bundler is configured.
func TestGetCABundle_NoBundlerConfigured(t *testing.T) {
	service := NewService(nil, nil, nil)

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

// TestGetCABundle_WithStoreTypeFilter tests filtering by store type.
func TestGetCABundle_WithStoreTypeFilter(t *testing.T) {
	rootCA, rootKey := createTestRootCACert(t)
	intermediateCA, intermediateKey := createTestIntermediateCACert(t, rootCA, rootKey)
	leafCert := createTestLeafCert(t, intermediateCA, intermediateKey)

	certs := []*x509.Certificate{leafCert, intermediateCA, rootCA}
	bundlePEM := encodeCertsToPEM(certs)

	mockBundler := &mockCABundler{
		bundle: bundlePEM,
	}

	service := NewService(nil, nil, nil)
	service.SetCABundler(mockBundler)

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

// TestGetCABundle_FilterNoMatch tests filtering when no certificates match.
func TestGetCABundle_FilterNoMatch(t *testing.T) {
	rootCA, _ := createTestRootCACert(t)
	bundlePEM := encodeCertsToPEM([]*x509.Certificate{rootCA})

	mockBundler := &mockCABundler{
		bundle: bundlePEM,
	}

	service := NewService(nil, nil, nil)
	service.SetCABundler(mockBundler)

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

// TestContentTypePEMCertificateChain tests the content type constant.
func TestContentTypePEMCertificateChain(t *testing.T) {
	expected := "application/pem-certificate-chain"
	if ContentTypePEMCertificateChain != expected {
		t.Errorf("Expected '%s', got '%s'", expected, ContentTypePEMCertificateChain)
	}
}
