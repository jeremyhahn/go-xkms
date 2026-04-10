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

package rest

import (
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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCABundler implements CABundler for testing
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

// generateTestRSACACert creates a self-signed RSA CA certificate for testing
func generateTestRSACACert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test RSA Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// generateTestECDSACACert creates a self-signed ECDSA CA certificate for testing
func generateTestECDSACACert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test ECDSA Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// generateTestEd25519CACert creates a self-signed Ed25519 CA certificate for testing
func generateTestEd25519CACert(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "Test Ed25519 Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, priv
}

// generateTestIntermediateCert creates an intermediate CA certificate signed by parent
func generateTestIntermediateCert(t *testing.T, parent *x509.Certificate, parentKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// generateTestLeafCert creates a leaf/end-entity certificate signed by parent
func generateTestLeafCert(t *testing.T, parent *x509.Certificate, parentKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject: pkix.Name{
			CommonName:   "Test Leaf Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// certToPEM encodes a certificate to PEM format
func certToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// certsToPEM encodes multiple certificates to PEM format
func certsToPEM(certs []*x509.Certificate) []byte {
	var result []byte
	for _, cert := range certs {
		result = append(result, certToPEM(cert)...)
	}
	return result
}

// TestSetGetCABundler tests setting and getting the CA bundler
func TestSetGetCABundler(t *testing.T) {
	// Preserve original bundler for cleanup
	originalBundler := caBundler
	t.Cleanup(func() {
		caBundler = originalBundler
	})

	t.Run("initially nil", func(t *testing.T) {
		caBundler = nil
		assert.Nil(t, GetCABundler())
	})

	t.Run("set and get bundler", func(t *testing.T) {
		mock := &mockCABundler{bundle: []byte("test")}
		SetCABundler(mock)
		assert.Equal(t, mock, GetCABundler())
	})

	t.Run("set to nil", func(t *testing.T) {
		mock := &mockCABundler{bundle: []byte("test")}
		SetCABundler(mock)
		SetCABundler(nil)
		assert.Nil(t, GetCABundler())
	})

	t.Run("replace existing bundler", func(t *testing.T) {
		mock1 := &mockCABundler{bundle: []byte("test1")}
		mock2 := &mockCABundler{bundle: []byte("test2")}

		SetCABundler(mock1)
		assert.Equal(t, mock1, GetCABundler())

		SetCABundler(mock2)
		assert.Equal(t, mock2, GetCABundler())
	})
}

// TestGetCABundleHandler_NoBundlerConfigured tests handler when bundler is not set
func TestGetCABundleHandler_NoBundlerConfigured(t *testing.T) {
	// Preserve original bundler for cleanup
	originalBundler := caBundler
	t.Cleanup(func() {
		caBundler = originalBundler
	})

	caBundler = nil

	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/v1/ca/bundle", nil)
	w := httptest.NewRecorder()

	ctx.GetCABundleHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "CA bundler not configured")
}

// TestGetCABundleHandler_EmptyBundle tests handler when bundle is empty
func TestGetCABundleHandler_EmptyBundle(t *testing.T) {
	// Preserve original bundler for cleanup
	originalBundler := caBundler
	t.Cleanup(func() {
		caBundler = originalBundler
	})

	caBundler = &mockCABundler{bundle: []byte{}}

	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/v1/ca/bundle", nil)
	w := httptest.NewRecorder()

	ctx.GetCABundleHandler(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "CA bundle is empty")
}

// TestGetCABundleHandler_BundlerError tests handler when bundler returns error
func TestGetCABundleHandler_BundlerError(t *testing.T) {
	// Preserve original bundler for cleanup
	originalBundler := caBundler
	t.Cleanup(func() {
		caBundler = originalBundler
	})

	testErr := errors.New("bundler error")
	caBundler = &mockCABundler{err: testErr}

	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/v1/ca/bundle", nil)
	w := httptest.NewRecorder()

	ctx.GetCABundleHandler(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "bundler error")
}

// TestGetCABundleHandler_Success tests successful bundle retrieval
func TestGetCABundleHandler_Success(t *testing.T) {
	// Preserve original bundler for cleanup
	originalBundler := caBundler
	t.Cleanup(func() {
		caBundler = originalBundler
	})

	rootCert, _ := generateTestRSACACert(t)
	bundlePEM := certToPEM(rootCert)
	caBundler = &mockCABundler{bundle: bundlePEM, cert: rootCert}

	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/v1/ca/bundle", nil)
	w := httptest.NewRecorder()

	ctx.GetCABundleHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, ContentTypePEMCertChain, w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Body.String(), "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, w.Body.String(), "-----END CERTIFICATE-----")
}

// TestGetCABundleHandler_WithStoreTypeFilter tests filtering by store type
func TestGetCABundleHandler_WithStoreTypeFilter(t *testing.T) {
	// Preserve original bundler for cleanup
	originalBundler := caBundler
	t.Cleanup(func() {
		caBundler = originalBundler
	})

	// Generate root, intermediate, and leaf certificates
	rootCert, rootKey := generateTestRSACACert(t)
	intermediateCert, intermediateKey := generateTestIntermediateCert(t, rootCert, rootKey)
	leafCert, _ := generateTestLeafCert(t, intermediateCert, intermediateKey)

	allCerts := []*x509.Certificate{rootCert, intermediateCert, leafCert}
	bundlePEM := certsToPEM(allCerts)
	caBundler = &mockCABundler{bundle: bundlePEM, cert: rootCert}

	tests := []struct {
		name          string
		storeType     string
		expectedCount int
		containsCN    string
	}{
		{
			name:          "filter by root",
			storeType:     "root",
			expectedCount: 1,
			containsCN:    "Test RSA Root CA",
		},
		{
			name:          "filter by intermediate",
			storeType:     "intermediate",
			expectedCount: 1,
			containsCN:    "Test Intermediate CA",
		},
		{
			name:          "filter by leaf",
			storeType:     "leaf",
			expectedCount: 1,
			containsCN:    "Test Leaf Certificate",
		},
		{
			name:          "filter by end-entity",
			storeType:     "end-entity",
			expectedCount: 1,
			containsCN:    "Test Leaf Certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newTestHandlerContext()
			req := httptest.NewRequest(http.MethodGet, "/v1/ca/bundle?store_type="+tt.storeType, nil)
			w := httptest.NewRecorder()

			ctx.GetCABundleHandler(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			// Parse returned certificates
			certs, err := parsePEMCertificates(w.Body.Bytes())
			require.NoError(t, err)
			assert.Len(t, certs, tt.expectedCount)

			if tt.expectedCount > 0 {
				assert.Equal(t, tt.containsCN, certs[0].Subject.CommonName)
			}
		})
	}
}

// TestGetCABundleHandler_WithAlgorithmFilter tests filtering by algorithm
func TestGetCABundleHandler_WithAlgorithmFilter(t *testing.T) {
	// Preserve original bundler for cleanup
	originalBundler := caBundler
	t.Cleanup(func() {
		caBundler = originalBundler
	})

	// Generate certificates with different algorithms
	rsaCert, _ := generateTestRSACACert(t)
	ecdsaCert, _ := generateTestECDSACACert(t)
	ed25519Cert, _ := generateTestEd25519CACert(t)

	allCerts := []*x509.Certificate{rsaCert, ecdsaCert, ed25519Cert}
	bundlePEM := certsToPEM(allCerts)
	caBundler = &mockCABundler{bundle: bundlePEM, cert: rsaCert}

	tests := []struct {
		name           string
		algorithm      string
		expectedCount  int
		expectedAlgStr string
	}{
		{
			name:           "filter by RSA",
			algorithm:      "RSA",
			expectedCount:  1,
			expectedAlgStr: "RSA",
		},
		{
			name:           "filter by ECDSA",
			algorithm:      "ECDSA",
			expectedCount:  1,
			expectedAlgStr: "ECDSA",
		},
		{
			name:           "filter by Ed25519",
			algorithm:      "Ed25519",
			expectedCount:  1,
			expectedAlgStr: "Ed25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newTestHandlerContext()
			req := httptest.NewRequest(http.MethodGet, "/v1/ca/bundle?algorithm="+tt.algorithm, nil)
			w := httptest.NewRecorder()

			ctx.GetCABundleHandler(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			// Parse returned certificates
			certs, err := parsePEMCertificates(w.Body.Bytes())
			require.NoError(t, err)
			assert.Len(t, certs, tt.expectedCount)

			if tt.expectedCount > 0 {
				assert.Equal(t, tt.expectedAlgStr, certs[0].PublicKeyAlgorithm.String())
			}
		})
	}
}

// TestGetCABundleHandler_CombinedFilters tests using both filters together
func TestGetCABundleHandler_CombinedFilters(t *testing.T) {
	// Preserve original bundler for cleanup
	originalBundler := caBundler
	t.Cleanup(func() {
		caBundler = originalBundler
	})

	// Generate RSA root
	rsaRootCert, rsaRootKey := generateTestRSACACert(t)
	// Generate ECDSA intermediate (signed by RSA root)
	ecdsaIntermediate, _ := generateTestIntermediateCert(t, rsaRootCert, rsaRootKey)

	allCerts := []*x509.Certificate{rsaRootCert, ecdsaIntermediate}
	bundlePEM := certsToPEM(allCerts)
	caBundler = &mockCABundler{bundle: bundlePEM, cert: rsaRootCert}

	t.Run("root+RSA returns RSA root", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/v1/ca/bundle?store_type=root&algorithm=RSA", nil)
		w := httptest.NewRecorder()

		ctx.GetCABundleHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		certs, err := parsePEMCertificates(w.Body.Bytes())
		require.NoError(t, err)
		assert.Len(t, certs, 1)
		assert.Equal(t, "Test RSA Root CA", certs[0].Subject.CommonName)
	})

	t.Run("intermediate+ECDSA returns ECDSA intermediate", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/v1/ca/bundle?store_type=intermediate&algorithm=ECDSA", nil)
		w := httptest.NewRecorder()

		ctx.GetCABundleHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		certs, err := parsePEMCertificates(w.Body.Bytes())
		require.NoError(t, err)
		assert.Len(t, certs, 1)
		assert.Equal(t, "Test Intermediate CA", certs[0].Subject.CommonName)
	})
}

// TestGetCABundleHandler_FilterNoMatch tests when filter matches nothing
func TestGetCABundleHandler_FilterNoMatch(t *testing.T) {
	// Preserve original bundler for cleanup
	originalBundler := caBundler
	t.Cleanup(func() {
		caBundler = originalBundler
	})

	// Only RSA root cert
	rsaCert, _ := generateTestRSACACert(t)
	bundlePEM := certToPEM(rsaCert)
	caBundler = &mockCABundler{bundle: bundlePEM, cert: rsaCert}

	tests := []struct {
		name  string
		query string
	}{
		{
			name:  "no ECDSA certs when filtering for ECDSA",
			query: "algorithm=ECDSA",
		},
		{
			name:  "no Ed25519 certs when filtering for Ed25519",
			query: "algorithm=Ed25519",
		},
		{
			name:  "no leaf certs when filtering for leaf",
			query: "store_type=leaf",
		},
		{
			name:  "no intermediate certs when filtering for intermediate",
			query: "store_type=intermediate",
		},
		{
			name:  "unknown store type",
			query: "store_type=unknown",
		},
		{
			name:  "unknown algorithm",
			query: "algorithm=UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newTestHandlerContext()
			req := httptest.NewRequest(http.MethodGet, "/v1/ca/bundle?"+tt.query, nil)
			w := httptest.NewRecorder()

			ctx.GetCABundleHandler(w, req)

			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.Contains(t, w.Body.String(), "CA bundle is empty")
		})
	}
}

// TestParsePEMCertificates tests PEM parsing
func TestParsePEMCertificates(t *testing.T) {
	t.Run("parse single certificate", func(t *testing.T) {
		cert, _ := generateTestRSACACert(t)
		pemData := certToPEM(cert)

		certs, err := parsePEMCertificates(pemData)
		require.NoError(t, err)
		assert.Len(t, certs, 1)
		assert.Equal(t, cert.Subject.CommonName, certs[0].Subject.CommonName)
	})

	t.Run("parse multiple certificates", func(t *testing.T) {
		cert1, _ := generateTestRSACACert(t)
		cert2, _ := generateTestECDSACACert(t)
		pemData := append(certToPEM(cert1), certToPEM(cert2)...)

		certs, err := parsePEMCertificates(pemData)
		require.NoError(t, err)
		assert.Len(t, certs, 2)
	})

	t.Run("parse empty data", func(t *testing.T) {
		certs, err := parsePEMCertificates([]byte{})
		require.NoError(t, err)
		assert.Empty(t, certs)
	})

	t.Run("parse nil data", func(t *testing.T) {
		certs, err := parsePEMCertificates(nil)
		require.NoError(t, err)
		assert.Empty(t, certs)
	})

	t.Run("skip non-certificate blocks", func(t *testing.T) {
		cert, _ := generateTestRSACACert(t)
		certPEM := certToPEM(cert)

		// Add a private key PEM block
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: []byte("fake key data"),
		})

		mixed := append(privateKeyPEM, certPEM...)

		certs, err := parsePEMCertificates(mixed)
		require.NoError(t, err)
		assert.Len(t, certs, 1)
		assert.Equal(t, cert.Subject.CommonName, certs[0].Subject.CommonName)
	})

	t.Run("error on invalid certificate data", func(t *testing.T) {
		invalidPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not a valid certificate"),
		})

		certs, err := parsePEMCertificates(invalidPEM)
		assert.Error(t, err)
		assert.Nil(t, certs)
	})

	t.Run("parse mixed valid and invalid blocks", func(t *testing.T) {
		// Non-PEM data at the start
		nonPEM := []byte("some random non-PEM data\n")
		cert, _ := generateTestRSACACert(t)
		certPEM := certToPEM(cert)

		mixed := append(nonPEM, certPEM...)

		certs, err := parsePEMCertificates(mixed)
		require.NoError(t, err)
		assert.Len(t, certs, 1)
	})
}

// TestEncodeCertsToPEM tests encoding certificates to PEM
func TestEncodeCertsToPEM(t *testing.T) {
	t.Run("encode single certificate", func(t *testing.T) {
		cert, _ := generateTestRSACACert(t)
		result := encodeCertsToPEM([]*x509.Certificate{cert})

		assert.Contains(t, string(result), "-----BEGIN CERTIFICATE-----")
		assert.Contains(t, string(result), "-----END CERTIFICATE-----")

		// Verify we can parse it back
		parsed, err := parsePEMCertificates(result)
		require.NoError(t, err)
		assert.Len(t, parsed, 1)
		assert.Equal(t, cert.Subject.CommonName, parsed[0].Subject.CommonName)
	})

	t.Run("encode multiple certificates", func(t *testing.T) {
		cert1, _ := generateTestRSACACert(t)
		cert2, _ := generateTestECDSACACert(t)
		result := encodeCertsToPEM([]*x509.Certificate{cert1, cert2})

		// Verify we can parse both back
		parsed, err := parsePEMCertificates(result)
		require.NoError(t, err)
		assert.Len(t, parsed, 2)
	})

	t.Run("encode empty slice", func(t *testing.T) {
		result := encodeCertsToPEM([]*x509.Certificate{})
		assert.Empty(t, result)
	})

	t.Run("encode nil slice", func(t *testing.T) {
		result := encodeCertsToPEM(nil)
		assert.Empty(t, result)
	})
}

// TestFilterCACertificates tests the filter logic
func TestFilterCACertificates(t *testing.T) {
	// Generate test certificates
	rsaRoot, rsaRootKey := generateTestRSACACert(t)
	ecdsaRoot, ecdsaRootKey := generateTestECDSACACert(t)
	intermediate, intermediateKey := generateTestIntermediateCert(t, rsaRoot, rsaRootKey)
	leaf, _ := generateTestLeafCert(t, intermediate, intermediateKey)
	ecdsaLeaf, _ := generateTestLeafCert(t, ecdsaRoot, ecdsaRootKey)

	allCerts := []*x509.Certificate{rsaRoot, ecdsaRoot, intermediate, leaf, ecdsaLeaf}

	t.Run("no filters returns all", func(t *testing.T) {
		result := filterCACertificates(allCerts, "", "")
		assert.Len(t, result, 5)
	})

	t.Run("filter by root only", func(t *testing.T) {
		result := filterCACertificates(allCerts, "root", "")
		assert.Len(t, result, 2) // rsaRoot and ecdsaRoot
		for _, cert := range result {
			assert.True(t, cert.IsCA)
			assert.NoError(t, cert.CheckSignatureFrom(cert)) // self-signed
		}
	})

	t.Run("filter by intermediate only", func(t *testing.T) {
		result := filterCACertificates(allCerts, "intermediate", "")
		assert.Len(t, result, 1)
		assert.Equal(t, "Test Intermediate CA", result[0].Subject.CommonName)
	})

	t.Run("filter by leaf only", func(t *testing.T) {
		result := filterCACertificates(allCerts, "leaf", "")
		assert.Len(t, result, 2) // leaf and ecdsaLeaf
		for _, cert := range result {
			assert.False(t, cert.IsCA)
		}
	})

	t.Run("filter by RSA algorithm only", func(t *testing.T) {
		result := filterCACertificates(allCerts, "", "RSA")
		assert.Len(t, result, 1) // only rsaRoot
		assert.Equal(t, x509.RSA, result[0].PublicKeyAlgorithm)
	})

	t.Run("filter by ECDSA algorithm only", func(t *testing.T) {
		result := filterCACertificates(allCerts, "", "ECDSA")
		assert.Len(t, result, 4) // ecdsaRoot, intermediate, leaf, ecdsaLeaf
		for _, cert := range result {
			assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)
		}
	})

	t.Run("combined filters", func(t *testing.T) {
		result := filterCACertificates(allCerts, "root", "RSA")
		assert.Len(t, result, 1)
		assert.Equal(t, "Test RSA Root CA", result[0].Subject.CommonName)
	})

	t.Run("combined filters with no match", func(t *testing.T) {
		result := filterCACertificates(allCerts, "root", "Ed25519")
		assert.Empty(t, result)
	})

	t.Run("unknown store type matches nothing", func(t *testing.T) {
		result := filterCACertificates(allCerts, "unknown", "")
		assert.Empty(t, result)
	})

	t.Run("unknown algorithm matches nothing", func(t *testing.T) {
		result := filterCACertificates(allCerts, "", "UNKNOWN")
		assert.Empty(t, result)
	})

	t.Run("empty input returns empty", func(t *testing.T) {
		result := filterCACertificates([]*x509.Certificate{}, "root", "RSA")
		assert.Empty(t, result)
	})

	t.Run("nil input returns nil", func(t *testing.T) {
		result := filterCACertificates(nil, "root", "RSA")
		assert.Nil(t, result)
	})
}

// TestMatchesCertStoreType tests store type matching
func TestMatchesCertStoreType(t *testing.T) {
	rsaRoot, rsaRootKey := generateTestRSACACert(t)
	intermediate, intermediateKey := generateTestIntermediateCert(t, rsaRoot, rsaRootKey)
	leaf, _ := generateTestLeafCert(t, intermediate, intermediateKey)

	tests := []struct {
		name      string
		cert      *x509.Certificate
		storeType string
		expected  bool
	}{
		{"root matches root", rsaRoot, "root", true},
		{"root does not match intermediate", rsaRoot, "intermediate", false},
		{"root does not match leaf", rsaRoot, "leaf", false},
		{"root does not match end-entity", rsaRoot, "end-entity", false},

		{"intermediate matches intermediate", intermediate, "intermediate", true},
		{"intermediate does not match root", intermediate, "root", false},
		{"intermediate does not match leaf", intermediate, "leaf", false},
		{"intermediate does not match end-entity", intermediate, "end-entity", false},

		{"leaf matches leaf", leaf, "leaf", true},
		{"leaf matches end-entity", leaf, "end-entity", true},
		{"leaf does not match root", leaf, "root", false},
		{"leaf does not match intermediate", leaf, "intermediate", false},

		{"unknown type returns false for root", rsaRoot, "unknown", false},
		{"empty type returns false", rsaRoot, "", false},
		{"case sensitive RSA root", rsaRoot, "ROOT", false},
		{"whitespace in type", rsaRoot, " root ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesCertStoreType(tt.cert, tt.storeType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMatchesCertAlgorithm tests algorithm matching
func TestMatchesCertAlgorithm(t *testing.T) {
	rsaCert, _ := generateTestRSACACert(t)
	ecdsaCert, _ := generateTestECDSACACert(t)
	ed25519Cert, _ := generateTestEd25519CACert(t)

	tests := []struct {
		name      string
		cert      *x509.Certificate
		algorithm string
		expected  bool
	}{
		// RSA certificate
		{"RSA matches RSA", rsaCert, "RSA", true},
		{"RSA does not match ECDSA", rsaCert, "ECDSA", false},
		{"RSA does not match Ed25519", rsaCert, "Ed25519", false},
		{"RSA does not match DSA", rsaCert, "DSA", false},

		// ECDSA certificate
		{"ECDSA matches ECDSA", ecdsaCert, "ECDSA", true},
		{"ECDSA does not match RSA", ecdsaCert, "RSA", false},
		{"ECDSA does not match Ed25519", ecdsaCert, "Ed25519", false},
		{"ECDSA does not match DSA", ecdsaCert, "DSA", false},

		// Ed25519 certificate
		{"Ed25519 matches Ed25519", ed25519Cert, "Ed25519", true},
		{"Ed25519 does not match RSA", ed25519Cert, "RSA", false},
		{"Ed25519 does not match ECDSA", ed25519Cert, "ECDSA", false},
		{"Ed25519 does not match DSA", ed25519Cert, "DSA", false},

		// Unknown/invalid algorithms
		{"unknown algorithm returns false", rsaCert, "UNKNOWN", false},
		{"empty algorithm returns false", rsaCert, "", false},
		{"case sensitive rsa", rsaCert, "rsa", false},
		{"case sensitive ecdsa", ecdsaCert, "ecdsa", false},
		{"case sensitive ed25519", ed25519Cert, "ed25519", false},
		{"whitespace in algorithm", rsaCert, " RSA ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesCertAlgorithm(tt.cert, tt.algorithm)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFilterCABundlePEM tests the combined filter and encode function
func TestFilterCABundlePEM(t *testing.T) {
	rsaRoot, rsaRootKey := generateTestRSACACert(t)
	intermediate, _ := generateTestIntermediateCert(t, rsaRoot, rsaRootKey)
	bundlePEM := certsToPEM([]*x509.Certificate{rsaRoot, intermediate})

	t.Run("filter with valid params", func(t *testing.T) {
		result, err := filterCABundlePEM(bundlePEM, "root", "RSA")
		require.NoError(t, err)

		certs, err := parsePEMCertificates(result)
		require.NoError(t, err)
		assert.Len(t, certs, 1)
		assert.Equal(t, "Test RSA Root CA", certs[0].Subject.CommonName)
	})

	t.Run("error on invalid PEM certificate", func(t *testing.T) {
		invalidPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid certificate data"),
		})

		_, err := filterCABundlePEM(invalidPEM, "root", "")
		assert.Error(t, err)
	})

	t.Run("empty result when filter matches nothing", func(t *testing.T) {
		result, err := filterCABundlePEM(bundlePEM, "leaf", "")
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

// TestCABundleErrors tests the typed error values
func TestCABundleErrors(t *testing.T) {
	t.Run("ErrCABundlerNotConfigured message", func(t *testing.T) {
		assert.Equal(t, "rest: CA bundler not configured", ErrCABundlerNotConfigured.Error())
	})

	t.Run("ErrCABundleEmpty message", func(t *testing.T) {
		assert.Equal(t, "rest: CA bundle is empty", ErrCABundleEmpty.Error())
	})
}

// TestContentTypePEMCertChain tests the content type constant
func TestContentTypePEMCertChain(t *testing.T) {
	assert.Equal(t, "application/pem-certificate-chain", ContentTypePEMCertChain)
}

// TestGetCABundleHandler_BootstrapEndpoint tests the /api/v1/ca/bundle path
func TestGetCABundleHandler_BootstrapEndpoint(t *testing.T) {
	// Preserve original bundler for cleanup
	originalBundler := caBundler
	t.Cleanup(func() {
		caBundler = originalBundler
	})

	rootCert, _ := generateTestRSACACert(t)
	bundlePEM := certToPEM(rootCert)
	caBundler = &mockCABundler{bundle: bundlePEM, cert: rootCert}

	ctx := newTestHandlerContext()
	// The handler doesn't care about the path, it's the router's job
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
	w := httptest.NewRecorder()

	ctx.GetCABundleHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "-----BEGIN CERTIFICATE-----")
}

// TestStoreTypeCertMatchers tests the map-based dispatch
func TestStoreTypeCertMatchers(t *testing.T) {
	t.Run("all expected store types are registered", func(t *testing.T) {
		expectedTypes := []string{"root", "intermediate", "leaf", "end-entity"}
		for _, storeType := range expectedTypes {
			_, ok := storeTypeCertMatchers[storeType]
			assert.True(t, ok, "expected store type %s to be registered", storeType)
		}
	})

	t.Run("unknown store type not registered", func(t *testing.T) {
		_, ok := storeTypeCertMatchers["unknown"]
		assert.False(t, ok)
	})
}

// TestAlgorithmCertMatchers tests the map-based dispatch
func TestAlgorithmCertMatchers(t *testing.T) {
	t.Run("all expected algorithms are registered", func(t *testing.T) {
		expectedAlgs := []string{"RSA", "ECDSA", "Ed25519", "DSA"}
		for _, alg := range expectedAlgs {
			_, ok := algorithmCertMatchers[alg]
			assert.True(t, ok, "expected algorithm %s to be registered", alg)
		}
	})

	t.Run("unknown algorithm not registered", func(t *testing.T) {
		_, ok := algorithmCertMatchers["unknown"]
		assert.False(t, ok)
	})

	t.Run("lowercase not registered", func(t *testing.T) {
		_, ok := algorithmCertMatchers["rsa"]
		assert.False(t, ok)
	})
}
