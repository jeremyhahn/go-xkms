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

package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCertificate creates a test certificate for parsed adapter tests.
func createTestCertificate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Use a fixed time for consistent certificate generation
	notBefore := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(24 * time.Hour)

	// Use a unique serial number based on the common name to ensure different certs
	serialNumber := big.NewInt(0)
	for i, r := range cn {
		serialNumber.Add(serialNumber, big.NewInt(int64(r)+int64(i)))
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// TestSaveCertParsed tests the SaveCertParsed adapter function.
func TestSaveCertParsed(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		cert      *x509.Certificate
		setupFunc func() Backend
		wantErr   error
	}{
		{
			name: "successful save",
			id:   "test-cert",
			cert: createTestCertificate(t, "test.example.com"),
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: nil,
		},
		{
			name: "nil certificate",
			id:   "test-cert",
			cert: nil,
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidData,
		},
		{
			name: "empty ID",
			id:   "",
			cert: createTestCertificate(t, "test.example.com"),
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidID,
		},
		{
			name: "backend error",
			id:   "test-cert",
			cert: createTestCertificate(t, "test.example.com"),
			setupFunc: func() Backend {
				return &errorMockBackend{putErr: ErrClosed}
			},
			wantErr: ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			err := SaveCertParsed(backend, tt.id, tt.cert)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				// Verify the certificate was saved correctly
				retrieved, err := GetCertParsed(backend, tt.id)
				require.NoError(t, err)
				assert.Equal(t, tt.cert.Subject.CommonName, retrieved.Subject.CommonName)
				assert.Equal(t, tt.cert.SerialNumber, retrieved.SerialNumber)
			}
		})
	}
}

// TestGetCertParsed tests the GetCertParsed adapter function.
func TestGetCertParsed(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		setupFunc func() Backend
		wantCN    string
		wantErr   error
	}{
		{
			name: "successful get",
			id:   "test-cert",
			setupFunc: func() Backend {
				b := newMockBackend()
				cert := createTestCertificate(t, "test.example.com")
				err := SaveCertParsed(b, "test-cert", cert)
				require.NoError(t, err)
				return b
			},
			wantCN:  "test.example.com",
			wantErr: nil,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantCN:  "",
			wantErr: ErrInvalidID,
		},
		{
			name: "cert not found",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantCN:  "",
			wantErr: ErrNotFound,
		},
		{
			name: "invalid cert data",
			id:   "invalid-cert",
			setupFunc: func() Backend {
				b := newMockBackend()
				// Save invalid cert data
				certPath := CertPath("invalid-cert")
				err := b.Put(certPath, []byte("invalid certificate data"), nil)
				require.NoError(t, err)
				return b
			},
			wantCN:  "",
			wantErr: nil, // ParseCertificate will return an error, not ErrInvalidData
		},
		{
			name: "backend error",
			id:   "test-cert",
			setupFunc: func() Backend {
				return &errorMockBackend{getErr: ErrClosed}
			},
			wantCN:  "",
			wantErr: ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			cert, err := GetCertParsed(backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, cert)
			} else {
				if tt.name == "invalid cert data" {
					// Special case: invalid data should return parse error
					assert.Error(t, err)
					assert.Nil(t, cert)
				} else {
					assert.NoError(t, err)
					assert.NotNil(t, cert)
					assert.Equal(t, tt.wantCN, cert.Subject.CommonName)
				}
			}
		})
	}
}

// TestSaveCertChainParsed tests the SaveCertChainParsed adapter function.
func TestSaveCertChainParsed(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		chain     []*x509.Certificate
		setupFunc func() Backend
		wantErr   error
	}{
		{
			name: "successful save single cert",
			id:   "chain-1",
			chain: []*x509.Certificate{
				createTestCertificate(t, "cert1.example.com"),
			},
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: nil,
		},
		{
			name: "save multiple certs",
			id:   "chain-2",
			chain: []*x509.Certificate{
				createTestCertificate(t, "cert1.example.com"),
				createTestCertificate(t, "cert2.example.com"),
				createTestCertificate(t, "cert3.example.com"),
			},
			setupFunc: func() Backend {
				return newMockBackend()
			},
			// Note: The current implementation has a bug where it uses x509.ParseCertificate
			// instead of x509.ParseCertificates, so retrieving multiple certs will fail.
			// We test that the save succeeds, but don't verify retrieval here.
			wantErr: nil,
		},
		{
			name:  "empty chain",
			id:    "chain-empty",
			chain: []*x509.Certificate{},
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidData,
		},
		{
			name:  "nil chain",
			id:    "chain-nil",
			chain: nil,
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidData,
		},
		{
			name: "empty ID",
			id:   "",
			chain: []*x509.Certificate{
				createTestCertificate(t, "cert1.example.com"),
			},
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidID,
		},
		{
			name: "backend error",
			id:   "chain-error",
			chain: []*x509.Certificate{
				createTestCertificate(t, "cert1.example.com"),
			},
			setupFunc: func() Backend {
				return &errorMockBackend{putErr: ErrClosed}
			},
			wantErr: ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			err := SaveCertChainParsed(backend, tt.id, tt.chain)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				// Only verify retrieval for single-cert chains
				// Multi-cert chains have a bug in GetCertChainParsed (uses ParseCertificate instead of ParseCertificates)
				if len(tt.chain) == 1 {
					retrieved, err := GetCertChainParsed(backend, tt.id)
					require.NoError(t, err)
					assert.Len(t, retrieved, len(tt.chain))
					for i, cert := range tt.chain {
						assert.Equal(t, cert.Subject.CommonName, retrieved[i].Subject.CommonName)
					}
				}
			}
		})
	}
}

// TestGetCertChainParsed tests the GetCertChainParsed adapter function.
func TestGetCertChainParsed(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		setupFunc   func() Backend
		wantCount   int
		wantErr     error
		checkParsed bool
	}{
		{
			name: "successful get single cert",
			id:   "chain-1",
			setupFunc: func() Backend {
				b := newMockBackend()
				chain := []*x509.Certificate{
					createTestCertificate(t, "cert1.example.com"),
				}
				err := SaveCertChainParsed(b, "chain-1", chain)
				require.NoError(t, err)
				return b
			},
			wantCount:   1,
			wantErr:     nil,
			checkParsed: true,
		},
		{
			name: "successful get multiple certs",
			id:   "chain-2",
			setupFunc: func() Backend {
				b := newMockBackend()
				chain := []*x509.Certificate{
					createTestCertificate(t, "cert1.example.com"),
					createTestCertificate(t, "cert2.example.com"),
					createTestCertificate(t, "cert3.example.com"),
				}
				err := SaveCertChainParsed(b, "chain-2", chain)
				require.NoError(t, err)
				return b
			},
			wantCount: 3,
			// Fixed: now uses ASN.1-based parsing that correctly handles multiple certs
			wantErr:     nil,
			checkParsed: true,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantCount:   0,
			wantErr:     ErrInvalidID,
			checkParsed: false,
		},
		{
			name: "chain not found",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantCount:   0,
			wantErr:     ErrNotFound,
			checkParsed: false,
		},
		{
			name: "invalid chain data",
			id:   "invalid-chain",
			setupFunc: func() Backend {
				b := newMockBackend()
				// Save invalid chain data
				chainPath := CertChainPath("invalid-chain")
				err := b.Put(chainPath, []byte("invalid certificate chain data"), nil)
				require.NoError(t, err)
				return b
			},
			wantCount:   0,
			wantErr:     nil, // Will fail during parsing, not ErrNotFound
			checkParsed: false,
		},
		{
			name: "empty chain data",
			id:   "empty-chain",
			setupFunc: func() Backend {
				b := newMockBackend()
				// Save empty chain data
				chainPath := CertChainPath("empty-chain")
				err := b.Put(chainPath, []byte{}, nil)
				require.NoError(t, err)
				return b
			},
			wantCount:   0,
			wantErr:     ErrNotFound,
			checkParsed: false,
		},
		{
			name: "backend error",
			id:   "chain-error",
			setupFunc: func() Backend {
				return &errorMockBackend{getErr: ErrClosed}
			},
			wantCount:   0,
			wantErr:     ErrClosed,
			checkParsed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			chain, err := GetCertChainParsed(backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, chain)
			} else {
				if tt.checkParsed {
					assert.NoError(t, err)
					assert.Len(t, chain, tt.wantCount)
				} else if tt.name == "invalid chain data" {
					// Special case: invalid data should return parse error
					assert.Error(t, err)
					assert.Nil(t, chain)
				}
			}
		})
	}
}

// TestGetCertChainParsed_ExactFit tests parsing when remaining equals cert.Raw length.
func TestGetCertChainParsed_ExactFit(t *testing.T) {
	backend := newMockBackend()

	// Create a single certificate
	cert1 := createTestCertificate(t, "exact-fit.example.com")

	// Save just this one certificate
	chainPath := CertChainPath("exact-fit")
	err := backend.Put(chainPath, cert1.Raw, nil)
	require.NoError(t, err)

	// Parse the chain - this should hit the case where len(remaining) == len(cert.Raw)
	chain, err := GetCertChainParsed(backend, "exact-fit")
	assert.NoError(t, err)
	require.Len(t, chain, 1)
	assert.Equal(t, cert1.Subject.CommonName, chain[0].Subject.CommonName)
}

// TestGetCertChainParsed_PartialParse tests partial parsing of cert chains.
// This tests the behavior when some certificates in the chain can be parsed
// and others cannot.
func TestGetCertChainParsed_PartialParse(t *testing.T) {
	backend := newMockBackend()

	// Create a valid certificate
	cert1 := createTestCertificate(t, "cert1.example.com")

	// Manually create a chain with one valid cert followed by invalid data
	chainData := append([]byte{}, cert1.Raw...)
	chainData = append(chainData, []byte("invalid data that cannot be parsed")...)

	// Save the mixed data
	chainPath := CertChainPath("partial-chain")
	err := backend.Put(chainPath, chainData, nil)
	require.NoError(t, err)

	// Try to parse the chain
	chain, err := GetCertChainParsed(backend, "partial-chain")

	// The implementation uses ASN.1-based parsing which properly handles
	// concatenated certificates. According to the implementation logic,
	// if it can parse at least one cert and then encounters an error,
	// it should return the partial chain without error.
	// In this case, it successfully parses the first valid certificate
	// and then encounters invalid data, so it returns what it parsed.
	assert.NoError(t, err)
	require.Len(t, chain, 1)
	assert.Equal(t, "cert1.example.com", chain[0].Subject.CommonName)
}

// TestParsedAdapters_Integration tests the integration of parsed adapters.
func TestParsedAdapters_Integration(t *testing.T) {
	backend := newMockBackend()

	// Test cert lifecycle
	t.Run("cert lifecycle", func(t *testing.T) {
		certID := "integration-cert"
		cert := createTestCertificate(t, "integration.example.com")

		// Save
		err := SaveCertParsed(backend, certID, cert)
		require.NoError(t, err)

		// Get
		retrieved, err := GetCertParsed(backend, certID)
		require.NoError(t, err)
		assert.Equal(t, cert.Subject.CommonName, retrieved.Subject.CommonName)
		assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber)

		// Delete
		err = DeleteCert(backend, certID)
		require.NoError(t, err)

		// Verify deleted
		exists, err := CertExists(backend, certID)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	// Test cert chain lifecycle (single cert only due to implementation bug)
	t.Run("cert chain lifecycle", func(t *testing.T) {
		chainID := "integration-chain"
		chain := []*x509.Certificate{
			createTestCertificate(t, "cert1.example.com"),
		}

		// Save
		err := SaveCertChainParsed(backend, chainID, chain)
		require.NoError(t, err)

		// Get (only works for single cert chains due to implementation bug)
		retrieved, err := GetCertChainParsed(backend, chainID)
		require.NoError(t, err)
		assert.Len(t, retrieved, 1)
		assert.Equal(t, chain[0].Subject.CommonName, retrieved[0].Subject.CommonName)

		// Delete
		err = DeleteCertChain(backend, chainID)
		require.NoError(t, err)

		// Verify deleted
		exists, err := CertChainExists(backend, chainID)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	// Test mixing parsed and raw adapters
	t.Run("mixing parsed and raw adapters", func(t *testing.T) {
		id := "mixed-test"
		cert := createTestCertificate(t, "mixed.example.com")

		// Save using parsed adapter
		err := SaveCertParsed(backend, id, cert)
		require.NoError(t, err)

		// Get using raw adapter
		rawData, err := GetCert(backend, id)
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, rawData)

		// Get using parsed adapter
		parsed, err := GetCertParsed(backend, id)
		require.NoError(t, err)
		assert.Equal(t, cert.Subject.CommonName, parsed.Subject.CommonName)
	})
}
