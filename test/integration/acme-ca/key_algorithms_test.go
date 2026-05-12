// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build local || integration

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-objstore/pkg/local"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// RSA Certificate Issuance Tests - All Key Sizes
// ============================================================================

// TestRSACertificateIssuance_AllKeySizes tests certificate issuance with all RSA key sizes
func TestRSACertificateIssuance_AllKeySizes(t *testing.T) {
	testCases := []struct {
		name    string
		keySize int
		sigAlgo x509.SignatureAlgorithm
	}{
		{
			name:    "RSA-2048",
			keySize: 2048,
			sigAlgo: x509.SHA256WithRSA,
		},
		{
			name:    "RSA-3072",
			keySize: 3072,
			sigAlgo: x509.SHA384WithRSA,
		},
		{
			name:    "RSA-4096",
			keySize: 4096,
			sigAlgo: x509.SHA512WithRSA,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create CA with RSA root using specified key size
			caInstance, cleanup := NewRSATestCA(t, tc.keySize)
			defer cleanup()

			t.Run("IssueCertificateWithCSR", func(t *testing.T) {
				// Generate client RSA key
				clientKey, err := rsa.GenerateKey(rand.Reader, tc.keySize)
				require.NoError(t, err)

				// Create CSR
				csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					Subject: subjectForTest("rsa-client-" + tc.name),
				}, clientKey)
				require.NoError(t, err)

				csrPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csrDER,
				})

				// Sign CSR
				request := &ca.CertificateRequest{
					Subject: ca.Subject{
						CommonName:   "rsa-client-" + tc.name + ".example.com",
						Organization: "Test Organization",
						Country:      "US",
					},
					Valid: 365,
				}

				cert, err := caInstance.SignCSR(csrPEM, request)
				require.NoError(t, err)

				// Verify certificate
				assertValidCertificate(t, cert, "rsa-client-"+tc.name+".example.com", tc.keySize, x509.RSA)
				assert.IsType(t, &rsa.PublicKey{}, cert.PublicKey)

				pubKey := cert.PublicKey.(*rsa.PublicKey)
				assert.Equal(t, tc.keySize, pubKey.N.BitLen(), "Key size should match")
			})

			t.Run("DirectCertificateIssuance", func(t *testing.T) {
				request := &ca.CertificateRequest{
					Subject: ca.Subject{
						CommonName:   "rsa-direct-" + tc.name + ".example.com",
						Organization: "Test Organization",
						Country:      "US",
					},
					Valid:       365,
					KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				}

				cert, err := caInstance.IssueCertificate(request)
				require.NoError(t, err)
				AssertCertificateValid(t, cert, "rsa-direct-"+tc.name+".example.com")
			})

			t.Run("VerifyCertificateChain", func(t *testing.T) {
				request := &ca.CertificateRequest{
					Subject: ca.Subject{
						CommonName:   "rsa-chain-" + tc.name + ".example.com",
						Organization: "Test Organization",
						Country:      "US",
					},
					Valid: 365,
				}

				cert, err := caInstance.IssueCertificate(request)
				require.NoError(t, err)

				chains, err := caInstance.Verify(cert, nil)
				require.NoError(t, err)
				assert.NotEmpty(t, chains, "Should have valid certificate chain")
			})
		})
	}
}

// ============================================================================
// ECDSA Certificate Issuance Tests - All Curves
// ============================================================================

// TestECDSACertificateIssuance_AllCurves tests certificate issuance with all ECDSA curves
func TestECDSACertificateIssuance_AllCurves(t *testing.T) {
	testCases := []struct {
		name      string
		curve     elliptic.Curve
		curveName string
		sigAlgo   x509.SignatureAlgorithm
	}{
		{
			name:      "ECDSA-P256",
			curve:     elliptic.P256(),
			curveName: "P256",
			sigAlgo:   x509.ECDSAWithSHA256,
		},
		{
			name:      "ECDSA-P384",
			curve:     elliptic.P384(),
			curveName: "P384",
			sigAlgo:   x509.ECDSAWithSHA384,
		},
		{
			name:      "ECDSA-P521",
			curve:     elliptic.P521(),
			curveName: "P521",
			sigAlgo:   x509.ECDSAWithSHA512,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create CA with ECDSA root using specified curve
			caInstance, cleanup := NewECDSATestCA(t, tc.curveName)
			defer cleanup()

			t.Run("IssueCertificateWithCSR", func(t *testing.T) {
				// Generate client ECDSA key
				clientKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
				require.NoError(t, err)

				// Create CSR
				csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					Subject: subjectForTest("ecdsa-client-" + tc.name),
				}, clientKey)
				require.NoError(t, err)

				csrPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csrDER,
				})

				// Sign CSR
				request := &ca.CertificateRequest{
					Subject: ca.Subject{
						CommonName:   "ecdsa-client-" + tc.name + ".example.com",
						Organization: "Test Organization",
						Country:      "US",
					},
					Valid: 365,
				}

				cert, err := caInstance.SignCSR(csrPEM, request)
				require.NoError(t, err)

				// Verify certificate
				assertValidCertificate(t, cert, "ecdsa-client-"+tc.name+".example.com", 0, x509.ECDSA)
				assert.IsType(t, &ecdsa.PublicKey{}, cert.PublicKey)

				pubKey := cert.PublicKey.(*ecdsa.PublicKey)
				assert.Equal(t, tc.curve, pubKey.Curve, "Curve should match")
			})

			t.Run("DirectCertificateIssuance", func(t *testing.T) {
				request := &ca.CertificateRequest{
					Subject: ca.Subject{
						CommonName:   "ecdsa-direct-" + tc.name + ".example.com",
						Organization: "Test Organization",
						Country:      "US",
					},
					Valid:       365,
					KeyUsage:    x509.KeyUsageDigitalSignature,
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				}

				cert, err := caInstance.IssueCertificate(request)
				require.NoError(t, err)
				AssertCertificateValid(t, cert, "ecdsa-direct-"+tc.name+".example.com")

				// Verify signature algorithm matches expected
				assert.Equal(t, tc.sigAlgo, cert.SignatureAlgorithm, "Signature algorithm should match curve")
			})

			t.Run("CertificateWithSANs", func(t *testing.T) {
				request := &ca.CertificateRequest{
					Subject: ca.Subject{
						CommonName:   "ecdsa-sans-" + tc.name + ".example.com",
						Organization: "Test Organization",
						Country:      "US",
					},
					SANS: &ca.SubjectAlternativeNames{
						DNS: []string{"www.example.com", "api.example.com", "*.example.com"},
						IPs: []string{"192.168.1.100", "10.0.0.1", "::1"},
					},
					Valid: 365,
				}

				cert, err := caInstance.IssueCertificate(request)
				require.NoError(t, err)
				AssertCertificateValid(t, cert, "ecdsa-sans-"+tc.name+".example.com")
				assert.Len(t, cert.DNSNames, 3)
				assert.Len(t, cert.IPAddresses, 3)
			})
		})
	}
}

// ============================================================================
// Ed25519 Certificate Issuance Tests
// ============================================================================

// TestEd25519CertificateIssuance tests certificate issuance with Ed25519 keys
func TestEd25519CertificateIssuance(t *testing.T) {
	// Create CA with Ed25519 root
	caInstance, cleanup := NewEd25519TestCA(t)
	defer cleanup()

	t.Run("IssueCertificateWithCSR", func(t *testing.T) {
		// Generate client Ed25519 key
		_, clientKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Create CSR
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: subjectForTest("ed25519-client"),
		}, clientKey)
		require.NoError(t, err)

		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})

		// Sign CSR
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "ed25519-client.example.com",
				Organization: "Test Organization",
				Country:      "US",
			},
			Valid: 365,
		}

		cert, err := caInstance.SignCSR(csrPEM, request)
		require.NoError(t, err)

		// Verify certificate
		assertValidCertificate(t, cert, "ed25519-client.example.com", 0, x509.Ed25519)
		_, ok := cert.PublicKey.(ed25519.PublicKey)
		assert.True(t, ok, "Public key should be Ed25519")
		assert.Equal(t, x509.PureEd25519, cert.SignatureAlgorithm)
	})

	t.Run("DirectCertificateIssuance", func(t *testing.T) {
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "ed25519-direct.example.com",
				Organization: "Test Organization",
				Country:      "US",
			},
			Valid:       365,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}

		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)
		AssertCertificateValid(t, cert, "ed25519-direct.example.com")
		assert.Equal(t, x509.PureEd25519, cert.SignatureAlgorithm)
	})

	t.Run("VerifyCertificateChain", func(t *testing.T) {
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "ed25519-chain.example.com",
				Organization: "Test Organization",
				Country:      "US",
			},
			Valid: 365,
		}

		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		chains, err := caInstance.Verify(cert, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, chains, "Should have valid certificate chain")
	})

	t.Run("Ed25519Signing", func(t *testing.T) {
		// Test that signing with Ed25519 works correctly
		data := []byte("test data for Ed25519 signing")

		// Sign with Ed25519 (uses crypto.Hash(0) as it doesn't use a separate hash)
		signature, err := caInstance.Sign(rand.Reader, data, crypto.Hash(0))
		require.NoError(t, err)
		assert.NotEmpty(t, signature)

		// Verify signature
		pubKey := caInstance.Public()
		edPubKey, ok := pubKey.(ed25519.PublicKey)
		require.True(t, ok, "Public key should be Ed25519")

		valid := ed25519.Verify(edPubKey, data, signature)
		assert.True(t, valid, "Ed25519 signature should be valid")
	})
}

// ============================================================================
// Cross-Algorithm Certificate Signing Tests
// ============================================================================

// TestCrossAlgorithmCertificateSigning tests signing certificates with different key types
func TestCrossAlgorithmCertificateSigning(t *testing.T) {
	t.Run("RSA_CA_Signs_ECDSA_Cert", func(t *testing.T) {
		// Create RSA CA
		caInstance, cleanup := NewRSATestCA(t, 2048)
		defer cleanup()

		// Generate ECDSA client key
		clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create CSR with ECDSA key
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: subjectForTest("ecdsa-from-rsa-ca"),
		}, clientKey)
		require.NoError(t, err)

		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})

		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "ecdsa-from-rsa-ca.example.com",
				Organization: "Test Organization",
			},
			Valid: 365,
		}

		cert, err := caInstance.SignCSR(csrPEM, request)
		require.NoError(t, err)

		// Certificate has ECDSA public key but RSA signature
		_, ok := cert.PublicKey.(*ecdsa.PublicKey)
		assert.True(t, ok, "Public key should be ECDSA")

		// The signature algorithm should be from the CA (RSA)
		assert.Contains(t, cert.SignatureAlgorithm.String(), "RSA")
	})

	t.Run("RSA_CA_Signs_Ed25519_Cert", func(t *testing.T) {
		// Create RSA CA
		caInstance, cleanup := NewRSATestCA(t, 2048)
		defer cleanup()

		// Generate Ed25519 client key
		_, clientKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Create CSR with Ed25519 key
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: subjectForTest("ed25519-from-rsa-ca"),
		}, clientKey)
		require.NoError(t, err)

		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})

		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "ed25519-from-rsa-ca.example.com",
				Organization: "Test Organization",
			},
			Valid: 365,
		}

		cert, err := caInstance.SignCSR(csrPEM, request)
		require.NoError(t, err)

		// Certificate has Ed25519 public key but RSA signature
		_, ok := cert.PublicKey.(ed25519.PublicKey)
		assert.True(t, ok, "Public key should be Ed25519")

		// The signature algorithm should be from the CA (RSA)
		assert.Contains(t, cert.SignatureAlgorithm.String(), "RSA")
	})

	t.Run("ECDSA_CA_Signs_RSA_Cert", func(t *testing.T) {
		// Create ECDSA CA
		caInstance, cleanup := NewECDSATestCA(t, "P256")
		defer cleanup()

		// Generate RSA client key
		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Create CSR with RSA key
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: subjectForTest("rsa-from-ecdsa-ca"),
		}, clientKey)
		require.NoError(t, err)

		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})

		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "rsa-from-ecdsa-ca.example.com",
				Organization: "Test Organization",
			},
			Valid: 365,
		}

		cert, err := caInstance.SignCSR(csrPEM, request)
		require.NoError(t, err)

		// Certificate has RSA public key but ECDSA signature
		_, ok := cert.PublicKey.(*rsa.PublicKey)
		assert.True(t, ok, "Public key should be RSA")

		// The signature algorithm should be from the CA (ECDSA)
		assert.Contains(t, cert.SignatureAlgorithm.String(), "ECDSA")
	})

	t.Run("Ed25519_CA_Signs_RSA_Cert", func(t *testing.T) {
		// Create Ed25519 CA
		caInstance, cleanup := NewEd25519TestCA(t)
		defer cleanup()

		// Generate RSA client key
		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Create CSR with RSA key
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: subjectForTest("rsa-from-ed25519-ca"),
		}, clientKey)
		require.NoError(t, err)

		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})

		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "rsa-from-ed25519-ca.example.com",
				Organization: "Test Organization",
			},
			Valid: 365,
		}

		cert, err := caInstance.SignCSR(csrPEM, request)
		require.NoError(t, err)

		// Certificate has RSA public key but Ed25519 signature
		_, ok := cert.PublicKey.(*rsa.PublicKey)
		assert.True(t, ok, "Public key should be RSA")

		// The signature algorithm should be from the CA (Ed25519)
		assert.Equal(t, x509.PureEd25519, cert.SignatureAlgorithm)
	})
}

// ============================================================================
// Signature Algorithm Mapping Tests
// ============================================================================

// TestSignatureAlgorithmMapping verifies correct signature algorithm selection
func TestSignatureAlgorithmMapping(t *testing.T) {
	testCases := []struct {
		name        string
		keyAlgo     x509.PublicKeyAlgorithm
		keySize     int
		curve       string
		expectedSig x509.SignatureAlgorithm
	}{
		// RSA uses SHA256WithRSA regardless of key size (Go's x509.CreateCertificate default)
		{"RSA-2048-uses-SHA256", x509.RSA, 2048, "", x509.SHA256WithRSA},
		{"RSA-3072-uses-SHA256", x509.RSA, 3072, "", x509.SHA256WithRSA},
		{"RSA-4096-uses-SHA256", x509.RSA, 4096, "", x509.SHA256WithRSA},

		// ECDSA mappings based on curve
		{"ECDSA-P256-uses-SHA256", x509.ECDSA, 0, "P256", x509.ECDSAWithSHA256},
		{"ECDSA-P384-uses-SHA384", x509.ECDSA, 0, "P384", x509.ECDSAWithSHA384},
		{"ECDSA-P521-uses-SHA512", x509.ECDSA, 0, "P521", x509.ECDSAWithSHA512},

		// Ed25519 always uses PureEd25519
		{"Ed25519-uses-PureEd25519", x509.Ed25519, 0, "", x509.PureEd25519},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var caInstance *ca.CA
			var cleanup func()

			switch tc.keyAlgo {
			case x509.RSA:
				caInstance, cleanup = NewRSATestCA(t, tc.keySize)
			case x509.ECDSA:
				caInstance, cleanup = NewECDSATestCA(t, tc.curve)
			case x509.Ed25519:
				caInstance, cleanup = NewEd25519TestCA(t)
			}
			defer cleanup()

			request := &ca.CertificateRequest{
				Subject: ca.Subject{
					CommonName:   "sig-algo-test-" + tc.name + ".example.com",
					Organization: "Test Organization",
				},
				Valid: 365,
			}

			cert, err := caInstance.IssueCertificate(request)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedSig, cert.SignatureAlgorithm,
				"Signature algorithm should be %v for %s", tc.expectedSig, tc.name)
		})
	}
}

// ============================================================================
// Certificate Extension Tests
// ============================================================================

// TestCertificateExtensions verifies correct handling of certificate extensions
func TestCertificateExtensions(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("KeyUsageExtensions", func(t *testing.T) {
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "key-usage-test.example.com",
				Organization: "Test Organization",
			},
			Valid:    365,
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		}

		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageCertSign,
			cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageCertSign))
	})

	t.Run("ExtendedKeyUsage", func(t *testing.T) {
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "ext-key-usage-test.example.com",
				Organization: "Test Organization",
			},
			Valid: 365,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning,
				x509.ExtKeyUsageEmailProtection,
			},
		}

		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		assert.Len(t, cert.ExtKeyUsage, 4)
		assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
		assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	})

	t.Run("SubjectAlternativeNames", func(t *testing.T) {
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "san-test.example.com",
				Organization: "Test Organization",
			},
			SANS: &ca.SubjectAlternativeNames{
				DNS:   []string{"www.example.com", "api.example.com", "*.example.com"},
				IPs:   []string{"192.168.1.1", "10.0.0.1", "2001:db8::1"},
				Email: []string{"admin@example.com"},
				// Note: URIs are not currently supported by the CA's addSANs function
			},
			Valid: 365,
		}

		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		assert.ElementsMatch(t, []string{"www.example.com", "api.example.com", "*.example.com"}, cert.DNSNames)
		assert.Len(t, cert.IPAddresses, 3)
		assert.ElementsMatch(t, []string{"admin@example.com"}, cert.EmailAddresses)
	})

	t.Run("CACertificate", func(t *testing.T) {
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "sub-ca.example.com",
				Organization: "Test Organization",
			},
			Valid:      3650, // 10 years
			IsCA:       true,
			MaxPathLen: 0, // Can't issue other CA certs
			KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}

		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		assert.True(t, cert.IsCA, "Should be a CA certificate")
		assert.True(t, cert.BasicConstraintsValid)
		assert.Equal(t, 0, cert.MaxPathLen)
		assert.True(t, cert.MaxPathLenZero)
	})
}

// ============================================================================
// TLS Certificate and Configuration Tests
// ============================================================================

// TestTLSCertificateOperations tests TLS certificate bundle and configuration
func TestTLSCertificateOperations(t *testing.T) {
	testCases := []struct {
		name     string
		keyAlgo  x509.PublicKeyAlgorithm
		keySize  int
		curve    string
		createCA func(t *testing.T) (*ca.CA, func())
	}{
		{
			name:    "RSA-2048",
			keyAlgo: x509.RSA,
			keySize: 2048,
			createCA: func(t *testing.T) (*ca.CA, func()) {
				return NewRSATestCA(t, 2048)
			},
		},
		{
			name:    "ECDSA-P256",
			keyAlgo: x509.ECDSA,
			curve:   "P256",
			createCA: func(t *testing.T) (*ca.CA, func()) {
				return NewECDSATestCA(t, "P256")
			},
		},
		{
			name:    "Ed25519",
			keyAlgo: x509.Ed25519,
			createCA: func(t *testing.T) (*ca.CA, func()) {
				return NewEd25519TestCA(t)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			caInstance, cleanup := tc.createCA(t)
			defer cleanup()

			// Issue a certificate first
			cn := "tls-test-" + tc.name + ".example.com"
			request := &ca.CertificateRequest{
				Subject: ca.Subject{
					CommonName:   cn,
					Organization: "Test Organization",
				},
				Valid:       365,
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}

			_, err := caInstance.IssueCertificate(request)
			require.NoError(t, err)

			// Get key attributes for the issued cert
			attrs := &xkmssdk.KeyAttributes{
				CN:           cn,
				KeyAlgorithm: tc.keyAlgo,
				StoreType:    xkmssdk.StoreSoftware,
				KeyType:      xkmssdk.KeyTypeTLS,
			}

			switch tc.keyAlgo {
			case x509.RSA:
				attrs.RSAAttributes = &xkmssdk.RSAAttributes{
					KeySize: tc.keySize,
				}
			case x509.ECDSA:
				attrs.ECCAttributes = &xkmssdk.ECCAttributes{
					Curve: curveFromName(tc.curve),
				}
			}

			t.Run("TLSCertificate", func(t *testing.T) {
				tlsCert, err := caInstance.TLSCertificate(attrs)
				require.NoError(t, err)
				assert.NotEmpty(t, tlsCert.Certificate)
				assert.NotNil(t, tlsCert.PrivateKey)
				assert.NotNil(t, tlsCert.Leaf)
			})

			t.Run("TLSConfig", func(t *testing.T) {
				tlsConfig, err := caInstance.TLSConfig(attrs)
				require.NoError(t, err)
				assert.NotNil(t, tlsConfig)
				assert.NotEmpty(t, tlsConfig.Certificates)
			})
		})
	}
}

// ============================================================================
// Certificate Validity Tests
// ============================================================================

// TestCertificateValidity tests certificate validity period handling
func TestCertificateValidity(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("DefaultValidity", func(t *testing.T) {
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "default-validity.example.com",
				Organization: "Test Organization",
			},
			Valid: 365,
		}

		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		expectedDuration := 365 * 24 * time.Hour
		actualDuration := cert.NotAfter.Sub(cert.NotBefore)

		// Allow 1 day tolerance for test timing
		assert.InDelta(t, expectedDuration.Hours(), actualDuration.Hours(), 24)
	})

	t.Run("CustomValidity", func(t *testing.T) {
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "custom-validity.example.com",
				Organization: "Test Organization",
			},
			Valid: 730, // 2 years
		}

		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		expectedDuration := 730 * 24 * time.Hour
		actualDuration := cert.NotAfter.Sub(cert.NotBefore)

		assert.InDelta(t, expectedDuration.Hours(), actualDuration.Hours(), 24)
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

// NewRSATestCA creates a CA with an RSA root key of the specified size
func NewRSATestCA(t *testing.T, keySize int) (*ca.CA, func()) {
	xkmssdk.ServiceReset()

	keyStorage, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	certStorageBackend, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)

	softwareBackend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	keyStore, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     softwareBackend,
		CertStorage: certStorageBackend,
	})
	require.NoError(t, err)

	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"software": keyStore,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	certAdapter := xkmssdk.NewStorageCertAdapter(certStorageBackend)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	blobStore := local.New()
	err = blobStore.Configure(map[string]string{"path": t.TempDir()})
	require.NoError(t, err)

	config := ca.Config{
		Identity: []ca.Identity{
			{
				Subject: ca.Subject{
					CommonName:   "Test RSA Root CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        10,
				KeyAlgorithm: x509.RSA,
				KeySize:      keySize,
				KeystoreType: "software",
				IsRoot:       true,
			},
			{
				Subject: ca.Subject{
					CommonName:   "Test RSA Intermediate CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        5,
				KeyAlgorithm: x509.RSA,
				KeySize:      keySize,
				KeystoreType: "software",
				ParentCA:     "Test RSA Root CA",
			},
		},
		SelectedCA:                1,
		DefaultValidityPeriod:     365,
		DefaultKeyAlgorithm:       x509.RSA,
		DefaultSignatureAlgorithm: mapRSASignatureAlgorithm(keySize),
		DefaultHash:               crypto.SHA256,
		LazyInitialization:        false,
	}

	caInstance, err := ca.New(config, certStore, blobStore)
	require.NoError(t, err)

	cleanup := func() {
		xkmssdk.ServiceReset()
	}

	return caInstance, cleanup
}

// NewECDSATestCA creates a CA with an ECDSA root key using the specified curve
func NewECDSATestCA(t *testing.T, curveName string) (*ca.CA, func()) {
	xkmssdk.ServiceReset()

	keyStorage, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	certStorageBackend, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)

	softwareBackend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	keyStore, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     softwareBackend,
		CertStorage: certStorageBackend,
	})
	require.NoError(t, err)

	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"software": keyStore,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	certAdapter := xkmssdk.NewStorageCertAdapter(certStorageBackend)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	blobStore := local.New()
	err = blobStore.Configure(map[string]string{"path": t.TempDir()})
	require.NoError(t, err)

	config := ca.Config{
		Identity: []ca.Identity{
			{
				Subject: ca.Subject{
					CommonName:   "Test ECDSA Root CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        10,
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     curveName,
				KeystoreType: "software",
				IsRoot:       true,
			},
			{
				Subject: ca.Subject{
					CommonName:   "Test ECDSA Intermediate CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        5,
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     curveName,
				KeystoreType: "software",
				ParentCA:     "Test ECDSA Root CA",
			},
		},
		SelectedCA:                1,
		DefaultValidityPeriod:     365,
		DefaultKeyAlgorithm:       x509.ECDSA,
		DefaultSignatureAlgorithm: mapECDSASignatureAlgorithm(curveName),
		DefaultHash:               crypto.SHA256,
		LazyInitialization:        false,
	}

	caInstance, err := ca.New(config, certStore, blobStore)
	require.NoError(t, err)

	cleanup := func() {
		xkmssdk.ServiceReset()
	}

	return caInstance, cleanup
}

// NewEd25519TestCA creates a CA with an Ed25519 root key
func NewEd25519TestCA(t *testing.T) (*ca.CA, func()) {
	xkmssdk.ServiceReset()

	keyStorage, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	certStorageBackend, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)

	softwareBackend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	keyStore, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     softwareBackend,
		CertStorage: certStorageBackend,
	})
	require.NoError(t, err)

	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"software": keyStore,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	certAdapter := xkmssdk.NewStorageCertAdapter(certStorageBackend)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	blobStore := local.New()
	err = blobStore.Configure(map[string]string{"path": t.TempDir()})
	require.NoError(t, err)

	config := ca.Config{
		Identity: []ca.Identity{
			{
				Subject: ca.Subject{
					CommonName:   "Test Ed25519 Root CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        10,
				KeyAlgorithm: x509.Ed25519,
				KeystoreType: "software",
				IsRoot:       true,
			},
			{
				Subject: ca.Subject{
					CommonName:   "Test Ed25519 Intermediate CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        5,
				KeyAlgorithm: x509.Ed25519,
				KeystoreType: "software",
				ParentCA:     "Test Ed25519 Root CA",
			},
		},
		SelectedCA:                1,
		DefaultValidityPeriod:     365,
		DefaultKeyAlgorithm:       x509.Ed25519,
		DefaultSignatureAlgorithm: x509.PureEd25519,
		DefaultHash:               crypto.SHA256,
		LazyInitialization:        false,
	}

	caInstance, err := ca.New(config, certStore, blobStore)
	require.NoError(t, err)

	cleanup := func() {
		xkmssdk.ServiceReset()
	}

	return caInstance, cleanup
}

// subjectForTest creates a pkix.Name for testing
func subjectForTest(name string) pkix.Name {
	return pkix.Name{
		CommonName:   name + ".example.com",
		Organization: []string{"Test Organization"},
		Country:      []string{"US"},
	}
}

// assertValidCertificate asserts that a certificate is valid
func assertValidCertificate(t *testing.T, cert *x509.Certificate, expectedCN string, expectedKeySize int, expectedKeyAlgo x509.PublicKeyAlgorithm) {
	require.NotNil(t, cert)
	assert.Equal(t, expectedCN, cert.Subject.CommonName)
	assert.True(t, time.Now().After(cert.NotBefore))
	assert.True(t, time.Now().Before(cert.NotAfter))
	assert.NotNil(t, cert.SerialNumber)
	assert.True(t, cert.SerialNumber.Cmp(big.NewInt(0)) > 0)

	switch expectedKeyAlgo {
	case x509.RSA:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		require.True(t, ok, "Expected RSA public key")
		if expectedKeySize > 0 {
			assert.Equal(t, expectedKeySize, pubKey.N.BitLen())
		}
	case x509.ECDSA:
		_, ok := cert.PublicKey.(*ecdsa.PublicKey)
		require.True(t, ok, "Expected ECDSA public key")
	case x509.Ed25519:
		_, ok := cert.PublicKey.(ed25519.PublicKey)
		require.True(t, ok, "Expected Ed25519 public key")
	}
}

// mapRSASignatureAlgorithm maps RSA key size to appropriate signature algorithm
func mapRSASignatureAlgorithm(keySize int) x509.SignatureAlgorithm {
	switch {
	case keySize <= 2048:
		return x509.SHA256WithRSA
	case keySize <= 3072:
		return x509.SHA384WithRSA
	default:
		return x509.SHA512WithRSA
	}
}

// mapECDSASignatureAlgorithm maps ECDSA curve to appropriate signature algorithm
func mapECDSASignatureAlgorithm(curveName string) x509.SignatureAlgorithm {
	switch curveName {
	case "P-256", "P256":
		return x509.ECDSAWithSHA256
	case "P-384", "P384":
		return x509.ECDSAWithSHA384
	case "P-521", "P521":
		return x509.ECDSAWithSHA512
	default:
		return x509.ECDSAWithSHA256
	}
}

// curveFromName returns the elliptic curve for a given name
func curveFromName(name string) elliptic.Curve {
	switch name {
	case "P-256", "P256":
		return elliptic.P256()
	case "P-384", "P384":
		return elliptic.P384()
	case "P-521", "P521":
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}
