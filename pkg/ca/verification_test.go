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

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// =============================================================================
// Test Certificate Generation Helpers
// =============================================================================
// NOTE: Uses generateTestECDSAKey, generateTestRSAKey, generateTestEd25519Key
// from test_helpers_test.go

// generateTestCertificate generates a test certificate with the given options.
func generateTestCertificate(t *testing.T, opts testCertOptions) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: opts.serial,
		Subject: pkix.Name{
			CommonName:   opts.commonName,
			Organization: []string{opts.organization},
		},
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              opts.keyUsage,
		ExtKeyUsage:           opts.extKeyUsage,
		BasicConstraintsValid: opts.isCA || opts.basicConstraintsValid,
		IsCA:                  opts.isCA,
		MaxPathLen:            opts.maxPathLen,
		MaxPathLenZero:        opts.maxPathLenZero,
		DNSNames:              opts.dnsNames,
	}

	// Use the provided signer or self-sign
	var parent *x509.Certificate
	var signerKey crypto.PrivateKey
	if opts.parent != nil {
		parent = opts.parent
		signerKey = opts.signerKey
	} else {
		parent = template
		signerKey = opts.key
	}

	var pubKey crypto.PublicKey
	switch k := opts.key.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	default:
		t.Fatalf("Unsupported key type: %T", opts.key)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, signerKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// testCertOptions contains options for generating test certificates.
type testCertOptions struct {
	serial                *big.Int
	commonName            string
	organization          string
	notBefore             time.Time
	notAfter              time.Time
	keyUsage              x509.KeyUsage
	extKeyUsage           []x509.ExtKeyUsage
	isCA                  bool
	basicConstraintsValid bool
	maxPathLen            int
	maxPathLenZero        bool
	dnsNames              []string
	key                   crypto.PrivateKey
	parent                *x509.Certificate
	signerKey             crypto.PrivateKey
}

// generateSelfSignedCA generates a self-signed CA certificate for testing.
func generateSelfSignedCA(t *testing.T, key crypto.PrivateKey) *x509.Certificate {
	t.Helper()
	return generateTestCertificate(t, testCertOptions{
		serial:       big.NewInt(1),
		commonName:   "Test Root CA",
		organization: "Test Org",
		notBefore:    time.Now().Add(-time.Hour),
		notAfter:     time.Now().Add(365 * 24 * time.Hour),
		keyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		isCA:         true,
		maxPathLen:   1,
		key:          key,
	})
}

// generateLeafCertificate generates a leaf certificate signed by the given CA.
func generateLeafCertificate(t *testing.T, ca *x509.Certificate, caKey, leafKey crypto.PrivateKey) *x509.Certificate {
	t.Helper()
	return generateTestCertificate(t, testCertOptions{
		serial:       big.NewInt(100),
		commonName:   "test.example.com",
		organization: "Test Org",
		notBefore:    time.Now().Add(-time.Hour),
		notAfter:     time.Now().Add(90 * 24 * time.Hour),
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		extKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		dnsNames:     []string{"test.example.com", "*.example.com"},
		key:          leafKey,
		parent:       ca,
		signerKey:    caKey,
	})
}

// =============================================================================
// IsExpired Tests
// =============================================================================

func TestIsExpired(t *testing.T) {
	key := generateTestECDSAKey(t)

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			expected: true,
		},
		{
			name: "expired certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(1),
				commonName: "Expired Cert",
				notBefore:  time.Now().Add(-48 * time.Hour),
				notAfter:   time.Now().Add(-24 * time.Hour),
				key:        key,
			}),
			expected: true,
		},
		{
			name: "valid certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(2),
				commonName: "Valid Cert",
				notBefore:  time.Now().Add(-24 * time.Hour),
				notAfter:   time.Now().Add(24 * time.Hour),
				key:        key,
			}),
			expected: false,
		},
		{
			name: "certificate expiring in 1 second",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(3),
				commonName: "Almost Expired Cert",
				notBefore:  time.Now().Add(-24 * time.Hour),
				notAfter:   time.Now().Add(time.Second),
				key:        key,
			}),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsExpired(tt.cert)
			if result != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// IsNotYetValid Tests
// =============================================================================

func TestIsNotYetValid(t *testing.T) {
	key := generateTestECDSAKey(t)

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			expected: true,
		},
		{
			name: "future certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(1),
				commonName: "Future Cert",
				notBefore:  time.Now().Add(24 * time.Hour),
				notAfter:   time.Now().Add(48 * time.Hour),
				key:        key,
			}),
			expected: true,
		},
		{
			name: "current certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(2),
				commonName: "Current Cert",
				notBefore:  time.Now().Add(-24 * time.Hour),
				notAfter:   time.Now().Add(24 * time.Hour),
				key:        key,
			}),
			expected: false,
		},
		{
			name: "certificate becoming valid in 1 hour",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(3),
				commonName: "Almost Valid Cert",
				notBefore:  time.Now().Add(time.Hour),
				notAfter:   time.Now().Add(24 * time.Hour),
				key:        key,
			}),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNotYetValid(tt.cert)
			if result != tt.expected {
				t.Errorf("IsNotYetValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// ValidityPeriod Tests
// =============================================================================

func TestValidityPeriod(t *testing.T) {
	key := generateTestECDSAKey(t)

	tests := []struct {
		name        string
		cert        *x509.Certificate
		expected    time.Duration
		expectError bool
	}{
		{
			name:        "nil certificate",
			cert:        nil,
			expectError: true,
		},
		{
			name: "90 day certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(1),
				commonName: "90 Day Cert",
				notBefore:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				notAfter:   time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC),
				key:        key,
			}),
			expected: 90 * 24 * time.Hour,
		},
		{
			name: "1 year certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(2),
				commonName: "1 Year Cert",
				notBefore:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				notAfter:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				key:        key,
			}),
			expected: 365 * 24 * time.Hour,
		},
		{
			name: "1 hour certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(3),
				commonName: "Short Cert",
				notBefore:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				notAfter:   time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC),
				key:        key,
			}),
			expected: time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidityPeriod(tt.cert)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("ValidityPeriod() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// DaysUntilExpiration Tests
// =============================================================================

func TestDaysUntilExpiration(t *testing.T) {
	key := generateTestECDSAKey(t)

	tests := []struct {
		name    string
		cert    *x509.Certificate
		minDays int
		maxDays int
	}{
		{
			name:    "nil certificate",
			cert:    nil,
			minDays: 0,
			maxDays: 0,
		},
		{
			name: "expired certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(1),
				commonName: "Expired Cert",
				notBefore:  time.Now().Add(-48 * time.Hour),
				notAfter:   time.Now().Add(-24 * time.Hour),
				key:        key,
			}),
			minDays: -2,
			maxDays: -1,
		},
		{
			name: "certificate expiring in 30 days",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(2),
				commonName: "30 Day Cert",
				notBefore:  time.Now().Add(-time.Hour),
				notAfter:   time.Now().Add(30 * 24 * time.Hour),
				key:        key,
			}),
			minDays: 29,
			maxDays: 30,
		},
		{
			name: "certificate expiring in 1 year",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(3),
				commonName: "1 Year Cert",
				notBefore:  time.Now().Add(-time.Hour),
				notAfter:   time.Now().Add(365 * 24 * time.Hour),
				key:        key,
			}),
			minDays: 364,
			maxDays: 365,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DaysUntilExpiration(tt.cert)
			if result < tt.minDays || result > tt.maxDays {
				t.Errorf("DaysUntilExpiration() = %d, want between %d and %d", result, tt.minDays, tt.maxDays)
			}
		})
	}
}

// =============================================================================
// RemainingValidity Tests
// =============================================================================

func TestRemainingValidity(t *testing.T) {
	key := generateTestECDSAKey(t)

	tests := []struct {
		name        string
		cert        *x509.Certificate
		minDuration time.Duration
		maxDuration time.Duration
	}{
		{
			name:        "nil certificate",
			cert:        nil,
			minDuration: 0,
			maxDuration: 0,
		},
		{
			name: "expired certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(1),
				commonName: "Expired Cert",
				notBefore:  time.Now().Add(-48 * time.Hour),
				notAfter:   time.Now().Add(-24 * time.Hour),
				key:        key,
			}),
			minDuration: -48 * time.Hour,
			maxDuration: -23 * time.Hour,
		},
		{
			name: "certificate with 1 hour remaining",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(2),
				commonName: "1 Hour Cert",
				notBefore:  time.Now().Add(-time.Hour),
				notAfter:   time.Now().Add(time.Hour),
				key:        key,
			}),
			minDuration: 59 * time.Minute,
			maxDuration: 61 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemainingValidity(tt.cert)
			if result < tt.minDuration || result > tt.maxDuration {
				t.Errorf("RemainingValidity() = %v, want between %v and %v", result, tt.minDuration, tt.maxDuration)
			}
		})
	}
}

// =============================================================================
// IsCA Tests
// =============================================================================

func TestIsCA(t *testing.T) {
	key := generateTestECDSAKey(t)

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			expected: false,
		},
		{
			name: "CA certificate with BasicConstraints",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(1),
				commonName: "Test CA",
				notBefore:  time.Now().Add(-time.Hour),
				notAfter:   time.Now().Add(24 * time.Hour),
				keyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				isCA:       true,
				key:        key,
			}),
			expected: true,
		},
		{
			name: "non-CA certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(2),
				commonName: "Leaf Cert",
				notBefore:  time.Now().Add(-time.Hour),
				notAfter:   time.Now().Add(24 * time.Hour),
				keyUsage:   x509.KeyUsageDigitalSignature,
				isCA:       false,
				key:        key,
			}),
			expected: false,
		},
		{
			name: "certificate with KeyUsageCertSign only",
			cert: generateTestCertificate(t, testCertOptions{
				serial:                big.NewInt(3),
				commonName:            "CertSign Only",
				notBefore:             time.Now().Add(-time.Hour),
				notAfter:              time.Now().Add(24 * time.Hour),
				keyUsage:              x509.KeyUsageCertSign,
				isCA:                  false,
				basicConstraintsValid: false,
				key:                   key,
			}),
			expected: true, // Has KeyUsageCertSign
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCA(tt.cert)
			if result != tt.expected {
				t.Errorf("IsCA() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// HasKeyUsage Tests
// =============================================================================

func TestHasKeyUsage(t *testing.T) {
	key := generateTestECDSAKey(t)

	cert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "Test Cert",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		keyUsage:   x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		key:        key,
	})

	tests := []struct {
		name     string
		cert     *x509.Certificate
		usage    x509.KeyUsage
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			usage:    x509.KeyUsageDigitalSignature,
			expected: false,
		},
		{
			name:     "has digital signature",
			cert:     cert,
			usage:    x509.KeyUsageDigitalSignature,
			expected: true,
		},
		{
			name:     "has key encipherment",
			cert:     cert,
			usage:    x509.KeyUsageKeyEncipherment,
			expected: true,
		},
		{
			name:     "has both usages",
			cert:     cert,
			usage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			expected: true,
		},
		{
			name:     "does not have cert sign",
			cert:     cert,
			usage:    x509.KeyUsageCertSign,
			expected: false,
		},
		{
			name:     "does not have all requested",
			cert:     cert,
			usage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasKeyUsage(tt.cert, tt.usage)
			if result != tt.expected {
				t.Errorf("HasKeyUsage() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// HasExtKeyUsage Tests
// =============================================================================

func TestHasExtKeyUsage(t *testing.T) {
	key := generateTestECDSAKey(t)

	cert := generateTestCertificate(t, testCertOptions{
		serial:      big.NewInt(1),
		commonName:  "Test Cert",
		notBefore:   time.Now().Add(-time.Hour),
		notAfter:    time.Now().Add(24 * time.Hour),
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		key:         key,
	})

	tests := []struct {
		name     string
		cert     *x509.Certificate
		usage    x509.ExtKeyUsage
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			usage:    x509.ExtKeyUsageServerAuth,
			expected: false,
		},
		{
			name:     "has server auth",
			cert:     cert,
			usage:    x509.ExtKeyUsageServerAuth,
			expected: true,
		},
		{
			name:     "has client auth",
			cert:     cert,
			usage:    x509.ExtKeyUsageClientAuth,
			expected: true,
		},
		{
			name:     "does not have code signing",
			cert:     cert,
			usage:    x509.ExtKeyUsageCodeSigning,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasExtKeyUsage(tt.cert, tt.usage)
			if result != tt.expected {
				t.Errorf("HasExtKeyUsage() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// HasAnyExtKeyUsage Tests
// =============================================================================

func TestHasAnyExtKeyUsage(t *testing.T) {
	key := generateTestECDSAKey(t)

	cert := generateTestCertificate(t, testCertOptions{
		serial:      big.NewInt(1),
		commonName:  "Test Cert",
		notBefore:   time.Now().Add(-time.Hour),
		notAfter:    time.Now().Add(24 * time.Hour),
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		key:         key,
	})

	tests := []struct {
		name     string
		cert     *x509.Certificate
		usages   []x509.ExtKeyUsage
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			expected: false,
		},
		{
			name:     "empty usages list",
			cert:     cert,
			usages:   []x509.ExtKeyUsage{},
			expected: false,
		},
		{
			name:     "has one of the requested usages",
			cert:     cert,
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
			expected: true,
		},
		{
			name:     "has none of the requested usages",
			cert:     cert,
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAnyExtKeyUsage(tt.cert, tt.usages...)
			if result != tt.expected {
				t.Errorf("HasAnyExtKeyUsage() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// HasAllExtKeyUsages Tests
// =============================================================================

func TestHasAllExtKeyUsages(t *testing.T) {
	key := generateTestECDSAKey(t)

	cert := generateTestCertificate(t, testCertOptions{
		serial:      big.NewInt(1),
		commonName:  "Test Cert",
		notBefore:   time.Now().Add(-time.Hour),
		notAfter:    time.Now().Add(24 * time.Hour),
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		key:         key,
	})

	tests := []struct {
		name     string
		cert     *x509.Certificate
		usages   []x509.ExtKeyUsage
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			expected: false,
		},
		{
			name:     "empty usages list",
			cert:     cert,
			usages:   []x509.ExtKeyUsage{},
			expected: true,
		},
		{
			name:     "has all requested usages",
			cert:     cert,
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			expected: true,
		},
		{
			name:     "missing one usage",
			cert:     cert,
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
			expected: false,
		},
		{
			name:     "has subset",
			cert:     cert,
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAllExtKeyUsages(tt.cert, tt.usages...)
			if result != tt.expected {
				t.Errorf("HasAllExtKeyUsages() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// IsSelfSigned Tests
// =============================================================================

func TestIsSelfSigned(t *testing.T) {
	caKey := generateTestECDSAKey(t)
	leafKey := generateTestECDSAKey(t)

	caCert := generateSelfSignedCA(t, caKey)
	leafCert := generateLeafCertificate(t, caCert, caKey, leafKey)

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			expected: false,
		},
		{
			name:     "self-signed CA",
			cert:     caCert,
			expected: true,
		},
		{
			name:     "CA-signed leaf",
			cert:     leafCert,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSelfSigned(tt.cert)
			if result != tt.expected {
				t.Errorf("IsSelfSigned() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// IsValidAt Tests
// =============================================================================

func TestIsValidAt(t *testing.T) {
	key := generateTestECDSAKey(t)

	cert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "Test Cert",
		notBefore:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		notAfter:   time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
		key:        key,
	})

	tests := []struct {
		name     string
		cert     *x509.Certificate
		time     time.Time
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			time:     time.Now(),
			expected: false,
		},
		{
			name:     "before validity period",
			cert:     cert,
			time:     time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC),
			expected: false,
		},
		{
			name:     "at NotBefore",
			cert:     cert,
			time:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			expected: true,
		},
		{
			name:     "during validity period",
			cert:     cert,
			time:     time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
			expected: true,
		},
		{
			name:     "at NotAfter",
			cert:     cert,
			time:     time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
			expected: true,
		},
		{
			name:     "after validity period",
			cert:     cert,
			time:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidAt(tt.cert, tt.time)
			if result != tt.expected {
				t.Errorf("IsValidAt() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// IsCurrentlyValid Tests
// =============================================================================

func TestIsCurrentlyValid(t *testing.T) {
	key := generateTestECDSAKey(t)

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			expected: false,
		},
		{
			name: "currently valid certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(1),
				commonName: "Valid Cert",
				notBefore:  time.Now().Add(-time.Hour),
				notAfter:   time.Now().Add(24 * time.Hour),
				key:        key,
			}),
			expected: true,
		},
		{
			name: "expired certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(2),
				commonName: "Expired Cert",
				notBefore:  time.Now().Add(-48 * time.Hour),
				notAfter:   time.Now().Add(-24 * time.Hour),
				key:        key,
			}),
			expected: false,
		},
		{
			name: "future certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(3),
				commonName: "Future Cert",
				notBefore:  time.Now().Add(24 * time.Hour),
				notAfter:   time.Now().Add(48 * time.Hour),
				key:        key,
			}),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCurrentlyValid(tt.cert)
			if result != tt.expected {
				t.Errorf("IsCurrentlyValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// MatchesDNSName Tests
// =============================================================================

func TestMatchesDNSName(t *testing.T) {
	key := generateTestECDSAKey(t)

	cert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "test.example.com",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		dnsNames:   []string{"test.example.com", "*.example.com"},
		key:        key,
	})

	tests := []struct {
		name     string
		cert     *x509.Certificate
		dnsName  string
		expected bool
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			dnsName:  "test.example.com",
			expected: false,
		},
		{
			name:     "empty name",
			cert:     cert,
			dnsName:  "",
			expected: false,
		},
		{
			name:     "exact match",
			cert:     cert,
			dnsName:  "test.example.com",
			expected: true,
		},
		{
			name:     "wildcard match",
			cert:     cert,
			dnsName:  "other.example.com",
			expected: true,
		},
		{
			name:     "no match",
			cert:     cert,
			dnsName:  "test.other.com",
			expected: false,
		},
		{
			name:     "wildcard does not match subdomain",
			cert:     cert,
			dnsName:  "sub.test.example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchesDNSName(tt.cert, tt.dnsName)
			if result != tt.expected {
				t.Errorf("MatchesDNSName() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// CertificateFingerprint Tests
// =============================================================================

func TestCertificateFingerprint(t *testing.T) {
	key := generateTestECDSAKey(t)

	cert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "Test Cert",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key,
	})

	tests := []struct {
		name      string
		cert      *x509.Certificate
		expectNil bool
		expectLen int
	}{
		{
			name:      "nil certificate",
			cert:      nil,
			expectNil: true,
		},
		{
			name:      "valid certificate",
			cert:      cert,
			expectLen: 32, // SHA-256 produces 32 bytes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CertificateFingerprint(tt.cert)
			if tt.expectNil {
				if result != nil {
					t.Errorf("CertificateFingerprint() = %v, want nil", result)
				}
				return
			}
			if len(result) != tt.expectLen {
				t.Errorf("CertificateFingerprint() length = %d, want %d", len(result), tt.expectLen)
			}
		})
	}
}

func TestCertificateFingerprint_Consistency(t *testing.T) {
	key := generateTestECDSAKey(t)
	cert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "Test Cert",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key,
	})

	// Same certificate should produce same fingerprint
	fp1 := CertificateFingerprint(cert)
	fp2 := CertificateFingerprint(cert)

	if !bytes.Equal(fp1, fp2) {
		t.Error("CertificateFingerprint() should return consistent results")
	}
}

// =============================================================================
// CertificatesMatch Tests
// =============================================================================

func TestCertificatesMatch(t *testing.T) {
	key := generateTestECDSAKey(t)
	key2 := generateTestECDSAKey(t)

	cert1 := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "Cert 1",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key,
	})

	cert2 := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(2),
		commonName: "Cert 2",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key2,
	})

	tests := []struct {
		name     string
		a        *x509.Certificate
		b        *x509.Certificate
		expected bool
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: true,
		},
		{
			name:     "first nil",
			a:        nil,
			b:        cert1,
			expected: false,
		},
		{
			name:     "second nil",
			a:        cert1,
			b:        nil,
			expected: false,
		},
		{
			name:     "same certificate",
			a:        cert1,
			b:        cert1,
			expected: true,
		},
		{
			name:     "different certificates",
			a:        cert1,
			b:        cert2,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CertificatesMatch(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("CertificatesMatch() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// SerialNumbersMatch Tests
// =============================================================================

func TestSerialNumbersMatch(t *testing.T) {
	key := generateTestECDSAKey(t)

	cert1 := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(12345),
		commonName: "Cert 1",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key,
	})

	cert2 := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(12345),
		commonName: "Cert 2",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key,
	})

	cert3 := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(54321),
		commonName: "Cert 3",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key,
	})

	tests := []struct {
		name     string
		a        *x509.Certificate
		b        *x509.Certificate
		expected bool
	}{
		{
			name:     "first nil",
			a:        nil,
			b:        cert1,
			expected: false,
		},
		{
			name:     "second nil",
			a:        cert1,
			b:        nil,
			expected: false,
		},
		{
			name:     "same serial number",
			a:        cert1,
			b:        cert2,
			expected: true,
		},
		{
			name:     "different serial numbers",
			a:        cert1,
			b:        cert3,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SerialNumbersMatch(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("SerialNumbersMatch() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// IsIssuedBy Tests
// =============================================================================

func TestIsIssuedBy(t *testing.T) {
	caKey := generateTestECDSAKey(t)
	leafKey := generateTestECDSAKey(t)
	otherCAKey := generateTestECDSAKey(t)

	caCert := generateSelfSignedCA(t, caKey)
	otherCACert := generateSelfSignedCA(t, otherCAKey)
	leafCert := generateLeafCertificate(t, caCert, caKey, leafKey)

	tests := []struct {
		name     string
		cert     *x509.Certificate
		issuer   *x509.Certificate
		expected bool
	}{
		{
			name:     "cert is nil",
			cert:     nil,
			issuer:   caCert,
			expected: false,
		},
		{
			name:     "issuer is nil",
			cert:     leafCert,
			issuer:   nil,
			expected: false,
		},
		{
			name:     "valid issuer relationship",
			cert:     leafCert,
			issuer:   caCert,
			expected: true,
		},
		{
			name:     "wrong issuer",
			cert:     leafCert,
			issuer:   otherCACert,
			expected: false,
		},
		{
			name:     "self-signed CA issued by itself",
			cert:     caCert,
			issuer:   caCert,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIssuedBy(tt.cert, tt.issuer)
			if result != tt.expected {
				t.Errorf("IsIssuedBy() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// BuildCertPool Tests
// =============================================================================

func TestBuildCertPool(t *testing.T) {
	key := generateTestECDSAKey(t)

	cert1 := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "Cert 1",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key,
	})

	cert2 := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(2),
		commonName: "Cert 2",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key,
	})

	tests := []struct {
		name  string
		certs []*x509.Certificate
	}{
		{
			name:  "empty pool",
			certs: nil,
		},
		{
			name:  "single certificate",
			certs: []*x509.Certificate{cert1},
		},
		{
			name:  "multiple certificates",
			certs: []*x509.Certificate{cert1, cert2},
		},
		{
			name:  "with nil certificates",
			certs: []*x509.Certificate{cert1, nil, cert2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := BuildCertPool(tt.certs...)
			if pool == nil {
				t.Error("BuildCertPool() returned nil")
			}
		})
	}
}

// =============================================================================
// VerifyChain Tests
// =============================================================================

func TestVerifyChain(t *testing.T) {
	caKey := generateTestECDSAKey(t)
	leafKey := generateTestECDSAKey(t)

	caCert := generateSelfSignedCA(t, caKey)
	leafCert := generateLeafCertificate(t, caCert, caKey, leafKey)
	rootPool := BuildCertPool(caCert)

	tests := []struct {
		name          string
		cert          *x509.Certificate
		intermediates []*x509.Certificate
		roots         *x509.CertPool
		expectError   bool
		errorType     error
	}{
		{
			name:        "nil certificate",
			cert:        nil,
			roots:       rootPool,
			expectError: true,
			errorType:   ErrInvalidCertificate,
		},
		{
			name:        "nil roots",
			cert:        leafCert,
			roots:       nil,
			expectError: true,
			errorType:   ErrRootNotFound,
		},
		{
			name:  "valid chain",
			cert:  leafCert,
			roots: rootPool,
		},
		{
			name:        "invalid chain - wrong root",
			cert:        leafCert,
			roots:       x509.NewCertPool(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chains, err := VerifyChain(tt.cert, tt.intermediates, tt.roots)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Errorf("Expected error type %v, got %v", tt.errorType, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(chains) == 0 {
				t.Error("Expected at least one chain")
			}
		})
	}
}

// =============================================================================
// VerifyCertificateAgainstPublicKey Tests
// =============================================================================

func TestVerifyCertificateAgainstPublicKey_RSA(t *testing.T) {
	rsaKey := generateTestRSAKey(t)
	otherKey := generateTestRSAKey(t)

	cert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "RSA Cert",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        rsaKey,
	})

	tests := []struct {
		name        string
		cert        *x509.Certificate
		pubKey      crypto.PublicKey
		expectError bool
	}{
		{
			name:        "nil certificate",
			cert:        nil,
			pubKey:      &rsaKey.PublicKey,
			expectError: true,
		},
		{
			name:        "nil public key",
			cert:        cert,
			pubKey:      nil,
			expectError: true,
		},
		{
			name:   "valid RSA signature",
			cert:   cert,
			pubKey: &rsaKey.PublicKey,
		},
		{
			name:        "wrong RSA public key",
			cert:        cert,
			pubKey:      &otherKey.PublicKey,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyCertificateAgainstPublicKey(tt.cert, tt.pubKey)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyCertificateAgainstPublicKey_ECDSA(t *testing.T) {
	ecdsaKey := generateTestECDSAKey(t)
	otherKey := generateTestECDSAKey(t)

	cert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "ECDSA Cert",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        ecdsaKey,
	})

	tests := []struct {
		name        string
		cert        *x509.Certificate
		pubKey      crypto.PublicKey
		expectError bool
	}{
		{
			name:   "valid ECDSA signature",
			cert:   cert,
			pubKey: &ecdsaKey.PublicKey,
		},
		{
			name:        "wrong ECDSA public key",
			cert:        cert,
			pubKey:      &otherKey.PublicKey,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyCertificateAgainstPublicKey(tt.cert, tt.pubKey)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyCertificateAgainstPublicKey_Ed25519(t *testing.T) {
	ed25519Key := generateTestEd25519Key(t)
	otherKey := generateTestEd25519Key(t)

	cert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "Ed25519 Cert",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        ed25519Key,
	})

	tests := []struct {
		name        string
		cert        *x509.Certificate
		pubKey      crypto.PublicKey
		expectError bool
	}{
		{
			name:   "valid Ed25519 signature",
			cert:   cert,
			pubKey: ed25519Key.Public(),
		},
		{
			name:        "wrong Ed25519 public key",
			cert:        cert,
			pubKey:      otherKey.Public(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyCertificateAgainstPublicKey(tt.cert, tt.pubKey)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyCertificateAgainstPublicKey_UnsupportedKeyType(t *testing.T) {
	key := generateTestECDSAKey(t)
	cert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "Test Cert",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key,
	})

	// Pass an unsupported key type
	unsupportedKey := struct{}{}
	err := VerifyCertificateAgainstPublicKey(cert, unsupportedKey)
	if err == nil {
		t.Error("Expected error for unsupported key type, got nil")
	}
}

// =============================================================================
// VerifyCertificateSignature Tests
// =============================================================================

func TestVerifyCertificateSignature(t *testing.T) {
	caKey := generateTestECDSAKey(t)
	leafKey := generateTestECDSAKey(t)
	otherCAKey := generateTestECDSAKey(t)

	caCert := generateSelfSignedCA(t, caKey)
	otherCACert := generateSelfSignedCA(t, otherCAKey)
	leafCert := generateLeafCertificate(t, caCert, caKey, leafKey)

	tests := []struct {
		name        string
		cert        *x509.Certificate
		issuer      *x509.Certificate
		expectError bool
	}{
		{
			name:        "nil certificate",
			cert:        nil,
			issuer:      caCert,
			expectError: true,
		},
		{
			name:        "nil issuer",
			cert:        leafCert,
			issuer:      nil,
			expectError: true,
		},
		{
			name:   "valid signature",
			cert:   leafCert,
			issuer: caCert,
		},
		{
			name:        "issuer mismatch",
			cert:        leafCert,
			issuer:      otherCACert,
			expectError: true,
		},
		{
			name:   "self-signed",
			cert:   caCert,
			issuer: caCert,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyCertificateSignature(tt.cert, tt.issuer)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// VerifyWithOptions Tests
// =============================================================================

func TestVerifyWithOptions(t *testing.T) {
	caKey := generateTestECDSAKey(t)
	leafKey := generateTestECDSAKey(t)

	// Create CA with longer validity for backdated tests
	caCert := generateTestCertificate(t, testCertOptions{
		serial:       big.NewInt(1),
		commonName:   "Test Root CA",
		organization: "Test Org",
		notBefore:    time.Now().Add(-72 * time.Hour), // Valid from 72 hours ago
		notAfter:     time.Now().Add(365 * 24 * time.Hour),
		keyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		isCA:         true,
		maxPathLen:   1,
		key:          caKey,
	})
	leafCert := generateLeafCertificate(t, caCert, caKey, leafKey)
	rootPool := BuildCertPool(caCert)

	expiredCert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(200),
		commonName: "expired.example.com",
		notBefore:  time.Now().Add(-48 * time.Hour),
		notAfter:   time.Now().Add(-24 * time.Hour),
		key:        leafKey,
		parent:     caCert,
		signerKey:  caKey,
	})

	futureCert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(300),
		commonName: "future.example.com",
		notBefore:  time.Now().Add(24 * time.Hour),
		notAfter:   time.Now().Add(48 * time.Hour),
		key:        leafKey,
		parent:     caCert,
		signerKey:  caKey,
	})

	tests := []struct {
		name        string
		cert        *x509.Certificate
		opts        *VerifyOptions
		expectError bool
	}{
		{
			name:        "nil certificate",
			cert:        nil,
			opts:        &VerifyOptions{Roots: rootPool},
			expectError: true,
		},
		{
			name:        "nil options uses defaults",
			cert:        leafCert,
			opts:        nil,
			expectError: true, // Will fail because no roots
		},
		{
			name: "valid certificate",
			cert: leafCert,
			opts: &VerifyOptions{Roots: rootPool},
		},
		{
			name:        "expired certificate",
			cert:        expiredCert,
			opts:        &VerifyOptions{Roots: rootPool},
			expectError: true,
		},
		{
			name:        "not yet valid certificate",
			cert:        futureCert,
			opts:        &VerifyOptions{Roots: rootPool},
			expectError: true,
		},
		{
			name: "custom current time - valid",
			cert: expiredCert,
			opts: &VerifyOptions{
				Roots:       rootPool,
				CurrentTime: time.Now().Add(-36 * time.Hour),
			},
		},
		{
			name: "DNS name match",
			cert: leafCert,
			opts: &VerifyOptions{
				Roots:   rootPool,
				DNSName: "test.example.com",
			},
		},
		{
			name: "DNS name mismatch - different domain",
			cert: leafCert,
			opts: &VerifyOptions{
				Roots:   rootPool,
				DNSName: "test.other-domain.com", // Different domain, not matched by *.example.com
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chains, err := VerifyWithOptions(tt.cert, tt.opts)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(chains) == 0 {
				t.Error("Expected at least one chain")
			}
		})
	}
}

// =============================================================================
// VerificationError Tests
// =============================================================================

func TestVerificationError(t *testing.T) {
	key := generateTestECDSAKey(t)
	cert := generateTestCertificate(t, testCertOptions{
		serial:     big.NewInt(1),
		commonName: "Test Cert",
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		key:        key,
	})

	tests := []struct {
		name            string
		err             *VerificationError
		expectedMessage string
	}{
		{
			name: "error with reason only",
			err: &VerificationError{
				Cert:   cert,
				Reason: "test reason",
			},
			expectedMessage: "ca: verification failed: test reason",
		},
		{
			name: "error with wrapped error",
			err: &VerificationError{
				Cert:    cert,
				Reason:  "outer reason",
				Wrapped: errors.New("inner error"),
			},
			expectedMessage: "ca: verification failed: outer reason: inner error",
		},
		{
			name:            "error with no details",
			err:             &VerificationError{},
			expectedMessage: "ca: verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expectedMessage {
				t.Errorf("Error() = %q, want %q", tt.err.Error(), tt.expectedMessage)
			}
		})
	}
}

func TestVerificationError_Unwrap(t *testing.T) {
	innerErr := errors.New("inner error")
	err := &VerificationError{
		Reason:  "test",
		Wrapped: innerErr,
	}

	if err.Unwrap() != innerErr {
		t.Error("Unwrap() did not return wrapped error")
	}

	errNoWrap := &VerificationError{Reason: "test"}
	if errNoWrap.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no wrapped error")
	}
}

func TestVerificationError_Is(t *testing.T) {
	err1 := &VerificationError{Reason: "same reason"}
	err2 := &VerificationError{Reason: "same reason"}
	err3 := &VerificationError{Reason: "different reason"}

	if !err1.Is(err2) {
		t.Error("Is() should return true for same reason")
	}

	if err1.Is(err3) {
		t.Error("Is() should return false for different reason")
	}

	if err1.Is(errors.New("not a verification error")) {
		t.Error("Is() should return false for non-VerificationError")
	}
}

// =============================================================================
// PathLength Tests
// =============================================================================

func TestPathLength(t *testing.T) {
	key := generateTestECDSAKey(t)

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected int
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			expected: 0,
		},
		{
			name: "non-CA certificate",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(1),
				commonName: "Leaf",
				notBefore:  time.Now().Add(-time.Hour),
				notAfter:   time.Now().Add(24 * time.Hour),
				isCA:       false,
				key:        key,
			}),
			expected: -1,
		},
		{
			name: "CA with path length 0",
			cert: generateTestCertificate(t, testCertOptions{
				serial:         big.NewInt(2),
				commonName:     "CA PathLen 0",
				notBefore:      time.Now().Add(-time.Hour),
				notAfter:       time.Now().Add(24 * time.Hour),
				isCA:           true,
				maxPathLen:     0,
				maxPathLenZero: true,
				key:            key,
			}),
			expected: 0,
		},
		{
			name: "CA with path length 2",
			cert: generateTestCertificate(t, testCertOptions{
				serial:     big.NewInt(3),
				commonName: "CA PathLen 2",
				notBefore:  time.Now().Add(-time.Hour),
				notAfter:   time.Now().Add(24 * time.Hour),
				isCA:       true,
				maxPathLen: 2,
				key:        key,
			}),
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PathLength(tt.cert)
			if result != tt.expected {
				t.Errorf("PathLength() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// hashForSignatureAlgorithm Tests
// =============================================================================

func TestHashForSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		algo     x509.SignatureAlgorithm
		expected crypto.Hash
	}{
		{
			name:     "SHA256WithRSA",
			algo:     x509.SHA256WithRSA,
			expected: crypto.SHA256,
		},
		{
			name:     "SHA384WithRSA",
			algo:     x509.SHA384WithRSA,
			expected: crypto.SHA384,
		},
		{
			name:     "SHA512WithRSA",
			algo:     x509.SHA512WithRSA,
			expected: crypto.SHA512,
		},
		{
			name:     "SHA256WithRSAPSS",
			algo:     x509.SHA256WithRSAPSS,
			expected: crypto.SHA256,
		},
		{
			name:     "ECDSAWithSHA256",
			algo:     x509.ECDSAWithSHA256,
			expected: crypto.SHA256,
		},
		{
			name:     "ECDSAWithSHA384",
			algo:     x509.ECDSAWithSHA384,
			expected: crypto.SHA384,
		},
		{
			name:     "PureEd25519",
			algo:     x509.PureEd25519,
			expected: 0,
		},
		{
			name:     "Unknown algorithm",
			algo:     x509.SignatureAlgorithm(999),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hashForSignatureAlgorithm(tt.algo)
			if result != tt.expected {
				t.Errorf("hashForSignatureAlgorithm() = %v, want %v", result, tt.expected)
			}
		})
	}
}
