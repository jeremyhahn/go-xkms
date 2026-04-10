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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertForDANE creates a self-signed test certificate.
func generateTestCertForDANE(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// writeCertPEM writes a certificate as PEM to a temporary file.
func writeCertPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "test.pem")

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	require.NoError(t, os.WriteFile(certFile, pemData, 0644))
	return certFile
}

// mockResolver is a test double for the tlsaResolver interface.
type mockResolver struct {
	records []tlsaRecord
	err     error
	// calledName and calledServer capture the arguments for verification.
	calledName   string
	calledServer string
}

func (m *mockResolver) LookupTLSA(tlsaName, dnsServer string) ([]tlsaRecord, error) {
	m.calledName = tlsaName
	m.calledServer = dnsServer
	return m.records, m.err
}

// withMockResolver replaces the package-level resolver with a mock for the
// duration of the test. It restores the original resolver when the test finishes.
func withMockResolver(t *testing.T, mock *mockResolver) {
	t.Helper()
	oldResolver := resolver
	resolver = mock
	t.Cleanup(func() { resolver = oldResolver })
}

// --- generateTLSA tests ---

func TestDANEGenerateTLSA(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	output := captureStdout(t, func() {
		generateTLSA(certFile, "kms.example.com", 443, TLSAUsageTrustAnchorAssertion, TLSASelectorSPKI, TLSAMatchSHA256, false)
	})

	// Verify the output format: _443._tcp.kms.example.com. IN TLSA 2 1 1 <hex>
	assert.Contains(t, output, "_443._tcp.kms.example.com.")
	assert.Contains(t, output, "IN TLSA")
	assert.Contains(t, output, "2 1 1")

	// Verify the hash matches what we compute manually
	expectedHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	expectedHex := hex.EncodeToString(expectedHash[:])
	assert.Contains(t, output, expectedHex)
}

func TestDANEGenerateTLSA_AllCombinations(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	output := captureStdout(t, func() {
		generateTLSA(certFile, "kms.example.com", 8443, 0, 0, 0, true)
	})

	lines := strings.Split(strings.TrimSpace(output), "\n")
	// generateCommonTLSARecords produces 6 records
	assert.Len(t, lines, 6)

	// All lines should use port 8443
	for _, line := range lines {
		assert.Contains(t, line, "_8443._tcp.kms.example.com.")
		assert.Contains(t, line, "IN TLSA")
	}

	// Check specific combos exist
	assert.Contains(t, output, "2 1 1") // DANE-TA SPKI SHA-256
	assert.Contains(t, output, "2 0 1") // DANE-TA Full SHA-256
	assert.Contains(t, output, "3 1 1") // DANE-EE SPKI SHA-256
	assert.Contains(t, output, "3 0 1") // DANE-EE Full SHA-256
	assert.Contains(t, output, "3 1 2") // DANE-EE SPKI SHA-512
	assert.Contains(t, output, "3 0 2") // DANE-EE Full SHA-512
}

func TestDANEGenerateTLSA_InvalidCertFile(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	generateTLSA("/nonexistent/cert.pem", "kms.example.com", 443, 2, 1, 1, false)
	assert.True(t, exitCalled)
}

func TestDANEGenerateTLSA_NoPEM(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "not-pem.txt")
	require.NoError(t, os.WriteFile(certFile, []byte("this is not PEM data"), 0644))

	generateTLSA(certFile, "kms.example.com", 443, 2, 1, 1, false)
	assert.True(t, exitCalled)
}

func TestDANEGenerateTLSA_MissingCertFile(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	generateTLSA("", "kms.example.com", 443, 2, 1, 1, false)
	assert.True(t, exitCalled)
}

func TestDANEGenerateTLSA_MissingHostname(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	generateTLSA(certFile, "", 443, 2, 1, 1, false)
	assert.True(t, exitCalled)
}

func TestDANEGenerateTLSA_InvalidSelector(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	generateTLSA(certFile, "kms.example.com", 443, 2, 99, 1, false)
	assert.True(t, exitCalled)
}

func TestDANEGenerateTLSA_InvalidMatchingType(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	generateTLSA(certFile, "kms.example.com", 443, 2, 1, 99, false)
	assert.True(t, exitCalled)
}

// --- showTLSA tests ---

func TestDANEShowTLSA_InvalidHostname(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	showTLSA("", 443, "")
	assert.True(t, exitCalled)
}

func TestDANEShowTLSA_DNSSuccess(t *testing.T) {
	cert := generateTestCertForDANE(t)
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spkiHex := hex.EncodeToString(spkiHash[:])

	mock := &mockResolver{
		records: []tlsaRecord{
			{
				Usage:        TLSAUsageDomainIssuedCert,
				Selector:     TLSASelectorSPKI,
				MatchingType: TLSAMatchSHA256,
				Data:         spkiHex,
			},
		},
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		showTLSA("kms.example.com", 443, "1.1.1.1:53")
	})

	// Verify query name was passed correctly
	assert.Equal(t, "_443._tcp.kms.example.com.", mock.calledName)
	assert.Equal(t, "1.1.1.1:53", mock.calledServer)

	// Verify output format
	assert.Contains(t, output, "TLSA record query: _443._tcp.kms.example.com.")
	assert.Contains(t, output, "DNS server:        1.1.1.1:53")
	assert.Contains(t, output, "Found 1 TLSA record(s):")
	assert.Contains(t, output, "Record 1:")
	assert.Contains(t, output, "3 - DANE-EE (Domain-Issued Certificate)")
	assert.Contains(t, output, "1 - SubjectPublicKeyInfo")
	assert.Contains(t, output, "1 - SHA-256")
	assert.Contains(t, output, spkiHex)
	assert.Contains(t, output, "IN TLSA 3 1 1")
}

func TestDANEShowTLSA_DNSMultipleRecords(t *testing.T) {
	cert := generateTestCertForDANE(t)
	spkiHash256 := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fullHash512 := sha512.Sum512(cert.Raw)

	mock := &mockResolver{
		records: []tlsaRecord{
			{
				Usage:        TLSAUsageTrustAnchorAssertion,
				Selector:     TLSASelectorSPKI,
				MatchingType: TLSAMatchSHA256,
				Data:         hex.EncodeToString(spkiHash256[:]),
			},
			{
				Usage:        TLSAUsageDomainIssuedCert,
				Selector:     TLSASelectorFullCert,
				MatchingType: TLSAMatchSHA512,
				Data:         hex.EncodeToString(fullHash512[:]),
			},
		},
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		showTLSA("secure.example.org", 8443, "9.9.9.9:53")
	})

	assert.Contains(t, output, "Found 2 TLSA record(s):")
	assert.Contains(t, output, "Record 1:")
	assert.Contains(t, output, "Record 2:")
	assert.Contains(t, output, "2 - DANE-TA (Trust Anchor Assertion)")
	assert.Contains(t, output, "3 - DANE-EE (Domain-Issued Certificate)")
	assert.Contains(t, output, "0 - Full Certificate")
	assert.Contains(t, output, "2 - SHA-512")
}

func TestDANEShowTLSA_DNSError(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	mock := &mockResolver{
		err: fmt.Errorf("%w: _443._tcp.norecords.example.com.: connection refused", ErrDNSQuery),
	}
	withMockResolver(t, mock)

	showTLSA("norecords.example.com", 443, "")
	assert.True(t, exitCalled)
}

func TestDANEShowTLSA_DNSNoRecords(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	mock := &mockResolver{
		err: fmt.Errorf("%w: _443._tcp.empty.example.com.", ErrDNSNoRecords),
	}
	withMockResolver(t, mock)

	showTLSA("empty.example.com", 443, "")
	assert.True(t, exitCalled)
}

func TestDANEShowTLSA_DefaultDNSServer(t *testing.T) {
	mock := &mockResolver{
		records: []tlsaRecord{
			{Usage: 3, Selector: 1, MatchingType: 1, Data: "abcd1234"},
		},
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		showTLSA("kms.example.com", 443, "")
	})

	// When dns-server is empty, should use defaultDNSServer
	assert.Equal(t, defaultDNSServer, mock.calledServer)
	assert.Contains(t, output, "DNS server:        "+defaultDNSServer)
}

func TestDANEShowTLSA_UnknownUsageValues(t *testing.T) {
	mock := &mockResolver{
		records: []tlsaRecord{
			{Usage: 255, Selector: 255, MatchingType: 255, Data: "deadbeef"},
		},
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		showTLSA("kms.example.com", 443, "8.8.8.8:53")
	})

	assert.Contains(t, output, "Unknown (255)")
}

func TestDANEShowTLSA_AllUsageLabels(t *testing.T) {
	records := []tlsaRecord{
		{Usage: TLSAUsageCAConstraint, Selector: TLSASelectorFullCert, MatchingType: TLSAMatchExact, Data: "aa"},
		{Usage: TLSAUsageServiceCertConstraint, Selector: TLSASelectorSPKI, MatchingType: TLSAMatchSHA256, Data: "bb"},
		{Usage: TLSAUsageTrustAnchorAssertion, Selector: TLSASelectorFullCert, MatchingType: TLSAMatchSHA512, Data: "cc"},
		{Usage: TLSAUsageDomainIssuedCert, Selector: TLSASelectorSPKI, MatchingType: TLSAMatchExact, Data: "dd"},
	}
	mock := &mockResolver{records: records}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		showTLSA("kms.example.com", 443, "8.8.8.8:53")
	})

	assert.Contains(t, output, "PKIX-TA (CA Constraint)")
	assert.Contains(t, output, "PKIX-EE (Service Certificate Constraint)")
	assert.Contains(t, output, "DANE-TA (Trust Anchor Assertion)")
	assert.Contains(t, output, "DANE-EE (Domain-Issued Certificate)")
	assert.Contains(t, output, "Full Certificate")
	assert.Contains(t, output, "SubjectPublicKeyInfo")
	assert.Contains(t, output, "Exact Match")
	assert.Contains(t, output, "SHA-256")
	assert.Contains(t, output, "SHA-512")
}

// --- verifyTLSA tests ---

func TestDANEVerifyTLSA_MissingHostname(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	verifyTLSA("some-file.pem", "", 443, "")
	assert.True(t, exitCalled)
}

func TestDANEVerifyTLSA_MissingCertFile(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	verifyTLSA("", "kms.example.com", 443, "")
	assert.True(t, exitCalled)
}

func TestDANEVerifyTLSA_DNSMatchingRecord(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spkiHex := hex.EncodeToString(spkiHash[:])

	mock := &mockResolver{
		records: []tlsaRecord{
			{
				Usage:        TLSAUsageDomainIssuedCert,
				Selector:     TLSASelectorSPKI,
				MatchingType: TLSAMatchSHA256,
				Data:         spkiHex,
			},
		},
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		verifyTLSA(certFile, "kms.example.com", 443, "1.1.1.1:53")
	})

	assert.Contains(t, output, "TLSA verification for:")
	assert.Contains(t, output, "Found 1 TLSA record(s) in DNS:")
	assert.Contains(t, output, "Verification:  MATCH")
	assert.Contains(t, output, "Result: 1 of 1 record(s) matched")
}

func TestDANEVerifyTLSA_DNSMismatchingRecord(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	mock := &mockResolver{
		records: []tlsaRecord{
			{
				Usage:        TLSAUsageDomainIssuedCert,
				Selector:     TLSASelectorSPKI,
				MatchingType: TLSAMatchSHA256,
				Data:         "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		verifyTLSA(certFile, "kms.example.com", 443, "8.8.8.8:53")
	})

	assert.Contains(t, output, "Verification:  MISMATCH")
	assert.Contains(t, output, "Expected:")
	assert.Contains(t, output, "Result: 0 of 1 record(s) matched")
	assert.True(t, exitCalled, "should call exit on zero matches")
}

func TestDANEVerifyTLSA_DNSMixedMatchMismatch(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spkiHex := hex.EncodeToString(spkiHash[:])

	mock := &mockResolver{
		records: []tlsaRecord{
			{
				Usage:        TLSAUsageDomainIssuedCert,
				Selector:     TLSASelectorSPKI,
				MatchingType: TLSAMatchSHA256,
				Data:         spkiHex, // This one matches
			},
			{
				Usage:        TLSAUsageDomainIssuedCert,
				Selector:     TLSASelectorFullCert,
				MatchingType: TLSAMatchSHA256,
				Data:         "aaaa", // This one does not match
			},
		},
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		verifyTLSA(certFile, "kms.example.com", 443, "8.8.8.8:53")
	})

	assert.Contains(t, output, "Verification:  MATCH")
	assert.Contains(t, output, "Verification:  MISMATCH")
	assert.Contains(t, output, "Result: 1 of 2 record(s) matched")
}

func TestDANEVerifyTLSA_DNSUnsupportedSelectorSkipped(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	mock := &mockResolver{
		records: []tlsaRecord{
			{
				Usage:        TLSAUsageDomainIssuedCert,
				Selector:     99, // unsupported
				MatchingType: TLSAMatchSHA256,
				Data:         "deadbeef",
			},
		},
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		verifyTLSA(certFile, "kms.example.com", 443, "8.8.8.8:53")
	})

	assert.Contains(t, output, "SKIP (unsupported selector/matching type)")
	assert.Contains(t, output, "Result: 0 of 1 record(s) matched")
	assert.True(t, exitCalled, "should call exit when zero matches after skips")
}

func TestDANEVerifyTLSA_DNSLookupFails_FallsBackToLocal(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	mock := &mockResolver{
		err: fmt.Errorf("%w: _443._tcp.kms.example.com.: timeout", ErrDNSQuery),
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		verifyTLSA(certFile, "kms.example.com", 443, "")
	})

	assert.Contains(t, output, "TLSA verification for:")
	assert.Contains(t, output, "DNS lookup:")
	assert.Contains(t, output, "Falling back to local verification")
	assert.Contains(t, output, "Expected TLSA records from certificate:")
}

func TestDANEVerifyTLSA_DefaultDNSServer(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spkiHex := hex.EncodeToString(spkiHash[:])

	mock := &mockResolver{
		records: []tlsaRecord{
			{Usage: 3, Selector: 1, MatchingType: 1, Data: spkiHex},
		},
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		verifyTLSA(certFile, "kms.example.com", 443, "")
	})

	assert.Equal(t, defaultDNSServer, mock.calledServer)
	assert.Contains(t, output, "DNS server:            "+defaultDNSServer)
}

func TestDANEVerifyTLSA_CaseInsensitiveDataMatch(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	// Use uppercase hex to verify case-insensitive comparison
	spkiHex := strings.ToUpper(hex.EncodeToString(spkiHash[:]))

	mock := &mockResolver{
		records: []tlsaRecord{
			{
				Usage:        TLSAUsageDomainIssuedCert,
				Selector:     TLSASelectorSPKI,
				MatchingType: TLSAMatchSHA256,
				Data:         spkiHex,
			},
		},
	}
	withMockResolver(t, mock)

	output := captureStdout(t, func() {
		verifyTLSA(certFile, "kms.example.com", 443, "8.8.8.8:53")
	})

	assert.Contains(t, output, "Verification:  MATCH")
}

// --- formatTLSAName tests ---

func TestFormatTLSAName(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		port     int
		want     string
	}{
		{
			name:     "standard hostname",
			hostname: "kms.example.com",
			port:     443,
			want:     "_443._tcp.kms.example.com.",
		},
		{
			name:     "hostname with trailing dot",
			hostname: "kms.example.com.",
			port:     443,
			want:     "_443._tcp.kms.example.com.",
		},
		{
			name:     "custom port",
			hostname: "kms.example.com",
			port:     8443,
			want:     "_8443._tcp.kms.example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatTLSAName(tt.hostname, tt.port)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- computeTLSAData tests ---

func TestComputeTLSAData(t *testing.T) {
	cert := generateTestCertForDANE(t)

	tests := []struct {
		name         string
		selector     int
		matchingType int
		wantErr      bool
		errTarget    error
		validate     func(t *testing.T, data string)
	}{
		{
			name:         "SPKI SHA-256",
			selector:     TLSASelectorSPKI,
			matchingType: TLSAMatchSHA256,
			validate: func(t *testing.T, data string) {
				expected := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				assert.Equal(t, hex.EncodeToString(expected[:]), data)
			},
		},
		{
			name:         "full cert SHA-256",
			selector:     TLSASelectorFullCert,
			matchingType: TLSAMatchSHA256,
			validate: func(t *testing.T, data string) {
				expected := sha256.Sum256(cert.Raw)
				assert.Equal(t, hex.EncodeToString(expected[:]), data)
			},
		},
		{
			name:         "SPKI SHA-512",
			selector:     TLSASelectorSPKI,
			matchingType: TLSAMatchSHA512,
			validate: func(t *testing.T, data string) {
				expected := sha512.Sum512(cert.RawSubjectPublicKeyInfo)
				assert.Equal(t, hex.EncodeToString(expected[:]), data)
			},
		},
		{
			name:         "full cert exact",
			selector:     TLSASelectorFullCert,
			matchingType: TLSAMatchExact,
			validate: func(t *testing.T, data string) {
				assert.Equal(t, hex.EncodeToString(cert.Raw), data)
			},
		},
		{
			name:         "invalid selector",
			selector:     99,
			matchingType: TLSAMatchSHA256,
			wantErr:      true,
			errTarget:    ErrTLSAInvalidSelector,
		},
		{
			name:         "invalid matching type",
			selector:     TLSASelectorSPKI,
			matchingType: 99,
			wantErr:      true,
			errTarget:    ErrTLSAInvalidMatchingType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := computeTLSAData(cert, tt.selector, tt.matchingType)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errTarget != nil {
					assert.True(t, errors.Is(err, tt.errTarget),
						"expected error wrapping %v, got %v", tt.errTarget, err)
				}
				return
			}
			require.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// --- generateCommonTLSARecords tests ---

func TestGenerateCommonTLSARecords(t *testing.T) {
	cert := generateTestCertForDANE(t)
	records := generateCommonTLSARecords(cert)

	// Should produce 6 common combinations
	assert.Len(t, records, 6)

	// Verify each record has non-empty data
	for _, rec := range records {
		assert.NotEmpty(t, rec.Data)
		assert.True(t, rec.Usage >= 0 && rec.Usage <= 3)
		assert.True(t, rec.Selector >= 0 && rec.Selector <= 1)
		assert.True(t, rec.MatchingType >= 0 && rec.MatchingType <= 2)
	}

	// Verify specific records
	assert.Equal(t, TLSAUsageTrustAnchorAssertion, records[0].Usage)
	assert.Equal(t, TLSASelectorSPKI, records[0].Selector)
	assert.Equal(t, TLSAMatchSHA256, records[0].MatchingType)

	assert.Equal(t, TLSAUsageDomainIssuedCert, records[2].Usage)
	assert.Equal(t, TLSASelectorSPKI, records[2].Selector)
	assert.Equal(t, TLSAMatchSHA256, records[2].MatchingType)
}

// --- loadCertFromPEM tests ---

func TestLoadCertFromPEM(t *testing.T) {
	cert := generateTestCertForDANE(t)
	certFile := writeCertPEM(t, cert)

	loaded, err := loadCertFromPEM(certFile)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, loaded.Raw)
}

func TestLoadCertFromPEM_FileNotFound(t *testing.T) {
	_, err := loadCertFromPEM("/nonexistent/cert.pem")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read certificate file")
}

func TestLoadCertFromPEM_NoPEM(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "bad.txt")
	require.NoError(t, os.WriteFile(certFile, []byte("not PEM"), 0644))

	_, err := loadCertFromPEM(certFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM data found")
}

func TestLoadCertFromPEM_InvalidDER(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "bad-der.pem")
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER"),
	}
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(pemBlock), 0644))

	_, err := loadCertFromPEM(certFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

// --- dnsResolver unit tests (error wrapping) ---

func TestDNSResolverLookupTLSA_ErrorWrapping(t *testing.T) {
	// Verify that the sentinel errors are properly used by the resolver
	// by checking they exist and are distinct
	assert.NotEqual(t, ErrDNSQuery.Error(), ErrDNSNoRecords.Error())
	assert.NotEqual(t, ErrDNSQuery.Error(), ErrDNSResponseCode.Error())
	assert.NotEqual(t, ErrDNSNoRecords.Error(), ErrDNSResponseCode.Error())
}

// --- printTLSARecordDetails tests ---

func TestPrintTLSARecordDetails_AllKnownValues(t *testing.T) {
	tests := []struct {
		name     string
		record   tlsaRecord
		contains []string
	}{
		{
			name:   "CA Constraint with Full Cert Exact Match",
			record: tlsaRecord{Usage: 0, Selector: 0, MatchingType: 0, Data: "aabbccdd"},
			contains: []string{
				"PKIX-TA (CA Constraint)",
				"Full Certificate",
				"Exact Match",
				"aabbccdd",
			},
		},
		{
			name:   "Service Cert with SPKI SHA-256",
			record: tlsaRecord{Usage: 1, Selector: 1, MatchingType: 1, Data: "11223344"},
			contains: []string{
				"PKIX-EE (Service Certificate Constraint)",
				"SubjectPublicKeyInfo",
				"SHA-256",
				"11223344",
			},
		},
		{
			name:   "DANE-TA with SPKI SHA-512",
			record: tlsaRecord{Usage: 2, Selector: 1, MatchingType: 2, Data: "55667788"},
			contains: []string{
				"DANE-TA (Trust Anchor Assertion)",
				"SubjectPublicKeyInfo",
				"SHA-512",
				"55667788",
			},
		},
		{
			name:   "Unknown values",
			record: tlsaRecord{Usage: 10, Selector: 5, MatchingType: 7, Data: "ff"},
			contains: []string{
				"Unknown (10)",
				"Unknown (5)",
				"Unknown (7)",
				"ff",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(t, func() {
				printTLSARecordDetails(tt.record)
			})
			for _, expected := range tt.contains {
				assert.Contains(t, output, expected)
			}
		})
	}
}

// --- TLSA label map coverage ---

func TestTLSAUsageLabels_Complete(t *testing.T) {
	assert.Equal(t, "PKIX-TA (CA Constraint)", tlsaUsageLabels[TLSAUsageCAConstraint])
	assert.Equal(t, "PKIX-EE (Service Certificate Constraint)", tlsaUsageLabels[TLSAUsageServiceCertConstraint])
	assert.Equal(t, "DANE-TA (Trust Anchor Assertion)", tlsaUsageLabels[TLSAUsageTrustAnchorAssertion])
	assert.Equal(t, "DANE-EE (Domain-Issued Certificate)", tlsaUsageLabels[TLSAUsageDomainIssuedCert])
	assert.Len(t, tlsaUsageLabels, 4)
}

func TestTLSASelectorLabels_Complete(t *testing.T) {
	assert.Equal(t, "Full Certificate", tlsaSelectorLabels[TLSASelectorFullCert])
	assert.Equal(t, "SubjectPublicKeyInfo", tlsaSelectorLabels[TLSASelectorSPKI])
	assert.Len(t, tlsaSelectorLabels, 2)
}

func TestTLSAMatchingTypeLabels_Complete(t *testing.T) {
	assert.Equal(t, "Exact Match", tlsaMatchingTypeLabels[TLSAMatchExact])
	assert.Equal(t, "SHA-256", tlsaMatchingTypeLabels[TLSAMatchSHA256])
	assert.Equal(t, "SHA-512", tlsaMatchingTypeLabels[TLSAMatchSHA512])
	assert.Len(t, tlsaMatchingTypeLabels, 3)
}
