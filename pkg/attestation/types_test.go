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

package attestation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestAttestationStatementValidate tests attestation statement validation
func TestAttestationStatementValidate(t *testing.T) {
	// Generate test RSA key pair for testing
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey

	// Generate test certificate
	testCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Attesting Key",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	tests := []struct {
		name    string
		stmt    *AttestationStatement
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid attestation statement",
			stmt: &AttestationStatement{
				Format:                "tpm2",
				AttestingKeyAlgorithm: x509.RSA,
				AttestingKeyPublic:    &publicKey,
				Signature:             []byte("test-signature"),
				SignatureAlgorithm:    x509.SHA256WithRSA,
				CertificateChain:      []*x509.Certificate{testCert},
				AttestedKeyPublic:     &publicKey,
				AttestationData:       []byte("test-data"),
			},
			wantErr: false,
		},
		{
			name: "missing format",
			stmt: &AttestationStatement{
				Format:             "",
				AttestingKeyPublic: &publicKey,
				Signature:          []byte("test-signature"),
				CertificateChain:   []*x509.Certificate{testCert},
				AttestedKeyPublic:  &publicKey,
				AttestationData:    []byte("test-data"),
				SignatureAlgorithm: x509.SHA256WithRSA,
			},
			wantErr: true,
			errMsg:  "attestation format is required",
		},
		{
			name: "missing attesting key public",
			stmt: &AttestationStatement{
				Format:             "tpm2",
				AttestingKeyPublic: nil,
				Signature:          []byte("test-signature"),
				CertificateChain:   []*x509.Certificate{testCert},
				AttestedKeyPublic:  &publicKey,
				AttestationData:    []byte("test-data"),
				SignatureAlgorithm: x509.SHA256WithRSA,
			},
			wantErr: true,
			errMsg:  "attesting key public is required",
		},
		{
			name: "missing signature",
			stmt: &AttestationStatement{
				Format:                "tpm2",
				AttestingKeyAlgorithm: x509.RSA,
				AttestingKeyPublic:    &publicKey,
				Signature:             nil,
				CertificateChain:      []*x509.Certificate{testCert},
				AttestedKeyPublic:     &publicKey,
				AttestationData:       []byte("test-data"),
				SignatureAlgorithm:    x509.SHA256WithRSA,
			},
			wantErr: true,
			errMsg:  "signature is required",
		},
		{
			name: "missing attested key public",
			stmt: &AttestationStatement{
				Format:                "tpm2",
				AttestingKeyAlgorithm: x509.RSA,
				AttestingKeyPublic:    &publicKey,
				Signature:             []byte("test-signature"),
				CertificateChain:      []*x509.Certificate{testCert},
				AttestedKeyPublic:     nil,
				AttestationData:       []byte("test-data"),
				SignatureAlgorithm:    x509.SHA256WithRSA,
			},
			wantErr: true,
			errMsg:  "attested key public is required",
		},
		{
			name: "empty certificate chain",
			stmt: &AttestationStatement{
				Format:                "tpm2",
				AttestingKeyAlgorithm: x509.RSA,
				AttestingKeyPublic:    &publicKey,
				Signature:             []byte("test-signature"),
				CertificateChain:      []*x509.Certificate{},
				AttestedKeyPublic:     &publicKey,
				AttestationData:       []byte("test-data"),
				SignatureAlgorithm:    x509.SHA256WithRSA,
			},
			wantErr: true,
			errMsg:  "certificate chain is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.stmt.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("Validate() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestVerifyOptionsValidate tests verification options validation
func TestVerifyOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		opts    *VerifyOptions
		wantErr bool
	}{
		{
			name:    "nil options",
			opts:    nil,
			wantErr: true,
		},
		{
			name: "valid options",
			opts: &VerifyOptions{
				CheckFreshness:  true,
				FreshnessWindow: 300,
			},
			wantErr: false,
		},
		{
			name: "negative freshness window",
			opts: &VerifyOptions{
				CheckFreshness:  true,
				FreshnessWindow: -1,
			},
			wantErr: true,
		},
		{
			name: "zero freshness window with freshness check",
			opts: &VerifyOptions{
				CheckFreshness:  true,
				FreshnessWindow: 0,
			},
			wantErr: false, // Should be set to default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestAttestationStatementString tests string representation
func TestAttestationStatementString(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey

	testCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Attesting Key",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    &publicKey,
		Signature:             []byte("test-signature"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{testCert},
		AttestedKeyPublic:     &publicKey,
		Backend:               "tpm2",
	}

	str := stmt.String()
	if str == "" {
		t.Errorf("String() returned empty string")
	}

	// Verify key information is in the string
	if !contains(str, "tpm2") {
		t.Errorf("String() should contain format, got: %s", str)
	}

	if !contains(str, "Certs:") {
		t.Errorf("String() should contain cert count, got: %s", str)
	}
}

// TestDefaultVerifyOptions tests default verification options
func TestDefaultVerifyOptions(t *testing.T) {
	opts := DefaultVerifyOptions()

	if !opts.CheckFreshness {
		t.Errorf("DefaultVerifyOptions() should enable freshness check")
	}

	if opts.FreshnessWindow != 300 {
		t.Errorf("DefaultVerifyOptions() freshness window = %d, want 300", opts.FreshnessWindow)
	}

	if opts.AllowSelfSigned {
		t.Errorf("DefaultVerifyOptions() should not allow self-signed by default")
	}
}

// TestInsecureVerifyOptions tests insecure verification options
func TestInsecureVerifyOptions(t *testing.T) {
	opts := InsecureVerifyOptions()

	if opts.CheckFreshness {
		t.Errorf("InsecureVerifyOptions() should not check freshness")
	}

	if !opts.AllowSelfSigned {
		t.Errorf("InsecureVerifyOptions() should allow self-signed")
	}
}

// TestResultString tests result string representation
func TestResultString(t *testing.T) {
	result := &Result{
		Valid:             true,
		AttestationFormat: "tpm2",
		ChainValid:        true,
		SignatureValid:    true,
	}

	str := result.String()
	if str == "" {
		t.Errorf("String() returned empty string")
	}

	if !contains(str, "VALID") {
		t.Errorf("String() should indicate valid, got: %s", str)
	}

	if !contains(str, "tpm2") {
		t.Errorf("String() should contain format, got: %s", str)
	}
}

// Helper function to check if string contains substring
func contains(str, substr string) bool {
	for i := 0; i < len(str)-len(substr)+1; i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// BenchmarkAttestationStatementValidate benchmarks validation
func BenchmarkAttestationStatementValidate(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey

	testCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Attesting Key",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    &publicKey,
		Signature:             []byte("test-signature"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{testCert},
		AttestedKeyPublic:     &publicKey,
		AttestationData:       []byte("test-data"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stmt.Validate()
	}
}
