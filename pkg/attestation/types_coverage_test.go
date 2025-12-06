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

// TestAttestationStatementValidateMissingSignatureAlgorithm tests validation with unknown signature algorithm
func TestAttestationStatementValidateMissingSignatureAlgorithm(t *testing.T) {
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
		SignatureAlgorithm:    x509.UnknownSignatureAlgorithm, // Unknown
		CertificateChain:      []*x509.Certificate{testCert},
		AttestedKeyPublic:     &publicKey,
		AttestationData:       []byte("test-data"),
	}

	err := stmt.Validate()
	if err == nil {
		t.Errorf("Validate() should fail with unknown signature algorithm")
	}

	expectedMsg := "signature algorithm is required"
	if err.Error() != expectedMsg {
		t.Errorf("Validate() error message = %v, want %v", err.Error(), expectedMsg)
	}
}

// TestAttestationStatementStringWithNilCertChain tests String method with nil certificate chain
func TestAttestationStatementStringWithNilCertChain(t *testing.T) {
	stmt := &AttestationStatement{
		Format:             "tpm2",
		SignatureAlgorithm: x509.SHA256WithRSA,
		CertificateChain:   nil, // Nil chain
		Backend:            "tpm2",
	}

	str := stmt.String()
	if str == "" {
		t.Errorf("String() returned empty string")
	}

	// Should contain "Certs: 0"
	if !contains(str, "Certs: 0") {
		t.Errorf("String() should show 0 certs for nil chain, got: %s", str)
	}
}

// TestAttestationStatementStringWithEmptyCertChain tests String method with empty certificate chain
func TestAttestationStatementStringWithEmptyCertChain(t *testing.T) {
	stmt := &AttestationStatement{
		Format:             "pkcs11",
		SignatureAlgorithm: x509.SHA384WithRSA,
		CertificateChain:   []*x509.Certificate{}, // Empty chain
		Backend:            "pkcs11",
	}

	str := stmt.String()
	if str == "" {
		t.Errorf("String() returned empty string")
	}

	// Should contain "Certs: 0"
	if !contains(str, "Certs: 0") {
		t.Errorf("String() should show 0 certs for empty chain, got: %s", str)
	}
}

// TestVerifyOptionsValidateDefaultFreshnessWindow tests that default freshness window is set
func TestVerifyOptionsValidateDefaultFreshnessWindow(t *testing.T) {
	opts := &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 0, // Zero should be set to default
	}

	err := opts.Validate()
	if err != nil {
		t.Errorf("Validate() should succeed and set default: %v", err)
	}

	if opts.FreshnessWindow != 300 {
		t.Errorf("Validate() should set default freshness window to 300, got %d", opts.FreshnessWindow)
	}
}

// TestVerifyOptionsValidateNoFreshnessCheck tests validation without freshness check
func TestVerifyOptionsValidateNoFreshnessCheck(t *testing.T) {
	opts := &VerifyOptions{
		CheckFreshness:  false,
		FreshnessWindow: 0, // Should not be modified since CheckFreshness is false
	}

	err := opts.Validate()
	if err != nil {
		t.Errorf("Validate() should succeed: %v", err)
	}

	if opts.FreshnessWindow != 0 {
		t.Errorf("Validate() should not modify freshness window when CheckFreshness is false, got %d", opts.FreshnessWindow)
	}
}

// TestResultStringInvalid tests Result.String with invalid result
func TestResultStringInvalid(t *testing.T) {
	result := &Result{
		Valid:             false,
		AttestationFormat: "pkcs11",
		ChainValid:        false,
		SignatureValid:    false,
	}

	str := result.String()
	if str == "" {
		t.Errorf("String() returned empty string")
	}

	if !contains(str, "INVALID") {
		t.Errorf("String() should indicate invalid, got: %s", str)
	}

	if !contains(str, "pkcs11") {
		t.Errorf("String() should contain format, got: %s", str)
	}
}

// TestResultStringPartiallyValid tests Result.String with mixed validity
func TestResultStringPartiallyValid(t *testing.T) {
	result := &Result{
		Valid:             false,
		AttestationFormat: "awskms",
		ChainValid:        true,  // Chain is valid
		SignatureValid:    false, // But signature is not
	}

	str := result.String()
	if str == "" {
		t.Errorf("String() returned empty string")
	}

	if !contains(str, "INVALID") {
		t.Errorf("String() should indicate overall invalid, got: %s", str)
	}

	if !contains(str, "Chain: true") {
		t.Errorf("String() should show chain validity, got: %s", str)
	}

	if !contains(str, "Signature: false") {
		t.Errorf("String() should show signature validity, got: %s", str)
	}
}

// TestDefaultVerifyOptionsValues tests all default option values
func TestDefaultVerifyOptionsValues(t *testing.T) {
	opts := DefaultVerifyOptions()

	if opts == nil {
		t.Fatalf("DefaultVerifyOptions() returned nil")
		return
	}

	if opts.CheckFreshness != true {
		t.Errorf("DefaultVerifyOptions() CheckFreshness = %v, want true", opts.CheckFreshness)
	}

	if opts.FreshnessWindow != 300 {
		t.Errorf("DefaultVerifyOptions() FreshnessWindow = %d, want 300", opts.FreshnessWindow)
	}

	if opts.AllowSelfSigned != false {
		t.Errorf("DefaultVerifyOptions() AllowSelfSigned = %v, want false", opts.AllowSelfSigned)
	}

	if opts.VerifyPCRs != false {
		t.Errorf("DefaultVerifyOptions() VerifyPCRs = %v, want false", opts.VerifyPCRs)
	}

	if opts.TrustedRoots != nil {
		t.Errorf("DefaultVerifyOptions() TrustedRoots should be nil")
	}

	if opts.ExpectedNonce != nil {
		t.Errorf("DefaultVerifyOptions() ExpectedNonce should be nil")
	}

	if opts.ExpectedPCRs != nil {
		t.Errorf("DefaultVerifyOptions() ExpectedPCRs should be nil")
	}

	if opts.CurrentTime != nil {
		t.Errorf("DefaultVerifyOptions() CurrentTime should be nil")
	}
}

// TestInsecureVerifyOptionsValues tests all insecure option values
func TestInsecureVerifyOptionsValues(t *testing.T) {
	opts := InsecureVerifyOptions()

	if opts == nil {
		t.Fatalf("InsecureVerifyOptions() returned nil")
		return
	}

	if opts.CheckFreshness != false {
		t.Errorf("InsecureVerifyOptions() CheckFreshness = %v, want false", opts.CheckFreshness)
	}

	if opts.AllowSelfSigned != true {
		t.Errorf("InsecureVerifyOptions() AllowSelfSigned = %v, want true", opts.AllowSelfSigned)
	}

	if opts.FreshnessWindow != 0 {
		t.Errorf("InsecureVerifyOptions() FreshnessWindow = %d, want 0", opts.FreshnessWindow)
	}
}

// TestAttestationStatementValidateAllFields tests comprehensive validation
func TestAttestationStatementValidateAllFields(t *testing.T) {
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

	// Test each required field individually
	tests := []struct {
		name     string
		modifyFn func(*AttestationStatement)
		wantErr  string
	}{
		{
			name: "all fields valid",
			modifyFn: func(stmt *AttestationStatement) {
				// No modification - should be valid
			},
			wantErr: "",
		},
		{
			name: "empty format",
			modifyFn: func(stmt *AttestationStatement) {
				stmt.Format = ""
			},
			wantErr: "attestation format is required",
		},
		{
			name: "nil attesting key",
			modifyFn: func(stmt *AttestationStatement) {
				stmt.AttestingKeyPublic = nil
			},
			wantErr: "attesting key public is required",
		},
		{
			name: "nil signature",
			modifyFn: func(stmt *AttestationStatement) {
				stmt.Signature = nil
			},
			wantErr: "signature is required",
		},
		{
			name: "empty signature",
			modifyFn: func(stmt *AttestationStatement) {
				stmt.Signature = []byte{}
			},
			wantErr: "signature is required",
		},
		{
			name: "nil attested key",
			modifyFn: func(stmt *AttestationStatement) {
				stmt.AttestedKeyPublic = nil
			},
			wantErr: "attested key public is required",
		},
		{
			name: "nil certificate chain",
			modifyFn: func(stmt *AttestationStatement) {
				stmt.CertificateChain = nil
			},
			wantErr: "certificate chain is required",
		},
		{
			name: "empty certificate chain",
			modifyFn: func(stmt *AttestationStatement) {
				stmt.CertificateChain = []*x509.Certificate{}
			},
			wantErr: "certificate chain is required",
		},
		{
			name: "unknown signature algorithm",
			modifyFn: func(stmt *AttestationStatement) {
				stmt.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
			},
			wantErr: "signature algorithm is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			tt.modifyFn(stmt)

			err := stmt.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error = %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error %q, got nil", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("Validate() error = %q, want %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

// TestAttestationStatementHashConsistency tests that Hash produces consistent results
func TestAttestationStatementHashConsistency(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		AttestedKeyPublic: publicKey,
	}

	hash1, err := stmt.Hash()
	if err != nil {
		t.Fatalf("Hash() failed: %v", err)
	}

	hash2, err := stmt.Hash()
	if err != nil {
		t.Fatalf("Hash() failed on second call: %v", err)
	}

	if !bytesEqual(hash1, hash2) {
		t.Errorf("Hash() should produce consistent results")
	}

	// Hash should be SHA256 (32 bytes)
	if len(hash1) != 32 {
		t.Errorf("Hash() returned %d bytes, want 32", len(hash1))
	}
}

// TestAttestationStatementHashDifferentKeys tests that different keys produce different hashes
func TestAttestationStatementHashDifferentKeys(t *testing.T) {
	privKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey1 := &privKey1.PublicKey

	privKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey2 := &privKey2.PublicKey

	stmt1 := &AttestationStatement{
		AttestedKeyPublic: publicKey1,
	}

	stmt2 := &AttestationStatement{
		AttestedKeyPublic: publicKey2,
	}

	hash1, err := stmt1.Hash()
	if err != nil {
		t.Fatalf("Hash() failed for key1: %v", err)
	}

	hash2, err := stmt2.Hash()
	if err != nil {
		t.Fatalf("Hash() failed for key2: %v", err)
	}

	if bytesEqual(hash1, hash2) {
		t.Errorf("Hash() should produce different hashes for different keys")
	}
}

// BenchmarkVerifyOptionsValidate benchmarks options validation
func BenchmarkVerifyOptionsValidate(b *testing.B) {
	opts := &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 300,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = opts.Validate()
	}
}

// BenchmarkAttestationStatementHash benchmarks hash computation
func BenchmarkAttestationStatementHash(b *testing.B) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		AttestedKeyPublic: publicKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = stmt.Hash()
	}
}
