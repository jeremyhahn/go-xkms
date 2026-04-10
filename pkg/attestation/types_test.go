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

package attestation

import (
	"bytes"
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
			name: "empty signature",
			stmt: &AttestationStatement{
				Format:                "tpm2",
				AttestingKeyAlgorithm: x509.RSA,
				AttestingKeyPublic:    &publicKey,
				Signature:             []byte{},
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
		{
			name: "nil certificate chain",
			stmt: &AttestationStatement{
				Format:                "tpm2",
				AttestingKeyAlgorithm: x509.RSA,
				AttestingKeyPublic:    &publicKey,
				Signature:             []byte("test-signature"),
				CertificateChain:      nil,
				AttestedKeyPublic:     &publicKey,
				AttestationData:       []byte("test-data"),
				SignatureAlgorithm:    x509.SHA256WithRSA,
			},
			wantErr: true,
			errMsg:  "certificate chain is required",
		},
		{
			name: "unknown signature algorithm",
			stmt: &AttestationStatement{
				Format:                "tpm2",
				AttestingKeyAlgorithm: x509.RSA,
				AttestingKeyPublic:    &publicKey,
				Signature:             []byte("test-signature"),
				SignatureAlgorithm:    x509.UnknownSignatureAlgorithm,
				CertificateChain:      []*x509.Certificate{testCert},
				AttestedKeyPublic:     &publicKey,
				AttestationData:       []byte("test-data"),
			},
			wantErr: true,
			errMsg:  "signature algorithm is required",
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

// TestVerifyOptionsValidateDefaultFreshnessWindow verifies that zero freshness window gets default
func TestVerifyOptionsValidateDefaultFreshnessWindow(t *testing.T) {
	opts := &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 0,
	}

	err := opts.Validate()
	if err != nil {
		t.Errorf("Validate() should succeed and set default: %v", err)
	}

	if opts.FreshnessWindow != 300 {
		t.Errorf("Validate() should set default freshness window to 300, got %d", opts.FreshnessWindow)
	}
}

// TestVerifyOptionsValidateNoFreshnessCheck verifies window is not modified when check is disabled
func TestVerifyOptionsValidateNoFreshnessCheck(t *testing.T) {
	opts := &VerifyOptions{
		CheckFreshness:  false,
		FreshnessWindow: 0,
	}

	err := opts.Validate()
	if err != nil {
		t.Errorf("Validate() should succeed: %v", err)
	}

	if opts.FreshnessWindow != 0 {
		t.Errorf("Validate() should not modify freshness window when CheckFreshness is false, got %d", opts.FreshnessWindow)
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

// TestAttestationStatementStringNilCertChain tests String() with nil certificate chain
func TestAttestationStatementStringNilCertChain(t *testing.T) {
	stmt := &AttestationStatement{
		Format:             "tpm2",
		SignatureAlgorithm: x509.SHA256WithRSA,
		CertificateChain:   nil,
		Backend:            "tpm2",
	}

	str := stmt.String()
	if str == "" {
		t.Errorf("String() returned empty string")
	}

	if !contains(str, "Certs: 0") {
		t.Errorf("String() should show 0 certs for nil chain, got: %s", str)
	}
}

// TestAttestationStatementStringEmptyCertChain tests String() with empty certificate chain
func TestAttestationStatementStringEmptyCertChain(t *testing.T) {
	stmt := &AttestationStatement{
		Format:             "pkcs11",
		SignatureAlgorithm: x509.SHA384WithRSA,
		CertificateChain:   []*x509.Certificate{},
		Backend:            "pkcs11",
	}

	str := stmt.String()
	if str == "" {
		t.Errorf("String() returned empty string")
	}

	if !contains(str, "Certs: 0") {
		t.Errorf("String() should show 0 certs for empty chain, got: %s", str)
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

	if opts.TrustedRoots != nil {
		t.Errorf("DefaultVerifyOptions() TrustedRoots should be nil")
	}

	if opts.ExpectedNonce != nil {
		t.Errorf("DefaultVerifyOptions() ExpectedNonce should be nil")
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

	if opts.FreshnessWindow != 0 {
		t.Errorf("InsecureVerifyOptions() FreshnessWindow = %d, want 0", opts.FreshnessWindow)
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
		ChainValid:        true,
		SignatureValid:    false,
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

	if !bytes.Equal(hash1, hash2) {
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

	if bytes.Equal(hash1, hash2) {
		t.Errorf("Hash() should produce different hashes for different keys")
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
