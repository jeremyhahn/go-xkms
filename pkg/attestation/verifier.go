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
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// Verifier implements the Attestation interface and provides
// cryptographic verification of attestation statements.
type Verifier struct {
	// trustedRoots are root certificates trusted for chain validation
	trustedRoots []*x509.Certificate
}

// NewVerifier creates a new attestation verifier.
//
// Parameters:
//   - trustedRoots: Root certificates to trust (can be empty for self-signed)
//
// Returns:
//   - A new Verifier instance
func NewVerifier(trustedRoots []*x509.Certificate) *Verifier {
	roots := make([]*x509.Certificate, len(trustedRoots))
	copy(roots, trustedRoots)
	return &Verifier{
		trustedRoots: roots,
	}
}

// Verify validates the entire attestation statement.
//
// Performs three main checks:
//  1. Certificate chain validation
//  2. Signature verification
//  3. Optional freshness and PCR validation
func (v *Verifier) Verify(stmt *AttestationStatement, opts *VerifyOptions) error {
	if err := stmt.Validate(); err != nil {
		return fmt.Errorf("attestation: invalid statement: %w", err)
	}

	if err := opts.Validate(); err != nil {
		return fmt.Errorf("attestation: invalid options: %w", err)
	}

	result := &Result{
		AttestationFormat: stmt.Format,
	}

	// Verify certificate chain
	if err := v.VerifyChain(stmt, opts); err != nil {
		result.ChainValid = false
		result.ChainErrors = append(result.ChainErrors, err)
		result.Error = err
		return err
	}
	result.ChainValid = true

	// Verify signature
	if err := v.VerifySignature(stmt, opts); err != nil {
		result.SignatureValid = false
		result.Error = err
		return fmt.Errorf("attestation: signature verification failed: %w", err)
	}
	result.SignatureValid = true

	// Verify freshness if requested
	if opts.CheckFreshness {
		if err := v.verifyFreshness(stmt, opts); err != nil {
			result.FreshnessValid = false
			result.Error = err
			return fmt.Errorf("attestation: freshness check failed: %w", err)
		}
		result.FreshnessValid = true
	}

	// Verify PCRs if requested (TPM2 only)
	if opts.VerifyPCRs && stmt.PCRValues != nil {
		if err := v.verifyPCRs(stmt, opts); err != nil {
			result.PCRsValid = false
			result.Error = err
			return fmt.Errorf("attestation: PCR verification failed: %w", err)
		}
		result.PCRsValid = true
	}

	result.Valid = true
	return nil
}

// VerifyChain validates the certificate chain in the attestation statement.
func (v *Verifier) VerifyChain(stmt *AttestationStatement, opts *VerifyOptions) error {
	if stmt.CertificateChain == nil || len(stmt.CertificateChain) == 0 {
		return errors.New("attestation: empty certificate chain")
	}

	// Get the attesting certificate (leaf)
	attestingCert := stmt.CertificateChain[0]

	// Verify the leaf certificate is not expired
	now := time.Now()
	if opts.CurrentTime != nil {
		now = time.Unix(*opts.CurrentTime, 0)
	}

	if now.Before(attestingCert.NotBefore) {
		return fmt.Errorf("attestation: certificate not yet valid (valid from %s)", attestingCert.NotBefore)
	}

	if now.After(attestingCert.NotAfter) {
		return fmt.Errorf("attestation: certificate expired (expired at %s)", attestingCert.NotAfter)
	}

	// If only one cert and it's self-signed, handle specially
	if len(stmt.CertificateChain) == 1 {
		if attestingCert.SignatureAlgorithm == x509.SHA256WithRSA ||
			attestingCert.SignatureAlgorithm == x509.SHA384WithRSA ||
			attestingCert.SignatureAlgorithm == x509.SHA512WithRSA {
			// Verify self-signed certificate
			if err := attestingCert.CheckSignature(attestingCert.SignatureAlgorithm,
				attestingCert.RawTBSCertificate,
				attestingCert.Signature); err != nil {
				return fmt.Errorf("attestation: invalid self-signed certificate: %w", err)
			}
		}
		return nil
	}

	// Verify chain of signatures
	for i := 0; i < len(stmt.CertificateChain)-1; i++ {
		currentCert := stmt.CertificateChain[i]
		nextCert := stmt.CertificateChain[i+1]

		// Verify current cert is signed by next cert
		if err := nextCert.CheckSignature(currentCert.SignatureAlgorithm,
			currentCert.RawTBSCertificate,
			currentCert.Signature); err != nil {
			return fmt.Errorf("attestation: invalid certificate chain at position %d: %w", i, err)
		}

		// Verify next cert is not expired
		if now.Before(nextCert.NotBefore) {
			return fmt.Errorf("attestation: intermediate certificate %d not yet valid", i+1)
		}

		if now.After(nextCert.NotAfter) {
			return fmt.Errorf("attestation: intermediate certificate %d expired", i+1)
		}
	}

	return nil
}

// VerifySignature verifies the cryptographic signature over the attestation data.
func (v *Verifier) VerifySignature(stmt *AttestationStatement, opts *VerifyOptions) error {
	if len(stmt.Signature) == 0 {
		return errors.New("attestation: signature is empty")
	}

	if stmt.AttestingKeyPublic == nil {
		return errors.New("attestation: attesting key public is nil")
	}

	// The data being signed is the attestation data
	dataToVerify := stmt.AttestationData
	if len(dataToVerify) == 0 {
		// Fallback: use public key bytes for verification
		pubBytes, err := x509.MarshalPKIXPublicKey(stmt.AttestedKeyPublic)
		if err != nil {
			return fmt.Errorf("attestation: failed to marshal attested key: %w", err)
		}
		dataToVerify = pubBytes
	}

	// Determine signature algorithm and verify
	switch pubKey := stmt.AttestingKeyPublic.(type) {
	case *rsa.PublicKey:
		return v.verifyRSASignature(pubKey, stmt.Signature, dataToVerify, stmt.SignatureAlgorithm)
	default:
		return fmt.Errorf("attestation: unsupported public key type: %T", stmt.AttestingKeyPublic)
	}
}

// verifyRSASignature verifies an RSA signature.
func (v *Verifier) verifyRSASignature(pubKey *rsa.PublicKey, sig, data []byte, sigAlg x509.SignatureAlgorithm) error {
	var hash crypto.Hash
	var hashFunc func() crypto.Hash

	switch sigAlg {
	case x509.SHA256WithRSA:
		hash = crypto.SHA256
		hashFunc = func() crypto.Hash { return crypto.SHA256 }
	case x509.SHA384WithRSA:
		hash = crypto.SHA384
		hashFunc = func() crypto.Hash { return crypto.SHA384 }
	case x509.SHA512WithRSA:
		hash = crypto.SHA512
		hashFunc = func() crypto.Hash { return crypto.SHA512 }
	default:
		return fmt.Errorf("attestation: unsupported signature algorithm: %s", sigAlg)
	}

	// Create hash of the data
	h := hash.New()
	if h == nil {
		return fmt.Errorf("attestation: unsupported hash algorithm: %s", hash)
	}
	h.Write(data)
	digest := h.Sum(nil)

	// Verify PKCS#1 v1.5 signature
	err := rsa.VerifyPKCS1v15(pubKey, hashFunc(), digest, sig)
	if err != nil {
		return fmt.Errorf("attestation: signature verification failed: %w", err)
	}

	return nil
}

// verifyFreshness checks that the attestation is not too old.
func (v *Verifier) verifyFreshness(stmt *AttestationStatement, opts *VerifyOptions) error {
	if opts.ExpectedNonce != nil {
		if !bytesEqual(stmt.Nonce, opts.ExpectedNonce) {
			return errors.New("attestation: nonce mismatch (replay attack detected)")
		}
	}

	if stmt.CreatedAt == "" {
		return errors.New("attestation: created timestamp is missing")
	}

	createdTime, err := time.Parse(time.RFC3339, stmt.CreatedAt)
	if err != nil {
		return fmt.Errorf("attestation: invalid created timestamp: %w", err)
	}

	now := time.Now()
	if opts.CurrentTime != nil {
		now = time.Unix(*opts.CurrentTime, 0)
	}

	age := now.Sub(createdTime)
	if age < 0 {
		return errors.New("attestation: created time is in the future (clock skew)")
	}

	window := time.Duration(opts.FreshnessWindow) * time.Second
	if age > window {
		return fmt.Errorf("attestation: too old (age: %v, allowed: %v)", age, window)
	}

	return nil
}

// verifyPCRs checks that TPM PCR values match expected values.
func (v *Verifier) verifyPCRs(stmt *AttestationStatement, opts *VerifyOptions) error {
	if stmt.PCRValues == nil || len(stmt.PCRValues) == 0 {
		if len(opts.ExpectedPCRs) > 0 {
			return errors.New("attestation: expected PCRs but none provided in attestation")
		}
		return nil
	}

	// If no expected PCRs provided, just verify PCRs exist
	if len(opts.ExpectedPCRs) == 0 {
		return nil
	}

	// Verify each expected PCR
	for pcrIdx, expectedDigest := range opts.ExpectedPCRs {
		actualDigest, ok := stmt.PCRValues[pcrIdx]
		if !ok {
			return fmt.Errorf("attestation: PCR %d not provided in attestation", pcrIdx)
		}

		if !bytesEqual(actualDigest, expectedDigest) {
			return fmt.Errorf("attestation: PCR %d mismatch (expected %x, got %x)",
				pcrIdx, expectedDigest, actualDigest)
		}
	}

	return nil
}

// Helper function to compare byte slices securely
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// Hash returns a hash of the attested public key.
func (stmt *AttestationStatement) Hash() ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(stmt.AttestedKeyPublic)
	if err != nil {
		return nil, fmt.Errorf("attestation: failed to marshal attested key: %w", err)
	}

	h := sha256.Sum256(pubBytes)
	return h[:], nil
}
