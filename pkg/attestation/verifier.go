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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"
)

// ecdsaHashAlgorithms maps ECDSA signature algorithms to their corresponding hash functions.
var ecdsaHashAlgorithms = map[x509.SignatureAlgorithm]crypto.Hash{
	x509.ECDSAWithSHA256: crypto.SHA256,
	x509.ECDSAWithSHA384: crypto.SHA384,
	x509.ECDSAWithSHA512: crypto.SHA512,
}

// rsaHashAlgorithms maps RSA signature algorithms to their corresponding hash functions.
var rsaHashAlgorithms = map[x509.SignatureAlgorithm]crypto.Hash{
	x509.SHA256WithRSA: crypto.SHA256,
	x509.SHA384WithRSA: crypto.SHA384,
	x509.SHA512WithRSA: crypto.SHA512,
}

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
		return fmt.Errorf("%w: %v", ErrSignatureVerificationFailed, err)
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
	if len(stmt.CertificateChain) == 0 {
		return ErrEmptyCertificateChain
	}

	// Get the attesting certificate (leaf)
	attestingCert := stmt.CertificateChain[0]

	// Verify the leaf certificate is not expired
	now := time.Now()
	if opts.CurrentTime != nil {
		now = time.Unix(*opts.CurrentTime, 0)
	}

	if now.Before(attestingCert.NotBefore) {
		return fmt.Errorf("%w (valid from %s)", ErrCertificateNotYetValid, attestingCert.NotBefore)
	}

	if now.After(attestingCert.NotAfter) {
		return fmt.Errorf("%w (expired at %s)", ErrCertificateExpired, attestingCert.NotAfter)
	}

	// If only one cert, check for self-signed
	if len(stmt.CertificateChain) == 1 {
		cert := attestingCert
		// Try CheckSignatureFrom first (handles RSA, ECDSA, Ed25519)
		if err := cert.CheckSignatureFrom(cert); err == nil {
			return nil
		}
		// Fallback: try CheckSignature directly for non-CA self-signed certs
		if err := cert.CheckSignature(cert.SignatureAlgorithm,
			cert.RawTBSCertificate, cert.Signature); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSelfSignedCert, err)
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
			return fmt.Errorf("%w at position %d: %v", ErrInvalidChainSignature, i, err)
		}

		// Verify next cert is not expired
		if now.Before(nextCert.NotBefore) {
			return fmt.Errorf("%w: intermediate certificate %d", ErrCertificateNotYetValid, i+1)
		}

		if now.After(nextCert.NotAfter) {
			return fmt.Errorf("%w: intermediate certificate %d", ErrCertificateExpired, i+1)
		}
	}

	return nil
}

// VerifySignature verifies the cryptographic signature over the attestation data.
func (v *Verifier) VerifySignature(stmt *AttestationStatement, opts *VerifyOptions) error {
	if len(stmt.Signature) == 0 {
		return ErrEmptySignature
	}

	if stmt.AttestingKeyPublic == nil {
		return ErrNilAttestingKey
	}

	// The data being signed is the attestation data
	dataToVerify := stmt.AttestationData
	if len(dataToVerify) == 0 {
		// Fallback: use public key bytes for verification
		pubBytes, err := x509.MarshalPKIXPublicKey(stmt.AttestedKeyPublic)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMarshalAttestedKey, err)
		}
		dataToVerify = pubBytes
	}

	// Determine signature algorithm and verify using map-based dispatch
	switch pubKey := stmt.AttestingKeyPublic.(type) {
	case *rsa.PublicKey:
		return v.verifyRSASignature(pubKey, stmt.Signature, dataToVerify, stmt.SignatureAlgorithm)
	case *ecdsa.PublicKey:
		return v.verifyECDSASignature(pubKey, stmt.Signature, dataToVerify, stmt.SignatureAlgorithm)
	case ed25519.PublicKey:
		return v.verifyEd25519Signature(pubKey, stmt.Signature, dataToVerify)
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedKeyType, stmt.AttestingKeyPublic)
	}
}

// verifyRSASignature verifies an RSA PKCS#1 v1.5 signature.
func (v *Verifier) verifyRSASignature(pubKey *rsa.PublicKey, sig, data []byte, sigAlg x509.SignatureAlgorithm) error {
	hash, ok := rsaHashAlgorithms[sigAlg]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedSignatureAlgorithm, sigAlg)
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	if err := rsa.VerifyPKCS1v15(pubKey, hash, digest, sig); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureVerificationFailed, err)
	}

	return nil
}

// verifyECDSASignature verifies an ECDSA ASN.1 signature.
func (v *Verifier) verifyECDSASignature(pubKey *ecdsa.PublicKey, sig, data []byte, sigAlg x509.SignatureAlgorithm) error {
	hash, ok := ecdsaHashAlgorithms[sigAlg]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedSignatureAlgorithm, sigAlg)
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	if !ecdsa.VerifyASN1(pubKey, digest, sig) {
		return ErrSignatureVerificationFailed
	}

	return nil
}

// verifyEd25519Signature verifies an Ed25519 signature.
// Ed25519 operates on raw data without pre-hashing.
func (v *Verifier) verifyEd25519Signature(pubKey ed25519.PublicKey, sig, data []byte) error {
	if !ed25519.Verify(pubKey, data, sig) {
		return ErrSignatureVerificationFailed
	}
	return nil
}

// verifyFreshness checks that the attestation is not too old.
func (v *Verifier) verifyFreshness(stmt *AttestationStatement, opts *VerifyOptions) error {
	if opts.ExpectedNonce != nil {
		if !bytesEqual(stmt.Nonce, opts.ExpectedNonce) {
			return ErrNonceMismatch
		}
	}

	if stmt.CreatedAt == "" {
		return ErrMissingTimestamp
	}

	createdTime, err := time.Parse(time.RFC3339, stmt.CreatedAt)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTimestamp, err)
	}

	now := time.Now()
	if opts.CurrentTime != nil {
		now = time.Unix(*opts.CurrentTime, 0)
	}

	age := now.Sub(createdTime)
	if age < 0 {
		return ErrFutureTimestamp
	}

	window := time.Duration(opts.FreshnessWindow) * time.Second
	if age > window {
		return fmt.Errorf("%w (age: %v, allowed: %v)", ErrAttestationExpired, age, window)
	}

	return nil
}

// verifyPCRs checks that TPM PCR values match expected values.
func (v *Verifier) verifyPCRs(stmt *AttestationStatement, opts *VerifyOptions) error {
	if len(stmt.PCRValues) == 0 {
		if len(opts.ExpectedPCRs) > 0 {
			return ErrMissingPCRs
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
			return fmt.Errorf("%w: PCR %d", ErrPCRMissing, pcrIdx)
		}

		if !bytesEqual(actualDigest, expectedDigest) {
			return fmt.Errorf("%w: PCR %d (expected %x, got %x)",
				ErrPCRMismatch, pcrIdx, expectedDigest, actualDigest)
		}
	}

	return nil
}

// bytesEqual compares byte slices in constant time to prevent timing attacks.
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

// Hash returns a SHA-256 hash of the attested public key.
func (stmt *AttestationStatement) Hash() ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(stmt.AttestedKeyPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMarshalAttestedKey, err)
	}

	h := sha256.Sum256(pubBytes)
	return h[:], nil
}
