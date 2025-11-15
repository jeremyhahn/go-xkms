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

// Package attestation provides key attestation functionality for hardware-backed
// cryptographic keys. It enables proof that a key was generated in hardware and
// never left the secure boundary.
//
// Key attestation is critical for:
//   - Zero-trust security architectures
//   - Compliance requirements (FIPS 140-2, Common Criteria)
//   - Supply chain security
//   - Hardware verification
//
// Typical workflow:
//  1. Generate a key with attestation support
//  2. Obtain attestation statement proving the key was generated in hardware
//  3. Verify the attestation chain and signatures
//  4. Store attestation evidence with the key for auditing
package attestation

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

// AttestationStatement contains cryptographic evidence that a key was generated
// in hardware and never left the secure boundary.
//
// The statement includes:
//   - Signature from the attesting key (hardware private key)
//   - Certificate chain proving the attesting key's authenticity
//   - Attested key public material
//   - Attestation evidence specific to the hardware backend
type AttestationStatement struct {
	// Format identifies the attestation format (e.g., "tpm2", "pkcs11", "none")
	Format string

	// AttestingKeyAlgorithm is the public key algorithm of the attesting key
	AttestingKeyAlgorithm x509.PublicKeyAlgorithm

	// AttestingKeyPublic is the public key that signed the attestation
	// For TPM2: the public part of the Certifying Key
	// For PKCS#11: the HSM's attestation key
	AttestingKeyPublic crypto.PublicKey

	// Signature is the cryptographic signature over the attestation data
	// This proves the attestation was created by the hardware
	Signature []byte

	// SignatureAlgorithm is the algorithm used for the signature
	SignatureAlgorithm x509.SignatureAlgorithm

	// CertificateChain contains the certificate chain proving the attesting key
	// Index 0 is the attesting key certificate
	// Remaining certificates form the chain to a trusted anchor
	CertificateChain []*x509.Certificate

	// AttestedKeyPublic is the public key that was attested
	AttestedKeyPublic crypto.PublicKey

	// AttestationData contains format-specific attestation evidence
	// For TPM2: contains TPM2_Certify output data
	// For PKCS#11: contains HSM-specific attestation info
	AttestationData []byte

	// CreatedAt is the timestamp when the attestation was created
	// Format: RFC3339 timestamp
	CreatedAt string

	// Backend identifies which backend generated this attestation
	// Values: "tpm2", "pkcs11", "awskms", "azurekv", "gcpkms"
	Backend string

	// Nonce is an optional challenge value included in the attestation
	// This can be used to prove freshness and prevent replay attacks
	Nonce []byte

	// PCRValues contains Trusted Component Register values (TPM2 only)
	// Maps PCR index to digest value
	PCRValues map[uint32][]byte

	// ClaimData is additional claims attested to (e.g., key properties, policies)
	ClaimData map[string][]byte
}

// Attestation provides operations for verifying key attestation statements.
type Attestation interface {
	// Verify validates an attestation statement and returns an error if verification fails.
	//
	// Verification checks:
	//   1. Signature validity over attestation data
	//   2. Certificate chain validity and expiration
	//   3. Trusted anchor presence in certificate chain
	//   4. Format-specific validation (e.g., TPM2 attestation properties)
	//   5. Nonce freshness (if provided and freshness check is enabled)
	//
	// Parameters:
	//   - stmt: The attestation statement to verify
	//   - opts: Verification options (trusted roots, nonce checking, etc)
	//
	// Returns:
	//   - An error if verification fails
	//   - nil if verification succeeds
	Verify(stmt *AttestationStatement, opts *VerifyOptions) error

	// VerifyChain validates the certificate chain in the attestation statement.
	//
	// Checks:
	//   1. Each certificate is properly signed by the next in the chain
	//   2. All certificates are valid (not expired, not revoked if CRL provided)
	//   3. Certificate usage constraints are satisfied
	//   4. At least one certificate is signed by a trusted root (if roots provided)
	//
	// Parameters:
	//   - stmt: The attestation statement containing the chain
	//   - opts: Options including trusted roots and CRL
	//
	// Returns:
	//   - Error if chain validation fails
	VerifyChain(stmt *AttestationStatement, opts *VerifyOptions) error

	// VerifySignature validates that the signature in the attestation was created
	// by the attesting key over the attestation data.
	//
	// Parameters:
	//   - stmt: The attestation statement containing signature and data
	//   - opts: Verification options
	//
	// Returns:
	//   - Error if signature verification fails
	VerifySignature(stmt *AttestationStatement, opts *VerifyOptions) error
}

// VerifyOptions contains configuration for attestation verification.
type VerifyOptions struct {
	// TrustedRoots are root certificates to trust for chain validation
	// If empty, any self-signed certificate in the chain is accepted
	TrustedRoots []*x509.Certificate

	// CheckFreshness enables nonce-based freshness verification
	// Verifies that the attestation was created recently
	CheckFreshness bool

	// ExpectedNonce is the nonce value expected in the attestation
	// Only checked if CheckFreshness is enabled
	ExpectedNonce []byte

	// FreshnessWindow is the maximum age of an attestation (seconds)
	// Only checked if CheckFreshness is enabled
	// Default: 300 seconds (5 minutes)
	FreshnessWindow int64

	// VerifyPCRs enables validation of TPM PCR values
	// For TPM2 attestations, verifies the PCR values in the attestation
	VerifyPCRs bool

	// ExpectedPCRs are the expected TPM PCR values
	// Format: map[pcr_index]expected_digest
	// Only checked if VerifyPCRs is enabled
	ExpectedPCRs map[uint32][]byte

	// AllowSelfSigned allows self-signed certificates in the chain
	// Useful for testing and lab environments
	// Should be false for production systems
	AllowSelfSigned bool

	// CurrentTime is the time to use for certificate expiration checks
	// If nil, the current time is used
	// Useful for testing and auditing
	CurrentTime *int64
}

// Result represents the outcome of an attestation verification.
type Result struct {
	// Valid indicates if the attestation is valid
	Valid bool

	// Error is the verification error (nil if valid)
	Error error

	// AttestationFormat is the format of the attestation (e.g., "tpm2", "pkcs11")
	AttestationFormat string

	// AttestedKeyPublicHash is the SHA-256 hash of the attested public key
	// Useful for tracking which key was attested
	AttestedKeyPublicHash []byte

	// ChainValid indicates if the certificate chain is valid
	ChainValid bool

	// SignatureValid indicates if the signature is valid
	SignatureValid bool

	// ChainErrors contains errors from certificate chain validation
	ChainErrors []error

	// FreshnessValid indicates if the attestation is fresh (not too old)
	FreshnessValid bool

	// PCRsValid indicates if TPM PCR values match expected values (TPM2 only)
	PCRsValid bool
}

// String returns a human-readable representation of the verification result.
func (r *Result) String() string {
	status := "INVALID"
	if r.Valid {
		status = "VALID"
	}
	return fmt.Sprintf("AttestationResult{Valid: %s, Format: %s, Chain: %v, Signature: %v}",
		status, r.AttestationFormat, r.ChainValid, r.SignatureValid)
}

// String returns a human-readable representation of the attestation statement.
func (stmt *AttestationStatement) String() string {
	certCount := 0
	if stmt.CertificateChain != nil {
		certCount = len(stmt.CertificateChain)
	}

	return fmt.Sprintf(
		"AttestationStatement{Format: %s, Algorithm: %s, Certs: %d, Backend: %s}",
		stmt.Format, stmt.SignatureAlgorithm, certCount, stmt.Backend,
	)
}

// Validate checks if the attestation statement is well-formed.
func (stmt *AttestationStatement) Validate() error {
	if stmt.Format == "" {
		return fmt.Errorf("attestation format is required")
	}

	if stmt.AttestingKeyPublic == nil {
		return fmt.Errorf("attesting key public is required")
	}

	if len(stmt.Signature) == 0 {
		return fmt.Errorf("signature is required")
	}

	if stmt.AttestedKeyPublic == nil {
		return fmt.Errorf("attested key public is required")
	}

	if len(stmt.CertificateChain) == 0 {
		return fmt.Errorf("certificate chain is required")
	}

	if stmt.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return fmt.Errorf("signature algorithm is required")
	}

	return nil
}

// VerifyOptions validation
func (opts *VerifyOptions) Validate() error {
	if opts == nil {
		return fmt.Errorf("verify options cannot be nil")
	}

	if opts.FreshnessWindow < 0 {
		return fmt.Errorf("freshness window cannot be negative")
	}

	if opts.FreshnessWindow == 0 && opts.CheckFreshness {
		opts.FreshnessWindow = 300 // Default 5 minutes
	}

	return nil
}

// DefaultVerifyOptions returns secure default verification options.
func DefaultVerifyOptions() *VerifyOptions {
	return &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 300, // 5 minutes
		AllowSelfSigned: false,
	}
}

// InsecureVerifyOptions returns minimal verification (not for production).
func InsecureVerifyOptions() *VerifyOptions {
	return &VerifyOptions{
		CheckFreshness:  false,
		AllowSelfSigned: true,
	}
}
