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

	"github.com/jeremyhahn/go-xkms/pkg/errs"
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
		return &errs.Wrapped{Msg: "attestation: invalid statement", Err: err}
	}

	if err := opts.Validate(); err != nil {
		return &errs.Wrapped{Msg: "attestation: invalid options", Err: err}
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
		return &errs.Detail{Err: ErrSignatureVerificationFailed, Detail: fmt.Sprintf("%v", err)}
	}
	result.SignatureValid = true

	// Verify freshness if requested
	if opts.CheckFreshness {
		if err := v.verifyFreshness(stmt, opts); err != nil {
			result.FreshnessValid = false
			result.Error = err
			return &errs.Wrapped{Msg: "attestation: freshness check failed", Err: err}
		}
		result.FreshnessValid = true
	}

	// Verify PCRs if requested (TPM2 only)
	if opts.VerifyPCRs && stmt.PCRValues != nil {
		if err := v.verifyPCRs(stmt, opts); err != nil {
			result.PCRsValid = false
			result.Error = err
			return &errs.Wrapped{Msg: "attestation: PCR verification failed", Err: err}
		}
		result.PCRsValid = true
	}

	result.Valid = true
	return nil
}

// TrustAnchorCount returns the number of trust anchors configured on the
// verifier. A verifier with zero anchors cannot establish hardware provenance
// and is rejected by VerifyChainAnchored.
func (v *Verifier) TrustAnchorCount() int {
	return len(v.trustedRoots)
}

// anchors returns the effective trust anchor set: the anchors the verifier was
// constructed with, plus any supplied per-call through the options.
func (v *Verifier) anchors(opts *VerifyOptions) []*x509.Certificate {
	if opts == nil || len(opts.TrustedRoots) == 0 {
		return v.trustedRoots
	}
	combined := make([]*x509.Certificate, 0, len(v.trustedRoots)+len(opts.TrustedRoots))
	combined = append(combined, v.trustedRoots...)
	combined = append(combined, opts.TrustedRoots...)
	return combined
}

// VerifyChain validates the certificate chain in the attestation statement.
//
// The chain is ordered leaf-first: index 0 is the attesting certificate and
// each subsequent entry is its issuer (YubiKey PIV: slot cert, f9 attestation
// cert, Yubico PIV Root CA; TPM 2.0: AK/IAK cert, EK cert, manufacturer CA).
//
// Verification is structural (each certificate is signed by the next, and no
// certificate in the chain is expired or not yet valid) and, when trust
// anchors are configured on the verifier or in the options, path validation
// against those anchors. Configured anchors are always enforced — they are
// never accepted and then ignored.
//
// VerifyChain does not by itself require an anchor: with no anchors configured
// it performs structural validation only, which proves nothing about hardware
// provenance because the whole chain is caller-supplied. Callers that gate a
// security decision on hardware provenance must use VerifyChainAnchored, which
// fails closed when no anchors are configured.
func (v *Verifier) VerifyChain(stmt *AttestationStatement, opts *VerifyOptions) error {
	if stmt == nil {
		return ErrNilStatement
	}
	if len(stmt.CertificateChain) == 0 {
		return ErrEmptyCertificateChain
	}

	now := time.Now()
	if opts != nil && opts.CurrentTime != nil {
		now = time.Unix(*opts.CurrentTime, 0)
	}

	if err := verifyChainStructure(stmt.CertificateChain, now); err != nil {
		return err
	}

	if anchors := v.anchors(opts); len(anchors) > 0 {
		return verifyChainAnchoring(stmt.CertificateChain, anchors, now)
	}

	return nil
}

// VerifyChainAnchored validates the certificate chain and requires that it
// terminate at a configured trust anchor.
//
// It fails closed. When no trust anchors are configured it returns
// ErrNoTrustAnchors instead of falling back to structural-only validation: a
// self-consistent chain minted by the caller must never satisfy an
// attestation gate.
func (v *Verifier) VerifyChainAnchored(stmt *AttestationStatement, opts *VerifyOptions) error {
	if stmt == nil {
		return ErrNilStatement
	}
	if len(v.anchors(opts)) == 0 {
		return ErrNoTrustAnchors
	}
	return v.VerifyChain(stmt, opts)
}

// verifyChainStructure checks that the leaf-first chain is internally
// consistent: every certificate is temporally valid and signed by its
// successor. A single-certificate chain must be self-signed.
func verifyChainStructure(chain []*x509.Certificate, now time.Time) error {
	attestingCert := chain[0]

	if now.Before(attestingCert.NotBefore) {
		return &errs.Affix{Err: ErrCertificateNotYetValid, Suffix: fmt.Sprintf(" (valid from %s)", attestingCert.NotBefore)}
	}

	if now.After(attestingCert.NotAfter) {
		return &errs.Affix{Err: ErrCertificateExpired, Suffix: fmt.Sprintf(" (expired at %s)", attestingCert.NotAfter)}
	}

	// If only one cert, check for self-signed
	if len(chain) == 1 {
		cert := attestingCert
		// Try CheckSignatureFrom first (handles RSA, ECDSA, Ed25519)
		if err := cert.CheckSignatureFrom(cert); err == nil {
			return nil
		}
		// Fallback: try CheckSignature directly for non-CA self-signed certs
		if err := cert.CheckSignature(cert.SignatureAlgorithm,
			cert.RawTBSCertificate, cert.Signature); err != nil {
			return &errs.Detail{Err: ErrInvalidSelfSignedCert, Detail: fmt.Sprintf("%v", err)}
		}
		return nil
	}

	// Verify chain of signatures
	for i := 0; i < len(chain)-1; i++ {
		currentCert := chain[i]
		nextCert := chain[i+1]

		// Verify current cert is signed by next cert
		if err := nextCert.CheckSignature(currentCert.SignatureAlgorithm,
			currentCert.RawTBSCertificate,
			currentCert.Signature); err != nil {
			return &errs.Affix{Err: ErrInvalidChainSignature, Suffix: fmt.Sprintf(" at position %d: %v", i, err)}
		}

		// Verify next cert is not expired
		if now.Before(nextCert.NotBefore) {
			return &errs.Detail{Err: ErrCertificateNotYetValid, Detail: fmt.Sprintf("intermediate certificate %d", i+1)}
		}

		if now.After(nextCert.NotAfter) {
			return &errs.Detail{Err: ErrCertificateExpired, Detail: fmt.Sprintf("intermediate certificate %d", i+1)}
		}
	}

	return nil
}

// verifyChainAnchoring performs X.509 path validation of the leaf-first chain
// against the supplied trust anchors. Every certificate the caller supplied
// beyond the leaf is offered as an intermediate only — none of them can act as
// an anchor, so a chain that terminates in a caller-minted root is rejected
// with ErrChainNotAnchored.
//
// ExtKeyUsageAny is used deliberately: hardware attestation certificates carry
// vendor extended key usages (for example the TCG tcg-kp-EKCertificate OID
// 2.23.133.8.1 on TPM EK certificates) rather than the TLS usages Go checks by
// default.
func verifyChainAnchoring(chain []*x509.Certificate, anchors []*x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	for _, anchor := range anchors {
		roots.AddCert(anchor)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return &errs.Detail{Err: ErrChainNotAnchored, Detail: fmt.Sprintf("%v", err)}
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
			return &errs.Detail{Err: ErrMarshalAttestedKey, Detail: fmt.Sprintf("%v", err)}
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
		return &errs.Detail{Err: ErrUnsupportedKeyType, Detail: fmt.Sprintf("%T", stmt.AttestingKeyPublic)}
	}
}

// verifyRSASignature verifies an RSA PKCS#1 v1.5 signature.
func (v *Verifier) verifyRSASignature(pubKey *rsa.PublicKey, sig, data []byte, sigAlg x509.SignatureAlgorithm) error {
	hash, ok := rsaHashAlgorithms[sigAlg]
	if !ok {
		return &errs.Detail{Err: ErrUnsupportedSignatureAlgorithm, Detail: sigAlg.String()}
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	if err := rsa.VerifyPKCS1v15(pubKey, hash, digest, sig); err != nil {
		return &errs.Detail{Err: ErrSignatureVerificationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	return nil
}

// verifyECDSASignature verifies an ECDSA ASN.1 signature.
func (v *Verifier) verifyECDSASignature(pubKey *ecdsa.PublicKey, sig, data []byte, sigAlg x509.SignatureAlgorithm) error {
	hash, ok := ecdsaHashAlgorithms[sigAlg]
	if !ok {
		return &errs.Detail{Err: ErrUnsupportedSignatureAlgorithm, Detail: sigAlg.String()}
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
		return &errs.Detail{Err: ErrInvalidTimestamp, Detail: fmt.Sprintf("%v", err)}
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
		return &errs.Affix{Err: ErrAttestationExpired, Suffix: fmt.Sprintf(" (age: %v, allowed: %v)", age, window)}
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
			return &errs.Detail{Err: ErrPCRMissing, Detail: fmt.Sprintf("PCR %d", pcrIdx)}
		}

		if !bytesEqual(actualDigest, expectedDigest) {
			return &errs.Detail{Err: ErrPCRMismatch, Detail: fmt.Sprintf("PCR %d (expected %x, got %x)", pcrIdx, expectedDigest, actualDigest)}
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
		return nil, &errs.Detail{Err: ErrMarshalAttestedKey, Detail: fmt.Sprintf("%v", err)}
	}

	h := sha256.Sum256(pubBytes)
	return h[:], nil
}
