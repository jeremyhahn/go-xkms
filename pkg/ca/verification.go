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

// Package ca provides certificate verification operations for XKMSCA.
//
// This file implements comprehensive X.509 certificate verification including:
//   - Chain verification against trust anchors
//   - Signature verification using various key types
//   - Revocation checking via CRL
//   - Certificate validity helpers
//   - Key usage verification
//
// # Verification Process
//
// Certificate verification follows RFC 5280 path validation:
//  1. Signature verification (issuer signed the certificate)
//  2. Validity period checking (not before, not after)
//  3. Basic constraints checking (CA flag, path length)
//  4. Key usage constraints
//  5. Name constraints (if present)
//  6. Revocation status (via CRL or OCSP)
//
// # Thread Safety
//
// All verification functions are thread-safe. They operate on immutable
// certificate data and do not modify any shared state.
//
// # Error Handling
//
// Verification functions return typed errors that wrap the underlying cause:
//   - VerificationError: Wraps verification failures with context
//   - ErrCertificateExpired: Certificate's NotAfter has passed
//   - ErrCertificateNotYetValid: Certificate's NotBefore is in the future
//   - ErrInvalidSignature: Signature verification failed
//   - ErrCertificateRevoked: Certificate appears in a CRL
//   - ErrInvalidCertificateChain: Chain cannot be built to a trust anchor
//   - ErrRootNotFound: No trusted root certificate found
package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// signatureAlgorithmToHash maps X.509 signature algorithms to their hash functions.
// This is used for signature verification.
var signatureAlgorithmToHash = map[x509.SignatureAlgorithm]crypto.Hash{
	x509.MD5WithRSA:       crypto.MD5,
	x509.SHA1WithRSA:      crypto.SHA1,
	x509.SHA256WithRSA:    crypto.SHA256,
	x509.SHA384WithRSA:    crypto.SHA384,
	x509.SHA512WithRSA:    crypto.SHA512,
	x509.SHA256WithRSAPSS: crypto.SHA256,
	x509.SHA384WithRSAPSS: crypto.SHA384,
	x509.SHA512WithRSAPSS: crypto.SHA512,
	x509.ECDSAWithSHA1:    crypto.SHA1,
	x509.ECDSAWithSHA256:  crypto.SHA256,
	x509.ECDSAWithSHA384:  crypto.SHA384,
	x509.ECDSAWithSHA512:  crypto.SHA512,
	x509.PureEd25519:      0, // Ed25519 doesn't use a separate hash
}

// VerificationError represents a certificate verification failure with context.
// It contains the certificate that failed verification, the reason for failure,
// and optionally wraps the underlying error.
type VerificationError struct {
	// Cert is the certificate that failed verification.
	// May be nil if the error occurred before certificate parsing.
	Cert *x509.Certificate

	// Reason describes why verification failed.
	Reason string

	// Wrapped is the underlying error, if any.
	Wrapped error
}

// Error returns a formatted error message.
func (e *VerificationError) Error() string {
	msg := "ca: verification failed"
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Wrapped != nil {
		msg += ": " + e.Wrapped.Error()
	}
	return msg
}

// Unwrap returns the wrapped error for errors.Is and errors.As compatibility.
func (e *VerificationError) Unwrap() error {
	return e.Wrapped
}

// Is implements errors.Is for VerificationError.
// It checks if the target is a VerificationError with the same reason.
func (e *VerificationError) Is(target error) bool {
	var ve *VerificationError
	if errors.As(target, &ve) {
		return e.Reason == ve.Reason
	}
	return false
}

// VerifyOptions contains options for certificate verification.
// It allows customization of the verification process including
// which checks to perform and what trust anchors to use.
type VerifyOptions struct {
	// DNSName, if set, requires the certificate to be valid for this DNS name.
	// The name is checked against the certificate's DNS SANs and Common Name.
	DNSName string

	// KeyUsages specifies the required extended key usages.
	// If empty, any extended key usage is accepted.
	KeyUsages []x509.ExtKeyUsage

	// CurrentTime is the time at which to check certificate validity.
	// If zero, time.Now() is used. This is useful for testing or
	// verifying certificates at a specific point in time.
	CurrentTime time.Time

	// Intermediates contains intermediate CA certificates that may be
	// needed to build the certificate chain.
	Intermediates []*x509.Certificate

	// Roots is the pool of trusted root CA certificates.
	// If nil, the system root pool is used.
	Roots *x509.CertPool

	// CheckRevocation enables CRL-based revocation checking.
	// When enabled, the CRL field must contain valid CRL data.
	CheckRevocation bool

	// CRL contains the DER-encoded CRL to check against.
	// Only used if CheckRevocation is true.
	CRL []byte
}

// VerifySignature verifies that the given certificate was signed by this CA.
//
// This method checks that:
//   - The certificate's issuer matches the CA certificate's subject
//   - The certificate's signature is valid using the CA's public key
//
// This does NOT check validity periods, revocation status, or chain constraints.
// For full verification, use the Verify method instead.
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrInvalidCertificate if cert is nil
//   - ErrInvalidSignature if signature verification fails
//
// Thread-safe: Yes
func (ca *CA) VerifySignature(cert *x509.Certificate) error {
	if !ca.initialized.Load() {
		return ErrNotInitialized
	}

	if cert == nil {
		return ErrInvalidCertificate
	}

	ca.mu.RLock()
	issuingCert := ca.getIssuingCertificate()
	ca.mu.RUnlock()

	if issuingCert == nil {
		return ErrCertificateNotFound
	}

	return VerifyCertificateSignature(cert, issuingCert)
}

// VerifyChain verifies a certificate against intermediates and a root pool.
//
// This function builds and validates the certificate chain from the leaf
// certificate through any intermediates up to a trusted root. It performs
// all standard X.509 path validation checks.
//
// Parameters:
//   - cert: The leaf certificate to verify
//   - intermediates: Intermediate CA certificates (may be nil or empty)
//   - roots: Pool of trusted root CA certificates
//
// Returns the verified certificate chains on success.
//
// Returns:
//   - ErrInvalidCertificate if cert is nil
//   - ErrRootNotFound if roots is nil or empty
//   - ErrInvalidCertificateChain if chain verification fails
//
// Thread-safe: Yes (pure function)
func VerifyChain(
	cert *x509.Certificate,
	intermediates []*x509.Certificate,
	roots *x509.CertPool,
) ([][]*x509.Certificate, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}

	if roots == nil {
		return nil, ErrRootNotFound
	}

	// Build intermediate pool
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		if intermediate != nil {
			intermediatePool.AddCert(intermediate)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediatePool,
		CurrentTime:   time.Now(),
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return nil, &VerificationError{
			Cert:    cert,
			Reason:  "chain verification failed",
			Wrapped: err,
		}
	}

	return chains, nil
}

// VerifyWithOptions verifies a certificate with custom verification options.
//
// This function provides full control over the verification process including:
//   - DNS name matching
//   - Extended key usage requirements
//   - Custom verification time (for testing)
//   - Intermediate certificates
//   - Root trust anchors
//   - CRL-based revocation checking
//
// If opts is nil, default options are used (current time, system roots).
//
// Returns the verified certificate chains on success.
//
// Returns:
//   - ErrInvalidCertificate if cert is nil
//   - ErrCertificateExpired if the certificate has expired
//   - ErrCertificateNotYetValid if the certificate is not yet valid
//   - ErrCertificateRevoked if revocation checking is enabled and cert is revoked
//   - ErrInvalidCertificateChain if chain verification fails
//
// Thread-safe: Yes (pure function)
func VerifyWithOptions(
	cert *x509.Certificate,
	opts *VerifyOptions,
) ([][]*x509.Certificate, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}

	// Use defaults if opts is nil
	if opts == nil {
		opts = &VerifyOptions{}
	}

	// Determine verification time
	currentTime := opts.CurrentTime
	if currentTime.IsZero() {
		currentTime = time.Now()
	}

	// Check validity period first (fail fast)
	if currentTime.Before(cert.NotBefore) {
		return nil, &VerificationError{
			Cert:    cert,
			Reason:  "certificate not yet valid",
			Wrapped: ErrCertificateNotYetValid,
		}
	}
	if currentTime.After(cert.NotAfter) {
		return nil, &VerificationError{
			Cert:    cert,
			Reason:  "certificate has expired",
			Wrapped: ErrCertificateExpired,
		}
	}

	// Check revocation status if requested
	if opts.CheckRevocation && len(opts.CRL) > 0 {
		revoked, err := VerifyAgainstCRL(cert, opts.CRL)
		if err != nil {
			return nil, &VerificationError{
				Cert:    cert,
				Reason:  "revocation check failed",
				Wrapped: err,
			}
		}
		if revoked {
			return nil, &VerificationError{
				Cert:    cert,
				Reason:  "certificate is revoked",
				Wrapped: ErrCertificateRevoked,
			}
		}
	}

	// Build intermediate pool
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range opts.Intermediates {
		if intermediate != nil {
			intermediatePool.AddCert(intermediate)
		}
	}

	// Build verification options
	verifyOpts := x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: intermediatePool,
		CurrentTime:   currentTime,
		DNSName:       opts.DNSName,
		KeyUsages:     opts.KeyUsages,
	}

	// Perform chain verification
	chains, err := cert.Verify(verifyOpts)
	if err != nil {
		return nil, &VerificationError{
			Cert:    cert,
			Reason:  "chain verification failed",
			Wrapped: err,
		}
	}

	return chains, nil
}

// BuildCertPool creates a certificate pool from the provided certificates.
//
// This is a convenience function for creating x509.CertPool instances
// from a slice of certificates. Nil certificates in the input are skipped.
//
// Returns an empty pool if no valid certificates are provided.
//
// Thread-safe: Yes (pure function)
func BuildCertPool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		if cert != nil {
			pool.AddCert(cert)
		}
	}
	return pool
}

// hashForSignatureAlgorithm returns the crypto.Hash for the given signature algorithm.
// Returns 0 for algorithms that don't use a separate hash (like Ed25519) or unknown algorithms.
func hashForSignatureAlgorithm(algo x509.SignatureAlgorithm) crypto.Hash {
	if h, ok := signatureAlgorithmToHash[algo]; ok {
		return h
	}
	return 0
}

// VerifyCertificateAgainstPublicKey verifies that a certificate was signed
// by the private key corresponding to the given public key.
//
// This function supports RSA, ECDSA, and Ed25519 public keys. It extracts
// the signature algorithm from the certificate and performs the appropriate
// verification.
//
// Parameters:
//   - cert: The certificate to verify
//   - pubKey: The public key to verify against
//
// Returns:
//   - ErrInvalidCertificate if cert is nil
//   - ErrInvalidSignature if pubKey is nil or unsupported
//   - ErrInvalidSignature if signature verification fails
//
// Thread-safe: Yes (pure function)
func VerifyCertificateAgainstPublicKey(cert *x509.Certificate, pubKey crypto.PublicKey) error {
	if cert == nil {
		return ErrInvalidCertificate
	}

	if pubKey == nil {
		return &VerificationError{
			Cert:    cert,
			Reason:  "public key is nil",
			Wrapped: ErrInvalidSignature,
		}
	}

	// Get the hash algorithm for the signature
	hashAlgo := hashForSignatureAlgorithm(cert.SignatureAlgorithm)

	// Verify based on key type
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return verifyRSASignature(cert, key, hashAlgo)
	case *ecdsa.PublicKey:
		return verifyECDSASignature(cert, key, hashAlgo)
	case ed25519.PublicKey:
		return verifyEd25519Signature(cert, key)
	default:
		return &VerificationError{
			Cert:    cert,
			Reason:  "unsupported public key type",
			Wrapped: ErrInvalidSignature,
		}
	}
}

// verifyRSASignature verifies an RSA signature on a certificate.
func verifyRSASignature(
	cert *x509.Certificate,
	pubKey *rsa.PublicKey,
	hashAlgo crypto.Hash,
) error {
	if hashAlgo == 0 {
		return &VerificationError{
			Cert:    cert,
			Reason:  "unsupported signature algorithm for RSA",
			Wrapped: ErrInvalidSignature,
		}
	}

	// Compute the hash of the TBSCertificate
	hash := hashAlgo.New()
	hash.Write(cert.RawTBSCertificate)
	digest := hash.Sum(nil)

	var err error

	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		// PSS signature
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashAlgo,
		}
		err = rsa.VerifyPSS(pubKey, hashAlgo, digest, cert.Signature, pssOpts)
	default:
		// PKCS#1 v1.5 signature
		err = rsa.VerifyPKCS1v15(pubKey, hashAlgo, digest, cert.Signature)
	}

	if err != nil {
		return &VerificationError{
			Cert:    cert,
			Reason:  "RSA signature verification failed",
			Wrapped: ErrInvalidSignature,
		}
	}
	return nil
}

// verifyECDSASignature verifies an ECDSA signature on a certificate.
func verifyECDSASignature(
	cert *x509.Certificate,
	pubKey *ecdsa.PublicKey,
	hashAlgo crypto.Hash,
) error {
	if hashAlgo == 0 {
		return &VerificationError{
			Cert:    cert,
			Reason:  "unsupported signature algorithm for ECDSA",
			Wrapped: ErrInvalidSignature,
		}
	}

	// Compute the hash of the TBSCertificate
	hash := hashAlgo.New()
	hash.Write(cert.RawTBSCertificate)
	digest := hash.Sum(nil)

	// ECDSA signatures in X.509 certificates are DER-encoded
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(cert.Signature, &sig); err != nil {
		return &VerificationError{
			Cert:    cert,
			Reason:  "failed to parse ECDSA signature",
			Wrapped: ErrInvalidSignature,
		}
	}

	if !ecdsa.Verify(pubKey, digest, sig.R, sig.S) {
		return &VerificationError{
			Cert:    cert,
			Reason:  "ECDSA signature verification failed",
			Wrapped: ErrInvalidSignature,
		}
	}
	return nil
}

// verifyEd25519Signature verifies an Ed25519 signature on a certificate.
func verifyEd25519Signature(cert *x509.Certificate, pubKey ed25519.PublicKey) error {
	// Ed25519 uses the raw TBSCertificate, not a hash
	if !ed25519.Verify(pubKey, cert.RawTBSCertificate, cert.Signature) {
		return &VerificationError{
			Cert:    cert,
			Reason:  "Ed25519 signature verification failed",
			Wrapped: ErrInvalidSignature,
		}
	}
	return nil
}

// VerifyCertificateSignature verifies that a certificate was signed by the issuer.
//
// This is a convenience function that extracts the public key from the issuer
// certificate and verifies the subject certificate's signature.
//
// Parameters:
//   - cert: The certificate to verify
//   - issuer: The issuing CA certificate
//
// Returns:
//   - ErrInvalidCertificate if cert or issuer is nil
//   - ErrInvalidSignature if signature verification fails
//
// Thread-safe: Yes (pure function)
func VerifyCertificateSignature(cert, issuer *x509.Certificate) error {
	if cert == nil || issuer == nil {
		return ErrInvalidCertificate
	}

	// Verify issuer/subject relationship
	if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) {
		return &VerificationError{
			Cert:    cert,
			Reason:  "certificate issuer does not match",
			Wrapped: ErrInvalidSignature,
		}
	}

	return VerifyCertificateAgainstPublicKey(cert, issuer.PublicKey)
}

// =============================================================================
// Validation Helpers
// =============================================================================

// IsExpired returns true if the certificate has expired.
//
// A certificate is considered expired if the current time is after
// the certificate's NotAfter time.
//
// Thread-safe: Yes (pure function)
func IsExpired(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	return time.Now().After(cert.NotAfter)
}

// IsNotYetValid returns true if the certificate is not yet valid.
//
// A certificate is not yet valid if the current time is before
// the certificate's NotBefore time.
//
// Thread-safe: Yes (pure function)
func IsNotYetValid(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	return time.Now().Before(cert.NotBefore)
}

// ValidityPeriod returns the total validity period of the certificate.
//
// This is the duration between NotBefore and NotAfter.
//
// Returns ErrInvalidCertificate if cert is nil.
//
// Thread-safe: Yes (pure function)
func ValidityPeriod(cert *x509.Certificate) (time.Duration, error) {
	if cert == nil {
		return 0, ErrInvalidCertificate
	}
	return cert.NotAfter.Sub(cert.NotBefore), nil
}

// DaysUntilExpiration returns the number of days until the certificate expires.
//
// Returns a negative value if the certificate has already expired.
// Returns 0 if cert is nil.
//
// Thread-safe: Yes (pure function)
func DaysUntilExpiration(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}
	duration := time.Until(cert.NotAfter)
	return int(duration.Hours() / 24)
}

// RemainingValidity returns the remaining validity duration of the certificate.
//
// Returns a negative duration if the certificate has already expired.
// Returns 0 if cert is nil.
//
// Thread-safe: Yes (pure function)
func RemainingValidity(cert *x509.Certificate) time.Duration {
	if cert == nil {
		return 0
	}
	return time.Until(cert.NotAfter)
}

// IsCA returns true if the certificate is a CA certificate.
//
// A certificate is considered a CA certificate if:
//   - BasicConstraintsValid is true AND IsCA is true, OR
//   - The certificate has KeyUsageCertSign set
//
// Thread-safe: Yes (pure function)
func IsCA(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		return true
	}
	// Also check if it has cert sign key usage
	return cert.KeyUsage&x509.KeyUsageCertSign != 0
}

// HasKeyUsage returns true if the certificate has the specified key usage.
//
// Multiple key usages can be checked by combining them with OR:
//
//	HasKeyUsage(cert, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
//
// This returns true if the certificate has ALL the specified usages.
//
// Thread-safe: Yes (pure function)
func HasKeyUsage(cert *x509.Certificate, usage x509.KeyUsage) bool {
	if cert == nil {
		return false
	}
	return cert.KeyUsage&usage == usage
}

// HasExtKeyUsage returns true if the certificate has the specified extended key usage.
//
// Thread-safe: Yes (pure function)
func HasExtKeyUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool {
	if cert == nil {
		return false
	}
	for _, u := range cert.ExtKeyUsage {
		if u == usage {
			return true
		}
	}
	return false
}

// HasAnyExtKeyUsage returns true if the certificate has any of the specified
// extended key usages.
//
// Thread-safe: Yes (pure function)
func HasAnyExtKeyUsage(cert *x509.Certificate, usages ...x509.ExtKeyUsage) bool {
	if cert == nil || len(usages) == 0 {
		return false
	}
	for _, want := range usages {
		for _, have := range cert.ExtKeyUsage {
			if want == have {
				return true
			}
		}
	}
	return false
}

// HasAllExtKeyUsages returns true if the certificate has all of the specified
// extended key usages.
//
// Thread-safe: Yes (pure function)
func HasAllExtKeyUsages(cert *x509.Certificate, usages ...x509.ExtKeyUsage) bool {
	if cert == nil {
		return false
	}
	if len(usages) == 0 {
		return true
	}
	for _, want := range usages {
		found := false
		for _, have := range cert.ExtKeyUsage {
			if want == have {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// IsSelfSigned returns true if the certificate is self-signed.
//
// A certificate is self-signed if:
//   - Its subject and issuer are the same, AND
//   - It can verify its own signature
//
// Thread-safe: Yes (pure function)
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	// Quick check: subject == issuer
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	// Verify signature against its own public key
	err := VerifyCertificateAgainstPublicKey(cert, cert.PublicKey)
	return err == nil
}

// IsValidAt returns true if the certificate is valid at the specified time.
//
// A certificate is valid at a time if that time is within the certificate's
// NotBefore and NotAfter bounds (inclusive of NotBefore, exclusive of NotAfter).
//
// Thread-safe: Yes (pure function)
func IsValidAt(cert *x509.Certificate, t time.Time) bool {
	if cert == nil {
		return false
	}
	return !t.Before(cert.NotBefore) && !t.After(cert.NotAfter)
}

// IsCurrentlyValid returns true if the certificate is currently valid.
//
// This is equivalent to IsValidAt(cert, time.Now()).
//
// Thread-safe: Yes (pure function)
func IsCurrentlyValid(cert *x509.Certificate) bool {
	return IsValidAt(cert, time.Now())
}

// MatchesDNSName returns true if the certificate is valid for the given DNS name.
//
// This checks:
//   - The certificate's DNS SANs
//   - The certificate's Common Name (if no SANs are present)
//
// Wildcard matching is supported per RFC 6125.
//
// Thread-safe: Yes (pure function)
func MatchesDNSName(cert *x509.Certificate, name string) bool {
	if cert == nil || name == "" {
		return false
	}

	// Use the standard library's verification to handle wildcards properly
	err := cert.VerifyHostname(name)
	return err == nil
}

// PathLength returns the maximum path length constraint from the certificate.
//
// Returns:
//   - The path length if BasicConstraintsValid is true and the certificate is a CA
//   - -1 if no path length constraint is set
//   - 0 if cert is nil
//
// Thread-safe: Yes (pure function)
func PathLength(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return -1
	}
	if cert.MaxPathLenZero {
		return 0
	}
	if cert.MaxPathLen > 0 {
		return cert.MaxPathLen
	}
	return -1 // No constraint
}

// CertificateFingerprint returns the SHA-256 fingerprint of the certificate.
//
// The fingerprint is computed over the DER-encoded certificate (Raw field).
// This is commonly used to identify certificates regardless of encoding.
//
// Returns nil if cert is nil.
//
// Thread-safe: Yes (pure function)
func CertificateFingerprint(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	hash := crypto.SHA256.New()
	hash.Write(cert.Raw)
	return hash.Sum(nil)
}

// CertificatesMatch returns true if two certificates are identical.
//
// Comparison is done on the DER-encoded certificate data, which is
// a complete byte-for-byte comparison of the certificate.
//
// Thread-safe: Yes (pure function)
func CertificatesMatch(a, b *x509.Certificate) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a.Raw, b.Raw)
}

// SerialNumbersMatch returns true if two certificates have the same serial number.
//
// Thread-safe: Yes (pure function)
func SerialNumbersMatch(a, b *x509.Certificate) bool {
	if a == nil || b == nil {
		return false
	}
	if a.SerialNumber == nil || b.SerialNumber == nil {
		return false
	}
	return a.SerialNumber.Cmp(b.SerialNumber) == 0
}

// IsIssuedBy returns true if the certificate was issued by the given issuer.
//
// This checks:
//   - The certificate's issuer DN matches the issuer's subject DN
//   - The certificate's Authority Key Identifier matches the issuer's Subject Key Identifier (if present)
//
// Thread-safe: Yes (pure function)
func IsIssuedBy(cert, issuer *x509.Certificate) bool {
	if cert == nil || issuer == nil {
		return false
	}

	// Check issuer/subject match
	if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) {
		return false
	}

	// If both have key identifiers, verify they match
	if len(cert.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 {
		return bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId)
	}

	return true
}
