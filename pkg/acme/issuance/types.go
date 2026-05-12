// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package issuance

import (
	"context"
	"crypto"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
)

// Request contains the parameters for certificate issuance.
type Request struct {
	// CSR is the certificate signing request.
	CSR *x509.CertificateRequest

	// Template is the certificate template with desired extensions.
	// If nil, a template is generated from the CSR.
	Template *x509.Certificate

	// NotBefore is the start of the certificate validity period.
	NotBefore time.Time

	// NotAfter is the end of the certificate validity period.
	NotAfter time.Time

	// Profile is the issuance profile to use (e.g., "default", "tls", "ca").
	Profile string

	// SkipCT skips Certificate Transparency if true.
	// Should only be used for internal/private certificates.
	SkipCT bool

	// SkipLint skips certificate linting if true.
	// Should only be used for testing or special cases.
	SkipLint bool

	// RequestMetadata contains optional metadata for audit logging.
	RequestMetadata map[string]string
}

// Result contains the results of certificate issuance.
type Result struct {
	// Precert is the precertificate (with poison extension).
	Precert *x509.Certificate

	// FinalCert is the final certificate (with SCT list extension).
	FinalCert *x509.Certificate

	// Serial is the certificate serial number.
	Serial *big.Int

	// SCTs contains the SCTs obtained from CT logs.
	SCTs []ct.SignedCertificateTimestamp

	// IssuanceTime is when issuance completed.
	IssuanceTime time.Time

	// IssuanceID is a unique identifier for this issuance.
	IssuanceID string
}

// Issuer defines the interface for certificate issuance.
type Issuer interface {
	// Issue performs two-phase certificate issuance.
	Issue(ctx context.Context, req *Request) (*Result, error)
}

// CertificateSigner defines the interface for certificate signing operations.
type CertificateSigner interface {
	// Signer returns the crypto.Signer for signing.
	Signer() (crypto.Signer, error)

	// Certificate returns the issuing certificate.
	Certificate() (*x509.Certificate, error)

	// SignCertificate signs a certificate template.
	SignCertificate(template, parent *x509.Certificate, pub, priv interface{}) ([]byte, error)
}

// SerialStorage defines the interface for serial number persistence.
type SerialStorage interface {
	// ReserveSerial reserves a serial number before signing.
	// Returns an error if the serial is already reserved.
	ReserveSerial(ctx context.Context, serial *big.Int, metadata SerialMetadata) error

	// ConfirmSerial confirms a serial was used for issuance.
	ConfirmSerial(ctx context.Context, serial *big.Int) error

	// RevokeReservation revokes a serial reservation (for cleanup on failure).
	RevokeReservation(ctx context.Context, serial *big.Int) error

	// IsSerialUsed checks if a serial has been used.
	IsSerialUsed(ctx context.Context, serial *big.Int) (bool, error)
}

// SerialMetadata contains metadata for serial reservation.
type SerialMetadata struct {
	// ReservedAt is when the serial was reserved.
	ReservedAt time.Time

	// RequestID identifies the issuance request.
	RequestID string

	// Subject is the certificate subject.
	Subject string

	// Profile is the issuance profile.
	Profile string
}

// CertificateStorage defines the interface for certificate persistence.
type CertificateStorage interface {
	// StoreCertificate stores a certificate.
	StoreCertificate(ctx context.Context, cert *x509.Certificate) error

	// StorePrecert stores a precertificate for audit.
	StorePrecert(ctx context.Context, precert *x509.Certificate) error

	// GetCertificateBySerial retrieves a certificate by serial.
	GetCertificateBySerial(ctx context.Context, serial *big.Int) (*x509.Certificate, error)
}

// AuditLogger defines the interface for audit logging.
type AuditLogger interface {
	// LogIssuanceIntent logs the intent to issue a certificate.
	LogIssuanceIntent(ctx context.Context, req *Request, serial *big.Int) error

	// LogPrecertCreated logs precertificate creation.
	LogPrecertCreated(ctx context.Context, precert *x509.Certificate) error

	// LogCTSubmission logs CT submission results.
	LogCTSubmission(ctx context.Context, scts []ct.SignedCertificateTimestamp, errors []error) error

	// LogIssuanceComplete logs successful issuance.
	LogIssuanceComplete(ctx context.Context, result *Result) error

	// LogIssuanceFailure logs issuance failure.
	LogIssuanceFailure(ctx context.Context, req *Request, phase IssuancePhase, err error) error
}

// KeyValidator defines the interface for key validation.
type KeyValidator interface {
	// CheckKey validates a public key.
	CheckKey(ctx context.Context, key crypto.PublicKey) error
}

// CertificateLinter defines the interface for certificate linting.
type CertificateLinter interface {
	// LintCertificate lints a certificate.
	LintCertificate(cert *x509.Certificate) (LintResult, error)

	// LintDER lints a DER-encoded certificate.
	LintDER(der []byte) (LintResult, error)
}

// LintResult contains the results of certificate linting.
type LintResult interface {
	// Passed returns true if linting passed.
	Passed() bool

	// Summary returns a summary of lint results.
	Summary() string

	// Errors returns lint errors.
	Errors() []string

	// Warnings returns lint warnings.
	Warnings() []string
}

// CTSubmitter defines the interface for CT log submission.
type CTSubmitter interface {
	// GetSCTs submits a precert to CT logs and returns SCTs.
	GetSCTs(ctx context.Context, precertDER []byte, chain [][]byte, expiry time.Time) ([]ct.SignedCertificateTimestamp, error)
}

// Profile defines an issuance profile configuration.
type Profile struct {
	// Name is the profile identifier.
	Name string

	// MaxValidityDays is the maximum validity period in days.
	MaxValidityDays int

	// AllowedKeyAlgorithms lists allowed key algorithms.
	AllowedKeyAlgorithms []x509.PublicKeyAlgorithm

	// AllowedKeyUsages lists allowed key usages.
	AllowedKeyUsages []x509.KeyUsage

	// AllowedExtKeyUsages lists allowed extended key usages.
	AllowedExtKeyUsages []x509.ExtKeyUsage

	// RequireCT requires Certificate Transparency.
	RequireCT bool

	// LintProfile is the lint profile to use.
	LintProfile string
}

// DefaultProfile returns the default issuance profile.
func DefaultProfile() Profile {
	return Profile{
		Name:            "default",
		MaxValidityDays: 398, // 13 months per CABF
		AllowedKeyAlgorithms: []x509.PublicKeyAlgorithm{
			x509.RSA,
			x509.ECDSA,
			x509.Ed25519,
		},
		AllowedKeyUsages: []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageKeyEncipherment,
		},
		AllowedExtKeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		RequireCT:   true,
		LintProfile: "default",
	}
}

// TLSProfile returns a profile for TLS server certificates.
func TLSProfile() Profile {
	return Profile{
		Name:            "tls",
		MaxValidityDays: 398,
		AllowedKeyAlgorithms: []x509.PublicKeyAlgorithm{
			x509.RSA,
			x509.ECDSA,
		},
		AllowedKeyUsages: []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageKeyEncipherment,
		},
		AllowedExtKeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		RequireCT:   true,
		LintProfile: "tls",
	}
}

// InternalProfile returns a profile for internal/private certificates.
func InternalProfile() Profile {
	return Profile{
		Name:            "internal",
		MaxValidityDays: 365 * 2, // 2 years for internal certs
		AllowedKeyAlgorithms: []x509.PublicKeyAlgorithm{
			x509.RSA,
			x509.ECDSA,
			x509.Ed25519,
		},
		AllowedKeyUsages: []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageKeyEncipherment,
			x509.KeyUsageCertSign,
		},
		AllowedExtKeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
		},
		RequireCT:   false, // No CT for internal certs
		LintProfile: "lenient",
	}
}
