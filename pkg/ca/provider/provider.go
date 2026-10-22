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

// Package provider defines interfaces for Certificate Authority operations
// using only standard library types. This breaks the import cycle between
// pkg/xkms and pkg/ca: the CA concrete type in pkg/ca implements these
// interfaces, and pkg/xkms references them by type rather than duck typing.
//
// No adapters, no servicers — the CA struct already has all of these methods
// via its "Raw" adapter methods in pkg/ca/service_adapter.go.
package provider

import (
	"context"
	"crypto/x509"
	"math/big"
)

// CA defines the Certificate Authority operations that the XKMSService
// needs. All methods use only stdlib types to avoid import cycles.
//
// The concrete ca.CA type satisfies this interface directly — its methods
// from ca.go and service_adapter.go match these signatures exactly.
type CA interface {
	// CABundle returns the CA certificate chain in PEM format.
	CABundle() ([]byte, error)

	// CACertificate returns the CA's certificate.
	CACertificate() (*x509.Certificate, error)

	// SignCSRRaw signs a CSR using primitive parameter types.
	// If profile and validityDays are both zero-values, CA defaults are used.
	// tenantID is the caller's tenant, which the certificate carries as its
	// subject's first organizational unit.
	SignCSRRaw(ctx context.Context, csrPEM []byte, profile string, validityDays int, tenantID string) (*x509.Certificate, error)

	// SignCSRWithSPIFFE signs a CSR and, when trustDomain and tenantID are
	// both non-empty, synthesizes a tenant-scoped SPIFFE URI SAN of the form
	// spiffe://<tenantID>/<kind>/<name> onto the issued
	// certificate. kind defaults to "user" and name defaults to the subject
	// CommonName when empty. When trustDomain or tenantID is empty this
	// behaves exactly like SignCSRRaw.
	SignCSRWithSPIFFE(ctx context.Context, csrPEM []byte, profile string, validityDays int, trustDomain, tenantID, kind, name string) (*x509.Certificate, error)

	// IssueCertificateRaw issues a certificate using primitive parameter types.
	// sans entries use prefix notation: "DNS:example.com", "IP:1.2.3.4".
	// tenantID ("" for the system/platform scope) is recorded as the
	// certificate's issuing tenant, exactly as SignCSRWithSPIFFE's tenantID
	// is for a CSR-signed certificate; CertificateTenant reads it back.
	// Returns certificate PEM, chain PEM, private key PEM, and hex serial.
	IssueCertificateRaw(
		ctx context.Context,
		commonName, organization string,
		sans []string,
		validityDays int,
		profile, algorithm, tenantID string,
	) (certPEM, chainPEM, keyPEM []byte, serialHex string, err error)

	// Revoke marks a certificate as revoked by serial number and reason code.
	Revoke(ctx context.Context, serial *big.Int, reason int) error

	// CertificateTenant returns the tenant recorded at issuance for the
	// certificate identified by serial ("" for the system/platform scope,
	// including when the certificate was issued through a path that
	// records no tenant at all -- see the concrete CA type's doc comment).
	CertificateTenant(ctx context.Context, serial *big.Int) (string, error)

	// GenerateCRL forces regeneration of a Certificate Revocation List in
	// DER format, even when a still-valid one is already published.
	GenerateCRL(ctx context.Context) ([]byte, error)

	// CRL returns the current CRL DER, regenerating and persisting it first
	// only when none has been published yet or the published artifact's
	// NextUpdate has passed.
	CRL(ctx context.Context) ([]byte, error)

	// IsRevoked checks whether a certificate serial number is revoked.
	IsRevoked(serial *big.Int) (bool, error)

	// Identity returns the CA's identity string (typically the CN).
	Identity() string

	// IsInitialized returns true if the CA has been initialized.
	IsInitialized() bool
}

// TCGCA extends CA with TCG Trusted Computing certificate operations
// for TPM device identity, attestation keys, and endorsement keys.
//
// The concrete ca.CA type satisfies this interface directly via its
// Raw adapter methods in pkg/ca/service_adapter.go. Each tenantID is the
// caller's tenant, which the EK, AK, IAK and IDevID certificates carry as
// their subject's first organizational unit.
type TCGCA interface {
	CA

	// IssueEKCertificateRaw issues an Endorsement Key certificate.
	// ekPubDER is DER-encoded public key bytes.
	IssueEKCertificateRaw(ctx context.Context, commonName, organization string, ekPubDER []byte, tenantID string) (certDER []byte, err error)

	// IssueAKCertificateRaw issues an Attestation Key certificate.
	// pubDER is DER-encoded public key bytes.
	IssueAKCertificateRaw(ctx context.Context, commonName, organization string, pubDER []byte, tenantID string) (certDER []byte, err error)

	// SignTCGCSRIDevIDRaw signs a packed TCG-CSR-IDEVID.
	// packedCSR is the binary-marshalled TCG_CSR_IDEVID bytes.
	// Returns IAK cert DER and IDevID cert DER.
	SignTCGCSRIDevIDRaw(ctx context.Context, commonName, organization string, packedCSR []byte, tenantID string) (iakDER, idevidDER []byte, err error)

	// EnrollDeviceRaw performs TCG device enrollment.
	// packedCSR is the binary-packed TCG_CSR_IDEVID bytes.
	EnrollDeviceRaw(ctx context.Context, commonName, organization string, packedCSR []byte, tenantID string) (
		iakDER, idevidDER, credBlob, encSecret, plainSecret []byte, err error,
	)

	// IssueLAKCertificateRaw issues a Local Attestation Key certificate in
	// the WebAuthn Level 2 §8.3.1 profile (go-xkms#715), after verifying the
	// LAK's TPM2_Certify evidence against the device's IAK certificate.
	// iakCertDER is the device's IAK certificate (DER). certifyInfo and
	// signature are the raw TPM2_Certify evidence; signatureAlgorithm is the
	// IAK's X.509 signature algorithm; lakPublicArea is the LAK's marshalled
	// TPMT_PUBLIC; nonce is the qualifying data the evidence must echo.
	IssueLAKCertificateRaw(
		ctx context.Context,
		tpmManufacturer, tpmModel, tpmFirmwareVersion string,
		iakCertDER []byte,
		certifyInfo, signature []byte,
		signatureAlgorithm x509.SignatureAlgorithm,
		lakPublicArea, nonce []byte,
	) (certDER []byte, err error)
}
