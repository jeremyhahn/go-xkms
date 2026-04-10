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
	SignCSRRaw(csrPEM []byte, profile string, validityDays int) (*x509.Certificate, error)

	// IssueCertificateRaw issues a certificate using primitive parameter types.
	// sans entries use prefix notation: "DNS:example.com", "IP:1.2.3.4".
	// Returns certificate PEM, chain PEM, private key PEM, and hex serial.
	IssueCertificateRaw(
		commonName, organization string,
		sans []string,
		validityDays int,
		profile, algorithm string,
	) (certPEM, chainPEM, keyPEM []byte, serialHex string, err error)

	// Revoke marks a certificate as revoked by serial number and reason code.
	Revoke(serial *big.Int, reason int) error

	// GenerateCRL generates a Certificate Revocation List in DER format.
	GenerateCRL() ([]byte, error)

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
// Raw adapter methods in pkg/ca/service_adapter.go.
type TCGCA interface {
	CA

	// IssueEKCertificateRaw issues an Endorsement Key certificate.
	// ekPubDER is DER-encoded public key bytes.
	IssueEKCertificateRaw(commonName, organization string, ekPubDER []byte) (certDER []byte, err error)

	// IssueAKCertificateRaw issues an Attestation Key certificate.
	// pubDER is DER-encoded public key bytes.
	IssueAKCertificateRaw(commonName, organization string, pubDER []byte) (certDER []byte, err error)

	// SignTCGCSRIDevIDRaw signs a packed TCG-CSR-IDEVID.
	// packedCSR is the binary-marshalled TCG_CSR_IDEVID bytes.
	// Returns IAK cert DER and IDevID cert DER.
	SignTCGCSRIDevIDRaw(commonName, organization string, packedCSR []byte) (iakDER, idevidDER []byte, err error)

	// EnrollDeviceRaw performs TCG device enrollment.
	// packedCSR is the binary-packed TCG_CSR_IDEVID bytes.
	EnrollDeviceRaw(commonName, organization string, packedCSR []byte) (
		iakDER, idevidDER, credBlob, encSecret, plainSecret []byte, err error,
	)
}
