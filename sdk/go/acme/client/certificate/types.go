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

// Package certificate provides the ACME certificate client operations.
package certificate

import "time"

// Status represents the status of a certificate.
type Status string

const (
	// StatusValid indicates the certificate is valid.
	StatusValid Status = "valid"

	// StatusRevoked indicates the certificate has been revoked.
	StatusRevoked Status = "revoked"

	// StatusExpired indicates the certificate has expired.
	StatusExpired Status = "expired"
)

// RevocationReason represents the reason for certificate revocation (RFC 5280).
type RevocationReason int

const (
	// ReasonUnspecified is an unspecified revocation reason.
	ReasonUnspecified RevocationReason = 0

	// ReasonKeyCompromise indicates the private key was compromised.
	ReasonKeyCompromise RevocationReason = 1

	// ReasonCACompromise indicates the CA was compromised.
	ReasonCACompromise RevocationReason = 2

	// ReasonAffiliationChanged indicates the subject's affiliation changed.
	ReasonAffiliationChanged RevocationReason = 3

	// ReasonSuperseded indicates the certificate has been superseded.
	ReasonSuperseded RevocationReason = 4

	// ReasonCessationOfOperation indicates the certificate is no longer needed.
	ReasonCessationOfOperation RevocationReason = 5

	// ReasonCertificateHold indicates the certificate is on hold.
	ReasonCertificateHold RevocationReason = 6

	// ReasonRemoveFromCRL indicates the certificate should be removed from CRL.
	ReasonRemoveFromCRL RevocationReason = 8

	// ReasonPrivilegeWithdrawn indicates the subject's privileges were withdrawn.
	ReasonPrivilegeWithdrawn RevocationReason = 9

	// ReasonAACompromise indicates the attribute authority was compromised.
	ReasonAACompromise RevocationReason = 10
)

// Certificate represents an ACME certificate.
type Certificate struct {
	// ID is the unique identifier for the certificate.
	ID uint64 `json:"id,omitempty"`

	// URL is the certificate download URL.
	URL string `json:"url"`

	// PEM is the certificate chain in PEM format.
	PEM string `json:"pem"`

	// Status is the current status of the certificate.
	Status Status `json:"status"`

	// IssuedAt is the timestamp when the certificate was issued.
	IssuedAt time.Time `json:"issued"`

	// ExpiresAt is the timestamp when the certificate expires.
	ExpiresAt time.Time `json:"expires"`

	// SerialNumber is the certificate serial number.
	SerialNumber string `json:"serialNumber,omitempty"`

	// Subject is the certificate subject DN.
	Subject string `json:"subject,omitempty"`

	// Issuer is the certificate issuer DN.
	Issuer string `json:"issuer,omitempty"`

	// DNSNames contains the DNS names in the certificate.
	DNSNames []string `json:"dnsNames,omitempty"`

	// IPAddresses contains the IP addresses in the certificate.
	IPAddresses []string `json:"ipAddresses,omitempty"`
}

// GetRequest contains the parameters for retrieving a certificate.
type GetRequest struct {
	// CertificateURL is the URL of the certificate to retrieve.
	CertificateURL string `json:"certificateUrl"`

	// PreferredChain is the preferred issuer CN for alternate chain selection.
	PreferredChain string `json:"preferredChain,omitempty"`
}

// GetResponse contains the response from retrieving a certificate.
type GetResponse struct {
	// Certificate is the retrieved certificate.
	Certificate *Certificate `json:"certificate"`

	// Chain is the full certificate chain in PEM format.
	Chain string `json:"chain"`

	// AlternateLinks contains URLs to alternate certificate chains.
	AlternateLinks []string `json:"alternateLinks,omitempty"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}

// RevokeRequest contains the parameters for revoking a certificate.
type RevokeRequest struct {
	// Certificate is the certificate to revoke in DER format, base64url-encoded.
	// Either Certificate or CertificateURL must be provided.
	Certificate string `json:"certificate,omitempty"`

	// CertificateURL is the URL of the certificate to revoke.
	// Either Certificate or CertificateURL must be provided.
	CertificateURL string `json:"certificateUrl,omitempty"`

	// Reason is the revocation reason code (RFC 5280).
	Reason RevocationReason `json:"reason,omitempty"`
}

// RevokeResponse contains the response from revoking a certificate.
type RevokeResponse struct {
	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}
