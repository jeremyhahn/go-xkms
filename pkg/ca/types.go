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

// Package ca provides type definitions for the XKMSCA certificate authority.
//
// This package defines the core types used for certificate signing requests,
// certificate issuance, revocation tracking, and X.509 subject/SAN configuration.
// These types are designed to work with go-xkms's backend-agnostic key storage.
package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// CAConfig provides configuration for creating a CA instance.
//
// This configuration controls the CA's identity, validity periods,
// and certificate extensions. Key parameters are specified via KeyAttributes
// on the Params struct, not duplicated here.
type CAConfig struct {
	// Identity is the Common Name (CN) of the CA certificate.
	// This is used to identify the CA in certificate subjects and logs.
	// Required.
	Identity string `yaml:"identity" json:"identity" mapstructure:"identity"`

	// Subject contains the full X.509 distinguished name for the CA certificate.
	// If provided, it overrides Identity for the CommonName field.
	// Optional.
	Subject *Subject `yaml:"subject" json:"subject" mapstructure:"subject"`

	// ValidityDays is the validity period for the CA certificate in days.
	// Default: 3650 (10 years) for root CAs, 1825 (5 years) for intermediate CAs.
	ValidityDays int `yaml:"validity-days" json:"validity_days" mapstructure:"validity-days"`

	// IsRootCA indicates whether this is a root CA (self-signed) or
	// intermediate CA (signed by parent).
	IsRootCA bool `yaml:"is-root-ca" json:"is_root_ca" mapstructure:"is-root-ca"`

	// MaxPathLength specifies the maximum number of intermediate CAs
	// that can appear below this CA in the certificate chain.
	// Default: 0 for intermediate CAs, 1 for root CAs.
	MaxPathLength int `yaml:"max-path-length" json:"max_path_length" mapstructure:"max-path-length"`

	// MaxPathLengthZero indicates whether MaxPathLength should be set to 0
	// (as opposed to being absent from the certificate).
	MaxPathLengthZero bool `yaml:"max-path-length-zero" json:"max_path_length_zero" mapstructure:"max-path-length-zero"`

	// CRLDistributionPoints specifies URLs where the CRL can be retrieved.
	// Optional.
	CRLDistributionPoints []string `yaml:"crl-distribution-points" json:"crl_distribution_points" mapstructure:"crl-distribution-points"`

	// OCSPServers specifies URLs of OCSP responders.
	// Optional.
	OCSPServers []string `yaml:"ocsp-servers" json:"ocsp_servers" mapstructure:"ocsp-servers"`

	// IssuingCertificateURLs specifies URLs where the issuing CA certificate
	// can be retrieved (Authority Information Access).
	// Optional.
	IssuingCertificateURLs []string `yaml:"issuing-certificate-urls" json:"issuing_certificate_urls" mapstructure:"issuing-certificate-urls"`

	// PolicyIdentifiers specifies certificate policy OIDs.
	// Optional.
	PolicyIdentifiers []string `yaml:"policy-identifiers" json:"policy_identifiers" mapstructure:"policy-identifiers"`

	// StoreType specifies the backend type for storing the CA's private key.
	// Default: types.StoreSoftware
	StoreType types.StoreType `yaml:"store-type" json:"store_type" mapstructure:"store-type"`

	// DefaultCertValidityDays is the default validity period for issued certificates.
	// Default: 365 days
	DefaultCertValidityDays int `yaml:"default-cert-validity-days" json:"default_cert_validity_days" mapstructure:"default-cert-validity-days"`

	// CRLValidityDays is the validity period for generated CRLs.
	// Default: 7 days
	CRLValidityDays int `yaml:"crl-validity-days" json:"crl_validity_days" mapstructure:"crl-validity-days"`

	// PermitCriticalExtensions allows the CA to sign certificates with unknown
	// critical extensions. Default: false
	PermitCriticalExtensions bool `yaml:"permit-critical-extensions" json:"permit_critical_extensions" mapstructure:"permit-critical-extensions"`

	// RequireCSRSignature requires all CSRs to have a valid signature.
	// Default: true
	RequireCSRSignature bool `yaml:"require-csr-signature" json:"require_csr_signature" mapstructure:"require-csr-signature"`
}

// Validate checks that the CAConfig has valid required fields.
func (c *CAConfig) Validate() error {
	if c.Identity == "" && (c.Subject == nil || c.Subject.CommonName == "") {
		return ErrSubjectCommonNameRequired
	}

	if c.ValidityDays < 0 {
		return ErrInvalidValidityPeriod
	}

	if c.MaxPathLength < 0 {
		return ErrInvalidPathLength
	}

	return nil
}

// Subject represents an X.509 distinguished name (DN) containing the identity
// information for a certificate subject or issuer.
type Subject struct {
	// CommonName is the common name (CN) attribute, typically the FQDN or entity name.
	// This field is required for certificate requests.
	CommonName string `yaml:"cn" json:"cn" mapstructure:"cn"`

	// Organization is the organization (O) attribute.
	Organization string `yaml:"organization" json:"organization" mapstructure:"organization"`

	// OrganizationalUnit is the organizational unit (OU) attribute.
	OrganizationalUnit string `yaml:"organizational-unit" json:"organizational_unit" mapstructure:"organizational-unit"`

	// Country is the country (C) attribute using ISO 3166-1 alpha-2 codes.
	Country string `yaml:"country" json:"country" mapstructure:"country"`

	// Province is the state or province (ST) attribute.
	Province string `yaml:"province" json:"province" mapstructure:"province"`

	// Locality is the city or locality (L) attribute.
	Locality string `yaml:"locality" json:"locality" mapstructure:"locality"`

	// Address is the street address attribute.
	Address string `yaml:"address" json:"address" mapstructure:"address"`

	// PostalCode is the postal code attribute.
	PostalCode string `yaml:"postal-code" json:"postal_code" mapstructure:"postal-code"`
}

// ToPkixName converts the Subject to a pkix.Name for use in x509 certificate operations.
func (s *Subject) ToPkixName() pkix.Name {
	name := pkix.Name{
		CommonName: s.CommonName,
	}

	if s.Organization != "" {
		name.Organization = []string{s.Organization}
	}
	if s.OrganizationalUnit != "" {
		name.OrganizationalUnit = []string{s.OrganizationalUnit}
	}
	if s.Country != "" {
		name.Country = []string{s.Country}
	}
	if s.Province != "" {
		name.Province = []string{s.Province}
	}
	if s.Locality != "" {
		name.Locality = []string{s.Locality}
	}
	if s.Address != "" {
		name.StreetAddress = []string{s.Address}
	}
	if s.PostalCode != "" {
		name.PostalCode = []string{s.PostalCode}
	}

	return name
}

// Validate checks that the Subject has at minimum a CommonName set.
func (s *Subject) Validate() error {
	if s.CommonName == "" {
		return ErrSubjectCommonNameRequired
	}
	return nil
}

// HardwareModuleInfo contains hardware module identification information
// as specified in RFC 4108 for TPM and HSM device identity certificates.
type HardwareModuleInfo struct {
	// HWType is the OID identifying the hardware module type.
	// Common values:
	//   - 2.23.133.1 for TCG Platform
	//   - 2.23.133.2 for TCG Endorsement Key
	HWType asn1.ObjectIdentifier `yaml:"hw-type" json:"hw_type" mapstructure:"hw-type"`

	// HWSerialNumber is the unique serial number of the hardware module.
	HWSerialNumber string `yaml:"hw-serial" json:"hw_serial" mapstructure:"hw-serial"`
}

// SubjectAlternativeNames represents the Subject Alternative Names (SANs)
// extension for X.509 certificates, supporting multiple name types.
type SubjectAlternativeNames struct {
	// DNS contains DNS names (dNSName) for the certificate.
	DNS []string `yaml:"dns" json:"dns" mapstructure:"dns"`

	// IPs contains IP addresses (iPAddress) for the certificate.
	// Each entry should be a valid IPv4 or IPv6 address string.
	IPs []string `yaml:"ips" json:"ips" mapstructure:"ips"`

	// Email contains email addresses (rfc822Name) for the certificate.
	Email []string `yaml:"email" json:"email" mapstructure:"email"`

	// URIs contains uniform resource identifiers (uniformResourceIdentifier).
	// Each entry should be a valid URI string.
	URIs []string `yaml:"uris" json:"uris" mapstructure:"uris"`

	// HardwareModuleName contains hardware module identification for TPM/HSM
	// device identity certificates per RFC 4108.
	HardwareModuleName *HardwareModuleInfo `yaml:"hardware-module" json:"hardware_module" mapstructure:"hardware-module"`
}

// ParseIPs parses the IP address strings and returns valid net.IP values.
// Invalid addresses are silently skipped.
func (s *SubjectAlternativeNames) ParseIPs() []net.IP {
	if s == nil || len(s.IPs) == 0 {
		return nil
	}

	ips := make([]net.IP, 0, len(s.IPs))
	for _, ipStr := range s.IPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// ParseURIs parses the URI strings and returns valid url.URL values.
// Invalid URIs are silently skipped.
func (s *SubjectAlternativeNames) ParseURIs() []*url.URL {
	if s == nil || len(s.URIs) == 0 {
		return nil
	}

	uris := make([]*url.URL, 0, len(s.URIs))
	for _, uriStr := range s.URIs {
		if u, err := url.Parse(uriStr); err == nil && u.Scheme != "" {
			uris = append(uris, u)
		}
	}
	return uris
}

// CertificateRequest contains all parameters needed to request a certificate
// from the CA, including subject information, SANs, validity, and key usage.
type CertificateRequest struct {
	// Subject contains the X.509 distinguished name for the certificate.
	Subject Subject `yaml:"subject" json:"subject" mapstructure:"subject"`

	// SANS contains Subject Alternative Names for the certificate.
	SANS *SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`

	// Valid specifies the certificate validity period in days.
	// A value of 0 uses the CA's default validity period.
	Valid int `yaml:"valid" json:"valid" mapstructure:"valid"`

	// KeyUsage specifies the certificate key usage flags.
	// Not serialized as it uses x509.KeyUsage bit flags.
	KeyUsage x509.KeyUsage `yaml:"-" json:"-"`

	// ExtKeyUsage specifies extended key usage purposes.
	// Not serialized as it uses x509.ExtKeyUsage values.
	ExtKeyUsage []x509.ExtKeyUsage `yaml:"-" json:"-"`

	// IsCA indicates whether this certificate is a CA certificate.
	IsCA bool `yaml:"is-ca" json:"is_ca" mapstructure:"is-ca"`

	// MaxPathLen specifies the maximum path length for CA certificates.
	// A value of 0 means no subordinate CAs are allowed.
	// Only meaningful when IsCA is true.
	MaxPathLen int `yaml:"max-path-len" json:"max_path_len" mapstructure:"max-path-len"`

	// MaxPathLenZero indicates whether MaxPathLen of 0 should be explicitly set.
	// When true and IsCA is true, no subordinate CAs are allowed.
	MaxPathLenZero bool `yaml:"max-path-len-zero" json:"max_path_len_zero" mapstructure:"max-path-len-zero"`

	// KeyAttributes specifies key generation parameters from go-xkms.
	// If nil, a new key will be generated with default attributes.
	// Not serialized as it contains complex xkms types.
	KeyAttributes *types.KeyAttributes `yaml:"-" json:"-"`

	// Signer provides an external crypto.Signer for the certificate.
	// If provided, KeyAttributes is ignored for key generation.
	// Not serialized as it contains runtime objects.
	Signer crypto.Signer `yaml:"-" json:"-"`

	// IssuerCert optionally specifies the issuing CA certificate.
	// If nil, the CA's own certificate is used as the issuer.
	// Not serialized as it contains parsed certificate data.
	IssuerCert *x509.Certificate `yaml:"-" json:"-"`

	// ProdModel is the TPM product model string for TCG certificate extensions.
	// Used by IssueEKCertificate to add the TPM model extension.
	ProdModel string `yaml:"prod-model" json:"prod_model" mapstructure:"prod-model"`

	// ProdSerial is the TPM product serial string for TCG certificate extensions.
	// Used by IssueEKCertificate to add the TPM version extension.
	ProdSerial string `yaml:"prod-serial" json:"prod_serial" mapstructure:"prod-serial"`

	// PermanentID is an optional permanent identifier for TCG certificates.
	// When set, a PermanentIdentifier extension is added to the certificate.
	PermanentID string `yaml:"permanent-id" json:"permanent_id" mapstructure:"permanent-id"`

	// IssuerKeyStoreType indicates the CA's keystore backend type for TCG extensions.
	// When set, adds a tp-issuerKeyStore extension. Common values: "TPM2", "PKCS8", "PKCS11".
	IssuerKeyStoreType string `yaml:"issuer-keystore-type" json:"issuer_keystore_type" mapstructure:"issuer-keystore-type"`
}

// Validate checks that the CertificateRequest has valid required fields.
func (cr *CertificateRequest) Validate() error {
	if err := cr.Subject.Validate(); err != nil {
		return err
	}

	if cr.Valid < 0 {
		return ErrInvalidValidityPeriod
	}

	if cr.IsCA && cr.MaxPathLen < 0 {
		return ErrInvalidPathLength
	}

	return nil
}

// RevocationInfo contains information about a revoked certificate.
type RevocationInfo struct {
	// SerialNumber is the unique serial number of the revoked certificate.
	SerialNumber *big.Int

	// RevocationTime is when the certificate was revoked.
	RevocationTime time.Time

	// Reason specifies the revocation reason code per RFC 5280 Section 5.3.1:
	//   0 - Unspecified
	//   1 - KeyCompromise
	//   2 - CACompromise
	//   3 - AffiliationChanged
	//   4 - Superseded
	//   5 - CessationOfOperation
	//   6 - CertificateHold
	//   8 - RemoveFromCRL
	//   9 - PrivilegeWithdrawn
	//   10 - AACompromise
	Reason int
}

// IssuedCertificate contains the result of a successful certificate issuance,
// including the certificate, any generated private key, and chain information.
type IssuedCertificate struct {
	// Certificate is the parsed X.509 certificate.
	Certificate *x509.Certificate

	// CertificatePEM is the PEM-encoded certificate.
	CertificatePEM []byte

	// PrivateKey is the generated private key (nil if external signer was used).
	PrivateKey crypto.PrivateKey

	// PrivateKeyPEM is the PEM-encoded private key (nil if external signer was used
	// or if the key is stored in hardware).
	PrivateKeyPEM []byte

	// CACertificatePEM is the PEM-encoded issuing CA certificate.
	CACertificatePEM []byte

	// ChainPEM contains the full certificate chain in PEM format,
	// from the issued certificate up to (but not including) the root.
	ChainPEM []byte

	// SerialNumber is the certificate's serial number.
	SerialNumber *big.Int

	// NotBefore is when the certificate becomes valid.
	NotBefore time.Time

	// NotAfter is when the certificate expires.
	NotAfter time.Time
}

// TCGEnrollmentResult contains the output of a TCG-CSR-IDEVID enrollment.
// After receiving this result, the caller must complete the ActivateCredential
// challenge/response before delivering the certificates to the device.
type TCGEnrollmentResult struct {
	// IAKCertDER is the DER-encoded IAK certificate (issued after CSR verification).
	IAKCertDER []byte

	// IDevIDCertDER is the DER-encoded IDevID certificate.
	IDevIDCertDER []byte

	// CredentialBlob is the TPM2B_ID_OBJECT for the ActivateCredential challenge.
	CredentialBlob []byte

	// EncryptedSecret is the TPM2B_ENCRYPTED_SECRET for ActivateCredential.
	EncryptedSecret []byte

	// PlainSecret is the original secret for verification after ActivateCredential.
	// Compare this with the secret returned by the device's ActivateCredential
	// to prove EK possession.
	PlainSecret []byte
}

// SignOptions contains optional parameters for certificate signing operations,
// allowing customization of the signing process.
type SignOptions struct {
	// Profile specifies a named certificate profile to use.
	// Profiles define default key usage, validity, and other settings.
	Profile string

	// ValidityDays overrides the default validity period.
	// A value of 0 uses the profile or CA default.
	ValidityDays int

	// NotBefore specifies a custom not-before time.
	// If zero, the current time is used.
	NotBefore time.Time

	// KeyUsage overrides the profile's key usage settings.
	// A value of 0 uses the profile default.
	KeyUsage x509.KeyUsage

	// ExtKeyUsage overrides the profile's extended key usage settings.
	// If nil, the profile default is used.
	ExtKeyUsage []x509.ExtKeyUsage

	// Subject overrides the CSR subject fields.
	// Individual fields that are empty use the CSR values.
	Subject *Subject

	// SANS provides additional SANs to include beyond those in the CSR.
	SANS *SubjectAlternativeNames
}
