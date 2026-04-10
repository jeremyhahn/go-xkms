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

// Package profiles provides certificate profile implementations for the XKMSCA.
//
// # PIV Certificate Profiles per NIST SP 800-73-4
//
// This file implements Personal Identity Verification (PIV) certificate profiles
// as defined in NIST Special Publication 800-73-4 "Interfaces for Personal Identity
// Verification". These profiles support the four standard PIV certificate slots:
//
// # PIV Certificate Slots
//
// Slot 9A - PIV Authentication Certificate:
// Used for authentication to systems and networks. The private key is used to
// authenticate the cardholder to the PIV system. Digital signatures are produced
// using the private key as part of challenge/response authentication.
//
// Slot 9C - Digital Signature Certificate:
// Used for digital signatures on documents and data. The private key is intended
// for signing operations where non-repudiation is required. Each use of the
// private key requires PIN entry to ensure explicit cardholder consent.
//
// Slot 9D - Key Management Certificate:
// Used for key establishment and data encryption. The private key supports
// decryption of session keys, key wrapping, and key agreement operations.
//
// Slot 9E - Card Authentication Certificate:
// Used for supporting physical access applications. This certificate is used
// to authenticate the PIV card rather than the cardholder. It supports contactless
// card authentication without requiring PIN entry.
//
// # Usage
//
//	// Get a profile for a specific PIV slot
//	profile, err := profiles.PIVProfileForSlot(profiles.SlotAuthentication)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Register all PIV profiles with a registry
//	registry := ca.NewDefaultProfileRegistry()
//	if err := profiles.RegisterPIVProfiles(registry); err != nil {
//	    log.Fatal(err)
//	}
//
// # References
//
//   - NIST SP 800-73-4: https://csrc.nist.gov/publications/detail/sp/800-73/4/final
//   - NIST SP 800-76-2: Biometric Specifications for PIV
//   - NIST SP 800-78-4: Cryptographic Algorithms and Key Sizes for PIV
//   - FIPS 201-3: PIV of Federal Employees and Contractors
package profiles

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// =============================================================================
// PIV Slot Constants
// =============================================================================

// PIV slot identifiers as defined in NIST SP 800-73-4.
const (
	// SlotAuthentication (9A) is used for PIV Authentication.
	// The certificate in this slot is used for authentication to systems
	// and networks. The private key supports digital signature operations
	// for challenge/response authentication protocols.
	SlotAuthentication = "9a"

	// SlotSignature (9C) is used for Digital Signature operations.
	// The certificate in this slot is used for signing documents and data
	// where non-repudiation is required. PIN entry is required before each
	// private key operation.
	SlotSignature = "9c"

	// SlotKeyManagement (9D) is used for Key Management operations.
	// The certificate in this slot is used for key establishment, including
	// key decryption, key agreement, and key wrapping operations.
	SlotKeyManagement = "9d"

	// SlotCardAuth (9E) is used for Card Authentication.
	// The certificate in this slot is used for authenticating the PIV card
	// itself (as opposed to the cardholder). It supports contactless
	// authentication without requiring PIN entry.
	SlotCardAuth = "9e"
)

// =============================================================================
// PIV OID Constants
// =============================================================================

// PIV-related Object Identifiers (OIDs) for extended key usage and extensions.
var (
	// OIDSmartCardLogon is the Microsoft OID for Smart Card Logon.
	// This EKU is required for Windows smart card authentication.
	// OID: 1.3.6.1.4.1.311.20.2.2
	OIDSmartCardLogon = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}

	// OIDDocumentSigning is the Adobe OID for Document Signing.
	// This EKU indicates the certificate can be used for PDF signing.
	// OID: 1.2.840.113583.1.1.5
	OIDDocumentSigning = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 5}

	// OIDPIVInterim is the OID for PIV Interim credentials.
	// Used during the transition period before permanent PIV credentials are issued.
	// OID: 2.16.840.1.101.3.6.9.1
	OIDPIVInterim = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 9, 1}

	// OIDPIVContentSigning is the OID for PIV Content Signing.
	// Used for signing PIV data objects.
	// OID: 2.16.840.1.101.3.8.7.1
	OIDPIVContentSigning = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 8, 7, 1}

	// OIDPIVCardAuthentication is the OID for PIV Card Authentication.
	// Used in the Card Authentication certificate (slot 9E).
	// OID: 2.16.840.1.101.3.6.8
	OIDPIVCardAuthentication = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 8}

	// OIDPIVCHUID is the OID for the PIV Card Holder Unique Identifier.
	// OID: 2.16.840.1.101.3.6.6
	OIDPIVCHUID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 6}
)

// Federal PKI policy OIDs commonly used with PIV certificates.
var (
	// OIDFPKICommonPolicy is the Federal PKI Common Policy OID.
	// OID: 2.16.840.1.101.3.2.1.3
	OIDFPKICommonPolicy = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3}

	// OIDFPKICommonHardware is the Federal PKI Common Hardware policy.
	// Indicates keys are stored in hardware.
	// OID: 2.16.840.1.101.3.2.1.3.7
	OIDFPKICommonHardware = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 7}

	// OIDFPKICommonHighAssurance is the Federal PKI Common High Assurance policy.
	// OID: 2.16.840.1.101.3.2.1.3.13
	OIDFPKICommonHighAssurance = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 13}
)

// =============================================================================
// PIV Profile Constants
// =============================================================================

// Default validity periods for PIV certificates in days.
const (
	// DefaultPIVValidityDays is the standard validity period for PIV certificates (3 years).
	DefaultPIVValidityDays = 1095

	// DefaultPIVCardAuthValidityDays matches the card validity (typically 5 years).
	DefaultPIVCardAuthValidityDays = 1825
)

// PIV profile names for registry lookups.
const (
	ProfileNamePIVAuthentication = "piv-authentication"
	ProfileNamePIVSignature      = "piv-signature"
	ProfileNamePIVKeyManagement  = "piv-key-management"
	ProfileNamePIVCardAuth       = "piv-card-auth"
)

// =============================================================================
// Base PIV Profile
// =============================================================================

// basePIVProfile provides common PIV profile functionality.
type basePIVProfile struct {
	name            string
	slot            string
	description     string
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	extKeyUsageOIDs []asn1.ObjectIdentifier
	defaultValidity int
}

// Name returns the profile name.
func (p *basePIVProfile) Name() string {
	return p.name
}

// KeyUsage returns the key usage for this profile.
func (p *basePIVProfile) KeyUsage() x509.KeyUsage {
	return p.keyUsage
}

// ExtKeyUsage returns the extended key usage for this profile.
func (p *basePIVProfile) ExtKeyUsage() []x509.ExtKeyUsage {
	return p.extKeyUsage
}

// DefaultValidity returns the default validity period in days.
func (p *basePIVProfile) DefaultValidity() int {
	return p.defaultValidity
}

// Slot returns the PIV slot identifier for this profile.
func (p *basePIVProfile) Slot() string {
	return p.slot
}

// Description returns a human-readable description of the profile.
func (p *basePIVProfile) Description() string {
	return p.description
}

// Apply applies the base PIV profile to a certificate template.
func (p *basePIVProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	if template == nil {
		return ca.ErrInvalidProfile
	}

	template.KeyUsage = p.keyUsage
	template.ExtKeyUsage = p.extKeyUsage

	// Add custom OID-based extended key usages as unknown EKUs
	if len(p.extKeyUsageOIDs) > 0 {
		template.UnknownExtKeyUsage = append(template.UnknownExtKeyUsage, p.extKeyUsageOIDs...)
	}

	return nil
}

// =============================================================================
// PIV Authentication Profile (Slot 9A)
// =============================================================================

// PIVAuthenticationProfile implements the PIV Authentication certificate profile.
//
// This profile is used for certificates in PIV slot 9A, which supports
// authentication to systems and networks. The certificate is used with
// challenge/response protocols where the private key produces digital
// signatures to prove cardholder identity.
//
// Per NIST SP 800-73-4:
//   - Key Usage: digitalSignature
//   - Extended Key Usage: id-piv-auth-ekpolicy, id-ms-sc-logon, TLS Client Auth
//   - Validity: Typically 3 years
type PIVAuthenticationProfile struct {
	*basePIVProfile
}

// NewPIVAuthenticationProfile creates a profile for PIV Authentication (slot 9A).
//
// The PIV Authentication certificate is used for:
//   - Authentication to systems and networks
//   - TLS client authentication
//   - Windows smart card logon
//   - PIV authentication protocols
//
// Key Usage: Digital Signature
// Extended Key Usage: Client Auth, Smart Card Logon
// Default Validity: 3 years (1095 days)
func NewPIVAuthenticationProfile() *PIVAuthenticationProfile {
	return &PIVAuthenticationProfile{
		basePIVProfile: &basePIVProfile{
			name:        ProfileNamePIVAuthentication,
			slot:        SlotAuthentication,
			description: "PIV Authentication Certificate for user authentication",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
			extKeyUsageOIDs: []asn1.ObjectIdentifier{
				OIDSmartCardLogon,
			},
			defaultValidity: DefaultPIVValidityDays,
		},
	}
}

// Apply applies the PIV Authentication profile to a certificate template.
func (p *PIVAuthenticationProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	if err := p.basePIVProfile.Apply(template, request); err != nil {
		return err
	}

	// PIV Authentication certificates should not be CA certificates
	template.IsCA = false
	template.BasicConstraintsValid = true

	return nil
}

// =============================================================================
// PIV Digital Signature Profile (Slot 9C)
// =============================================================================

// PIVSignatureProfile implements the PIV Digital Signature certificate profile.
//
// This profile is used for certificates in PIV slot 9C, which supports
// digital signature operations where non-repudiation is required. Each use
// of the private key requires explicit PIN entry to ensure cardholder consent.
//
// Per NIST SP 800-73-4:
//   - Key Usage: digitalSignature, nonRepudiation (contentCommitment)
//   - Extended Key Usage: id-piv-sign-ekpolicy, id-adobe-doc-sign, Email Protection
//   - Validity: Typically 3 years
type PIVSignatureProfile struct {
	*basePIVProfile
}

// NewPIVSignatureProfile creates a profile for PIV Digital Signature (slot 9C).
//
// The PIV Digital Signature certificate is used for:
//   - Signing documents with non-repudiation
//   - S/MIME email signing
//   - PDF document signing
//   - Code signing (in some deployments)
//
// Key Usage: Digital Signature, Content Commitment (Non-Repudiation)
// Extended Key Usage: Email Protection, Document Signing
// Default Validity: 3 years (1095 days)
//
// Note: The private key requires PIN entry before each use to ensure
// explicit cardholder consent for signing operations.
func NewPIVSignatureProfile() *PIVSignatureProfile {
	return &PIVSignatureProfile{
		basePIVProfile: &basePIVProfile{
			name:        ProfileNamePIVSignature,
			slot:        SlotSignature,
			description: "PIV Digital Signature Certificate for signing documents",
			keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			extKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageEmailProtection,
			},
			extKeyUsageOIDs: []asn1.ObjectIdentifier{
				OIDDocumentSigning,
			},
			defaultValidity: DefaultPIVValidityDays,
		},
	}
}

// Apply applies the PIV Digital Signature profile to a certificate template.
func (p *PIVSignatureProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	if err := p.basePIVProfile.Apply(template, request); err != nil {
		return err
	}

	// PIV Signature certificates should not be CA certificates
	template.IsCA = false
	template.BasicConstraintsValid = true

	return nil
}

// =============================================================================
// PIV Key Management Profile (Slot 9D)
// =============================================================================

// PIVKeyManagementProfile implements the PIV Key Management certificate profile.
//
// This profile is used for certificates in PIV slot 9D, which supports
// key management operations including key establishment, key agreement,
// and data encryption. Historical key management keys may be stored for
// decryption of previously encrypted data.
//
// Per NIST SP 800-73-4:
//   - Key Usage: keyEncipherment, keyAgreement, dataEncipherment
//   - Extended Key Usage: id-piv-km-ekpolicy, Email Protection
//   - Validity: Typically 3 years
type PIVKeyManagementProfile struct {
	*basePIVProfile
}

// NewPIVKeyManagementProfile creates a profile for PIV Key Management (slot 9D).
//
// The PIV Key Management certificate is used for:
//   - Key establishment and key agreement
//   - Decryption of session keys
//   - S/MIME email encryption
//   - Data encryption operations
//   - Key wrapping
//
// Key Usage: Key Encipherment, Key Agreement, Data Encipherment
// Extended Key Usage: Email Protection
// Default Validity: 3 years (1095 days)
//
// Note: Historical key management keys should be retained for decryption
// of data encrypted under previous keys.
func NewPIVKeyManagementProfile() *PIVKeyManagementProfile {
	return &PIVKeyManagementProfile{
		basePIVProfile: &basePIVProfile{
			name:        ProfileNamePIVKeyManagement,
			slot:        SlotKeyManagement,
			description: "PIV Key Management Certificate for encryption",
			keyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageDataEncipherment,
			extKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageEmailProtection,
			},
			extKeyUsageOIDs: nil, // No additional OID-based EKUs for key management
			defaultValidity: DefaultPIVValidityDays,
		},
	}
}

// Apply applies the PIV Key Management profile to a certificate template.
func (p *PIVKeyManagementProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	if err := p.basePIVProfile.Apply(template, request); err != nil {
		return err
	}

	// PIV Key Management certificates should not be CA certificates
	template.IsCA = false
	template.BasicConstraintsValid = true

	return nil
}

// =============================================================================
// PIV Card Authentication Profile (Slot 9E)
// =============================================================================

// PIVCardAuthProfile implements the PIV Card Authentication certificate profile.
//
// This profile is used for certificates in PIV slot 9E, which supports
// card authentication for physical access control. The certificate authenticates
// the PIV card itself rather than the cardholder, and can be used without
// PIN entry for contactless authentication.
//
// Per NIST SP 800-73-4:
//   - Key Usage: digitalSignature
//   - Extended Key Usage: id-piv-cardauth-ekpolicy, TLS Client Auth, Smart Card Logon
//   - Validity: Matches card validity (typically 5 years)
type PIVCardAuthProfile struct {
	*basePIVProfile
}

// NewPIVCardAuthProfile creates a profile for PIV Card Authentication (slot 9E).
//
// The PIV Card Authentication certificate is used for:
//   - Physical access control systems
//   - Contactless card authentication
//   - Card-to-card authentication
//   - Low-security authentication scenarios
//
// Key Usage: Digital Signature
// Extended Key Usage: Client Auth, Smart Card Logon
// Default Validity: 5 years (1825 days) - matches typical card validity
//
// Note: This certificate authenticates the card itself, not the cardholder.
// It can be used without PIN entry, making it suitable for contactless
// physical access applications where speed is important.
func NewPIVCardAuthProfile() *PIVCardAuthProfile {
	return &PIVCardAuthProfile{
		basePIVProfile: &basePIVProfile{
			name:        ProfileNamePIVCardAuth,
			slot:        SlotCardAuth,
			description: "PIV Card Authentication Certificate for physical access",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
			extKeyUsageOIDs: []asn1.ObjectIdentifier{
				OIDSmartCardLogon,
				OIDPIVCardAuthentication,
			},
			defaultValidity: DefaultPIVCardAuthValidityDays,
		},
	}
}

// Apply applies the PIV Card Authentication profile to a certificate template.
func (p *PIVCardAuthProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	if err := p.basePIVProfile.Apply(template, request); err != nil {
		return err
	}

	// PIV Card Authentication certificates should not be CA certificates
	template.IsCA = false
	template.BasicConstraintsValid = true

	return nil
}

// =============================================================================
// PIV Profile Interface
// =============================================================================

// PIVProfile extends ProfileProvider with PIV-specific methods.
type PIVProfile interface {
	ca.ProfileProvider

	// Slot returns the PIV slot identifier (9a, 9c, 9d, or 9e).
	Slot() string

	// Description returns a human-readable description of the profile.
	Description() string
}

// =============================================================================
// PIV Profile Helper Functions
// =============================================================================

// pivSlotProfiles maps PIV slot identifiers to their profile constructors.
var pivSlotProfiles = map[string]func() PIVProfile{
	SlotAuthentication: func() PIVProfile { return NewPIVAuthenticationProfile() },
	SlotSignature:      func() PIVProfile { return NewPIVSignatureProfile() },
	SlotKeyManagement:  func() PIVProfile { return NewPIVKeyManagementProfile() },
	SlotCardAuth:       func() PIVProfile { return NewPIVCardAuthProfile() },
}

// PIVProfileForSlot returns the appropriate PIV profile for the given slot identifier.
//
// Valid slot identifiers are:
//   - "9a" - PIV Authentication
//   - "9c" - Digital Signature
//   - "9d" - Key Management
//   - "9e" - Card Authentication
//
// Returns ErrInvalidProfile if the slot is not a valid PIV slot.
//
// Example:
//
//	profile, err := PIVProfileForSlot("9a")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Use profile for slot 9A operations
func PIVProfileForSlot(slot string) (PIVProfile, error) {
	constructor, exists := pivSlotProfiles[slot]
	if !exists {
		return nil, ca.ErrInvalidProfile
	}
	return constructor(), nil
}

// RegisterPIVProfiles registers all PIV profiles with the given registry.
//
// This registers the following profiles:
//   - piv-authentication (slot 9A)
//   - piv-signature (slot 9C)
//   - piv-key-management (slot 9D)
//   - piv-card-auth (slot 9E)
//
// Returns an error if any profile fails to register.
//
// Example:
//
//	registry := ca.NewDefaultProfileRegistry()
//	if err := RegisterPIVProfiles(registry); err != nil {
//	    log.Fatal(err)
//	}
func RegisterPIVProfiles(registry ca.ProfileRegistry) error {
	profiles := []ca.ProfileProvider{
		NewPIVAuthenticationProfile(),
		NewPIVSignatureProfile(),
		NewPIVKeyManagementProfile(),
		NewPIVCardAuthProfile(),
	}

	for _, profile := range profiles {
		if err := registry.Register(profile.Name(), profile); err != nil {
			return err
		}
	}

	return nil
}

// AllPIVProfiles returns all PIV profiles.
//
// This is useful for iterating over all PIV profiles or for batch operations.
func AllPIVProfiles() []PIVProfile {
	return []PIVProfile{
		NewPIVAuthenticationProfile(),
		NewPIVSignatureProfile(),
		NewPIVKeyManagementProfile(),
		NewPIVCardAuthProfile(),
	}
}

// PIVSlots returns all valid PIV slot identifiers.
func PIVSlots() []string {
	return []string{
		SlotAuthentication,
		SlotSignature,
		SlotKeyManagement,
		SlotCardAuth,
	}
}

// =============================================================================
// PIV Extension Helpers
// =============================================================================

// PIVExtension represents a PIV-specific certificate extension.
type PIVExtension struct {
	// OID is the object identifier for the extension.
	OID asn1.ObjectIdentifier

	// Critical indicates whether the extension is critical.
	Critical bool

	// Value is the raw extension value (ASN.1 encoded).
	Value []byte
}

// NewPIVAuthenticationExtension creates the PIV authentication policy extension.
//
// This extension can be added to certificates to indicate they comply with
// PIV authentication requirements.
func NewPIVAuthenticationExtension() (*pkix.Extension, error) {
	// Create a basic PIV authentication policy extension
	// The value is typically a policy OID sequence
	policyValue, err := asn1.Marshal(OIDFPKICommonHardware)
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:       OIDFPKICommonPolicy,
		Critical: false,
		Value:    policyValue,
	}, nil
}

// IsPIVSlot returns true if the given string is a valid PIV slot identifier.
func IsPIVSlot(slot string) bool {
	_, exists := pivSlotProfiles[slot]
	return exists
}

// PIVSlotName returns a human-readable name for the given PIV slot.
//
// Returns an empty string if the slot is not valid.
func PIVSlotName(slot string) string {
	names := map[string]string{
		SlotAuthentication: "PIV Authentication",
		SlotSignature:      "Digital Signature",
		SlotKeyManagement:  "Key Management",
		SlotCardAuth:       "Card Authentication",
	}
	return names[slot]
}
