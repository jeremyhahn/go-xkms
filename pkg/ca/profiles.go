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

// Package ca provides certificate profile management.
//
// Profiles encapsulate standard certificate configurations for different use cases.
// Each profile specifies key usage, extended key usage, validity periods, and other
// certificate attributes appropriate for its intended purpose.
package ca

import (
	"crypto/x509"
	"encoding/asn1"
	"sort"
	"strings"
	"sync"
)

// =============================================================================
// Default Profile Registry
// =============================================================================

// defaultProfileRegistry implements ProfileRegistry with built-in certificate profiles.
type defaultProfileRegistry struct {
	profiles map[string]ProfileProvider
	mu       sync.RWMutex
}

// NewDefaultProfileRegistry creates a ProfileRegistry with standard built-in profiles.
//
// Built-in profiles include:
//   - server: TLS server authentication
//   - client: TLS client authentication
//   - code-signing: Code signing operations
//   - email: S/MIME email protection
//   - ocsp-responder: OCSP response signing
//   - timestamping: Timestamp authority
//   - ca: Certificate Authority (subordinate CA)
//   - fido2-attestation: FIDO2 authenticator attestation (WebAuthn L2 8.2.1)
//   - dice-idevid: DICE initial device identity (DICE Certificate Profiles 5.1.6.1)
//   - ipsec-vtep: IKEv2 tunnel endpoint (RFC 4945), caller-supplied names
//   - x509-svid: SPIFFE X.509-SVID leaf, caller-supplied names
//
// Thread-safe: Yes
func NewDefaultProfileRegistry() ProfileRegistry {
	registry := &defaultProfileRegistry{
		profiles: make(map[string]ProfileProvider),
	}

	// Register built-in profiles
	registry.registerBuiltinProfiles()

	return registry
}

// registerBuiltinProfiles registers all built-in certificate profiles.
func (r *defaultProfileRegistry) registerBuiltinProfiles() {
	profiles := []ProfileProvider{
		NewServerProfile(),
		NewClientProfile(),
		NewCodeSigningProfile(),
		NewEmailProfile(),
		NewOCSPResponderProfile(),
		NewTimestampingProfile(),
		NewCAProfile(),
		NewACMELeafProfile(),
		NewTCGEndorsementKeyProfile(),
		NewTCGAttestationKeyProfile(),
		NewTCGInitialAttestationKeyProfile(),
		NewTCGDeviceIdentityProfile(),
		NewTCGLocalAttestationKeyProfile(),
		NewFIDO2AttestationProfile(),
		NewDICEDeviceIdentityProfile(),
		NewIPsecVTEPProfile(),
		NewX509SVIDProfile(),
	}

	for _, profile := range profiles {
		r.profiles[strings.ToLower(profile.Name())] = profile
	}
}

// Register registers a profile with the given name.
//
// If a profile with the same name already exists, it is replaced.
// Profile names are case-insensitive and normalized to lowercase.
//
// Returns ErrInvalidProfile if the profile is nil or invalid.
//
// Thread-safe: Yes
func (r *defaultProfileRegistry) Register(name string, profile ProfileProvider) error {
	if profile == nil {
		return ErrInvalidProfile
	}

	normalizedName := strings.ToLower(strings.TrimSpace(name))
	if normalizedName == "" {
		return ErrInvalidProfile
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.profiles[normalizedName] = profile
	return nil
}

// Get returns a profile by name.
//
// Profile names are case-insensitive.
//
// Returns ErrProfileNotFound if no profile with the given name exists.
//
// Thread-safe: Yes
func (r *defaultProfileRegistry) Get(name string) (ProfileProvider, error) {
	normalizedName := strings.ToLower(strings.TrimSpace(name))

	r.mu.RLock()
	defer r.mu.RUnlock()

	profile, exists := r.profiles[normalizedName]
	if !exists {
		return nil, ErrProfileNotFound
	}

	return profile, nil
}

// List returns all registered profile names.
//
// The returned slice is sorted alphabetically and contains the
// normalized (lowercase) profile names.
//
// Thread-safe: Yes
func (r *defaultProfileRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.profiles))
	for name := range r.profiles {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// =============================================================================
// Base Profile Implementation
// =============================================================================

// baseProfile provides a base implementation for certificate profiles.
type baseProfile struct {
	name            string
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	defaultValidity int

	// basicConstraintsValid controls whether the issued certificate carries a
	// Basic Constraints extension at all. End-entity profiles for TLS assert
	// an explicit non-CA constraint; the TCG credential profiles and the ACME
	// leaf profile deliberately omit the extension, which is a policy decision
	// and therefore lives on the profile rather than at a call site.
	basicConstraintsValid bool

	// policies are the certificate policy OIDs the profile stamps onto every
	// certificate it issues, such as the TCG verified-TPM-residency and
	// verified-TPM-fixed policies.
	policies []x509.OID

	// unknownExtKeyUsage are extended key usage OIDs crypto/x509 has no
	// x509.ExtKeyUsage constant for, such as the TCG DevID §8.1 extended key
	// usage. They are encoded into the same extension as extKeyUsage.
	unknownExtKeyUsage []asn1.ObjectIdentifier
}

// Name returns the profile name.
func (p *baseProfile) Name() string {
	return p.name
}

// KeyUsage returns the key usage for this profile.
func (p *baseProfile) KeyUsage() x509.KeyUsage {
	return p.keyUsage
}

// ExtKeyUsage returns the extended key usage for this profile.
func (p *baseProfile) ExtKeyUsage() []x509.ExtKeyUsage {
	return p.extKeyUsage
}

// DefaultValidity returns the default validity period in days.
func (p *baseProfile) DefaultValidity() int {
	return p.defaultValidity
}

// Apply applies the profile to a certificate template.
//
// This method modifies the certificate template in place, setting
// key usage, extended key usage, and other profile-specific attributes.
//
// The profile is the last word on the fields it owns: key usage, extended key
// usage, basic constraints and certificate policies are overwritten rather
// than merged, so that every issuance path funnelling through Issuer.Issue
// produces the same policy for the same profile.
func (p *baseProfile) Apply(template *x509.Certificate, request *CertificateRequest) error {
	if template == nil {
		return ErrInvalidProfile
	}

	template.KeyUsage = p.keyUsage
	template.ExtKeyUsage = p.extKeyUsage
	template.UnknownExtKeyUsage = p.unknownExtKeyUsage
	template.BasicConstraintsValid = p.basicConstraintsValid
	template.Policies = p.policies

	return nil
}

// =============================================================================
// Built-in Certificate Profiles
// =============================================================================

// serverProfile provides configuration for TLS server certificates.
type serverProfile struct {
	baseProfile
}

// NewServerProfile creates a profile for TLS server authentication certificates.
//
// Key usage:
//   - DigitalSignature
//   - KeyEncipherment
//
// Extended key usage:
//   - ServerAuth
//
// Default validity: 365 days
func NewServerProfile() ProfileProvider {
	return &serverProfile{
		baseProfile: baseProfile{
			name:                  "server",
			keyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			defaultValidity:       365,
			basicConstraintsValid: true,
		},
	}
}

// clientProfile provides configuration for TLS client certificates.
type clientProfile struct {
	baseProfile
}

// NewClientProfile creates a profile for TLS client authentication certificates.
//
// Key usage:
//   - DigitalSignature
//   - KeyEncipherment
//
// Extended key usage:
//   - ClientAuth
//
// Default validity: 365 days
func NewClientProfile() ProfileProvider {
	return &clientProfile{
		baseProfile: baseProfile{
			name:                  "client",
			keyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			defaultValidity:       365,
			basicConstraintsValid: true,
		},
	}
}

// codeSigningProfile provides configuration for code signing certificates.
type codeSigningProfile struct {
	baseProfile
}

// NewCodeSigningProfile creates a profile for code signing certificates.
//
// Key usage:
//   - DigitalSignature
//
// Extended key usage:
//   - CodeSigning
//
// Default validity: 365 days
func NewCodeSigningProfile() ProfileProvider {
	return &codeSigningProfile{
		baseProfile: baseProfile{
			name:                  "code-signing",
			keyUsage:              x509.KeyUsageDigitalSignature,
			extKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			defaultValidity:       365,
			basicConstraintsValid: true,
		},
	}
}

// emailProfile provides configuration for S/MIME email certificates.
type emailProfile struct {
	baseProfile
}

// NewEmailProfile creates a profile for S/MIME email protection certificates.
//
// Key usage:
//   - DigitalSignature
//   - ContentCommitment (nonRepudiation)
//   - KeyEncipherment
//
// Extended key usage:
//   - EmailProtection
//
// Default validity: 365 days
func NewEmailProfile() ProfileProvider {
	return &emailProfile{
		baseProfile: baseProfile{
			name:                  "email",
			keyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
			extKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			defaultValidity:       365,
			basicConstraintsValid: true,
		},
	}
}

// ocspResponderProfile provides configuration for OCSP responder certificates.
type ocspResponderProfile struct {
	baseProfile
}

// NewOCSPResponderProfile creates a profile for OCSP response signing certificates.
//
// Key usage:
//   - DigitalSignature
//
// Extended key usage:
//   - OCSPSigning
//
// Default validity: 90 days (OCSP responder certs are typically short-lived)
func NewOCSPResponderProfile() ProfileProvider {
	return &ocspResponderProfile{
		baseProfile: baseProfile{
			name:                  "ocsp-responder",
			keyUsage:              x509.KeyUsageDigitalSignature,
			extKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			defaultValidity:       90,
			basicConstraintsValid: true,
		},
	}
}

// timestampingProfile provides configuration for timestamping certificates.
type timestampingProfile struct {
	baseProfile
}

// NewTimestampingProfile creates a profile for timestamp authority certificates.
//
// Key usage:
//   - DigitalSignature
//   - ContentCommitment (nonRepudiation)
//
// Extended key usage:
//   - TimeStamping
//
// Default validity: 365 days
func NewTimestampingProfile() ProfileProvider {
	return &timestampingProfile{
		baseProfile: baseProfile{
			name:                  "timestamping",
			keyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			extKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			defaultValidity:       365,
			basicConstraintsValid: true,
		},
	}
}

// ProfileNameCA is the registry name of the CA profile. Root, intermediate and
// per-tenant CA certificates are all issued with it, so a change to the CA
// profile reaches every CA certificate this project creates.
const ProfileNameCA = "ca"

// caProfile provides configuration for subordinate CA certificates.
type caProfile struct {
	baseProfile
}

// NewCAProfile creates a profile for subordinate CA certificates.
//
// Key usage:
//   - CertSign
//   - CRLSign
//   - DigitalSignature
//
// Extended key usage: (none - CA certificates don't need EKU)
//
// Default validity: 1825 days (5 years)
func NewCAProfile() ProfileProvider {
	return &caProfile{
		baseProfile: baseProfile{
			name:            ProfileNameCA,
			keyUsage:        x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			extKeyUsage:     nil,
			defaultValidity: 1825, // 5 years
		},
	}
}

// Apply applies the CA profile to a certificate template.
// This overrides the base implementation to set IsCA and BasicConstraintsValid.
func (p *caProfile) Apply(template *x509.Certificate, request *CertificateRequest) error {
	if template == nil {
		return ErrInvalidProfile
	}

	template.KeyUsage = p.keyUsage
	template.ExtKeyUsage = p.extKeyUsage
	template.Policies = p.policies
	template.IsCA = true
	template.BasicConstraintsValid = true

	// Set path length from request if specified
	if request != nil {
		template.MaxPathLen = request.MaxPathLen
		template.MaxPathLenZero = request.MaxPathLenZero
	}

	return nil
}

// =============================================================================
// End-Entity Profiles
// =============================================================================

// ProfileNameACMELeaf is the registry name of the ACME end-entity profile.
const ProfileNameACMELeaf = "acme-leaf"

// NewACMELeafProfile creates the profile for end-entity certificates issued by
// the ACME issuance pipeline.
//
// Key usage:
//   - DigitalSignature
//   - KeyEncipherment
//
// Extended key usage:
//   - ServerAuth
//   - ClientAuth
//
// Basic constraints are deliberately omitted: an ACME subscriber certificate
// derives its non-CA status from the issuing CA's path length constraint, and
// the CA/Browser Forum baseline requirements do not require the extension on
// subscriber certificates.
//
// Default validity: 90 days, the ACME convention.
func NewACMELeafProfile() ProfileProvider {
	return &baseProfile{
		name:            ProfileNameACMELeaf,
		keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		defaultValidity: 90,
	}
}

// newTLSLeafProfile creates the profile applied to a CSR-signing operation
// whose caller did not name one.
//
// keyUsage and extKeyUsage carry the caller's SignOptions overrides, or the
// CA's TLS defaults when the caller supplied none. Expressing even the
// "no profile requested" case as a profile is what lets Issuer.Issue require a
// profile unconditionally, so no issuance path can bypass Profile.Apply.
func newTLSLeafProfile(keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, defaultValidity int) ProfileProvider {
	return &baseProfile{
		name:                  "tls-leaf",
		keyUsage:              keyUsage,
		extKeyUsage:           extKeyUsage,
		defaultValidity:       defaultValidity,
		basicConstraintsValid: true,
	}
}

// =============================================================================
// TCG Credential Profiles
// =============================================================================

// Registry names of the TCG credential profiles. Each corresponds to one
// certificate type in the TCG EK Credential Profile and TCG TPM 2.0 Keys for
// Device Identity and Attestation specifications.
const (
	ProfileNameTCGEndorsementKey = "tcg-ek"
	ProfileNameTCGAttestationKey = "tcg-ak"
	ProfileNameTCGInitialAK      = "tcg-iak"
	ProfileNameTCGDeviceIdentity = "tcg-idevid"
	ProfileNameTCGLocalAK        = "tcg-lak"
)

// tcgExtKeyUsage is the extended key usage shared by every TCG credential this
// CA issues. The order is significant: it is encoded into the certificate and
// changing it changes the certificate.
func tcgExtKeyUsage() []x509.ExtKeyUsage {
	return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
}

// tcgAttestationPolicies are the TCG policy OIDs stamped on an ATTESTATION
// key certificate (AK, IAK, LAK): the key is TPM-resident and Restricted — it
// can only sign digests the TPM itself produced, so data it signs is genuinely
// TPM internal data. TCG DevID v1 r12 §8.2 requires a relying party to check
// verifiedTPMRestricted before trusting an attestation, which is only possible
// if the CA stamps it.
//
// verifiedTPMFixed is deliberately absent. §8.2 (spec text lines 3010-3013):
// tcg-cap-verifiedTPMRestricted "MUST NOT be combined with TCG-CE-FixedTPM",
// and symmetrically tcg-cap-verifiedTPMFixed "MUST NOT be combined with
// TCG-CE-FixedTPM-RestrictedKey". The restricted assertion already states that
// the CA "has verified both the fixedTPM and Restricted bits are set", so the
// pair is not merely prohibited but redundant.
func tcgAttestationPolicies() []x509.OID {
	return []x509.OID{
		TCGVerifiedTPMResidencyPolicy,
		TCGVerifiedTPMRestrictedPolicy,
	}
}

// tcgIdentityPolicies are the TCG policy OIDs stamped on a device IDENTITY
// key certificate (IDevID, LDevID): TPM-resident and fixed, but deliberately
// NOT Restricted — the spec creates the identity key Unrestricted precisely
// so it can sign arbitrary data such as a TLS CertificateVerify, and marks
// the two classes differently "to prevent the possibility of spoofing".
// Stamping verifiedTPMRestricted on an identity key would assert a property
// the key does not have.
func tcgIdentityPolicies() []x509.OID {
	return []x509.OID{TCGVerifiedTPMResidencyPolicy, TCGVerifiedTPMFixedPolicy}
}

// tcgAttestationExtKeyUsage and tcgIdentityExtKeyUsage are the TCG extended
// key usage a DevID credential carries beside the TLS usages.
//
// TCG DevID v1 r12 §8.1 (spec text line 2977): Extended Key Usage "SHOULD be
// populated with the one TCG OID most appropriate for the type of key used,
// either 'TCG-CE-FixedTPM' or 'TCG-CE-FixedTPM-RestrictedKey'. Refer to section
// 8.2 for the details of these OIDs." §8.2 gives those two OIDs as
// tcg-cap-verifiedTPMFixed (2.23.133.11.1.2) for a key whose fixedTPM bit was
// verified and tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3) for a key whose
// fixedTPM and Restricted bits were both verified — so an attestation key takes
// the restricted OID and an identity key the fixed one, exactly one each.
//
// The TLS client and server usages stay: §8.1 is explicit that these
// credentials authenticate TLS connections, and RFC 5280 section 4.2.1.12
// requires every purpose a certificate is used for to appear.
func tcgAttestationExtKeyUsage() []asn1.ObjectIdentifier {
	return []asn1.ObjectIdentifier{OIDTCGVerifiedTPMRestricted}
}

func tcgIdentityExtKeyUsage() []asn1.ObjectIdentifier {
	return []asn1.ObjectIdentifier{OIDTCGVerifiedTPMFixed}
}

// tcgEKCertificateExtKeyUsage is the extended key usage marking a certificate
// as a TCG endorsement key credential: tcg-kp-EKCertificate (2.23.133.8.1).
//
// The TCG EK Credential Profile defines this OID as an Extended Key Usage
// purpose, so it belongs inside the certificate's standard ExtKeyUsage
// extension (RFC 5280 section 4.2.1.12) alongside the purposes tcgExtKeyUsage
// already asserts — not as a standalone extension under the OID's own Id,
// which is where it once lived and which requireTCGEKCertificateEKU (the
// check this CA runs against an EK certificate chain before IAK/IDevID
// issuance) does not look, nor where ImportEndorsementKeyCertificate and
// EndorsementKeyCertificate looked for it.
func tcgEKCertificateExtKeyUsage() []asn1.ObjectIdentifier {
	return []asn1.ObjectIdentifier{OIDTCGKpEKCertificate}
}

// tcgAIKCertificateExtKeyUsage is the extended key usage marking a
// certificate as a TCG AIK/IAK credential: tcg-kp-AIKCertificate
// (2.23.133.8.3), combined with the attestation key's own TPM-residency and
// Restricted assertion (tcgAttestationExtKeyUsage).
//
// WebAuthn L2 §8.3.1 "TPM Attestation Statement Certificate Requirements"
// requires tcg-kp-AIKCertificate inside the certificate's standard
// ExtKeyUsage extension: go-webauthn's "tpm" attestation format verifier
// parses the ExtKeyUsage extension (OID 2.5.29.37, RFC 5280 section 4.2.1.12)
// and looks for this OID among its values, not for a standalone extension
// whose own Id is tcg-kp-AIKCertificate — an encoding no such verifier reads.
func tcgAIKCertificateExtKeyUsage() []asn1.ObjectIdentifier {
	return append([]asn1.ObjectIdentifier{OIDTCGKpAIKCertificate}, tcgAttestationExtKeyUsage()...)
}

// tcgValidityDays is the validity a TCG credential is issued for. TCG device
// credentials do not expire in the ordinary sense; the issuance paths encode
// the "no well-defined expiration" date from RFC 5280 section 4.1.2.5 instead
// of computing NotAfter from this value, which exists so the profile satisfies
// ProfileProvider.
const tcgValidityDays = 0

// NewTCGEndorsementKeyProfile creates the profile for TPM endorsement key
// certificates per the TCG EK Credential Profile.
//
// Key usage is KeyEncipherment: an endorsement key is an encryption key, not a
// signing key.
func NewTCGEndorsementKeyProfile() ProfileProvider {
	return &baseProfile{
		name:               ProfileNameTCGEndorsementKey,
		keyUsage:           x509.KeyUsageKeyEncipherment,
		extKeyUsage:        tcgExtKeyUsage(),
		unknownExtKeyUsage: tcgEKCertificateExtKeyUsage(),
		defaultValidity:    tcgValidityDays,
	}
}

// NewTCGAttestationKeyProfile creates the profile for TPM attestation key
// certificates.
//
// Key usage is DigitalSignature: an attestation key signs quotes and
// certification structures.
//
// BasicConstraintsValid is asserted with IsCA left false. WebAuthn L2 §8.3.1
// requirement 5 is "The Basic Constraints extension MUST have the CA
// component set to false"; the TCG TPM 2.0 Keys for Device Identity and
// Attestation specification never mentions Basic Constraints for an AK/IAK
// certificate, so asserting it explicitly satisfies WebAuthn without
// contradicting TCG.
func NewTCGAttestationKeyProfile() ProfileProvider {
	return &baseProfile{
		name:                  ProfileNameTCGAttestationKey,
		keyUsage:              x509.KeyUsageDigitalSignature,
		extKeyUsage:           tcgExtKeyUsage(),
		unknownExtKeyUsage:    tcgAIKCertificateExtKeyUsage(),
		defaultValidity:       tcgValidityDays,
		policies:              tcgAttestationPolicies(),
		basicConstraintsValid: true,
	}
}

// NewTCGInitialAttestationKeyProfile creates the profile for the initial
// attestation key (IAK) certificate issued from a TCG-CSR-IDEVID.
//
// BasicConstraintsValid is asserted with IsCA left false; see
// NewTCGAttestationKeyProfile for why.
func NewTCGInitialAttestationKeyProfile() ProfileProvider {
	return &baseProfile{
		name:                  ProfileNameTCGInitialAK,
		keyUsage:              x509.KeyUsageDigitalSignature,
		extKeyUsage:           tcgExtKeyUsage(),
		unknownExtKeyUsage:    tcgAIKCertificateExtKeyUsage(),
		defaultValidity:       tcgValidityDays,
		policies:              tcgAttestationPolicies(),
		basicConstraintsValid: true,
	}
}

// NewTCGDeviceIdentityProfile creates the profile for the initial device
// identity (IDevID) certificate issued from a TCG-CSR-IDEVID.
//
// Key usage is DigitalSignature alone. TCG DevID v1 r12 §8.1 Table 22 (spec
// text lines 2844-2851) gives an IDevID "digitalSignature (only) is
// RECOMMENDED" and reserves the encryption usages for a Combined key —
// "digitalSignature and dataEncipherment (Combined IDevID)". This CA refuses a
// CSR whose IDevID key has the TPM Decrypt attribute set (§4.2
// "Not-decrypting"), so the key certified here is never a Combined key and
// keyEncipherment would advertise a capability the key does not have.
func NewTCGDeviceIdentityProfile() ProfileProvider {
	return &baseProfile{
		name:               ProfileNameTCGDeviceIdentity,
		keyUsage:           x509.KeyUsageDigitalSignature,
		extKeyUsage:        tcgExtKeyUsage(),
		unknownExtKeyUsage: tcgIdentityExtKeyUsage(),
		defaultValidity:    tcgValidityDays,
		policies:           tcgIdentityPolicies(),
	}
}

// NewTCGLocalAttestationKeyProfile creates the profile for a Local
// Attestation Key (LAK) certificate: the WebAuthn Level 2 §8.3.1 "TPM
// Attestation Statement Certificate Requirements" profile go-xkms#715 issues
// over a LAK whose TPM2_Certify evidence the IAK has signed.
//
// It is deliberately narrower than NewTCGAttestationKeyProfile:
//
//   - Extended key usage is tcg-kp-AIKCertificate (2.23.133.8.3) alone, the
//     one OID §8.3.1 requirement 4 requires. The TLS ClientAuth/ServerAuth
//     purposes tcgExtKeyUsage adds for the IAK and IDevID describe a TCG
//     DevID credential's role in authenticating TLS connections (TCG TPM 2.0
//     Keys for Device Identity and Attestation v1.00 r12 §8.1); a LAK
//     authenticates nothing but its own WebAuthn attestations and asserting
//     TLS purposes it is never used for would be false.
//   - No certificate policies: tcg-cap-verifiedTPMResidency and
//     -verifiedTPMRestricted (tcgAttestationPolicies) are TCG DevID
//     assertions a WebAuthn relying party's "tpm" format verifier does not
//     read, and WebAuthn §8.3.1 names no certificate policy requirement of
//     its own.
//
// BasicConstraintsValid is asserted with IsCA left false (requirement 5). The
// Subject is the caller's to leave empty; subjectAltName criticality follows
// automatically from an empty Subject (BuildSubjectAltName), which is what
// requirement 2 ("Subject field MUST be empty") and requirement 3's critical
// TCG directoryName both need.
func NewTCGLocalAttestationKeyProfile() ProfileProvider {
	return &baseProfile{
		name:                  ProfileNameTCGLocalAK,
		keyUsage:              x509.KeyUsageDigitalSignature,
		unknownExtKeyUsage:    []asn1.ObjectIdentifier{OIDTCGKpAIKCertificate},
		defaultValidity:       tcgValidityDays,
		basicConstraintsValid: true,
	}
}

// =============================================================================
// Custom Profile Builder
// =============================================================================

// ProfileBuilder provides a fluent interface for creating custom profiles.
type ProfileBuilder struct {
	name                  string
	keyUsage              x509.KeyUsage
	extKeyUsage           []x509.ExtKeyUsage
	defaultValidity       int
	isCA                  bool
	basicConstraintsValid bool
	policies              []x509.OID
}

// NewProfileBuilder creates a new ProfileBuilder for creating custom profiles.
//
// Custom profiles assert basic constraints by default; call
// WithBasicConstraints(false) for a profile whose certificates must omit the
// extension entirely.
func NewProfileBuilder(name string) *ProfileBuilder {
	return &ProfileBuilder{
		name:                  name,
		defaultValidity:       365, // Default to 1 year
		basicConstraintsValid: true,
	}
}

// WithBasicConstraints controls whether certificates issued with this profile
// carry a Basic Constraints extension.
func (b *ProfileBuilder) WithBasicConstraints(valid bool) *ProfileBuilder {
	b.basicConstraintsValid = valid
	return b
}

// WithPolicies sets the certificate policy OIDs stamped onto certificates
// issued with this profile.
func (b *ProfileBuilder) WithPolicies(policies ...x509.OID) *ProfileBuilder {
	b.policies = policies
	return b
}

// WithKeyUsage sets the key usage flags.
func (b *ProfileBuilder) WithKeyUsage(usage x509.KeyUsage) *ProfileBuilder {
	b.keyUsage = usage
	return b
}

// WithExtKeyUsage sets the extended key usage values.
func (b *ProfileBuilder) WithExtKeyUsage(usage ...x509.ExtKeyUsage) *ProfileBuilder {
	b.extKeyUsage = usage
	return b
}

// WithDefaultValidity sets the default validity period in days.
func (b *ProfileBuilder) WithDefaultValidity(days int) *ProfileBuilder {
	b.defaultValidity = days
	return b
}

// AsCA marks this profile as a CA profile.
func (b *ProfileBuilder) AsCA() *ProfileBuilder {
	b.isCA = true
	b.keyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return b
}

// Build creates the ProfileProvider from the builder configuration.
func (b *ProfileBuilder) Build() ProfileProvider {
	if b.isCA {
		return &customCAProfile{
			baseProfile: baseProfile{
				name:                  b.name,
				keyUsage:              b.keyUsage,
				extKeyUsage:           b.extKeyUsage,
				defaultValidity:       b.defaultValidity,
				basicConstraintsValid: true,
				policies:              b.policies,
			},
		}
	}

	return &baseProfile{
		name:                  b.name,
		keyUsage:              b.keyUsage,
		extKeyUsage:           b.extKeyUsage,
		defaultValidity:       b.defaultValidity,
		basicConstraintsValid: b.basicConstraintsValid,
		policies:              b.policies,
	}
}

// customCAProfile is a custom CA profile created via the builder.
type customCAProfile struct {
	baseProfile
}

// Apply applies the custom CA profile to a certificate template.
func (p *customCAProfile) Apply(template *x509.Certificate, request *CertificateRequest) error {
	if template == nil {
		return ErrInvalidProfile
	}

	template.KeyUsage = p.keyUsage
	template.ExtKeyUsage = p.extKeyUsage
	template.Policies = p.policies
	template.IsCA = true
	template.BasicConstraintsValid = true

	if request != nil {
		template.MaxPathLen = request.MaxPathLen
		template.MaxPathLenZero = request.MaxPathLenZero
	}

	return nil
}
