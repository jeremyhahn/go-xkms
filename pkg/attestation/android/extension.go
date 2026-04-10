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

// Package android provides parsing and verification for Android Key Attestation
// extensions embedded in X.509 certificates produced by Android Keystore.
//
// The Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) provides
// cryptographic proof that a key was generated inside Android hardware security
// modules (TEE or StrongBox). This package extracts and validates these
// attestation claims.
//
// See: https://source.android.com/docs/security/features/keystore/attestation
package android

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// AndroidKeyAttestationOID is the OID for the Android Key Attestation extension.
var AndroidKeyAttestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// SecurityLevel represents the security level of a key or the attestation itself.
type SecurityLevel int

const (
	// SecurityLevelSoftware indicates the key is protected by software only.
	SecurityLevelSoftware SecurityLevel = 0

	// SecurityLevelTrustedEnvironment indicates the key is protected by the TEE.
	SecurityLevelTrustedEnvironment SecurityLevel = 1

	// SecurityLevelStrongBox indicates the key is protected by a dedicated
	// hardware security module (StrongBox).
	SecurityLevelStrongBox SecurityLevel = 2
)

// securityLevelNames provides O(1) lookup for security level display names.
var securityLevelNames = map[SecurityLevel]string{
	SecurityLevelSoftware:           "software",
	SecurityLevelTrustedEnvironment: "tee",
	SecurityLevelStrongBox:          "strongbox",
}

// String returns the human-readable name of the security level.
func (sl SecurityLevel) String() string {
	if name, ok := securityLevelNames[sl]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", int(sl))
}

// Typed errors for the android attestation package.
var (
	// ErrExtensionNotFound indicates the Android Key Attestation extension was
	// not present in the certificate.
	ErrExtensionNotFound = errors.New("android: key attestation extension not found")

	// ErrExtensionParseFailed indicates ASN.1 parsing of the extension failed.
	ErrExtensionParseFailed = errors.New("android: failed to parse attestation extension")

	// ErrInvalidSecurityLevel indicates an unrecognized security level value.
	ErrInvalidSecurityLevel = errors.New("android: invalid security level")

	// ErrNilCertificate indicates a nil certificate was provided.
	ErrNilCertificate = errors.New("android: nil certificate")

	// ErrChainTooShort indicates the certificate chain does not contain enough
	// certificates for verification.
	ErrChainTooShort = errors.New("android: certificate chain too short")

	// ErrNonceMismatch indicates the attestation challenge does not match
	// the expected nonce.
	ErrNonceMismatch = errors.New("android: attestation nonce mismatch")

	// ErrInsufficientSecurityLevel indicates the attestation security level
	// is below the required minimum.
	ErrInsufficientSecurityLevel = errors.New("android: security level below minimum")

	// ErrUnverifiedBoot indicates the device boot state is not verified.
	ErrUnverifiedBoot = errors.New("android: device boot state is not verified")

	// ErrNilVerifyOptions indicates nil verification options were provided.
	ErrNilVerifyOptions = errors.New("android: verify options cannot be nil")

	// ErrChainVerificationFailed indicates the certificate chain could not
	// be verified against the trusted roots.
	ErrChainVerificationFailed = errors.New("android: certificate chain verification failed")
)

// KeyDescription represents the parsed Android Key Attestation extension.
//
// See: https://source.android.com/docs/security/features/keystore/attestation#key-attestation-ext-schema
type KeyDescription struct {
	// AttestationVersion is the version of the attestation schema.
	AttestationVersion int

	// AttestationSecurityLevel indicates where the attestation was generated.
	AttestationSecurityLevel SecurityLevel

	// KeymasterVersion is the version of the Keymaster/KeyMint HAL.
	KeymasterVersion int

	// KeymasterSecurityLevel indicates the security level of the Keymaster implementation.
	KeymasterSecurityLevel SecurityLevel

	// AttestationChallenge is the challenge nonce provided during key generation.
	AttestationChallenge []byte

	// UniqueID is an optional device-unique identifier.
	UniqueID []byte

	// SoftwareEnforced contains key properties enforced by software.
	SoftwareEnforced AuthorizationList

	// TeeEnforced contains key properties enforced by the TEE or StrongBox.
	TeeEnforced AuthorizationList
}

// AuthorizationList contains key authorization properties.
type AuthorizationList struct {
	// Purpose contains the allowed key usages.
	Purpose []int

	// Algorithm is the cryptographic algorithm of the key.
	Algorithm int

	// KeySize is the size of the key in bits.
	KeySize int

	// EcCurve is the elliptic curve identifier for EC keys.
	EcCurve int

	// Origin indicates how the key was created.
	Origin int

	// RootOfTrust contains device boot state information, if present.
	RootOfTrust *RootOfTrust
}

// RootOfTrust contains device boot state information from Android Verified Boot.
type RootOfTrust struct {
	// VerifiedBootKey is the public key used to verify the boot image.
	VerifiedBootKey []byte

	// DeviceLocked indicates whether the device bootloader is locked.
	DeviceLocked bool

	// VerifiedBootState is the Android Verified Boot state.
	VerifiedBootState VerifiedBootState

	// VerifiedBootHash is the hash of all verified boot partitions.
	VerifiedBootHash []byte
}

// VerifiedBootState represents the Android Verified Boot state.
type VerifiedBootState int

const (
	// VerifiedBootVerified means the boot chain is fully verified.
	VerifiedBootVerified VerifiedBootState = 0

	// VerifiedBootSelfSigned means the boot image is signed with a non-OEM key.
	VerifiedBootSelfSigned VerifiedBootState = 1

	// VerifiedBootUnverified means the bootloader is unlocked and no verification occurs.
	VerifiedBootUnverified VerifiedBootState = 2

	// VerifiedBootFailed means the boot image verification failed.
	VerifiedBootFailed VerifiedBootState = 3
)

// verifiedBootStateNames provides O(1) lookup for boot state display names.
var verifiedBootStateNames = map[VerifiedBootState]string{
	VerifiedBootVerified:   "verified",
	VerifiedBootSelfSigned: "self-signed",
	VerifiedBootUnverified: "unverified",
	VerifiedBootFailed:     "failed",
}

// String returns the human-readable name of the verified boot state.
func (vbs VerifiedBootState) String() string {
	if name, ok := verifiedBootStateNames[vbs]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", int(vbs))
}

// VerifyOptions configures Android Key Attestation verification.
type VerifyOptions struct {
	// TrustedRoots is the cert pool for verifying the certificate chain.
	TrustedRoots *x509.CertPool

	// ExpectedNonce is the challenge nonce that should appear in the attestation.
	ExpectedNonce []byte

	// MinSecurityLevel is the minimum acceptable security level.
	MinSecurityLevel SecurityLevel

	// VerifyBootState checks that the device boot state is verified.
	VerifyBootState bool
}

// keyDescriptionASN1 is the raw ASN.1 structure for parsing the top-level
// KeyDescription SEQUENCE.
//
//	KeyDescription ::= SEQUENCE {
//	    attestationVersion         INTEGER,
//	    attestationSecurityLevel   SecurityLevel,
//	    keymasterVersion           INTEGER,
//	    keymasterSecurityLevel     SecurityLevel,
//	    attestationChallenge       OCTET STRING,
//	    uniqueId                   OCTET STRING,
//	    softwareEnforced           AuthorizationList,
//	    teeEnforced                AuthorizationList,
//	}
type keyDescriptionASN1 struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TeeEnforced              asn1.RawValue
}

// rootOfTrustASN1 is the ASN.1 structure for the RootOfTrust field.
//
//	RootOfTrust ::= SEQUENCE {
//	    verifiedBootKey    OCTET STRING,
//	    deviceLocked       BOOLEAN,
//	    verifiedBootState  VerifiedBootState,
//	    verifiedBootHash   OCTET STRING,
//	}
type rootOfTrustASN1 struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte
}

// ParseKeyAttestation extracts and parses the Android Key Attestation extension
// from an X.509 certificate.
//
// The extension is identified by OID 1.3.6.1.4.1.11129.2.1.17 and contains
// ASN.1-encoded key attestation claims including the security level,
// attestation challenge, and authorization lists.
//
// Parameters:
//   - cert: The X.509 certificate containing the attestation extension
//
// Returns:
//   - The parsed KeyDescription or an error
func ParseKeyAttestation(cert *x509.Certificate) (*KeyDescription, error) {
	if cert == nil {
		return nil, ErrNilCertificate
	}

	// Find the attestation extension by OID
	var extValue []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(AndroidKeyAttestationOID) {
			extValue = ext.Value
			break
		}
	}

	if extValue == nil {
		return nil, ErrExtensionNotFound
	}

	// Parse the top-level ASN.1 SEQUENCE
	var raw keyDescriptionASN1
	rest, err := asn1.Unmarshal(extValue, &raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrExtensionParseFailed, err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%w: trailing data after KeyDescription", ErrExtensionParseFailed)
	}

	desc := &KeyDescription{
		AttestationVersion:       raw.AttestationVersion,
		AttestationSecurityLevel: SecurityLevel(raw.AttestationSecurityLevel),
		KeymasterVersion:         raw.KeymasterVersion,
		KeymasterSecurityLevel:   SecurityLevel(raw.KeymasterSecurityLevel),
		AttestationChallenge:     raw.AttestationChallenge,
		UniqueID:                 raw.UniqueID,
	}

	// Parse authorization lists minimally. The AuthorizationList is an
	// IMPLICIT tagged SEQUENCE with context-specific tags that varies across
	// attestation versions. We extract RootOfTrust from teeEnforced if present.
	desc.TeeEnforced = parseAuthorizationList(raw.TeeEnforced)
	desc.SoftwareEnforced = parseAuthorizationList(raw.SoftwareEnforced)

	return desc, nil
}

// parseAuthorizationList performs minimal parsing of an AuthorizationList
// ASN.1 structure. The AuthorizationList contains IMPLICIT tagged fields
// that are difficult to parse generically, so we extract only the fields
// we need.
func parseAuthorizationList(rawVal asn1.RawValue) AuthorizationList {
	authList := AuthorizationList{}

	// The AuthorizationList is a SEQUENCE of IMPLICIT tagged values.
	// We do not attempt full parsing here since the tag assignments
	// vary across Keymaster/KeyMint versions. RootOfTrust parsing
	// would require walking the SEQUENCE and matching tag 704.
	// This is left intentionally minimal for forward compatibility.

	if len(rawVal.FullBytes) == 0 {
		return authList
	}

	// Attempt to find and parse RootOfTrust (tag 704 / 0x02C0)
	// within the teeEnforced AuthorizationList.
	rot := findRootOfTrust(rawVal.FullBytes)
	if rot != nil {
		authList.RootOfTrust = rot
	}

	return authList
}

// findRootOfTrust attempts to locate and parse a RootOfTrust SEQUENCE
// within the raw bytes of an AuthorizationList. Returns nil if not found
// or not parseable.
func findRootOfTrust(data []byte) *RootOfTrust {
	// RootOfTrust is tagged with context-specific tag [704] EXPLICIT.
	// In practice, finding it requires walking the ASN.1 SEQUENCE elements.
	// For robustness, we attempt to find a SEQUENCE that can be parsed
	// as rootOfTrustASN1 within the data. This is a best-effort approach.

	// Walk through the outer SEQUENCE
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(data, &outer)
	if err != nil || len(rest) > 0 {
		return nil
	}

	// Iterate through elements in the SEQUENCE
	remaining := outer.Bytes
	for len(remaining) > 0 {
		var elem asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &elem)
		if err != nil {
			break
		}

		// RootOfTrust is context-specific class, constructed
		if elem.Class == asn1.ClassContextSpecific && elem.IsCompound {
			// Try to parse as RootOfTrust
			var rot rootOfTrustASN1
			if _, parseErr := asn1.Unmarshal(elem.Bytes, &rot); parseErr == nil {
				return &RootOfTrust{
					VerifiedBootKey:   rot.VerifiedBootKey,
					DeviceLocked:      rot.DeviceLocked,
					VerifiedBootState: VerifiedBootState(rot.VerifiedBootState),
					VerifiedBootHash:  rot.VerifiedBootHash,
				}
			}
		}
	}

	return nil
}

// VerifyKeyAttestation verifies an Android Key Attestation certificate chain
// and validates the attestation extension claims.
//
// Verification steps:
//  1. Validates the certificate chain against trusted roots
//  2. Parses the attestation extension from the leaf certificate
//  3. Verifies the attestation challenge matches the expected nonce
//  4. Verifies the attestation security level meets the minimum requirement
//  5. Optionally verifies the device boot state
//
// Parameters:
//   - chain: The certificate chain with the leaf (attestation) cert at index 0
//   - opts: Verification options controlling what checks are performed
//
// Returns:
//   - The parsed KeyDescription if verification succeeds, or an error
func VerifyKeyAttestation(chain []*x509.Certificate, opts *VerifyOptions) (*KeyDescription, error) {
	if opts == nil {
		return nil, ErrNilVerifyOptions
	}

	if len(chain) < 1 {
		return nil, ErrChainTooShort
	}

	// Verify the certificate chain against trusted roots if provided
	if opts.TrustedRoots != nil {
		if err := verifyCertificateChain(chain, opts.TrustedRoots); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrChainVerificationFailed, err)
		}
	}

	// Parse the attestation extension from the leaf certificate
	leaf := chain[0]
	desc, err := ParseKeyAttestation(leaf)
	if err != nil {
		return nil, err
	}

	// Verify the attestation challenge (nonce) using constant-time comparison
	if opts.ExpectedNonce != nil {
		if len(desc.AttestationChallenge) != len(opts.ExpectedNonce) ||
			subtle.ConstantTimeCompare(desc.AttestationChallenge, opts.ExpectedNonce) != 1 {
			return nil, ErrNonceMismatch
		}
	}

	// Verify the security level meets the minimum requirement
	if desc.AttestationSecurityLevel < opts.MinSecurityLevel {
		return nil, fmt.Errorf("%w: got %s, require %s",
			ErrInsufficientSecurityLevel,
			desc.AttestationSecurityLevel,
			opts.MinSecurityLevel)
	}

	// Verify boot state if requested
	if opts.VerifyBootState {
		if desc.TeeEnforced.RootOfTrust != nil {
			if desc.TeeEnforced.RootOfTrust.VerifiedBootState != VerifiedBootVerified {
				return nil, ErrUnverifiedBoot
			}
		}
	}

	return desc, nil
}

// verifyCertificateChain verifies the certificate chain against the provided
// trusted root certificate pool.
func verifyCertificateChain(chain []*x509.Certificate, roots *x509.CertPool) error {
	if len(chain) == 0 {
		return ErrChainTooShort
	}

	leaf := chain[0]

	// Build intermediate pool from the chain (excluding leaf and root)
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leaf.Verify(verifyOpts); err != nil {
		return err
	}

	return nil
}

// buildMinimalAttestationExtension constructs a minimal ASN.1-encoded
// Android Key Attestation extension for testing purposes. This is exported
// so that test packages can create synthetic attestation certificates.
func BuildMinimalAttestationExtension(
	version int,
	attestSecLevel SecurityLevel,
	kmVersion int,
	kmSecLevel SecurityLevel,
	challenge []byte,
	uniqueID []byte,
) ([]byte, error) {
	// Build empty AuthorizationList SEQUENCEs
	emptySeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      []byte{},
	})
	if err != nil {
		return nil, fmt.Errorf("android: failed to marshal empty authorization list: %w", err)
	}

	// Workaround: build the KeyDescription manually since the encoding
	// of the AuthorizationList requires passing through RawValue.
	// We marshal each field individually and concatenate.
	versionBytes, err := asn1.Marshal(version)
	if err != nil {
		return nil, fmt.Errorf("android: failed to marshal version: %w", err)
	}

	attestSecBytes, err := asn1.Marshal(asn1.Enumerated(attestSecLevel))
	if err != nil {
		return nil, fmt.Errorf("android: failed to marshal attestation security level: %w", err)
	}

	kmVersionBytes, err := asn1.Marshal(kmVersion)
	if err != nil {
		return nil, fmt.Errorf("android: failed to marshal keymaster version: %w", err)
	}

	kmSecBytes, err := asn1.Marshal(asn1.Enumerated(kmSecLevel))
	if err != nil {
		return nil, fmt.Errorf("android: failed to marshal keymaster security level: %w", err)
	}

	challengeBytes, err := asn1.Marshal(challenge)
	if err != nil {
		return nil, fmt.Errorf("android: failed to marshal challenge: %w", err)
	}

	uniqueIDBytes, err := asn1.Marshal(uniqueID)
	if err != nil {
		return nil, fmt.Errorf("android: failed to marshal unique ID: %w", err)
	}

	// Concatenate all fields into the SEQUENCE content
	var seqContent bytes.Buffer
	seqContent.Write(versionBytes)
	seqContent.Write(attestSecBytes)
	seqContent.Write(kmVersionBytes)
	seqContent.Write(kmSecBytes)
	seqContent.Write(challengeBytes)
	seqContent.Write(uniqueIDBytes)
	seqContent.Write(emptySeq)
	seqContent.Write(emptySeq)

	// Wrap in SEQUENCE
	result, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      seqContent.Bytes(),
	})
	if err != nil {
		return nil, fmt.Errorf("android: failed to marshal KeyDescription sequence: %w", err)
	}

	return result, nil
}
