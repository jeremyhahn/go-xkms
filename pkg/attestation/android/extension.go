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
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
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
	// Purpose contains the allowed key usages (tag 1), one of the
	// Purpose* constants per entry. Nil means the list carried no purpose
	// claim, which is not the same as an explicit empty set -- ASN.1 has no
	// way to tell those apart here, so both parse to nil.
	Purpose []int

	// Algorithm is the cryptographic algorithm of the key.
	Algorithm int

	// KeySize is the size of the key in bits.
	KeySize int

	// EcCurve is the elliptic curve identifier for EC keys.
	EcCurve int

	// Origin indicates how the key was created (tag 702), one of the
	// Origin* constants. It is OriginUnknown when the list carried no
	// origin claim at all, never the bare zero value -- OriginGenerated is
	// also zero, and an absent claim must not read as a claim of GENERATED
	// (go-xkms#132).
	Origin int

	// RootOfTrust contains device boot state information, if present.
	RootOfTrust *RootOfTrust

	// AttestationApplicationID identifies the application that requested the
	// attestation, if present. Populated by the Keystore daemon rather than
	// by the calling application, so an app cannot name itself something else.
	//
	// It appears in the softwareEnforced list, which means a compromised
	// system image could forge it -- it identifies the caller, it does not by
	// itself prove the platform is sound. Pair it with the RootOfTrust checks,
	// which are TEE-enforced.
	AttestationApplicationID *AttestationApplicationID
}

// AttestationApplicationID names the application a key was attested for.
//
//	AttestationApplicationId ::= SEQUENCE {
//	    packageInfos     SET OF AttestationPackageInfo,
//	    signatureDigests SET OF OCTET_STRING,
//	}
type AttestationApplicationID struct {
	// Packages lists the packages sharing the calling UID.
	Packages []AttestationPackageInfo

	// SignatureDigests holds the SHA-256 digests of the signing certificates
	// of those packages. This is what pins a build: a rebuild signed with a
	// different key produces a different digest, so an attacker's repackaged
	// copy of the app cannot pass as the real one.
	SignatureDigests [][]byte
}

// AttestationPackageInfo is one package entry inside an
// AttestationApplicationID.
type AttestationPackageInfo struct {
	// Name is the Android package name.
	Name string

	// Version is the package's version code.
	Version int64
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

	// CurrentTime is the instant the certificate chain is validated against.
	// The zero value defers to crypto/x509, which uses the current time, so
	// leaving it unset keeps expiry enforcement on the real clock. Set it only
	// to reason about a chain at a fixed instant — auditing evidence captured
	// earlier, or testing against a chain whose validity window has passed.
	CurrentTime time.Time
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
		return nil, &errs.Detail{Err: ErrExtensionParseFailed, Detail: fmt.Sprintf("%v", err)}
	}
	if len(rest) > 0 {
		return nil, &errs.Detail{Err: ErrExtensionParseFailed, Detail: "trailing data after KeyDescription"}
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
// Context-specific tag numbers inside an AuthorizationList, from the Android
// KeyMint attestation schema.
const (
	tagPurpose                  = 1
	tagOrigin                   = 702
	tagRootOfTrust              = 704
	tagAttestationApplicationID = 709
)

// Well-known key-origin values (KeyMint tag ORIGIN / keymaster_key_origin_t).
// Origin records how the key came to exist inside the enforcement domain
// that authorized it -- generated in place, derived in place, or imported
// from outside it.
const (
	// OriginGenerated means the key was generated inside the enforcement
	// domain and never existed anywhere else.
	OriginGenerated = 0

	// OriginDerived means the key was derived inside the enforcement domain
	// from other key material, and never existed outside it in this form.
	OriginDerived = 1

	// OriginImported means the key material entered the enforcement domain
	// from outside it, and may therefore exist elsewhere too.
	OriginImported = 2

	// OriginUnknown is what some Keymaster implementations report for keys
	// that predate the origin tag. It is also parseAuthorizationList's
	// default when an AuthorizationList carries no origin claim at all: zero
	// is OriginGenerated's value, and a claim that was never made must not
	// read as a claim of GENERATED.
	OriginUnknown = 3
)

// Well-known key-purpose values (KeyMint tag PURPOSE / keymaster_purpose_t).
// Purpose is the set of operations the key's enforcement domain will
// perform with it.
const (
	PurposeEncrypt   = 0
	PurposeDecrypt   = 1
	PurposeSign      = 2
	PurposeVerify    = 3
	PurposeDeriveKey = 4
	PurposeWrapKey   = 5
	PurposeAgreeKey  = 6
	PurposeAttestKey = 7
)

// attestationApplicationIDASN1 mirrors the DER inside the tag-709 OCTET STRING.
type attestationApplicationIDASN1 struct {
	PackageInfos     []attestationPackageInfoASN1 `asn1:"set"`
	SignatureDigests [][]byte                     `asn1:"set"`
}

type attestationPackageInfoASN1 struct {
	PackageName []byte
	Version     int64
}

// findAttestationApplicationID walks the AuthorizationList for tag 709 and
// decodes the application identity inside it.
//
// The value is an OCTET STRING whose contents are themselves DER, so it takes
// two decodes: the outer tagged element, then the structure within.
func findAttestationApplicationID(data []byte) *AttestationApplicationID {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(data, &outer)
	if err != nil || len(rest) > 0 {
		return nil
	}

	remaining := outer.Bytes
	for len(remaining) > 0 {
		var elem asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &elem)
		if err != nil {
			break
		}
		if elem.Class != asn1.ClassContextSpecific || elem.Tag != tagAttestationApplicationID {
			continue
		}

		// Unwrap the OCTET STRING, then decode what it wraps.
		var wrapped []byte
		if _, wrapErr := asn1.Unmarshal(elem.Bytes, &wrapped); wrapErr != nil {
			return nil
		}

		var parsed attestationApplicationIDASN1
		if _, parseErr := asn1.Unmarshal(wrapped, &parsed); parseErr != nil {
			return nil
		}

		appID := &AttestationApplicationID{
			Packages:         make([]AttestationPackageInfo, 0, len(parsed.PackageInfos)),
			SignatureDigests: parsed.SignatureDigests,
		}
		for _, pkg := range parsed.PackageInfos {
			appID.Packages = append(appID.Packages, AttestationPackageInfo{
				Name:    string(pkg.PackageName),
				Version: pkg.Version,
			})
		}
		return appID
	}

	return nil
}

func parseAuthorizationList(rawVal asn1.RawValue) AuthorizationList {
	authList := AuthorizationList{Origin: OriginUnknown}

	// The AuthorizationList is a SEQUENCE of IMPLICIT tagged values.
	// We do not attempt full parsing here since the tag assignments
	// vary across Keymaster/KeyMint versions. Instead each field this
	// package consumes is located by its own context-specific tag,
	// independent of the others' presence or absence.
	//
	// The zero value is not returned for Origin, deliberately: the caller
	// must be able to tell "the TEE never claimed an origin" apart from "the
	// TEE claimed origin 0 (GENERATED)" (go-xkms#132).

	if len(rawVal.FullBytes) == 0 {
		return authList
	}

	// Attempt to find and parse RootOfTrust (tag 704 / 0x02C0)
	// within the teeEnforced AuthorizationList.
	rot := findRootOfTrust(rawVal.FullBytes)
	if rot != nil {
		authList.RootOfTrust = rot
	}

	if appID := findAttestationApplicationID(rawVal.FullBytes); appID != nil {
		authList.AttestationApplicationID = appID
	}

	if origin, ok := findOrigin(rawVal.FullBytes); ok {
		authList.Origin = origin
	}

	authList.Purpose = findPurpose(rawVal.FullBytes)

	return authList
}

// findOrigin walks the AuthorizationList for tag 702 and decodes the
// EXPLICIT INTEGER inside it -- the enforcement domain's claim about how the
// key came to exist (go-xkms#132). ok is false when the tag is absent or
// does not decode; the caller must treat that as "no claim", never as
// OriginGenerated, because zero is also OriginGenerated's value.
func findOrigin(data []byte) (origin int, ok bool) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(data, &outer)
	if err != nil || len(rest) > 0 {
		return 0, false
	}

	remaining := outer.Bytes
	for len(remaining) > 0 {
		var elem asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &elem)
		if err != nil {
			break
		}
		if elem.Class != asn1.ClassContextSpecific || elem.Tag != tagOrigin {
			continue
		}

		var value int
		if _, unmarshalErr := asn1.Unmarshal(elem.Bytes, &value); unmarshalErr != nil {
			return 0, false
		}
		return value, true
	}

	return 0, false
}

// findPurpose walks the AuthorizationList for tag 1 and decodes the EXPLICIT
// SET OF INTEGER inside it -- the operations the enforcement domain will
// perform with the key (go-xkms#132). Returns nil if the tag is absent or
// does not decode.
func findPurpose(data []byte) []int {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(data, &outer)
	if err != nil || len(rest) > 0 {
		return nil
	}

	remaining := outer.Bytes
	for len(remaining) > 0 {
		var elem asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &elem)
		if err != nil {
			break
		}
		if elem.Class != asn1.ClassContextSpecific || elem.Tag != tagPurpose {
			continue
		}

		var purposes []int
		if _, unmarshalErr := asn1.UnmarshalWithParams(elem.Bytes, &purposes, "set"); unmarshalErr != nil {
			return nil
		}
		return purposes
	}

	return nil
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

		// RootOfTrust is context-specific class, constructed, tag 704.
		// The tag is checked rather than trying every compound element in
		// turn: several other entries in this list are also context-specific
		// SEQUENCEs, and one of them parsing as a RootOfTrust by coincidence
		// would report a boot state that was never attested.
		if elem.Class == asn1.ClassContextSpecific && elem.IsCompound &&
			elem.Tag == tagRootOfTrust {
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
		if err := verifyCertificateChain(chain, opts.TrustedRoots, opts.CurrentTime); err != nil {
			return nil, &errs.Detail{Err: ErrChainVerificationFailed, Detail: fmt.Sprintf("%v", err)}
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
		return nil, &errs.Detail{Err: ErrInsufficientSecurityLevel, Detail: fmt.Sprintf("got %s, require %s", desc.AttestationSecurityLevel, opts.MinSecurityLevel)}
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
// trusted root certificate pool, as of now. A zero now is passed through to
// crypto/x509, which substitutes the current time.
func verifyCertificateChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) error {
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
		CurrentTime:   now,
	}

	if _, err := leaf.Verify(verifyOpts); err != nil {
		return err
	}

	return nil
}

// AttestationExtensionOptions carries the teeEnforced AuthorizationList
// claims a fixture can assert beyond RootOfTrust: Origin and Purpose
// (go-xkms#132).
//
// It exists as a sibling to BuildAttestationExtension's rot parameter rather
// than a further positional argument, per the doc comment BuildAttestation
// Extension already carried: that function cannot grow again without
// breaking its callers a second time.
//
// HasOrigin distinguishes an explicit teeEnforced claim of Origin=GENERATED
// (0) from no origin claim at all -- the same distinction findOrigin makes
// when parsing one back.
type AttestationExtensionOptions struct {
	// RootOfTrust is teeEnforced's boot-state claim. Nil omits tag 704.
	RootOfTrust *RootOfTrust

	// Origin is teeEnforced's key-origin claim, encoded as tag 702 only
	// when HasOrigin is true.
	Origin    int
	HasOrigin bool

	// Purpose is teeEnforced's key-purpose claim, encoded as tag 1 when
	// non-empty. A nil or empty slice omits the tag.
	Purpose []int
}

// marshalExplicitInt DER-encodes an EXPLICIT context-specific INTEGER tag,
// matching how findOrigin reads it back: the tag's content is the DER of a
// plain INTEGER.
func marshalExplicitInt(tag, value int) ([]byte, error) {
	body, err := asn1.Marshal(value)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      body,
	})
}

// marshalExplicitIntSet DER-encodes an EXPLICIT context-specific SET OF
// INTEGER tag, matching how findPurpose reads it back.
func marshalExplicitIntSet(tag int, values []int) ([]byte, error) {
	body, err := asn1.MarshalWithParams(values, "set")
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      body,
	})
}

// BuildAttestationExtension builds a KeyDescription extension whose
// teeEnforced AuthorizationList carries a RootOfTrust.
//
// rot may be nil, which reproduces the minimal builder's shape: a verified,
// nonce-matching chain that says nothing at all about boot state. That case
// exists to be REFUSED by a caller that requires the claim, so it needs to be
// constructible on purpose.
//
// This is BuildAttestationExtensionWithOptions with only RootOfTrust set; a
// fixture that also needs Origin or Purpose claims calls that instead.
func BuildAttestationExtension(
	version int,
	attestSecLevel SecurityLevel,
	kmVersion int,
	kmSecLevel SecurityLevel,
	challenge []byte,
	uniqueID []byte,
	rot *RootOfTrust,
) ([]byte, error) {
	return BuildAttestationExtensionWithOptions(version, attestSecLevel, kmVersion, kmSecLevel,
		challenge, uniqueID, &AttestationExtensionOptions{RootOfTrust: rot})
}

// BuildAttestationExtensionWithOptions builds a KeyDescription extension
// whose teeEnforced AuthorizationList carries the claims in opts:
// RootOfTrust, Origin, and Purpose (go-xkms#132).
//
// A nil opts reproduces BuildMinimalAttestationExtension's shape: neither
// authorization list makes any claim.
func BuildAttestationExtensionWithOptions(
	version int,
	attestSecLevel SecurityLevel,
	kmVersion int,
	kmSecLevel SecurityLevel,
	challenge []byte,
	uniqueID []byte,
	opts *AttestationExtensionOptions,
) ([]byte, error) {
	if opts == nil {
		opts = &AttestationExtensionOptions{}
	}

	var teeEnforced bytes.Buffer

	// Ordered to match the schema's own field order (tags 1, 702, 704), not
	// that findOrigin/findPurpose/findRootOfTrust care: each looks up its own
	// tag independent of position.
	if len(opts.Purpose) > 0 {
		tagged, err := marshalExplicitIntSet(tagPurpose, opts.Purpose)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "android: failed to marshal purpose", Err: err}
		}
		teeEnforced.Write(tagged)
	}

	if opts.HasOrigin {
		tagged, err := marshalExplicitInt(tagOrigin, opts.Origin)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "android: failed to marshal origin", Err: err}
		}
		teeEnforced.Write(tagged)
	}

	if opts.RootOfTrust != nil {
		body, err := asn1.Marshal(rootOfTrustASN1{
			VerifiedBootKey:   opts.RootOfTrust.VerifiedBootKey,
			DeviceLocked:      opts.RootOfTrust.DeviceLocked,
			VerifiedBootState: asn1.Enumerated(opts.RootOfTrust.VerifiedBootState),
			VerifiedBootHash:  opts.RootOfTrust.VerifiedBootHash,
		})
		if err != nil {
			return nil, &errs.Wrapped{Msg: "android: failed to marshal root of trust", Err: err}
		}

		// [704] EXPLICIT, matching findRootOfTrust: it takes the element's
		// CONTENT and unmarshals that as the RootOfTrust SEQUENCE.
		tagged, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        tagRootOfTrust,
			IsCompound: true,
			Bytes:      body,
		})
		if err != nil {
			return nil, &errs.Wrapped{Msg: "android: failed to marshal tagged root of trust", Err: err}
		}
		teeEnforced.Write(tagged)
	}

	return buildAttestationExtension(version, attestSecLevel, kmVersion, kmSecLevel,
		challenge, uniqueID, teeEnforced.Bytes())
}

// BuildMinimalAttestationExtension builds a KeyDescription extension whose
// authorization lists are both empty SEQUENCEs, so nothing it produces can
// exercise any TeeEnforced check -- RootOfTrust, Origin, or Purpose. A
// fixture that needs to make one of those claims calls
// BuildAttestationExtension or BuildAttestationExtensionWithOptions instead.
func BuildMinimalAttestationExtension(
	version int,
	attestSecLevel SecurityLevel,
	kmVersion int,
	kmSecLevel SecurityLevel,
	challenge []byte,
	uniqueID []byte,
) ([]byte, error) {
	return buildAttestationExtension(version, attestSecLevel, kmVersion, kmSecLevel,
		challenge, uniqueID, nil)
}

// buildAttestationExtension is the shared encoder. teeEnforcedContent is the
// DER of the teeEnforced AuthorizationList's ELEMENTS (nil for an empty list).
func buildAttestationExtension(
	version int,
	attestSecLevel SecurityLevel,
	kmVersion int,
	kmSecLevel SecurityLevel,
	challenge []byte,
	uniqueID []byte,
	teeEnforcedContent []byte,
) ([]byte, error) {
	// Build the AuthorizationList SEQUENCEs. softwareEnforced is always empty
	// here; teeEnforced carries whatever the caller supplied.
	emptySeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      []byte{},
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "android: failed to marshal empty authorization list", Err: err}
	}

	teeSeq := emptySeq
	if len(teeEnforcedContent) > 0 {
		teeSeq, err = asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      teeEnforcedContent,
		})
		if err != nil {
			return nil, &errs.Wrapped{Msg: "android: failed to marshal tee authorization list", Err: err}
		}
	}

	// Workaround: build the KeyDescription manually since the encoding
	// of the AuthorizationList requires passing through RawValue.
	// We marshal each field individually and concatenate.
	versionBytes, err := asn1.Marshal(version)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "android: failed to marshal version", Err: err}
	}

	attestSecBytes, err := asn1.Marshal(asn1.Enumerated(attestSecLevel))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "android: failed to marshal attestation security level", Err: err}
	}

	kmVersionBytes, err := asn1.Marshal(kmVersion)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "android: failed to marshal keymaster version", Err: err}
	}

	kmSecBytes, err := asn1.Marshal(asn1.Enumerated(kmSecLevel))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "android: failed to marshal keymaster security level", Err: err}
	}

	challengeBytes, err := asn1.Marshal(challenge)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "android: failed to marshal challenge", Err: err}
	}

	uniqueIDBytes, err := asn1.Marshal(uniqueID)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "android: failed to marshal unique ID", Err: err}
	}

	// Concatenate all fields into the SEQUENCE content
	var seqContent bytes.Buffer
	seqContent.Write(versionBytes)
	seqContent.Write(attestSecBytes)
	seqContent.Write(kmVersionBytes)
	seqContent.Write(kmSecBytes)
	seqContent.Write(challengeBytes)
	seqContent.Write(uniqueIDBytes)
	seqContent.Write(emptySeq) // softwareEnforced
	seqContent.Write(teeSeq)   // teeEnforced

	// Wrap in SEQUENCE
	result, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      seqContent.Bytes(),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "android: failed to marshal KeyDescription sequence", Err: err}
	}

	return result, nil
}
