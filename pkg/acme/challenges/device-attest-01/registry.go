// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package deviceattest01

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// The registry-anchored DICE verifier (go-xkms#1441)
//
// A DICE alias certificate is signed by the key it carries, so on its own it
// vouches only for itself: a host can mint one for a key it generated and name
// any device's UEID in it. What says which key is a device's DeviceID key is
// the device's provisioning record, written at provisioning outside any field
// host and returned by the injected DeviceResolver. Every "dice" attestation is
// anchored there before any claim of its leaf is believed, along one of two
// paths:
//
//   - raw key: the record holds the DeviceID public key. The leaf must carry
//     exactly that key AND its signature over its TBSCertificate must verify
//     under it. Neither alone is enough: a leaf can copy the registered key and
//     forge its measurements, and dice.Verify does not check a leaf's signature
//     when no roots are given.
//   - endorsement: the record holds a DeviceID certificate. It must name the
//     same UEID, and [alias, DeviceID certificate] must anchor in
//     TrustAnchors.DICERoots. With no DICE root configured the device is
//     refused; it never falls back to the raw-key path or to no anchor.
//
// Only then does dice.Verify check the claims: the eat_nonce that makes the
// answer this challenge's, the UEID, and the configured DICE policy. The key
// the record vouches for is returned as the attested SPKI, which finalize
// compares the certificate request with, and re-confirms against the registry
// (ConfirmRegisteredDevice) so a device decommissioned in between is refused.

var (
	// ErrDeviceNotAuthorized leads every refusal the device registry makes:
	// no registry, no record, a lookup failure, a record that does not vouch
	// for the evidence's key. The ACME server reports it as unauthorized. The
	// specific reason is joined to it.
	ErrDeviceNotAuthorized = errors.New("device-attest-01: the device's provisioning record does not authorize this attestation")

	// ErrDeviceNotProvisioned is what a DeviceResolver wraps when it holds no
	// record for a UEID. It is distinct from a lookup that failed, so a caller
	// can tell a device nobody provisioned from a registry that is down; both
	// refuse the device.
	ErrDeviceNotProvisioned = errors.New("device-attest-01: no provisioning record for the device")

	// ErrNoDeviceResolver is returned when a "dice" attestation reaches a
	// verifier with no device registry. There is no default registry, so the
	// absence is a refusal.
	ErrNoDeviceResolver = errors.New("device-attest-01: no device registry configured")

	// ErrProvisioningRecordInvalid is returned when a registry returns a record
	// that cannot vouch for anything: neither or both of a key and a
	// certificate, a key that is not an ECDSA P-256 SubjectPublicKeyInfo, or a
	// certificate that does not parse.
	ErrProvisioningRecordInvalid = errors.New("device-attest-01: the provisioning record is invalid")

	// ErrAttestedKeyMismatch is returned when the alias certificate's key is
	// not the provisioned DeviceID key, or when the provisioned key changed
	// between the challenge and finalization.
	ErrAttestedKeyMismatch = errors.New("device-attest-01: the attested key is not the provisioned DeviceID key")

	// ErrAliasSignatureInvalid is returned when the alias certificate's
	// signature does not verify under the provisioned DeviceID key.
	ErrAliasSignatureInvalid = errors.New("device-attest-01: the alias certificate's signature does not verify under the provisioned DeviceID key")

	// ErrDeviceEndorsementInvalid is returned when a provisioned DeviceID
	// certificate does not endorse the alias certificate: it names another
	// UEID, or [alias, DeviceID certificate] does not anchor in the DICE roots.
	ErrDeviceEndorsementInvalid = errors.New("device-attest-01: the DeviceID certificate does not endorse the alias certificate")
)

// RegisteredDeviceVerifier is the half of an AttestationVerifier that anchors
// "dice" evidence in the device registry. An AttestationVerifier that does not
// implement it refuses every "dice" attestation with ErrNoDeviceResolver.
type RegisteredDeviceVerifier interface {
	// VerifyRegisteredDevice anchors the alias leaf in its device's
	// provisioning record and then checks its claims against
	// keyAuthorization. It returns the verified attestation's Leaf,
	// AttestedSPKI -- the DER SubjectPublicKeyInfo of the key the
	// provisioning record vouches for -- and RootType, the root of trust the
	// verified chain's DiceTcbInfo declares.
	VerifyRegisteredDevice(ctx context.Context, leaf *x509.Certificate, keyAuthorization string) (*VerifiedAttestation, error)

	// ConfirmRegisteredDevice re-queries the registry at finalization and
	// refuses a device whose record is gone or whose key is no longer
	// attestedSPKI.
	ConfirmRegisteredDevice(ctx context.Context, ueid string, attestedSPKI []byte) error
}

var _ RegisteredDeviceVerifier = (*TrustAnchorVerifier)(nil)

// VerifyRegisteredDevice implements RegisteredDeviceVerifier. Every refusal of
// the device by its record is reported under ErrDeviceNotAuthorized; evidence
// the record vouches for but whose claims fail (a nonce from another
// challenge, a refused operational state) is ErrCertificateChainInvalid.
func (v *TrustAnchorVerifier) VerifyRegisteredDevice(ctx context.Context, leaf *x509.Certificate, keyAuthorization string) (*VerifiedAttestation, error) {
	if leaf == nil {
		return nil, &errs.Detail{Err: ErrInvalidAttestationObject, Detail: "no dice leaf certificate"}
	}
	if keyAuthorization == "" {
		return nil, &errs.Detail{Err: ErrInvalidAttestationObject, Detail: "no key authorization to bind the dice attestation to"}
	}

	// The UEID is only the lookup key here. Nothing the leaf says is believed
	// until the record has vouched for the key that signed it.
	ueid, err := diceDeviceIdentity(leaf)
	if err != nil {
		return nil, notAuthorized(err)
	}
	record, err := v.resolve(ctx, ueid)
	if err != nil {
		return nil, err
	}
	if len(record.DeviceIDCertificate) > 0 {
		return v.verifyEndorsedDevice(leaf, record.DeviceIDCertificate, ueid, keyAuthorization)
	}
	return v.verifyRawKeyDevice(leaf, record.DeviceIDKey, keyAuthorization)
}

// ConfirmRegisteredDevice implements RegisteredDeviceVerifier.
func (v *TrustAnchorVerifier) ConfirmRegisteredDevice(ctx context.Context, ueid string, attestedSPKI []byte) error {
	record, err := v.resolve(ctx, ueid)
	if err != nil {
		return err
	}
	current, err := record.deviceIDSPKI()
	if err != nil {
		return notAuthorized(err)
	}
	if !bytes.Equal(current, attestedSPKI) {
		return notAuthorized(&errs.Detail{Err: ErrAttestedKeyMismatch, Detail: "the provisioned DeviceID key changed after the challenge was validated"})
	}
	return nil
}

// resolve looks ueid up in the registry and refuses a record that does not
// carry exactly one of a key and a certificate.
func (v *TrustAnchorVerifier) resolve(ctx context.Context, ueid string) (*ProvisionedDevice, error) {
	if v.devices == nil {
		return nil, notAuthorized(ErrNoDeviceResolver)
	}
	record, err := v.devices.ResolveDevice(ctx, ueid)
	if err != nil {
		return nil, notAuthorized(err)
	}
	if record == nil {
		return nil, notAuthorized(&errs.Detail{Err: ErrProvisioningRecordInvalid, Detail: "the registry returned neither a record nor an error"})
	}
	if (len(record.DeviceIDKey) > 0) == (len(record.DeviceIDCertificate) > 0) {
		return nil, notAuthorized(&errs.Detail{Err: ErrProvisioningRecordInvalid, Detail: "a record carries exactly one of a DeviceID key and a DeviceID certificate"})
	}
	return record, nil
}

// verifyRawKeyDevice is the raw-key path: the leaf must carry the provisioned
// key and be signed by it before its claims are checked.
func (v *TrustAnchorVerifier) verifyRawKeyDevice(leaf *x509.Certificate, deviceIDKey []byte, keyAuthorization string) (*VerifiedAttestation, error) {
	key, err := provisionedKey(deviceIDKey)
	if err != nil {
		return nil, notAuthorized(err)
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, deviceIDKey) {
		return nil, notAuthorized(ErrAttestedKeyMismatch)
	}
	if err := verifyAliasSignature(leaf, key); err != nil {
		return nil, notAuthorized(err)
	}
	// No roots: the signature check above is the anchor. It is not a trusted
	// root, so the root type reads unreported (CA m452); only the endorsed
	// DeviceID path below reports one.
	rootType, err := v.verifyDICEClaims([]*x509.Certificate{leaf}, nil, keyAuthorization)
	if err != nil {
		return nil, err
	}
	return &VerifiedAttestation{Leaf: leaf, AttestedSPKI: bytes.Clone(deviceIDKey), RootType: rootType}, nil
}

// verifyEndorsedDevice is the endorsement path: the provisioned DeviceID
// certificate must name the leaf's UEID, and the two must anchor in the DICE
// roots together.
func (v *TrustAnchorVerifier) verifyEndorsedDevice(leaf *x509.Certificate, deviceIDDER []byte, ueid, keyAuthorization string) (*VerifiedAttestation, error) {
	if v.dicePool == nil {
		return nil, notAuthorized(&errs.Detail{Err: ErrNoTrustAnchors, Detail: "a DeviceID certificate anchors in the DICE roots, and none is configured"})
	}
	deviceID, err := x509.ParseCertificate(deviceIDDER)
	if err != nil {
		return nil, notAuthorized(&errs.Joined{Lead: ErrProvisioningRecordInvalid, Detail: "the DeviceID certificate does not parse", Cause: err})
	}
	endorsed, err := diceDeviceIdentity(deviceID)
	if err != nil {
		return nil, notAuthorized(&errs.Joined{Lead: ErrDeviceEndorsementInvalid, Cause: err})
	}
	if endorsed != ueid {
		return nil, notAuthorized(&errs.Detail{Err: ErrDeviceEndorsementInvalid, Detail: "the DeviceID certificate names ueid " + endorsed + ", not " + ueid})
	}
	rootType, err := v.verifyDICEClaims([]*x509.Certificate{leaf, deviceID}, v.dicePool, keyAuthorization)
	if err != nil {
		if errors.Is(err, dice.ErrChainVerificationFailed) {
			return nil, notAuthorized(&errs.Joined{Lead: ErrDeviceEndorsementInvalid, Cause: err})
		}
		return nil, err
	}
	return &VerifiedAttestation{Leaf: leaf, AttestedSPKI: bytes.Clone(deviceID.RawSubjectPublicKeyInfo), RootType: rootType}, nil
}

// verifyDICEClaims runs dice.Verify over chain with the configured DICE policy
// and the nonce derived from keyAuthorization, and returns the root type the
// chain's DiceTcbInfo declares.
//
// The device echoes SHA-256 of the key authorization, not the string (see
// DICENonce). EAT bounds eat_nonce at 8-64 bytes, and a key authorization is
// "<token>.<RFC 7638 thumbprint>" -- 87 bytes, since the thumbprint alone is 43
// base64url characters -- so the raw form cannot be carried by a conforming
// UCCS claims set at all. Hashing is what Apple's device-attest-01 profile
// does, for the same reason.
func (v *TrustAnchorVerifier) verifyDICEClaims(chain []*x509.Certificate, roots *x509.CertPool, keyAuthorization string) (dice.RootType, error) {
	evidence, err := dice.Verify(chain, &dice.VerifyOptions{
		TrustedRoots: roots,
		// The identity is read from the Ueid, so it is not optional.
		RequireUeid:             true,
		ExpectedNonce:           DICENonce(keyAuthorization),
		RequireDeviceSignedLeaf: v.dice.RequireDeviceSignedLeaf,
		RequireMeasurement:      v.dice.RequireMeasurement,
		RequireTcbInfo:          v.dice.RequireTcbInfo,
		PermittedFlags:          v.dice.PermittedFlags,
	})
	if err != nil {
		return dice.RootTypeUnreported, &errs.Joined{Lead: ErrCertificateChainInvalid, Detail: "the dice evidence does not satisfy the configured DICE policy", Cause: err}
	}
	return evidence.RootType, nil
}

// deviceIDSPKI is the DER SubjectPublicKeyInfo the record vouches for: the
// provisioned key, or the DeviceID certificate's key.
func (d *ProvisionedDevice) deviceIDSPKI() ([]byte, error) {
	if len(d.DeviceIDKey) > 0 {
		return d.DeviceIDKey, nil
	}
	deviceID, err := x509.ParseCertificate(d.DeviceIDCertificate)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrProvisioningRecordInvalid, Detail: "the DeviceID certificate does not parse", Cause: err}
	}
	return deviceID.RawSubjectPublicKeyInfo, nil
}

// provisionedKey parses a provisioned DeviceID key, which must be ECDSA P-256:
// the key a DICE secure element signs with.
func provisionedKey(spki []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrProvisioningRecordInvalid, Detail: "the DeviceID key is not a DER SubjectPublicKeyInfo", Cause: err}
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, &errs.Detail{Err: ErrProvisioningRecordInvalid, Detail: "the DeviceID key is not an ECDSA P-256 key"}
	}
	return key, nil
}

// verifyAliasSignature verifies the alias certificate's signature over its
// TBSCertificate with the provisioned key, under the ECDSA with SHA-256
// algorithm the device signs with.
func verifyAliasSignature(leaf *x509.Certificate, key *ecdsa.PublicKey) error {
	if leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return &errs.Detail{Err: ErrAliasSignatureInvalid, Detail: "the alias certificate is signed with " + leaf.SignatureAlgorithm.String() + ", not ECDSA with SHA-256"}
	}
	digest := sha256.Sum256(leaf.RawTBSCertificate)
	if !ecdsa.VerifyASN1(key, digest[:], leaf.Signature) {
		return ErrAliasSignatureInvalid
	}
	return nil
}

// notAuthorized reports a refusal of the device by its provisioning record.
func notAuthorized(reason error) error {
	return &errs.Joined{Lead: ErrDeviceNotAuthorized, Cause: reason}
}

// ConfirmRegistration re-queries the device registry for a "dice" attestation
// at finalization (go-xkms#1441) and refuses, under ErrDeviceNotAuthorized, a
// device whose record is gone or whose key is no longer the attested SPKI. A
// format that is not anchored in the registry has nothing to confirm.
func (v *VerifiedAttestation) ConfirmRegistration(ctx context.Context, verifier AttestationVerifier) error {
	if v == nil {
		return ErrNoVerifiedAttestation
	}
	if v.Format != FormatDICE {
		return nil
	}
	registry, ok := verifier.(RegisteredDeviceVerifier)
	if !ok {
		return notAuthorized(ErrNoDeviceResolver)
	}
	ueid, err := v.DeviceIdentity()
	if err != nil {
		return notAuthorized(err)
	}
	return registry.ConfirmRegisteredDevice(ctx, ueid, v.AttestedSPKI)
}
