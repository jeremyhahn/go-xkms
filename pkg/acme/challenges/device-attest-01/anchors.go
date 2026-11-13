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
	"context"
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// The production AttestationVerifier
//
// AttestationVerifier is the server's policy over a device's evidence: the
// anchors an x5c chain must reach. TrustAnchorVerifier is that policy built
// from trust anchors an operator configured, using this repository's own
// primitives rather than a second implementation of them:
//
//   - "tpm": the AIK certificate in x5c[0] must chain, through the
//     intermediates the device sent after it, to a configured TPM root
//     (evidence.VerifyAKCertificate). Roots are the CAs that vouch for AIKs:
//     a TPM manufacturer's attestation CA, a privacy CA, or the operator's own
//     CA when it certifies AIKs. The EK-to-manufacturer link is not
//     re-proven here, because a "tpm" statement carries no EK: an AIK
//     certificate is the issuer's statement that the key is a restricted key in
//     a TPM whose EK it verified, and that issuer is the anchor. For a go-xkms
//     CA that verification is enroll-01's (pkg/ca verifyEKCertificateChain,
//     against the configured manufacturer roots) at the moment it issues the
//     IAK. The statement's own requirements (WebAuthn Level 2 section 8.3.1,
//     the TPM2_Certify binding) are applied by the evidence verifier that runs
//     after this one.
//   - "dice": the alias certificate is anchored in the device's provisioning
//     record, which the injected DeviceResolver returns
//     (VerifyRegisteredDevice, go-xkms#1441), and only then must satisfy the
//     configured DICE policy (dice.Verify), including the eat_nonce that makes
//     the answer this challenge's. A DICE root alone anchors nothing: the alias
//     certificate is self-signed by the key it carries, so it vouches only for
//     itself.
//
// The two root sets are separate on purpose. A root that vouches for TPM
// AIKs has no say over DICE certificates and the reverse, and a format
// with no configured anchor is REFUSED rather than verified against another
// format's: configuring only TPM roots leaves DICE unavailable.

// TrustAnchors configures a TrustAnchorVerifier.
type TrustAnchors struct {
	// TPMRoots anchor the AIK certificate chain of a "tpm" attestation.
	TPMRoots []*x509.Certificate

	// DICERoots anchor the DeviceID certificate a provisioning record
	// returns for a "dice" attestation (the endorsement path; see
	// DeviceResolver). They are never an anchor on their own: a "dice"
	// attestation is refused unless Devices vouches for the device.
	DICERoots []*x509.Certificate

	// Devices is the device registry a "dice" attestation is anchored in
	// (go-xkms#1441). Nil refuses every "dice" attestation as unauthorized:
	// there is no default registry, and nothing else can say which key is a
	// device's DeviceID key.
	Devices DeviceResolver

	// DICE is the policy a "dice" leaf must meet beyond anchoring.
	DICE DICEPolicy
}

// DeviceResolver looks up a DICE device's provisioning record (go-xkms#1441).
//
// go-xkms declares it and the platform that owns enrolment implements it and
// injects it through TrustAnchors.Devices, so the dependency points from the
// enrolment layer to go-xkms and never back. The record is written at
// provisioning, outside any field host, and that is what makes it an anchor:
// a self-signed alias certificate vouches only for itself.
type DeviceResolver interface {
	// ResolveDevice returns the provisioning record of the device whose UEID
	// is ueid: the lowercase hex of the complete RFC 9711 UEID, 0x01 followed
	// by the DeviceID, 34 digits for a 16-byte DeviceID. It reports a device
	// with no record with an error wrapping ErrDeviceNotProvisioned, and any
	// other failure with any other error. Both refuse the device.
	ResolveDevice(ctx context.Context, ueid string) (*ProvisionedDevice, error)
}

// ProvisionedDevice is a DICE device's provisioning record. Exactly one of
// its fields is set; a record with neither or both is refused.
type ProvisionedDevice struct {
	// DeviceIDKey is the provisioned DeviceID public key as a DER
	// SubjectPublicKeyInfo (the raw-key path). The alias certificate must
	// carry exactly this key and verify under it.
	DeviceIDKey []byte

	// DeviceIDCertificate is the DER DeviceID certificate issued at
	// provisioning (the endorsement path). It must anchor in
	// TrustAnchors.DICERoots, name the same UEID, and have signed the alias
	// certificate.
	DeviceIDCertificate []byte

	// ApplicationReference is the 32-byte application evidence registered
	// for the device: the value the possession request's measurements must
	// carry at finalize (VerifiedAttestation.VerifyPossessionCSR). A record
	// whose reference is set with any other length is refused.
	ApplicationReference []byte
}

// ApplicationReferenceSize is the length of a registered application
// reference: the 32-byte hash-entry value the possession request carries.
const ApplicationReferenceSize = 32

// DICEPolicy is the policy a DICE alias certificate must meet. Each field is a
// requirement of dice.VerifyOptions; the zero value is the strictest operational
// state (no notConfigured, notSecure, recovery or debug flag is tolerated) with
// no requirement about which extensions the leaf carries.
type DICEPolicy struct {
	// RequireDeviceSignedLeaf states that the leaf's issuer is device-resident,
	// which pins its signature algorithm to the one hardware performs
	// (dice.VerifyOptions.RequireDeviceSignedLeaf). Set it for a constrained-device
	// or secure-element profile whose alias certificate is signed by a key the
	// element holds.
	RequireDeviceSignedLeaf bool

	// RequireMeasurement demands that the leaf's DiceTcbInfo carry a firmware
	// measurement (dice.VerifyOptions.RequireMeasurement).
	RequireMeasurement bool

	// RequireTcbInfo demands a DiceTcbInfo extension on the leaf
	// (dice.VerifyOptions.RequireTcbInfo).
	RequireTcbInfo bool

	// RequireApplicationReference refuses at finalize a device whose
	// provisioning record registers no ApplicationReference. Off, such a
	// device is admitted without the application evidence comparison; a
	// registered reference is always compared.
	RequireApplicationReference bool

	// PermittedFlags are the operational states tolerated; none by default.
	PermittedFlags dice.OperationalFlags
}

// TrustAnchorVerifier is the AttestationVerifier built from configured trust
// anchors. It is safe for concurrent use: it is immutable after construction.
type TrustAnchorVerifier struct {
	tpmPool  *x509.CertPool
	dicePool *x509.CertPool

	// roots are the roots of both formats, for the format-blind chain check.
	roots []*x509.Certificate

	// devices is the registry "dice" evidence is anchored in; nil refuses it.
	devices DeviceResolver

	dice DICEPolicy
}

var _ AttestationVerifier = (*TrustAnchorVerifier)(nil)

// NewTrustAnchorVerifier returns a verifier for anchors. It returns
// ErrNoTrustAnchors when no TPM root, no DICE root and no device registry is
// configured: a verifier with nothing to anchor to would have nothing to
// refuse a forged chain with, so it cannot exist.
func NewTrustAnchorVerifier(anchors TrustAnchors) (*TrustAnchorVerifier, error) {
	if len(anchors.TPMRoots) == 0 && len(anchors.DICERoots) == 0 && anchors.Devices == nil {
		return nil, ErrNoTrustAnchors
	}
	verifier := &TrustAnchorVerifier{devices: anchors.Devices, dice: anchors.DICE}
	tpmRoots, tpmPool, err := anchorSet(anchors.TPMRoots)
	if err != nil {
		return nil, err
	}
	diceRoots, dicePool, err := anchorSet(anchors.DICERoots)
	if err != nil {
		return nil, err
	}
	verifier.tpmPool, verifier.dicePool = tpmPool, dicePool
	verifier.roots = append(append(make([]*x509.Certificate, 0, len(tpmRoots)+len(diceRoots)), tpmRoots...), diceRoots...)
	return verifier, nil
}

// anchorSet copies roots and builds the pool they anchor. A nil certificate is
// refused: it would be a configured anchor that anchors nothing.
func anchorSet(roots []*x509.Certificate) ([]*x509.Certificate, *x509.CertPool, error) {
	if len(roots) == 0 {
		return nil, nil, nil
	}
	pool := x509.NewCertPool()
	owned := make([]*x509.Certificate, 0, len(roots))
	for _, root := range roots {
		if root == nil {
			return nil, nil, &errs.Detail{Err: ErrNoTrustAnchors, Detail: "a configured trust anchor is nil"}
		}
		pool.AddCert(root)
		owned = append(owned, root)
	}
	return owned, pool, nil
}

// VerifyAttestationObject anchors a "tpm" obj to the TPM roots. It is the
// authoritative check: it knows the format, so a chain anchored to the other
// format's roots does not satisfy it.
//
// A "dice" obj is refused with ErrDeviceNotAuthorized. Its chain anchors
// nothing on its own; VerifyRegisteredDevice anchors it in the device
// registry, and VerifyAttestation calls that instead.
func (v *TrustAnchorVerifier) VerifyAttestationObject(obj *AttestationObject, _ []byte) error {
	if obj == nil {
		return &errs.Detail{Err: ErrInvalidAttestationObject, Detail: "no attestation object"}
	}
	chain, err := x5cCertificates(obj.AttStatement.X5c)
	if err != nil {
		return err
	}
	switch format := AttestationFormat(obj.Format); format {
	case FormatTPM:
		return v.verifyTPMChain(chain)
	case FormatDICE:
		return &errs.Detail{Err: ErrDeviceNotAuthorized, Detail: "dice evidence is anchored in the device registry, never by its chain alone"}
	default:
		return &errs.Detail{Err: ErrInvalidAttestationFormat, Detail: "format " + obj.Format}
	}
}

// verifyTPMChain anchors an AIK certificate chain, leaf first, to the TPM roots.
func (v *TrustAnchorVerifier) verifyTPMChain(chain []*x509.Certificate) error {
	if v.tpmPool == nil {
		return &errs.Detail{Err: ErrNoTrustAnchors, Detail: "no TPM root is configured for the tpm format"}
	}
	// An AIK certificate's subjectAltName is critical and holds only the TCG
	// directoryName (TCG EK Credential Profile section 3.2.9), which
	// crypto/x509 reports as an unhandled critical extension. It is read here
	// -- checkAIKCertificate requires it to name the TPM -- and only then
	// marked handled, on a copy, so the chain is not refused for an extension
	// this verifier understood.
	if err := checkAIKCertificate(chain[0]); err != nil {
		return err
	}
	aik := withSubjectAltNameHandled(chain[0])

	// The tcg-cap-verifiedTPMRestricted policy is not demanded: WebAuthn Level
	// 2 section 8.3.1 asks of an AIK certificate the tcg-kp-AIKCertificate
	// extended key usage, which is the issuer's statement that the key is a
	// restricted attestation key and is enforced with the rest of the
	// certification (the TPM2 invariants gate).
	if _, err := evidence.VerifyAKCertificate(aik, chain[1:], evidence.AKCertificateOptions{
		Roots:             v.tpmPool,
		AllowUnrestricted: true,
	}); err != nil {
		return &errs.Joined{Lead: ErrCertificateChainInvalid, Detail: "the AIK certificate does not chain to a configured TPM root", Cause: err}
	}
	return nil
}

// oidSubjectAltName is RFC 5280 id-ce-subjectAltName.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// withSubjectAltNameHandled returns cert with the subjectAltName removed from
// its unhandled critical extensions, on a copy: marking the caller's
// certificate would leave it handled for every later verifier in the process.
func withSubjectAltNameHandled(cert *x509.Certificate) *x509.Certificate {
	remaining := make([]asn1.ObjectIdentifier, 0, len(cert.UnhandledCriticalExtensions))
	for _, oid := range cert.UnhandledCriticalExtensions {
		if !oid.Equal(oidSubjectAltName) {
			remaining = append(remaining, oid)
		}
	}
	if len(remaining) == len(cert.UnhandledCriticalExtensions) {
		return cert
	}
	handled := *cert
	handled.UnhandledCriticalExtensions = remaining
	return &handled
}

// VerifyAKCertificateChain checks the x5c chain, leaf first, against the
// configured roots without knowing its format: each certificate is inside its
// validity window and signed by the next, and the last is a configured root of
// either kind or signed by one.
//
// It is the format-blind half of the check; VerifyAttestationObject is the half
// that knows the format and is the stricter of the two. A chain must satisfy
// both, so this one only ever removes chains, never admits one.
//
// Signatures are checked directly rather than through crypto/x509 path
// building because a DICE chain carries critical extensions path building does
// not understand (dice.Verify reads them; this does not need to).
func (v *TrustAnchorVerifier) VerifyAKCertificateChain(certs [][]byte) error {
	if len(certs) == 0 {
		return &errs.Detail{Err: ErrCertificateChainInvalid, Detail: "the chain is empty"}
	}
	chain := make([]*x509.Certificate, 0, len(certs))
	for _, der := range certs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return &errs.Joined{Lead: ErrCertificateChainInvalid, Detail: "a chain entry does not parse", Cause: err}
		}
		chain = append(chain, cert)
	}

	now := time.Now()
	for i, cert := range chain {
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return &errs.Detail{Err: ErrCertificateChainInvalid, Detail: "a certificate in the chain is outside its validity window: " + cert.Subject.String()}
		}
		if i+1 < len(chain) {
			if err := cert.CheckSignatureFrom(chain[i+1]); err != nil {
				return &errs.Joined{Lead: ErrCertificateChainInvalid, Detail: "a certificate is not signed by the next in the chain", Cause: err}
			}
		}
	}

	last := chain[len(chain)-1]
	for _, root := range v.roots {
		if last.Equal(root) || last.CheckSignatureFrom(root) == nil {
			return nil
		}
	}
	return &errs.Detail{Err: ErrCertificateChainInvalid, Detail: "the chain does not reach a configured trust anchor"}
}

// x5cCertificates parses an attestation statement's x5c, leaf first. Every
// entry must be a DER certificate and the chain must not be empty: dropping an
// entry that is not would anchor a chain other than the one the device sent.
func x5cCertificates(x5c []interface{}) ([]*x509.Certificate, error) {
	if len(x5c) == 0 {
		return nil, &errs.Detail{Err: ErrCertificateChainInvalid, Detail: "x5c is absent"}
	}
	chain := make([]*x509.Certificate, 0, len(x5c))
	for _, entry := range x5c {
		der, ok := entry.([]byte)
		if !ok {
			return nil, &errs.Detail{Err: ErrCertificateChainInvalid, Detail: "an x5c entry is not a byte string"}
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrCertificateChainInvalid, Detail: "an x5c entry does not parse", Cause: err}
		}
		chain = append(chain, cert)
	}
	return chain, nil
}
