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

package dice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// VerifyOptions configures verification of a DICE certificate chain.
type VerifyOptions struct {
	// TrustedRoots anchors the chain. Leaving it nil skips anchoring, which is
	// only correct when the caller has already anchored the chain by another
	// route; on its own an unanchored DICE chain proves nothing, because a
	// chain is self-consistent whoever generated it.
	TrustedRoots *x509.CertPool

	// ExpectedNonce is the challenge this verifier issued. It is required:
	// a DICE device has no clock, so a nonce is the only thing that can
	// distinguish a live answer from a replayed recording.
	ExpectedNonce []byte

	// ExpectedUeid, when set, is the device identifier the caller expects. It
	// is the check that says "this is the device I enrolled" rather than
	// "this is a device from this manufacturer".
	ExpectedUeid []byte

	// RequireUeid demands a device identifier (see DeviceUeid) on the leaf even
	// when ExpectedUeid is not set, for a caller that intends to record the
	// identifier rather than match it.
	RequireUeid bool

	// ApplicationReference, when set, is the 32-byte application evidence
	// the caller registered for the device: the leaf's measurements claim
	// (273) must be the application evidence shape (ApplicationEvidence)
	// and carry exactly these bytes, or Verify refuses the chain with
	// ErrApplicationEvidenceMismatch. Nil leaves the claim unchecked; any
	// length other than 32 is ErrInvalidApplicationReference.
	ApplicationReference []byte

	// RequireMeasurement demands that the leaf's DiceTcbInfo carry at least
	// one FWID. Without one the certificate attests an identity while saying
	// nothing about the firmware that identity was derived from, which is the
	// half of DICE that makes the identity mean anything.
	//
	// It implies RequireTcbInfo: a measurement cannot be required from a
	// structure that is allowed to be absent.
	RequireMeasurement bool

	// RequireTcbInfo demands a tcg-dice-TcbInfo extension on the leaf.
	//
	// It is NOT the default, because r23 section 6.1.4 says a UCCS evidence
	// extension "MAY be used in addition to or in place of DiceTcbInfoSeq or
	// DiceTcbInfo" -- so a certificate carrying only UCCS is conforming, and a
	// verifier that refused it would refuse the profile a constrained device
	// can actually mint. A device that mints a fixed-template alias
	// certificate is exactly that: one extension, because its TBS is a
	// template in flash and a second extension costs space it does not have.
	//
	// SET IT WHEN POLICY DEPENDS ON THE OPERATIONAL FLAGS. Flags live in
	// DiceTcbInfo, so a UCCS-only certificate carries none -- and "no flags"
	// and "flags say notSecure is clear" are different facts that must not be
	// read alike. PermittedFlags is checked against an empty set on such a
	// certificate, which passes; a caller who needs to know the target is not
	// in recovery, debug or notSecure must require the structure that says so.
	RequireTcbInfo bool

	// RequireDeviceSignedLeaf states that the leaf's ISSUER is device-resident,
	// so the leaf must carry the one signature algorithm that hardware
	// performs: ECDSA with SHA-256.
	//
	// It exists because the issuer is usually not in the chain. A device mints
	// its alias certificate with a DeviceID key that lives in the same element,
	// but the DeviceID certificate is held by whoever provisioned the part, not
	// by a device with nowhere to keep it -- so the ordinary chain is the alias
	// leaf alone, or a DeviceID intermediate carrying no DICE extension of its
	// own. In both shapes the leaf is the only certificate the device signed
	// and nothing in the chain says so, which is why a caller who knows the
	// profile has to state it.
	//
	// Without it, an alias signed with ECDSA-SHA384 verifies: the signature
	// algorithm is the ISSUER's property and is therefore checked on
	// certificates a device-resident key signed, and with no device-resident
	// issuer present there is no certificate to check it on.
	RequireDeviceSignedLeaf bool

	// PermittedFlags are the operational states the verifier tolerates. The
	// zero value permits none, which is the safe default: notConfigured,
	// notSecure, recovery and debug each say the target TCB is not in its
	// trustworthy operating state.
	PermittedFlags OperationalFlags

	// CurrentTime is the instant the chain's validity windows are checked
	// against. The zero value defers to crypto/x509, which uses the current
	// time.
	//
	// This is the verifier's clock and is used for nothing but certificate
	// expiry. No value the device supplies is ever compared against it.
	CurrentTime time.Time
}

// Evidence is what a verified DICE chain established.
type Evidence struct {
	// TcbInfo is the leaf's decoded DiceTcbInfo, or nil when the leaf carried
	// none. Section 6.1.4 permits a UCCS evidence extension "in place of"
	// DiceTcbInfo, so nil here is a conforming certificate rather than a
	// defect -- and it means the operational flags are UNKNOWN, not clear.
	TcbInfo *TcbInfo

	// Claims is the leaf's decoded CWT claims set, the evidence the device
	// asserted in its tcg-dice-UCCS-evidence extension. Its Nonce is the
	// challenge that was matched; Other carries every claim this profile does
	// not model, so a caller can read what else the device said.
	Claims *ClaimsSet

	// Ueid is the device's unique identifier, read by DeviceUeid, or nil when
	// the leaf stated none and the options did not require one.
	Ueid []byte

	// Flags are the operational states the leaf declared. An absent flags
	// field decodes to all four inactive, which is what the specification
	// says an omitted field means.
	Flags OperationalFlags

	// RootType is where the device keeps its UDS, as the DiceTcbInfo of the
	// certificates on the verified path declares it (RootTypeFromPaths), or
	// RootTypeUnreported when they declare none or the chain was not anchored.
	RootType RootType
}

// Verify checks a DICE certificate chain and returns what it established.
//
// The chain is ordered leaf first. Verification is, in order:
//
//  1. Every device-resident certificate carries an ECDSA P-256 key, and every
//     certificate a device-resident key signed carries an ECDSA-SHA256
//     signature -- including the leaf itself when the caller set
//     RequireDeviceSignedLeaf, which is how a profile states that the leaf's
//     issuer is the device even though its certificate is not in the chain.
//  2. The chain terminates at a configured trust anchor, and every critical
//     DICE extension whose unhandled-critical entry is cleared to get there
//     decodes.
//  3. The leaf carries a readable DiceTcbInfo.
//  4. The device echoed the verifier's nonce in the eat_nonce claim of its
//     tcg-dice-UCCS-evidence extension.
//  5. The device reports no operational state the verifier refuses: neither
//     in the leaf's flags nor as a software root of trust -- notSecure or a
//     software vendorInfo -- on any certificate of the verified path.
//  6. The UEID and firmware measurement requirements the caller set are met.
//
// The root type is read only from the certificates on the paths that
// verified to TrustedRoots (RootTypeFromPaths, CA m452). Without
// TrustedRoots it is RootTypeUnreported, whatever the chain declares, and a
// supplied certificate on no verified path is never read.
//
// The order matters: nothing read out of the evidence means anything until the
// chain is known to descend from a root the operator configured, so anchoring
// comes before every claim that is read from it.
func Verify(chain []*x509.Certificate, opts *VerifyOptions) (*Evidence, error) {
	if opts == nil {
		return nil, ErrNilVerifyOptions
	}
	if opts.ApplicationReference != nil && len(opts.ApplicationReference) != sha256.Size {
		return nil, ErrInvalidApplicationReference
	}
	if len(chain) == 0 {
		return nil, ErrEmptyChain
	}
	for _, cert := range chain {
		if cert == nil {
			return nil, ErrNilCertificate
		}
	}

	leaf := chain[0]

	if err := verifyDeviceKeys(chain); err != nil {
		return nil, err
	}

	// The leaf's own signature, when the caller says its issuer is the device.
	// verifyDeviceKeys checks a signature algorithm only where the signing
	// certificate is in the chain, and for the common profiles it is not.
	if opts.RequireDeviceSignedLeaf {
		if err := verifyDeviceSignature(leaf); err != nil {
			return nil, err
		}
	}

	// paths stays nil for an unanchored chain, which RootTypeFromPaths reports
	// as unreported: nothing authenticated its DiceTcbInfo (CA m452).
	var paths [][]*x509.Certificate
	if opts.TrustedRoots != nil {
		var err error
		paths, err = VerifyChain(chain, opts.TrustedRoots, opts.CurrentTime)
		if err != nil {
			return nil, err
		}
	}

	// TcbInfo is OPTIONAL, per section 6.1.4. A certificate carrying only a
	// UCCS evidence extension is conforming, and this used to refuse it -- so
	// the verifier disagreed with the only profile a 4 KB-constrained device
	// can mint, in the same change set that added both.
	var info *TcbInfo
	var err error
	info, err = TcbInfoFromCertificate(leaf)
	switch {
	case err == nil:
	case errors.Is(err, ErrTcbInfoNotFound):
		if opts.RequireTcbInfo || opts.RequireMeasurement {
			return nil, err
		}
		info = nil
	default:
		return nil, err
	}

	// Read before the flags are judged against policy, so that an unreadable
	// DiceTcbInfo on the path is refused as that, whatever the policy permits.
	rootType, err := RootTypeFromPaths(paths)
	if err != nil {
		return nil, err
	}

	claims, err := verifyNonce(leaf, opts.ExpectedNonce)
	if err != nil {
		return nil, err
	}
	if err := verifyApplicationReference(claims, opts.ApplicationReference); err != nil {
		return nil, err
	}

	flags := OperationalFlags{}
	if info != nil && info.Flags != nil {
		flags = *info.Flags
	}
	if err := verifyOperationalFlags(flags, opts.PermittedFlags); err != nil {
		return nil, err
	}
	if err := verifyRootTypePermitted(rootType, opts.PermittedFlags); err != nil {
		return nil, err
	}

	// info is non-nil here whenever RequireMeasurement is set: the switch above
	// returns ErrTcbInfoNotFound rather than reaching this with a nil.
	if opts.RequireMeasurement && len(info.FWIDs) == 0 {
		return nil, ErrNoMeasurement
	}

	ueid, err := verifyUeid(leaf, opts)
	if err != nil {
		return nil, err
	}

	return &Evidence{TcbInfo: info, Claims: claims, Ueid: ueid, Flags: flags, RootType: rootType}, nil
}

// verifyApplicationReference holds the leaf's measurements claim to the
// registered application evidence, in constant time. A nil reference checks
// nothing.
func verifyApplicationReference(claims *ClaimsSet, reference []byte) error {
	if reference == nil {
		return nil
	}
	var measurements []byte
	if claims != nil {
		measurements = claims.Other[ClaimMeasurements]
	}
	if measurements == nil {
		return &errs.Detail{Err: ErrApplicationEvidenceMismatch, Detail: "the leaf carries no measurements claim"}
	}
	evidence, err := ApplicationEvidence(measurements)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(evidence, reference) != 1 {
		return ErrApplicationEvidenceMismatch
	}
	return nil
}

// verifyDeviceKeys enforces the ECDSA P-256 constraint on the certificates the
// device itself produced.
//
// The profile's hardware root of trust is a P-256-only key store: P-256 is the
// only curve it holds a key on, and it has no hardware Ed25519. A DICE
// certificate carrying any other key was not produced by that hardware, so accepting one would report
// hardware backing the device does not have.
//
// A certificate is device-resident if it is the leaf, or if it carries a DICE
// evidence extension -- the DeviceID and embedded CA certificates do. The
// constraint deliberately stops there: the manufacturer CA that anchors the
// device is not the hardware root of trust, and there is no reason its key
// should be limited to the device's curve. Holding it there would refuse every
// deployment whose CA is stronger than its devices.
//
// Two different things are checked, on two different certificates, because a
// certificate's key and the algorithm it was signed with belong to two
// different parties. The key is the subject's; the signature algorithm is the
// ISSUER's, so it is checked on the certificates a device-resident key signed
// rather than on the device-resident certificate itself.
func verifyDeviceKeys(chain []*x509.Certificate) error {
	for i, cert := range chain {
		deviceResident := i == 0 || HasExtensions(cert)
		if !deviceResident {
			continue
		}
		if err := verifyDeviceKey(cert); err != nil {
			return err
		}
		// Everything this device-resident key signed had to be signed with the
		// one algorithm the hardware performs.
		if i > 0 {
			if err := verifyDeviceSignature(chain[i-1]); err != nil {
				return err
			}
		}
	}
	return nil
}

// verifyDeviceKey checks that a device-resident certificate's subject key is
// one the hardware root of trust can hold.
func verifyDeviceKey(cert *x509.Certificate) error {
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return &errs.Detail{
			Err:    ErrUnsupportedKeyType,
			Detail: "certificate " + describeSubject(cert) + " carries a " + cert.PublicKeyAlgorithm.String() + " key",
		}
	}
	if public.Curve != elliptic.P256() {
		return &errs.Detail{
			Err:    ErrUnsupportedKeyType,
			Detail: "certificate " + describeSubject(cert) + " carries a key on " + public.Curve.Params().Name,
		}
	}
	return nil
}

// verifyDeviceSignature checks that a certificate signed by a device-resident
// key carries the only signature algorithm that hardware performs.
func verifyDeviceSignature(cert *x509.Certificate) error {
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return &errs.Detail{
			Err:    ErrUnsupportedSignatureAlgorithm,
			Detail: "certificate " + describeSubject(cert) + " is signed with " + cert.SignatureAlgorithm.String(),
		}
	}
	return nil
}

// VerifyChain anchors the chain to roots and returns the verified paths.
// attestation.Verifier anchors a DICE statement through it as well, so both
// verifiers read the root type from the same paths (CA m452).
//
// The DICE evidence extensions are removed from each certificate's unhandled
// critical extension set before verifying. DICE Attestation Architecture
// section 6.1.1 says the TcbInfo extension SHOULD be critical, and crypto/x509
// refuses any chain containing a critical extension it does not recognise --
// so without this, marking the extension critical as the specification asks
// would make every DICE chain unverifiable. This package does handle those
// extensions, which is precisely the condition under which clearing the entry
// is correct.
//
// "Handled" is MADE TRUE rather than asserted: every extension whose entry is
// cleared is decoded first, on every certificate in the chain and not only on
// the leaf. Verify reads the leaf's TcbInfo, UCCS and UEID and nothing above
// it, so an intermediate carrying malformed critical DICE evidence would
// otherwise pass anchoring on a promise nothing kept. A critical extension is
// the issuer saying a relying party must not use the certificate without
// understanding this; a verifier that cannot decode it has not understood it,
// and crypto/x509's own refusal is the behaviour being suppressed here.
//
// The clearing is done on copies. Mutating the caller's certificates would
// leave them permanently marked as handled for every later verifier in the
// process, including ones that do not understand DICE.
//
// It returns the verified paths, so that RootTypeFromPaths reads only the
// certificates they authenticate.
func VerifyChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) ([][]*x509.Certificate, error) {
	leaf, err := withDICEExtensionsHandled(chain[0])
	if err != nil {
		return nil, err
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		handled, err := withDICEExtensionsHandled(cert)
		if err != nil {
			return nil, err
		}
		intermediates.AddCert(handled)
	}

	paths, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   now,
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrChainVerificationFailed, Detail: describeSubject(chain[0]), Cause: err}
	}
	return paths, nil
}

// withDICEExtensionsHandled returns a shallow copy of the certificate with the
// DICE evidence OIDs removed from UnhandledCriticalExtensions.
//
// Each OID it removes is decoded first. Removing one without reading it would
// be this verifier telling crypto/x509 that it handled an extension it never
// looked at.
func withDICEExtensionsHandled(cert *x509.Certificate) (*x509.Certificate, error) {
	if len(cert.UnhandledCriticalExtensions) == 0 {
		return cert, nil
	}

	remaining := make([]asn1.ObjectIdentifier, 0, len(cert.UnhandledCriticalExtensions))
	for _, oid := range cert.UnhandledCriticalExtensions {
		if isDICEEvidence(oid) {
			if err := decodeEvidence(cert, oid); err != nil {
				return nil, err
			}
			continue
		}
		remaining = append(remaining, oid)
	}
	if len(remaining) == len(cert.UnhandledCriticalExtensions) {
		return cert, nil
	}

	duplicate := *cert
	duplicate.UnhandledCriticalExtensions = remaining
	return &duplicate, nil
}

// evidenceDecoders decodes one DICE evidence extension value, by OID.
//
// A map rather than a switch so it cannot drift from diceEvidenceOIDs: the
// test that walks that list and demands an entry here is what keeps a fourth
// evidence OID from being cleared without anyone able to read it.
var evidenceDecoders = map[string]func([]byte) error{
	OIDTcbInfo.String():      func(der []byte) error { _, err := ParseTcbInfo(der); return err },
	OIDUeid.String():         func(der []byte) error { _, err := ParseUeid(der); return err },
	OIDUccsEvidence.String(): func(der []byte) error { _, err := ParseUccsEvidence(der); return err },
}

// decodeEvidence reads one DICE evidence extension, reporting what it could
// not decode and on which certificate.
func decodeEvidence(cert *x509.Certificate, oid asn1.ObjectIdentifier) error {
	decode, known := evidenceDecoders[oid.String()]
	if !known {
		// Unreachable while diceEvidenceOIDs and evidenceDecoders agree, which
		// a test pins. Refusing rather than clearing is the safe direction if
		// they ever stop agreeing.
		return &errs.Detail{
			Err:    ErrCriticalEvidenceUnreadable,
			Detail: "no decoder for " + oid.String() + " on certificate " + describeSubject(cert),
		}
	}

	value, err := extensionValue(cert, oid, &errs.Detail{
		Err: ErrCriticalEvidenceUnreadable,
		Detail: "certificate " + describeSubject(cert) + " lists " + oid.String() +
			" as critical and carries no such extension",
	})
	if err != nil {
		return err
	}
	if err := decode(value); err != nil {
		return &errs.Joined{
			Lead:   ErrCriticalEvidenceUnreadable,
			Detail: oid.String() + " on certificate " + describeSubject(cert),
			Cause:  err,
		}
	}
	return nil
}

// verifyNonce checks that the device echoed the challenge this verifier
// issued, and returns the claims set it was read from.
//
// The nonce is the eat_nonce claim of the leaf's tcg-dice-UCCS-evidence
// extension. A leaf that carries no such extension is refused with
// ErrUccsEvidenceNotFound rather than falling back to
// DiceTcbInfo.vendorInfo: a fallback would let a device that placed its nonce
// outside the specification's mechanism verify anyway, which is the whole
// thing this placement exists to prevent.
func verifyNonce(leaf *x509.Certificate, expected []byte) (*ClaimsSet, error) {
	if len(expected) == 0 {
		return nil, ErrNonceRequired
	}
	claims, err := UccsFromCertificate(leaf)
	if err != nil {
		return nil, err
	}
	if len(claims.Nonce) != len(expected) ||
		subtle.ConstantTimeCompare(claims.Nonce, expected) != 1 {
		return nil, ErrNonceMismatch
	}
	return claims, nil
}

// verifyOperationalFlags refuses any state the verifier has not permitted.
func verifyOperationalFlags(reported, permitted OperationalFlags) error {
	refused := OperationalFlags{
		NotConfigured: reported.NotConfigured && !permitted.NotConfigured,
		NotSecure:     reported.NotSecure && !permitted.NotSecure,
		Recovery:      reported.Recovery && !permitted.Recovery,
		Debug:         reported.Debug && !permitted.Debug,
	}
	if !refused.Any() {
		return nil
	}
	return &errs.Detail{
		Err:    ErrOperationalStateNotPermitted,
		Detail: "device reports " + refused.String(),
	}
}

// verifyRootTypePermitted holds a software root of trust to the notSecure
// policy wherever on the verified path it was declared. CA m452: "A software
// root anywhere in the ancestry makes the identity software-rooted, so
// NotSecure on any layer propagates to attestation.Result."
// verifyOperationalFlags judges the leaf's own flags (TCG DICE Attestation
// Architecture r0.23 section 6.1.1), but an embedded CA may be the only
// certificate that sets notSecure, and a device whose UDS sits in storage is
// no more secure for having said so one certificate up.
func verifyRootTypePermitted(rootType RootType, permitted OperationalFlags) error {
	if rootType == RootTypeSoftware && !permitted.NotSecure {
		return &errs.Detail{Err: ErrOperationalStateNotPermitted, Detail: "the chain declares a software root of trust (notSecure)"}
	}
	return nil
}

// verifyUeid reads the device identifier and checks it against the caller's
// expectation.
func verifyUeid(leaf *x509.Certificate, opts *VerifyOptions) ([]byte, error) {
	ueid, err := DeviceUeid(leaf)
	if err != nil {
		// The caller did not ask for a UEID. A leaf without one is reported as
		// having none; a leaf with a malformed or contradictory one is still an
		// error, because that is evidence this verifier cannot read.
		if errors.Is(err, ErrUeidNotFound) && !opts.RequireUeid && len(opts.ExpectedUeid) == 0 {
			return nil, nil
		}
		return nil, err
	}
	if len(opts.ExpectedUeid) > 0 &&
		subtle.ConstantTimeCompare(ueid, opts.ExpectedUeid) != 1 {
		return nil, &errs.Detail{
			Err:    ErrUeidMismatch,
			Detail: "device reports ueid " + hex.EncodeToString(ueid),
		}
	}
	return ueid, nil
}

// describeSubject names a certificate for an operator reading a refusal.
func describeSubject(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return "with serial " + cert.SerialNumber.String()
}
