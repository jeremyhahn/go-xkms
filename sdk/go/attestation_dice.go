// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-License-Identifier: commercial

package xkms

import (
	"crypto/x509"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
)

// DICE device identity (go-xkms#646): a device whose key is derived from a
// Unique Device Secret and a measurement of its own firmware, presenting an
// X.509 chain carrying the TCG DICE evidence extensions.
//
// THIS FILE IS WHY THE CAPABILITY IS REACHABLE AT ALL. The constitution is
// explicit that a capability originating in go-xkms is implemented in go-xkms,
// EXPOSED THROUGH ITS SDK, and only routed by quicbaas. pkg/attestation/dice is
// the canonical implementation; these aliases are the surface go-quicbaas
// re-exports and go-trusted-platform reaches. Without them the work exists and
// no consumer can legally use it -- go-trusted-platform's own layer guard
// refuses a direct go-xkms import, so pkg/ is not an alternative route.
//
// Identifiers carry a DICE prefix for the same reason the peer surface carries
// Peer: Evidence, VerifyOptions and Verify already name the x509
// key-attestation surface in this flat namespace.

// DICEEvidence is what a verified DICE chain yielded: the decoded TcbInfo when
// the leaf carried one, the CWT claims set, the device identifier and the
// operational flags.
type DICEEvidence = dice.Evidence

// DICEVerifyOptions is what the verifier demands: trust anchors, the expected
// nonce, an expected UEID, and whether a TcbInfo and a measurement are
// required.
//
// Note RequireTcbInfo. TCG DICE r23 section 6.1.4 permits a UCCS evidence
// extension "in place of" DiceTcbInfo, so a conforming certificate may carry no
// TcbInfo at all -- and a constrained device mints exactly that. Operational
// flags live in TcbInfo, so on such a certificate there are NONE: "no flags"
// and "flags say notSecure is clear" are different facts, and a policy that
// turns on notSecure must require the structure that states it.
type DICEVerifyOptions = dice.VerifyOptions

// DICETcbInfo is the decoded tcg-dice-TcbInfo extension: what the device says
// about the TCB layer this key was derived for.
type DICETcbInfo = dice.TcbInfo

// DICEFWID is one firmware measurement inside a DICETcbInfo.
type DICEFWID = dice.FWID

// DICEOperationalFlags are the states the target TCB declared -- notConfigured,
// notSecure, recovery, debug. Each says the target is not in its expected
// operating state.
type DICEOperationalFlags = dice.OperationalFlags

// DICEUeid is the decoded tcg-dice-Ueid extension, the device's unique
// identifier.
type DICEUeid = dice.Ueid

// DICEClaimsSet is the CBOR Unprotected CWT Claims Set carried in
// tcg-dice-UCCS-evidence. Its Nonce is the challenge the device echoed; Other
// carries every claim this profile does not model, kept as raw CBOR so a
// verifier's report of what the device said stays true.
type DICEClaimsSet = dice.ClaimsSet

// DICEVerify verifies a DICE certificate chain and returns its evidence.
//
// Freshness is the nonce and nothing else: a DICE device has no clock, so
// nothing here compares a device-supplied value against the current time.
func DICEVerify(chain []*x509.Certificate, opts *DICEVerifyOptions) (*DICEEvidence, error) {
	return dice.Verify(chain, opts)
}

// DICEChallenge returns the nonce the leaf echoed, from the eat_nonce claim of
// its tcg-dice-UCCS-evidence extension.
var DICEChallenge = dice.Challenge

// DICEUccsFromCertificate decodes the claims set from a leaf's UCCS evidence
// extension.
var DICEUccsFromCertificate = dice.UccsFromCertificate

// DICETcbInfoFromCertificate decodes a leaf's TcbInfo, or reports that it
// carried none.
var DICETcbInfoFromCertificate = dice.TcbInfoFromCertificate

// DICEUeidFromCertificate decodes a leaf's device identifier.
var DICEUeidFromCertificate = dice.UeidFromCertificate

// DICEDeviceUeid returns a leaf's device identifier from either place a DICE
// device states it: the tcg-dice-Ueid extension or the ueid claim of the
// UCCS evidence. Prefer it to DICEUeidFromCertificate, which reads only the
// extension and so finds nothing on a device, like the arduino-generic AVR
// profile, that uses the claim.
var DICEDeviceUeid = dice.DeviceUeid

// DICEClaimUeid is the CWT claim key (256) of the ueid in a claims set.
const DICEClaimUeid = dice.ClaimUeid

// DICEHasExtensions reports whether a certificate carries any DICE evidence
// extension at all, for a caller deciding which verifier to route to.
var DICEHasExtensions = dice.HasExtensions

// DICECreateUccsEvidenceExtension builds the extension a device or a test
// signs into an alias certificate.
var DICECreateUccsEvidenceExtension = dice.CreateUccsEvidenceExtension

// DICECreateTcbInfoExtension builds a TcbInfo extension.
var DICECreateTcbInfoExtension = dice.CreateTcbInfoExtension

// DICECreateUeidExtension builds a Ueid extension.
var DICECreateUeidExtension = dice.CreateUeidExtension

// DICE refusals, re-exported so a consumer can tell them apart with errors.Is.
//
// Without these a downstream project can call DICEVerify and read the error's
// text, and nothing else: go-trusted-platform's layer guard refuses a direct
// go-xkms/pkg import, so `errors.Is(err, dice.ErrNonceMismatch)` is not
// available to it at any price. A gate that cannot distinguish "this device
// replayed an old answer" from "this chain does not reach my roots" from "this
// certificate is malformed" cannot report which happened, and the three call
// for three different operator actions.
//
// They are the canonical values rather than copies, so errors.Is matches an
// error produced anywhere in the stack.
var (
	// ErrDICENilCertificate reports a nil certificate.
	ErrDICENilCertificate = dice.ErrNilCertificate

	// ErrDICENilTcbInfo reports a nil TcbInfo supplied for encoding.
	ErrDICENilTcbInfo = dice.ErrNilTcbInfo

	// ErrDICETcbInfoNotFound reports a certificate carrying no
	// tcg-dice-TcbInfo. Section 6.1.4 permits it: a UCCS-only certificate is
	// conforming, so this is a fact to route on rather than a failure.
	ErrDICETcbInfoNotFound = dice.ErrTcbInfoNotFound

	// ErrDICEUeidNotFound reports a certificate carrying no tcg-dice-Ueid.
	ErrDICEUeidNotFound = dice.ErrUeidNotFound

	// ErrDICEMalformedTcbInfo reports a DiceTcbInfo that did not decode.
	ErrDICEMalformedTcbInfo = dice.ErrMalformedTcbInfo

	// ErrDICEMalformedUeid reports a TcgUeid that did not decode.
	ErrDICEMalformedUeid = dice.ErrMalformedUeid

	// ErrDICEMalformedFWID reports an FWID naming no usable measurement.
	ErrDICEMalformedFWID = dice.ErrMalformedFWID

	// ErrDICEUnknownTcbInfoField reports a DiceTcbInfo field tag outside the
	// ten the structure defines: a claim the verifier cannot weigh.
	ErrDICEUnknownTcbInfoField = dice.ErrUnknownTcbInfoField

	// ErrDICETcbInfoFieldOrder reports DiceTcbInfo fields out of DER order or
	// repeated.
	ErrDICETcbInfoFieldOrder = dice.ErrTcbInfoFieldOrder

	// ErrDICENegativeTcbInfoValue reports a negative svn, layer or index.
	ErrDICENegativeTcbInfoValue = dice.ErrNegativeTcbInfoValue

	// ErrDICEUnknownOperationalFlag reports a flags bit beyond the four states
	// the specification names -- an operational state nobody can read.
	ErrDICEUnknownOperationalFlag = dice.ErrUnknownOperationalFlag

	// ErrDICEEmptyUeid reports a UEID octet string that identifies no device.
	ErrDICEEmptyUeid = dice.ErrEmptyUeid

	// ErrDICENilClaimsSet reports a nil claims set supplied for encoding.
	ErrDICENilClaimsSet = dice.ErrNilClaimsSet

	// ErrDICEUccsEvidenceNotFound reports a leaf with no
	// tcg-dice-UCCS-evidence extension: a device that answered without the
	// challenge, which is distinct from one that answered with the wrong one.
	ErrDICEUccsEvidenceNotFound = dice.ErrUccsEvidenceNotFound

	// ErrDICEMalformedUccsEvidence reports an UccsEvidence that did not decode.
	ErrDICEMalformedUccsEvidence = dice.ErrMalformedUccsEvidence

	// ErrDICEMalformedClaimsSet reports CBOR that is not a claims set this
	// profile reads.
	ErrDICEMalformedClaimsSet = dice.ErrMalformedClaimsSet

	// ErrDICEDuplicateClaim reports one claim key carried twice.
	ErrDICEDuplicateClaim = dice.ErrDuplicateClaim

	// ErrDICENonceClaimMissing reports a claims set with no eat_nonce claim.
	ErrDICENonceClaimMissing = dice.ErrNonceClaimMissing

	// ErrDICEMalformedNonceClaim reports an eat_nonce that is not the single
	// byte string EAT defines.
	ErrDICEMalformedNonceClaim = dice.ErrMalformedNonceClaim

	// ErrDICENonceClaimLength reports an eat_nonce shorter than eight bytes,
	// which is guessable and establishes no freshness.
	ErrDICENonceClaimLength = dice.ErrNonceClaimLength

	// ErrDICENilVerifyOptions reports verification asked for with no options.
	ErrDICENilVerifyOptions = dice.ErrNilVerifyOptions

	// ErrDICEEmptyChain reports verification asked for with no certificates.
	ErrDICEEmptyChain = dice.ErrEmptyChain

	// ErrDICEChainVerificationFailed reports a chain that does not terminate at
	// a configured trust anchor.
	ErrDICEChainVerificationFailed = dice.ErrChainVerificationFailed

	// ErrDICEUnsupportedKeyType reports a device identity key that is not ECDSA
	// on P-256, which the hardware root of trust could not have produced.
	ErrDICEUnsupportedKeyType = dice.ErrUnsupportedKeyType

	// ErrDICEUnsupportedSignatureAlgorithm reports a certificate a device key
	// signed with something other than ECDSA-SHA256.
	ErrDICEUnsupportedSignatureAlgorithm = dice.ErrUnsupportedSignatureAlgorithm

	// ErrDICENonceMismatch reports a device that did not echo the verifier's
	// nonce: a replay, or an answer to somebody else's challenge. The nonce is
	// the whole of the freshness argument here, because the device has no clock.
	ErrDICENonceMismatch = dice.ErrNonceMismatch

	// ErrDICENonceRequired reports verification asked for with no challenge.
	ErrDICENonceRequired = dice.ErrNonceRequired

	// ErrDICEUeidMismatch reports a device other than the one expected.
	ErrDICEUeidMismatch = dice.ErrUeidMismatch

	// ErrDICEUeidConflict reports a leaf that states its device identifier in
	// both the tcg-dice-Ueid extension and the UCCS ueid claim, with two
	// different values.
	ErrDICEUeidConflict = dice.ErrUeidConflict

	// ErrDICEOperationalStateNotPermitted reports a device declaring
	// notConfigured, notSecure, recovery or debug where policy allows none.
	ErrDICEOperationalStateNotPermitted = dice.ErrOperationalStateNotPermitted

	// ErrDICENoMeasurement reports a leaf whose DiceTcbInfo carries no fwids,
	// so it attests an identity without attesting what the device runs.
	ErrDICENoMeasurement = dice.ErrNoMeasurement

	// ErrDICECriticalEvidenceUnreadable reports a certificate in the chain
	// marking DICE evidence critical that the verifier cannot decode.
	ErrDICECriticalEvidenceUnreadable = dice.ErrCriticalEvidenceUnreadable
)
