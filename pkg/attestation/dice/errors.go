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

import "errors"

// Parsing and encoding failures.
//
// Every one of these means the evidence in hand is not a DiceTcbInfo or a
// TcgUeid as the DICE Attestation Architecture defines it. None of them is
// recoverable by trying harder: a verifier that cannot say what a field
// contains cannot report what the device measured.
var (
	// ErrNilCertificate indicates a nil certificate was supplied.
	ErrNilCertificate = errors.New("dice: nil certificate")

	// ErrNilTcbInfo indicates a nil TcbInfo was supplied for encoding.
	ErrNilTcbInfo = errors.New("dice: nil tcb info")

	// ErrTcbInfoNotFound indicates the certificate carries no
	// tcg-dice-TcbInfo extension.
	ErrTcbInfoNotFound = errors.New("dice: tcg-dice-TcbInfo extension not found")

	// ErrUeidNotFound indicates the certificate carries no tcg-dice-Ueid
	// extension.
	ErrUeidNotFound = errors.New("dice: tcg-dice-Ueid extension not found")

	// ErrUeidConflict indicates the certificate states its device identifier
	// twice, in the tcg-dice-Ueid extension and in the UCCS ueid claim, and the
	// two differ.
	ErrUeidConflict = errors.New("dice: the ueid extension and the ueid claim disagree")

	// ErrMalformedTcbInfo indicates the DiceTcbInfo could not be decoded.
	ErrMalformedTcbInfo = errors.New("dice: malformed DiceTcbInfo")

	// ErrMalformedUeid indicates the TcgUeid could not be decoded.
	ErrMalformedUeid = errors.New("dice: malformed TcgUeid")

	// ErrMalformedFWID indicates an FWID entry is not a usable measurement.
	//
	// An FWID with no hash algorithm, or with an empty digest, names no
	// measurement at all. Accepting one would let a device present an
	// fwids list that appears populated and says nothing.
	ErrMalformedFWID = errors.New("dice: malformed FWID")

	// ErrUnknownTcbInfoField indicates a context-specific tag outside the ten
	// the DiceTcbInfo SEQUENCE defines.
	//
	// Refused rather than skipped. This is attestation evidence, and a field
	// the verifier cannot read is a claim it cannot weigh -- the same reason
	// the format gate refuses evidence whose format it does not recognise.
	ErrUnknownTcbInfoField = errors.New("dice: unknown DiceTcbInfo field")

	// ErrTcbInfoFieldOrder indicates the DiceTcbInfo fields are not in
	// strictly ascending tag order.
	//
	// DER requires it, and enforcing it is what makes a repeated tag
	// impossible: two vendor fields in one structure leave the verifier and
	// any other reader free to disagree about which one the device meant.
	ErrTcbInfoFieldOrder = errors.New("dice: DiceTcbInfo fields are out of order or repeated")

	// ErrNegativeTcbInfoValue indicates svn, layer or index was negative.
	// Each counts something, so a negative value describes no device.
	ErrNegativeTcbInfoValue = errors.New("dice: svn, layer and index cannot be negative")

	// ErrUnknownOperationalFlag indicates the flags BIT STRING carries a bit
	// beyond the four operational states the specification names.
	//
	// Refused for the same reason as an unknown field, and more sharply: an
	// unread flag is a state the device is declaring itself to be in.
	ErrUnknownOperationalFlag = errors.New("dice: unknown operational flag")

	// ErrEmptyUeid indicates the UEID octet string is empty, which identifies
	// no device.
	ErrEmptyUeid = errors.New("dice: empty ueid")

	// ErrUnknownRootType indicates a root type with no vendorInfo value was
	// asked for: RootTypeUnreported, or a value outside the ones defined.
	// Unreported is stated by omitting the value, never by encoding one.
	ErrUnknownRootType = errors.New("dice: root type has no vendorInfo value")
)

// tcg-dice-UCCS-evidence failures.
//
// The challenge travels in a CWT claims set inside this extension, so each of
// these means the verifier could not read the one claim that establishes
// freshness. None of them is skipped: a claims set this verifier cannot read
// in full is not a basis for concluding the device answered the challenge it
// was actually issued.
var (
	// ErrNilClaimsSet indicates a nil ClaimsSet was supplied for encoding.
	ErrNilClaimsSet = errors.New("dice: nil claims set")

	// ErrUccsEvidenceNotFound indicates the certificate carries no
	// tcg-dice-UCCS-evidence extension.
	//
	// It is returned rather than falling back to DiceTcbInfo.vendorInfo. A
	// fallback would mean a device that puts its nonce somewhere other than
	// where the specification says still verifies, which is exactly what
	// moving the nonce here was meant to stop.
	ErrUccsEvidenceNotFound = errors.New("dice: tcg-dice-UCCS-evidence extension not found")

	// ErrMalformedUccsEvidence indicates the UccsEvidence SEQUENCE could not
	// be decoded.
	ErrMalformedUccsEvidence = errors.New("dice: malformed UccsEvidence")

	// ErrMalformedClaimsSet indicates the CBOR inside the uccs octet string is
	// not a claims set this profile reads: not a map, tagged,
	// indefinite-length, empty, keyed by something other than an integer, or
	// followed by trailing bytes.
	ErrMalformedClaimsSet = errors.New("dice: malformed CWT claims set")

	// ErrDuplicateClaim indicates the claims set carries one claim key twice.
	//
	// Refused for the reason ErrTcbInfoFieldOrder is refused: two values for
	// one claim leave this verifier and every other reader free to disagree
	// about which one the device meant.
	ErrDuplicateClaim = errors.New("dice: duplicate CWT claim key")

	// ErrNonceClaimMissing indicates the claims set carries no eat_nonce
	// claim, so the device answered without the challenge.
	ErrNonceClaimMissing = errors.New("dice: the CWT claims set carries no eat_nonce claim")

	// ErrMalformedNonceClaim indicates the eat_nonce claim is not the single
	// byte string EAT defines it as.
	ErrMalformedNonceClaim = errors.New("dice: malformed eat_nonce claim")

	// ErrNonceClaimLength indicates the eat_nonce claim is shorter than the
	// eight bytes EAT requires, so the challenge it carries is guessable and
	// establishes no freshness. EAT's 64-byte upper bound is not enforced;
	// see nonceMinLen for why.
	ErrNonceClaimLength = errors.New("dice: eat_nonce must be at least 8 bytes")
)

// Verification failures.
var (
	// ErrNilVerifyOptions indicates nil verification options were supplied.
	ErrNilVerifyOptions = errors.New("dice: verify options cannot be nil")

	// ErrEmptyChain indicates no certificates were supplied.
	ErrEmptyChain = errors.New("dice: empty certificate chain")

	// ErrChainVerificationFailed indicates the chain does not terminate at a
	// configured trust anchor.
	ErrChainVerificationFailed = errors.New("dice: certificate chain verification failed")

	// ErrUnsupportedKeyType indicates a DICE certificate carries a key that is
	// not ECDSA on P-256.
	//
	// The profile's hardware root of trust is a key store that holds P-256
	// and nothing else. A DICE certificate presenting any other key was not
	// produced by the hardware this profile describes, so accepting it would
	// mean reporting hardware backing the device does not have.
	ErrUnsupportedKeyType = errors.New("dice: device identity keys must be ECDSA P-256")

	// ErrUnsupportedSignatureAlgorithm indicates a DICE certificate was signed
	// with something other than ECDSA with SHA-256.
	ErrUnsupportedSignatureAlgorithm = errors.New("dice: device identity certificates must be signed with ECDSA-SHA256")

	// ErrNonceMismatch indicates the device did not echo the nonce this
	// verifier issued.
	//
	// The nonce is the only freshness mechanism in this profile. The device
	// has no clock, so there is no timestamp it could supply that would mean
	// anything, and nothing here is ever compared against the wall clock.
	ErrNonceMismatch = errors.New("dice: attestation nonce mismatch")

	// ErrNonceRequired indicates verification was asked for without a nonce.
	// Freshness cannot be established after the fact, so a verifier that
	// issued no challenge is told so rather than handed stale evidence.
	ErrNonceRequired = errors.New("dice: a verifier nonce is required")

	// ErrUeidMismatch indicates the device reported a UEID other than the one
	// expected.
	ErrUeidMismatch = errors.New("dice: ueid mismatch")

	// ErrOperationalStateNotPermitted indicates the device reported an
	// operational state the verifier does not accept -- notConfigured,
	// notSecure, recovery or debug.
	ErrOperationalStateNotPermitted = errors.New("dice: device reports an operational state that is not permitted")

	// ErrNoMeasurement indicates the leaf's DiceTcbInfo carries no fwids, so
	// the certificate attests an identity without attesting what the device
	// is running.
	ErrNoMeasurement = errors.New("dice: leaf DiceTcbInfo carries no firmware measurement")

	// ErrApplicationEvidenceMismatch indicates VerifyOptions.ApplicationReference
	// is set and the leaf's measurements claim does not carry that application
	// evidence, or carries no measurements claim at all.
	ErrApplicationEvidenceMismatch = errors.New("dice: leaf application evidence is not the registered reference")

	// ErrInvalidApplicationReference indicates VerifyOptions.ApplicationReference
	// is set to something other than 32 bytes: a configuration error.
	ErrInvalidApplicationReference = errors.New("dice: application reference must be 32 bytes")

	// ErrCriticalEvidenceUnreadable indicates a certificate in the chain marks
	// a DICE evidence extension critical whose contents this verifier cannot
	// decode.
	//
	// Anchoring clears those OIDs from crypto/x509's unhandled-critical set,
	// which is a statement that this verifier read them. The statement is made
	// true by reading them, on EVERY certificate and not only on the leaf --
	// otherwise an intermediate could carry critical evidence nobody can parse
	// and still anchor, with the refusal crypto/x509 would have made suppressed
	// by this package.
	ErrCriticalEvidenceUnreadable = errors.New("dice: critical DICE evidence could not be decoded")
)
