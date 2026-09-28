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

package attestation

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	android "github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// Attestation invariant failures.
//
// These are not policy. They are the checks without which a signed certificate
// does not mean what a relying party will read it to mean, so there is no
// configuration that disables them.
var (
	// ErrKeyNotBound means the CSR asks the CA to certify a key the attestation
	// does not cover.
	//
	// The most important check in the whole path. Attestation chains are not
	// secret -- they travel with every enrollment -- so without binding, anyone
	// holding one can present it beside a CSR for a key they generated in
	// software and receive a certificate that reads as hardware-backed.
	ErrKeyNotBound = errors.New("attestation: the CSR key is not the attested key")

	// ErrStaleEvidence means the evidence does not carry the challenge this CA
	// issued, so it may be a recording of an earlier exchange.
	ErrStaleEvidence = errors.New("attestation: the challenge does not match")

	// ErrUnknownFormat means no profile describes what this format proves.
	// "We do not know what this evidence shows" is not a basis for issuing a
	// certificate that asserts hardware backing.
	ErrUnknownFormat = errors.New("attestation: no binding profile for format")

	// ErrBindingUnavailable means the format's binding mechanism is understood
	// but the evidence needed to check it was not supplied.
	ErrBindingUnavailable = errors.New("attestation: evidence cannot be bound to the CSR key")
)

// Wire tags for the evidence formats this CA understands.
const (
	FormatAndroidKey = "android-key-attestation"
	FormatYubiKeyPIV = "yubikey-piv"
	FormatTPM2       = "tpm2"
	FormatDICE       = "dice"
)

// Evidence is one attestation submission, normalised away from whichever
// carrier delivered it.
//
// Two carriers exist and neither is ours to redesign: a PKCS#10 CSR with
// format-tagged evidence alongside it, and the TCG-CSR-IDEVID packed structure.
// Both reduce to the fields below, which is what lets one gate judge both.
type Evidence struct {
	// Format is the wire tag naming what kind of evidence this is.
	Format string

	// Leaf is the attestation leaf certificate. Nil for carriers that identify
	// the attesting key by public area instead, as TCG does.
	Leaf *x509.Certificate

	// SubjectSPKI is the DER SubjectPublicKeyInfo of the key being certified.
	// Used by formats whose leaf certifies that key directly, and by TPM
	// formats whose CSR arrives separately from the certification: when set,
	// the key in SubjectPublicArea must be this key.
	SubjectSPKI []byte

	// AttesterPublicArea and SubjectPublicArea are marshalled TPMT_PUBLIC.
	// Used by TPM formats, where the binding is a Name over the public area
	// and cannot be derived from a public key.
	AttesterPublicArea []byte
	SubjectPublicArea  []byte

	// AttesterCertificate identifies the attesting key by its X.509
	// certificate, for TPM carriers that deliver it that way instead of as a
	// public area -- the WebAuthn "tpm" attestation statement's aikCert. Set
	// it or AttesterPublicArea, never both. Its chain must already be anchored.
	AttesterCertificate *x509.Certificate

	// CertifyInfo and CertifySignature are the TPM2_Certify structure binding
	// the subject key to the attesting key, and the raw signature over it.
	CertifyInfo      []byte
	CertifySignature []byte

	// CertifySignatureAlgorithm is the algorithm CertifySignature was made
	// with when the attester is identified by AttesterCertificate. The
	// signature is then that algorithm's ordinary encoding rather than a value
	// whose scheme a public area declares.
	CertifySignatureAlgorithm x509.SignatureAlgorithm

	// ExpectedChallenge is the nonce this CA issued, or nil when freshness is
	// established elsewhere in the ceremony. For a TPM2_Certify it is compared
	// with the certification's extraData.
	//
	// The TCG ceremony sets this nil deliberately: its certification is made
	// when the IDevID is created, long before a CA picks a challenge, and
	// freshness there comes from credential activation and the quote, both
	// bound to values chosen in-session.
	ExpectedChallenge []byte
}

// formatProfile declares what a format's evidence is able to prove.
//
// Whether a check applies is a property of the format and lives here in code.
// How strict a deployment wants to be is policy and lives in configuration.
// Key binding and freshness are in the first category, which is why nothing
// below is switchable.
type formatProfile struct {
	// bindLeafSPKI: the leaf's SubjectPublicKeyInfo is the attested key, so
	// binding is a direct comparison against the CSR.
	bindLeafSPKI bool

	// bindTPMCertify: the attesting key certified the subject through a
	// TPM2_Certify structure, so binding is a Name comparison.
	bindTPMCertify bool

	// challengeInCertify: the challenge, when one was issued, is the
	// TPM2_Certify extraData. It is read out of the signed certification by
	// the binding check rather than out of a leaf certificate.
	challengeInCertify bool

	// challenge extracts the caller-supplied nonce, or nil when the format has
	// no challenge mechanism.
	challenge func(*x509.Certificate) ([]byte, error)

	// note explains the profile to an operator reading a refusal.
	note string
}

var profiles = map[string]formatProfile{
	FormatAndroidKey: {
		bindLeafSPKI: true,
		challenge:    androidChallenge,
		note:         "the leaf certifies the attested key; the challenge is in the attestation extension",
	},
	FormatYubiKeyPIV: {
		bindLeafSPKI: true,
		// Deliberately nil. A PIV slot attestation certificate is minted once
		// when the key is generated and is static thereafter, so there is
		// nothing to bind to a request. Demanding a nonce would refuse every
		// genuine YubiKey; replay is defeated by binding instead, and the CSR
		// signature proves possession at the time of asking.
		challenge: nil,
		note:      "the leaf certifies the slot key; PIV attestation is static and carries no challenge",
	},
	FormatTPM2: {
		bindTPMCertify:     true,
		challengeInCertify: true,
		note:               "the attesting key certifies the subject key through TPM2_Certify; a challenge, when issued, is its extraData",
	},
	FormatDICE: {
		bindLeafSPKI: true,
		challenge:    dice.Challenge,
		// A DICE device has no clock, so a nonce is the only freshness this
		// format can offer -- there is no device-supplied timestamp that would
		// mean anything, and none is read. The device echoes the challenge in
		// the eat_nonce claim of the tcg-dice-UCCS-evidence extension of the
		// alias certificate it mints for the exchange: the mechanism TCG DICE
		// Attestation Architecture section 6.1.4 defines, so another DICE
		// verifier reading the same certificate finds the nonce where it
		// expects it.
		note: "the alias certificate certifies the attested key; the challenge is echoed in the eat_nonce claim of tcg-dice-UCCS-evidence",
	},
}

// androidChallenge reads the attestation challenge from an Android leaf.
func androidChallenge(leaf *x509.Certificate) ([]byte, error) {
	desc, err := android.ParseKeyAttestation(leaf)
	if err != nil {
		return nil, err
	}
	return desc.AttestationChallenge, nil
}

// Normalize canonicalises a wire-supplied format tag.
func Normalize(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}

// KnownFormat reports whether a profile describes this format.
func KnownFormat(format string) bool {
	_, ok := profiles[Normalize(format)]
	return ok
}

// VerifyInvariants applies the checks that hold for every format, each through
// that format's own mechanism.
//
// It must run *after* chain anchoring: everything read here is only meaningful
// once the evidence is known to descend from a root the operator configured.
//
// Anchoring itself stays with the caller because the two carriers establish it
// differently -- the generic path anchors an X.509 chain, the TCG path
// establishes EK trust from the manufacturer certificate -- and collapsing that
// would mean pretending they are the same when they are not.
func VerifyInvariants(ev *Evidence) error {
	if ev == nil {
		return fmt.Errorf("%w: no evidence supplied", ErrBindingUnavailable)
	}

	format := Normalize(ev.Format)
	profile, known := profiles[format]
	if !known {
		return fmt.Errorf("%w: %q", ErrUnknownFormat, ev.Format)
	}

	if err := verifyFreshness(profile, ev); err != nil {
		return err
	}
	return verifyBinding(profile, ev, format)
}

// verifyFreshness checks the attested challenge where the format carries one.
func verifyFreshness(profile formatProfile, ev *Evidence) error {
	if profile.challengeInCertify {
		// The challenge is inside the signed certification, so it is checked
		// with it, in verifyTPMCertifyBinding. Checking it here would mean
		// reading a field out of bytes whose signature has not yet verified.
		return nil
	}
	if profile.challenge == nil {
		// The format has no challenge mechanism. A caller that supplied one
		// anyway is confused about what this evidence can prove, and silently
		// ignoring it would let them believe freshness was checked.
		if len(ev.ExpectedChallenge) > 0 {
			return fmt.Errorf(
				"%w: %s carries no challenge, so one cannot be verified",
				ErrStaleEvidence, ev.Format)
		}
		return nil
	}

	if ev.Leaf == nil {
		return fmt.Errorf("%w: no leaf to read the challenge from", ErrBindingUnavailable)
	}
	attested, err := profile.challenge(ev.Leaf)
	if err != nil {
		return fmt.Errorf("%w: could not read the attested challenge: %v",
			ErrBindingUnavailable, err)
	}
	if len(ev.ExpectedChallenge) == 0 {
		return fmt.Errorf("%w: this format carries a challenge, so one must be issued",
			ErrStaleEvidence)
	}
	if subtle.ConstantTimeCompare(attested, ev.ExpectedChallenge) != 1 {
		return ErrStaleEvidence
	}
	return nil
}

// verifyBinding ties the evidence to the key being certified.
func verifyBinding(profile formatProfile, ev *Evidence, format string) error {
	switch {
	case profile.bindLeafSPKI:
		if ev.Leaf == nil {
			return fmt.Errorf("%w: %s binds through the leaf, which was not supplied",
				ErrBindingUnavailable, format)
		}
		if len(ev.SubjectSPKI) == 0 {
			return fmt.Errorf("%w: no subject key to bind", ErrKeyNotBound)
		}
		if subtle.ConstantTimeCompare(ev.SubjectSPKI, ev.Leaf.RawSubjectPublicKeyInfo) != 1 {
			return ErrKeyNotBound
		}
		return nil

	case profile.bindTPMCertify:
		return verifyTPMCertifyBinding(ev, format)

	default:
		return fmt.Errorf("%w: %s declares no binding mechanism", ErrUnknownFormat, format)
	}
}

// verifyTPMCertifyBinding checks a TPM2_Certify binding: that the attesting key
// certified the subject public area, that the certification carries the
// challenge when one was issued, and -- when the key being certified arrived
// separately, as a CSR does -- that it is the key the TPM certified.
//
// The attesting key is identified one of two ways, depending on the carrier:
// by its public area (TCG-CSR-IDEVID), or by its X.509 certificate (the
// WebAuthn "tpm" statement's aikCert). Either reaches the same pkg/tpm2
// verifier, so the two carriers cannot disagree about what a certification
// proves.
func verifyTPMCertifyBinding(ev *Evidence, format string) error {
	if len(ev.SubjectPublicArea) == 0 {
		// The TPM Name is a digest over the public *area* and cannot be
		// derived from a public key, so a carrier that omits the area cannot
		// express this binding at all.
		return &errs.Detail{
			Err:    ErrBindingUnavailable,
			Detail: format + " binds through TPM2_Certify, which needs the subject public area",
		}
	}

	opts := &tpm2.VerifyCertifyOptions{}
	if len(ev.ExpectedChallenge) > 0 {
		opts.ExpectedQualifyingData = ev.ExpectedChallenge
	}

	var err error
	switch {
	case len(ev.AttesterPublicArea) > 0 && ev.AttesterCertificate != nil:
		// Two identities for one attester is a caller unsure which was
		// verified. Picking one would leave the other believed checked.
		return &errs.Detail{
			Err:    ErrBindingUnavailable,
			Detail: format + " attester is identified by both a public area and a certificate",
		}
	case len(ev.AttesterPublicArea) > 0:
		_, err = tpm2.VerifyCertifyRaw(
			ev.CertifyInfo,
			ev.CertifySignature,
			ev.AttesterPublicArea,
			ev.SubjectPublicArea,
			opts,
		)
	case ev.AttesterCertificate != nil:
		_, err = tpm2.VerifyCertifyByCertificate(
			ev.CertifyInfo,
			ev.CertifySignature,
			ev.CertifySignatureAlgorithm,
			ev.AttesterCertificate,
			ev.SubjectPublicArea,
			opts,
		)
	default:
		return &errs.Detail{
			Err:    ErrBindingUnavailable,
			Detail: format + " binds through TPM2_Certify, which needs the attester's public area or certificate",
		}
	}
	if err != nil {
		if errors.Is(err, tpm2.ErrCertifyQualifyingDataMismatch) {
			return &errs.Joined{Lead: ErrStaleEvidence, Cause: err}
		}
		return &errs.Joined{Lead: ErrKeyNotBound, Cause: err}
	}

	if len(ev.SubjectSPKI) == 0 {
		// The subject public area is itself the key being certified, as in a
		// TCG-CSR-IDEVID, which packs it beside the certification.
		return nil
	}
	return verifyCertifiedKeyIsSubjectKey(ev.SubjectPublicArea, ev.SubjectSPKI)
}

// verifyCertifiedKeyIsSubjectKey checks that the key a TPM certified, read
// from its public area, is the key in subjectSPKI.
//
// The comparison is of keys, not encodings: a SubjectPublicKeyInfo can express
// one key more than one way, and refusing a CSR over its encoding would be
// refusing the right key.
func verifyCertifiedKeyIsSubjectKey(subjectPublicArea, subjectSPKI []byte) error {
	certified, err := tpm2.ExtractPublicKeyFromTPMPublic(subjectPublicArea)
	if err != nil {
		return &errs.Joined{Lead: ErrKeyNotBound, Detail: "the certified public area holds no usable key", Cause: err}
	}
	requested, err := x509.ParsePKIXPublicKey(subjectSPKI)
	if err != nil {
		return &errs.Joined{Lead: ErrKeyNotBound, Detail: "the subject key does not parse", Cause: err}
	}
	comparable, ok := certified.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !comparable.Equal(requested) {
		return ErrKeyNotBound
	}
	return nil
}
