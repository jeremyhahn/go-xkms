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
	"crypto/x509"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Binding the evidence to the key being certified
//
// An ACME order is two requests. The challenge carries the device's evidence
// and the finalize carries the CSR, and nothing in the protocol ties the key
// in the second to the device in the first. For a DICE device that tie is the
// whole point: the alias certificate the device mints certifies the key that
// is being enrolled, so the CSR's SubjectPublicKeyInfo must be the alias
// certificate's SubjectPublicKeyInfo and nothing else.
//
// A TPM device is bound the same way through a different container. Its
// evidence is a TPM2_Certify of pubArea by the AIK in x5c[0] (WebAuthn Level 2
// section 8.3), and the CSR's key must be pubArea's key: the ACME counterpart
// of section 8.3's "the public key in pubArea is identical to the
// credentialPublicKey".
//
// pkg/attestation declares both bindings -- bindLeafSPKI and bindTPMCertify in
// its profile table -- and is the one implementation of them in this
// repository, shared with the TCG and SignCSR carriers. This file is how the
// ACME carrier reaches it: the verified evidence is carried from challenge to
// finalization, and BindCSRKey applies the gate.
//
// Attestation chains are not secret. They travel with every enrollment, so
// without this comparison anyone who has seen one genuine device's answer can
// present it beside a CSR for a key they generated in software and receive a
// certificate that reads as hardware-backed to every relying party.

// VerifiedAttestation is what a device-attest-01 attestation established, and
// what remains to be checked.
//
// FOR A FORMAT THAT BINDS THROUGH THE CSR IT IS NOT AN AUTHORIZATION. It says
// the evidence was well formed, anchored and fresh; it does not say the
// certificate about to be issued is for the attested key. BindCSRKey is the
// step that says so, and a server must run it before issuance -- which is why
// Verify, the one-shot challenge verifier, refuses such a format outright
// rather than reporting a success that is only half of one.
type VerifiedAttestation struct {
	// Format is the attestation format the evidence was verified under.
	Format AttestationFormat

	// KeyAuthorization is the ACME key authorization the evidence answered. It
	// is kept because the binding gate re-checks freshness through the same
	// mechanism the challenge did, and deriving the nonce from it here keeps
	// one definition of what the device was asked.
	KeyAuthorization string

	// Leaf is the certificate whose evidence was verified: for FormatDICE the
	// alias certificate the device minted for this exchange, whose subject key
	// is the attested key; for FormatTPM the AIK certificate (x5c[0]) whose key
	// signed CertInfo, and whose subject key is NOT the attested key -- that
	// is PubArea's.
	Leaf *x509.Certificate

	// LeafDER is the same certificate as the device sent it.
	//
	// It is here because this record has to OUTLIVE THE REQUEST that produced
	// it: the challenge and the finalize are two requests, and any server that
	// is not a single process must write the record down in between. A parsed
	// certificate does not survive that trip and a re-encoded one is a
	// different document, so the bytes travel and BindCSRKey parses them back.
	LeafDER []byte

	// Algorithm is the FormatTPM statement's alg: the COSE algorithm Signature
	// was made with, whose hash also formed the extraData the certification
	// carries. Zero for FormatDICE.
	Algorithm int64

	// CertInfo, Signature and PubArea are the FormatTPM statement's certInfo,
	// sig and pubArea as the device sent them: the TPM2_Certify structure, the
	// AIK's signature over it, and the TPMT_PUBLIC of the key it certifies.
	// They are kept as bytes for the same reason LeafDER is, and BindCSRKey
	// verifies them again rather than trusting that they were verified. Nil
	// for FormatDICE.
	CertInfo  []byte
	Signature []byte
	PubArea   []byte

	// AttestedSPKI is, for FormatDICE, the DER SubjectPublicKeyInfo of the
	// key the device's provisioning record vouches for (go-xkms#1441): the
	// provisioned DeviceID key, or the key of the provisioned DeviceID
	// certificate. Only RegisteredDeviceVerifier sets it, after the registry
	// check, and never from the payload. BindCSRKey refuses a certificate
	// request for any other key, and a FormatDICE record without one. Nil for
	// FormatTPM.
	AttestedSPKI []byte
}

// csrEvidence builds the evidence the binding gate judges for one format,
// given the certificate request whose key must be the attested key.
type csrEvidence func(*VerifiedAttestation, *x509.CertificateRequest) (*attestation.Evidence, error)

// csrBindings maps each format whose key binding completes against the CSR to
// the evidence it hands the gate. A format absent from it has no binding this
// carrier can express, and BindCSRKey says so rather than passing.
var csrBindings = map[AttestationFormat]csrEvidence{
	FormatDICE: diceCSREvidence,
	FormatTPM:  tpmCSREvidence,
}

// bindsThroughTheCSR reports whether this format's key binding can only be
// completed against the CSR, which is to say later than the challenge.
func (v *VerifiedAttestation) bindsThroughTheCSR() bool {
	if v == nil {
		return false
	}
	_, binds := csrBindings[v.Format]
	return binds
}

// BindCSRKey checks that the CSR asks the CA to certify the attested key.
//
// It is the last gate before issuance and it runs at finalization, which is
// where the CSR exists. Two things are established:
//
//  1. The requester holds the private half of the key in the CSR. A PKCS#10 is
//     self-signed by the key it names, so an invalid signature means binding it
//     to attested hardware would certify a key nobody demonstrated control of.
//  2. The CSR's key is the attested key, and the evidence still carries the
//     challenge this exchange issued. For FormatDICE the key is AttestedSPKI,
//     the key the provisioning record vouched for, which the alias leaf must
//     also carry, and the challenge the leaf's eat_nonce; for
//     FormatTPM the key is PubArea's, re-verified as certified by the AIK
//     under the TPM2_Certify checks, and the challenge the certification's
//     extraData. Both are applied by pkg/attestation's gate rather than
//     open-coded here, so the ACME carrier and the SignCSR carrier cannot
//     drift into two different ideas of what binding means.
//
// Freshness is re-checked rather than assumed, and it is a nonce, never a
// clock: a DICE device has no clock, and a TPM's clockInfo is not signed
// against anything this server chose, so nothing here reads a timestamp.
func (v *VerifiedAttestation) BindCSRKey(csr *x509.CertificateRequest) error {
	if v == nil {
		return ErrNoVerifiedAttestation
	}
	if csr == nil {
		return &errs.Detail{Err: ErrKeyBindingUnavailable, Detail: "no certificate request to bind to"}
	}
	evidenceFor, binds := csrBindings[v.Format]
	if !binds {
		return &errs.Detail{
			Err:    ErrKeyBindingUnavailable,
			Detail: string(v.Format) + " does not bind the attested key through the CSR",
		}
	}
	evidence, err := evidenceFor(v, csr)
	if err != nil {
		return err
	}
	if err := csr.CheckSignature(); err != nil {
		return &errs.Joined{
			Lead:   attestation.ErrKeyNotBound,
			Detail: "the certificate request signature does not verify",
			Cause:  err,
		}
	}

	return attestation.VerifyInvariants(evidence)
}

// diceCSREvidence is the binding evidence for FormatDICE: the alias leaf must
// certify the CSR's key and still carry this exchange's nonce.
func diceCSREvidence(v *VerifiedAttestation, csr *x509.CertificateRequest) (*attestation.Evidence, error) {
	leaf, err := v.verifiedLeaf()
	if err != nil {
		return nil, err
	}
	// The key the provisioning record vouched for at the challenge. A record
	// without one was never anchored in the device registry, and a missing
	// comparison must never read as a passing one.
	if len(v.AttestedSPKI) == 0 {
		return nil, &errs.Detail{Err: ErrKeyBindingUnavailable, Detail: "the dice record carries no attested SPKI"}
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, v.AttestedSPKI) {
		return nil, &errs.Detail{Err: attestation.ErrKeyNotBound, Detail: "the certificate request's key is not the attested SPKI"}
	}
	return &attestation.Evidence{
		Format:            attestation.FormatDICE,
		Leaf:              leaf,
		SubjectSPKI:       csr.RawSubjectPublicKeyInfo,
		ExpectedChallenge: DICENonce(v.KeyAuthorization),
	}, nil
}

// tpmCSREvidence is the binding evidence for FormatTPM: the certification the
// challenge verified, now with the CSR's key, which must be PubArea's.
func tpmCSREvidence(v *VerifiedAttestation, csr *x509.CertificateRequest) (*attestation.Evidence, error) {
	evidence, err := v.tpmEvidence()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrKeyBindingUnavailable, Detail: "the recorded tpm evidence is incomplete", Cause: err}
	}
	evidence.SubjectSPKI = csr.RawSubjectPublicKeyInfo
	return evidence, nil
}

// verifiedLeaf returns the certificate the binding is made against.
//
// The device's own bytes win when the record carries them, so a record that
// travelled through storage and one that never left the process are bound
// against the same document rather than against whatever a caller left in the
// parsed field.
func (v *VerifiedAttestation) verifiedLeaf() (*x509.Certificate, error) {
	if len(v.LeafDER) > 0 {
		leaf, err := x509.ParseCertificate(v.LeafDER)
		if err != nil {
			return nil, &errs.Joined{
				Lead:   ErrKeyBindingUnavailable,
				Detail: "the recorded leaf certificate does not parse",
				Cause:  err,
			}
		}
		return leaf, nil
	}
	if v.Leaf == nil {
		return nil, &errs.Detail{Err: ErrKeyBindingUnavailable, Detail: "no verified leaf certificate"}
	}
	return v.Leaf, nil
}
