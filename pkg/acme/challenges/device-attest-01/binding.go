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
// pkg/attestation declares that binding for the dice format -- bindLeafSPKI in
// the profile table -- and is the one implementation of it in this repository,
// shared with the TCG and SignCSR carriers. This file is how the ACME carrier
// reaches it: the verified leaf is carried from challenge to finalization, and
// BindCSRKey applies the gate.
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
	// is the attested key. Nil for a format that certifies no such leaf.
	Leaf *x509.Certificate

	// LeafDER is the same certificate as the device sent it.
	//
	// It is here because this record has to OUTLIVE THE REQUEST that produced
	// it: the challenge and the finalize are two requests, and any server that
	// is not a single process must write the record down in between. A parsed
	// certificate does not survive that trip and a re-encoded one is a
	// different document, so the bytes travel and BindCSRKey parses them back.
	LeafDER []byte
}

// bindsThroughTheCSR reports whether this format's key binding can only be
// completed against the CSR, which is to say later than the challenge.
func (v *VerifiedAttestation) bindsThroughTheCSR() bool {
	return v != nil && v.Format == FormatDICE
}

// BindCSRKey checks that the CSR asks the CA to certify the attested key.
//
// It is the last gate before issuance and it runs at finalization, which is
// where the CSR exists. Two things are established:
//
//  1. The requester holds the private half of the key in the CSR. A PKCS#10 is
//     self-signed by the key it names, so an invalid signature means binding it
//     to attested hardware would certify a key nobody demonstrated control of.
//  2. The CSR's SubjectPublicKeyInfo is the leaf's SubjectPublicKeyInfo, and
//     the leaf still carries the nonce this exchange issued. Both are applied
//     by pkg/attestation's gate rather than open-coded here, so the ACME
//     carrier and the SignCSR carrier cannot drift into two different ideas of
//     what binding means.
//
// Freshness is re-checked rather than assumed, and it is a nonce, never a
// clock: a DICE device has no clock, so nothing here reads a timestamp.
func (v *VerifiedAttestation) BindCSRKey(csr *x509.CertificateRequest) error {
	if v == nil {
		return ErrNoVerifiedAttestation
	}
	if csr == nil {
		return &errs.Detail{Err: ErrKeyBindingUnavailable, Detail: "no certificate request to bind to"}
	}
	if !v.bindsThroughTheCSR() {
		return &errs.Detail{
			Err:    ErrKeyBindingUnavailable,
			Detail: string(v.Format) + " does not bind the attested key through the CSR",
		}
	}
	leaf, err := v.verifiedLeaf()
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

	return attestation.VerifyInvariants(&attestation.Evidence{
		Format:            attestation.FormatDICE,
		Leaf:              leaf,
		SubjectSPKI:       csr.RawSubjectPublicKeyInfo,
		ExpectedChallenge: DICENonce(v.KeyAuthorization),
	})
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
