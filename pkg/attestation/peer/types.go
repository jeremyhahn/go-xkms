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

package peer

import (
	"crypto/x509"
	"time"
)

// Evidence is what the peer produced and what the collector recorded about
// it. Nothing in it is trusted until Verify proves it.
type Evidence struct {
	// Quote is the marshaled TPMS_ATTEST the TPM produced for TPM2_Quote.
	Quote []byte

	// Signature is the attestation key's signature over Quote, in the form
	// TPM2.Quote returns it: the raw RSA signature (RSASSA or RSA-PSS), or
	// an ECDSA signature as ASN.1 DER. A raw r||s ECDSA signature is also
	// accepted.
	Signature []byte

	// Nonce is the value the verifier issued for this challenge. It must
	// appear in the quote's qualifying data, alone or bound to the channel
	// per Policy.ChannelBinding.
	Nonce []byte

	// PCRs maps PCR index to the value the peer read for it. The index set
	// must equal the quote's PCR selection; the values are proven only when
	// they hash to the digest the TPM signed.
	PCRs map[int][]byte

	// AKCertificatePEM is the peer's attestation key certificate, PEM
	// encoded. Further CERTIFICATE blocks after the first are treated as
	// intermediates. A bare public key is deliberately not accepted: without
	// the certificate the Restricted attribute cannot be checked, and TCG
	// DevID v1 r12 §8.2 makes that check a MUST.
	AKCertificatePEM []byte

	// CollectedAt is when the collector received this evidence. Freshness is
	// judged against it when Policy.MaxEvidenceAge is set, because the TPM's
	// own clock (TPMS_CLOCK_INFO) counts milliseconds of TPM up-time and has
	// no relation to wall-clock time without a per-TPM reference.
	CollectedAt time.Time
}

// Policy is what the verifier already knows and demands. It is provisioned,
// never learned from the peer.
type Policy struct {
	// Anchors are the roots the attestation key certificate must chain to.
	// A nil pool cannot anchor anything and fails the certificate check as
	// an absence.
	Anchors *x509.CertPool

	// Intermediates are additional issuing certificates that may complete
	// the chain. Intermediates carried in Evidence.AKCertificatePEM are
	// added to these.
	Intermediates *x509.CertPool

	// AllowUnrestrictedAK disables the tcg-cap-verifiedTPMRestricted
	// requirement on the attestation key certificate.
	//
	// The zero value requires it, as TCG DevID v1 r12 §8.2 demands: only a
	// Restricted key is prevented by the TPM from signing arbitrary external
	// data, so a certificate that does not attest that property does not
	// prove the quote came from a TPM. There is no good reason to set this
	// outside a test.
	AllowUnrestrictedAK bool

	// Baseline maps PCR index to the value the policy accepts. The proven
	// PCR set must equal this set exactly, and every value must match. An
	// empty baseline fails the baseline check as an absence: nothing can be
	// compared, so nothing passes.
	Baseline map[int][]byte

	// RequiredPCRs lists registers the quote must cover, whatever the
	// baseline says. A policy that must detect a swapped userspace daemon
	// lists PCR 10 here so a quote over the firmware registers alone cannot
	// pass. Each required PCR must appear in the quote's selection and in
	// Baseline.
	RequiredPCRs []int

	// MaxEvidenceAge bounds Evidence.CollectedAt: evidence older than this
	// at verification time fails the freshness check. Zero disables the
	// check, which is right for a live challenge whose nonce is fresh by
	// construction and wrong for cached evidence. Negative is invalid.
	MaxEvidenceAge time.Duration

	// ChannelBinding, when set, is the TLS exporter value of the connection
	// the evidence arrived on (see ChannelBinding). The quote's qualifying
	// data must then equal QualifyingData(Nonce, ChannelBinding); a quote
	// carrying the bare nonce, or a binding for another connection, fails.
	// Nil means the policy does not bind the quote to a channel.
	ChannelBinding []byte
}

// Checks reports each verification step individually. A field is true when
// the check ran and held. A check the policy does not demand (channel
// binding without Policy.ChannelBinding, freshness without MaxEvidenceAge,
// required PCRs with none listed) is recorded as holding, so Passed is the
// conjunction of all eight.
type Checks struct {
	// AKCertificate: the certificate chains to the anchors, is valid at
	// verification time, and carries tcg-cap-verifiedTPMRestricted.
	AKCertificate bool `json:"ak_certificate"`
	// Signature: Signature verifies over Quote under the certified key.
	Signature bool `json:"signature"`
	// Nonce: the quote's qualifying data carries the verifier's nonce.
	Nonce bool `json:"nonce"`
	// ChannelBinding: the qualifying data is bound to this connection.
	ChannelBinding bool `json:"channel_binding"`
	// PCRDigest: the reported PCR values hash to the signed digest.
	PCRDigest bool `json:"pcr_digest"`
	// RequiredPCRs: every required register was quoted and has a baseline.
	RequiredPCRs bool `json:"required_pcrs"`
	// Baseline: the proven values equal the policy baseline.
	Baseline bool `json:"baseline"`
	// Freshness: the evidence is within MaxEvidenceAge.
	Freshness bool `json:"freshness"`
}

// ClockInfo is the TPMS_CLOCK_INFO the TPM stamped into the quote. Clock is
// milliseconds of TPM up-time, not wall-clock time; ResetCount and
// RestartCount let a consumer holding an earlier quote from the same TPM
// notice a reboot. It is reported for that purpose and is not itself a
// check.
type ClockInfo struct {
	Clock        uint64 `json:"clock"`
	ResetCount   uint32 `json:"reset_count"`
	RestartCount uint32 `json:"restart_count"`
	Safe         bool   `json:"safe"`
}

// Verdict is the answer. Passed is true only when every check holds; a
// negative verdict says which checks failed, which class the failure falls
// in, and why.
type Verdict struct {
	// Passed is the overall result.
	Passed bool `json:"passed"`

	// Checks is the per-check outcome.
	Checks Checks `json:"checks"`

	// Failure classifies a negative verdict. FailureNone when Passed.
	Failure FailureClass `json:"failure"`

	// Reason joins the failed checks' reasons, in check order. Empty when
	// Passed.
	Reason string `json:"reason,omitempty"`

	// PCRs are the reported values once proven: the certificate, signature,
	// nonce and PCR digest checks all hold, so a consumer can record them (a
	// trust-on-first-use baseline, say) knowing a Restricted key in a TPM
	// signed them for this challenge. They are reported whether or not the
	// baseline check then holds, which is what lets a consumer capture a
	// first baseline from proven values. Nil when the values were not proven.
	PCRs map[int][]byte `json:"pcrs,omitempty"`

	// Clock is the TPM clock information from the quote, when it parsed.
	Clock ClockInfo `json:"clock"`

	// FirmwareVersion is the TPM's firmware version from the quote, when it
	// parsed.
	FirmwareVersion uint64 `json:"firmware_version"`

	// VerifiedAt is the verifier's clock at verification time.
	VerifiedAt time.Time `json:"verified_at"`

	// EvidenceAge is VerifiedAt minus Evidence.CollectedAt, when CollectedAt
	// was supplied.
	EvidenceAge time.Duration `json:"evidence_age"`
}

// FailureClass says what kind of failure a negative verdict is. The
// distinction decides what a consumer may do about it: cryptographic
// failures are evidence of a peer in a bad state; absence failures are
// evidence of nothing at all.
type FailureClass uint8

const (
	// FailureNone means the verdict passed.
	FailureNone FailureClass = iota

	// FailureAbsence means a check could not run: a certificate, anchor,
	// baseline, timestamp or required register was missing, or the
	// evidence is stale. The peer is denied but nothing has been proven
	// about its state.
	FailureAbsence

	// FailureCryptographic means a check ran and the evidence was wrong: the
	// certificate does not chain or is not Restricted, the signature does
	// not verify, the nonce or channel binding does not match, the reported
	// values do not hash to the signed digest, or a proven value diverges
	// from the baseline. This is the class that may justify quarantine.
	FailureCryptographic
)

var failureClassNames = map[FailureClass]string{
	FailureNone:          "none",
	FailureAbsence:       "absence",
	FailureCryptographic: "cryptographic",
}

var failureClassValues = map[string]FailureClass{
	"none":          FailureNone,
	"absence":       FailureAbsence,
	"cryptographic": FailureCryptographic,
}

// String returns the class name: "none", "absence" or "cryptographic".
func (c FailureClass) String() string {
	if name, ok := failureClassNames[c]; ok {
		return name
	}
	return "unknown"
}

// MarshalText encodes the class by name so it survives JSON on a cached
// report unchanged.
func (c FailureClass) MarshalText() ([]byte, error) {
	name, ok := failureClassNames[c]
	if !ok {
		return nil, &FailureClassError{Text: c.String()}
	}
	return []byte(name), nil
}

// UnmarshalText decodes a class by name.
func (c *FailureClass) UnmarshalText(text []byte) error {
	value, ok := failureClassValues[string(text)]
	if !ok {
		return &FailureClassError{Text: string(text)}
	}
	*c = value
	return nil
}
