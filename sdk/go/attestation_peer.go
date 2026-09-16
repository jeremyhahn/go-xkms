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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/attestation/peer"

// Attested-peer verification (go-xkms#273): does the other end of a
// connection hold a TPM quote that proves it is a currently attested system,
// not merely a certificate a trusted CA issued? The canonical implementation
// is pkg/attestation/peer; these aliases are the SDK surface quicbaas
// re-exports and go-trusted-platform reaches. Identifiers carry a Peer
// prefix because Evidence, Verifier and VerifyOptions already name the x509
// key-attestation surface in this flat namespace.

// PeerAttestationVerifier renders a PeerVerdict on a peer's evidence under a
// PeerPolicy. Verify returns an error only for an unusable policy or a done
// context; everything about the evidence is answered in the verdict.
type PeerAttestationVerifier = peer.Verifier

// PeerVerifierOption configures a PeerAttestationVerifier.
type PeerVerifierOption = peer.Option

// PeerEvidence is the quote, signature, nonce, reported PCR values,
// attestation key certificate and collection time a peer's evidence
// consists of.
type PeerEvidence = peer.Evidence

// PeerPolicy is what the verifier demands: trust anchors, the Restricted
// requirement, the PCR baseline, required registers (PCR 10 for measured
// userspace), a maximum evidence age and the TLS channel binding.
type PeerPolicy = peer.Policy

// PeerVerdict is the per-check result with a typed failure class.
type PeerVerdict = peer.Verdict

// PeerChecks is the per-check outcome inside a PeerVerdict.
type PeerChecks = peer.Checks

// PeerClockInfo is the TPMS_CLOCK_INFO the quote carried.
type PeerClockInfo = peer.ClockInfo

// PeerFailureClass separates evidence that was present and wrong
// (cryptographic) from a check that could not run (absence).
type PeerFailureClass = peer.FailureClass

const (
	// PeerFailureNone means the verdict passed.
	PeerFailureNone = peer.FailureNone
	// PeerFailureAbsence means a check could not run; deny, do not quarantine.
	PeerFailureAbsence = peer.FailureAbsence
	// PeerFailureCryptographic means a check ran and the evidence was wrong.
	PeerFailureCryptographic = peer.FailureCryptographic

	// PeerChannelBindingExporterLabel is the TLS exporter label both ends
	// derive the channel binding under.
	PeerChannelBindingExporterLabel = peer.ExporterLabel
	// PeerChannelBindingLength is the exporter output length in bytes.
	PeerChannelBindingLength = peer.ChannelBindingLength
)

// PeerPolicyError reports a PeerPolicy that cannot be evaluated as written.
type PeerPolicyError = peer.PolicyError

// PeerContextError reports a verification aborted by its context.
type PeerContextError = peer.ContextError

// PeerChannelBindingError reports a TLS connection that yields no binding.
type PeerChannelBindingError = peer.ChannelBindingError

// PeerFailureClassError reports a failure-class name that is not one of
// "none", "absence" or "cryptographic". It is the error PeerFailureClass's
// UnmarshalText returns, so a consumer that persists a verdict's class as text
// (JSON, a database column) parses it back through the alias type's own
// method and can errors.As the rejection to this type.
type PeerFailureClassError = peer.FailureClassError

// NewPeerAttestationVerifier constructs a PeerAttestationVerifier.
var NewPeerAttestationVerifier = peer.NewVerifier

// WithPeerVerifierClock pins the verifier's clock.
var WithPeerVerifierClock = peer.WithClock

// PeerChannelBinding derives the channel binding for a TLS connection from
// its exported keying material.
var PeerChannelBinding = peer.ChannelBinding

// PeerQualifyingData computes the qualifying data the quoting side hands to
// TPM2.Quote and the verifier expects: SHA-256(nonce || channelBinding), or
// the bare nonce when there is no binding.
var PeerQualifyingData = peer.QualifyingData

// Device-trust primitives. The same package owns two more pieces a consumer
// needs before it can gate on a verdict: recognising the peer's device
// credential, and turning the TLS connection a request arrived on into
// evidence bound to that connection. Both are library calls with no transport
// shape; the middleware that calls them on each transport stays with the
// consumer (go-qrdb#278).

// PeerDevIDPolicy is what a TCG device credential is checked against: the
// anchors it must chain to, any intermediates, and the clock (zero means now).
type PeerDevIDPolicy = peer.DevIDPolicy

// PeerTLSEvidence pairs a peer's evidence with the channel binding of the TLS
// connection it arrived on, so the two cannot drift apart.
type PeerTLSEvidence = peer.TLSEvidence

// PeerDevIDError reports a certificate that is not a usable TCG device
// credential, naming the credential class and the check it failed.
type PeerDevIDError = peer.DevIDError

// PeerDevIDPolicyError reports a PeerDevIDPolicy that cannot be evaluated,
// such as one with no trust anchors. It is kept apart from PeerDevIDError so
// a gate can tell a misconfigured verifier from a rejected device.
type PeerDevIDPolicyError = peer.DevIDPolicyError

// PeerVerifyIDevID reports whether a certificate is a usable TCG device
// identity credential (IDevID/LDevID): in its validity window, chained to the
// policy's anchors, carrying the digitalSignature key usage and not a CA,
// asserting tcg-cap-verifiedTPMFixed but not tcg-cap-verifiedTPMRestricted,
// and naming a TPM 2.0 through the two TCG DevID §8.1 subjectAltName
// otherNames. It returns *PeerDevIDError, *PeerDevIDPolicyError or
// *PeerContextError.
var PeerVerifyIDevID = peer.VerifyIDevID

// PeerVerifyIAK is PeerVerifyIDevID for the attestation class: an IAK/LAK
// MUST assert tcg-cap-verifiedTPMRestricted and MUST NOT assert
// tcg-cap-verifiedTPMFixed. This is the credential whose certificate
// PeerEvidence carries as AKCertificatePEM.
var PeerVerifyIAK = peer.VerifyIAK

// PeerIsIDevID reports whether a certificate has the shape of a device
// identity credential. It builds no chain and consults no clock: it is for
// routing a credential to the right handler, never for authorization, which
// is PeerVerifyIDevID.
var PeerIsIDevID = peer.IsIDevID

// PeerIsIAK reports whether a certificate has the shape of an attestation key
// credential. Like PeerIsIDevID it is a predicate, not an authorization
// decision.
var PeerIsIAK = peer.IsIAK

// PeerEvidenceFromTLS pairs reported evidence with the channel binding of the
// TLS connection it arrived on, returning a PeerTLSEvidence whose BindPolicy
// installs that binding in a PeerPolicy. It fails closed with
// *PeerChannelBindingError on a connection that cannot export keying
// material; there is no unbound fall-back.
var PeerEvidenceFromTLS = peer.EvidenceFromTLS

// PeerQualifyingDataFromTLS is the quoting side of the same pair: it derives
// the connection's binding and returns the qualifying data to hand to
// TPM2.Quote, so the quoting side cannot perform half of the binding.
var PeerQualifyingDataFromTLS = peer.QualifyingDataFromTLS
