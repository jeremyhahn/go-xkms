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
	"bytes"
	"crypto/tls"
)

// TLSEvidence is a peer's evidence together with the channel binding of the
// TLS connection it arrived on.
//
// The binding is not a field of Evidence: it is not something the peer
// reports, it is what the verifier observes about its own connection, and it
// enters verification through Policy.ChannelBinding. Keeping the two halves in
// one value is what stops the pair from drifting — evidence collected on one
// connection verified under another connection's binding is a bug that fails
// closed but wastes the quote, and evidence bound to a connection verified
// under a policy whose binding was left nil is a bug that silently accepts a
// relayed quote.
type TLSEvidence struct {
	// Evidence is what the verifier consumes. It copies the reported values,
	// so it does not alias the caller's buffers.
	Evidence Evidence

	// ChannelBinding is ChannelBindingLength bytes of exported keying
	// material for the connection, the value BindPolicy installs in a Policy.
	ChannelBinding []byte
}

// EvidenceFromTLS pairs the evidence a peer reported with the channel binding
// of the TLS connection it arrived on, so a caller can hand both to Verify
// without deriving the binding itself.
//
// It fails closed on the connection: a nil state, an incomplete handshake or a
// connection that cannot export keying material yields a
// *ChannelBindingError and no evidence. A caller that requires binding must
// deny on that error and never fall back to an unbound verification.
//
// It says nothing about the evidence. Missing or wrong quote fields are the
// verdict's business (Verify answers them as absence or cryptographic
// failures), not this function's, so a middleware that calls it gets an error
// only when its own connection is unusable. CollectedAt is carried through
// unchanged: the collector stamps receipt time, and this function is not the
// collector.
//
// This is deliberately the whole transport-facing surface of the feature. The
// request-time middleware that calls it on every transport, caches, and
// decides what a failed verdict does to a request belongs to the consumer
// (go-qrdb#278), and nothing here is HTTP- or gRPC-shaped.
func EvidenceFromTLS(state *tls.ConnectionState, reported Evidence) (TLSEvidence, error) {
	binding, err := ChannelBinding(state)
	if err != nil {
		return TLSEvidence{}, err
	}
	return TLSEvidence{
		Evidence: Evidence{
			Quote:            bytes.Clone(reported.Quote),
			Signature:        bytes.Clone(reported.Signature),
			Nonce:            bytes.Clone(reported.Nonce),
			PCRs:             copyPCRs(reported.PCRs),
			AKCertificatePEM: bytes.Clone(reported.AKCertificatePEM),
			CollectedAt:      reported.CollectedAt,
		},
		ChannelBinding: binding,
	}, nil
}

// BindPolicy returns policy with ChannelBinding set to this connection's
// binding, leaving every other field as the caller provisioned it. The
// returned policy demands that the quote's qualifying data is
// QualifyingData(nonce, binding): a quote carrying the bare nonce, or one
// bound to another connection, fails the ChannelBinding check.
//
// The policy is taken and returned by value, so the caller's provisioned
// policy is not modified and one policy value can bind many connections.
func (e TLSEvidence) BindPolicy(policy Policy) Policy {
	policy.ChannelBinding = bytes.Clone(e.ChannelBinding)
	return policy
}

// QualifyingDataFromTLS is the quoting side of the same pair: it derives the
// connection's channel binding and returns the qualifying data to hand to
// TPM2.Quote, which passes it to the TPM verbatim as TPM2B_DATA.
//
// It exists so that the quoting side cannot perform half of the binding. The
// two-step form (ChannelBinding then QualifyingData) leaves a path where the
// binding is derived, an error ignored, and the bare nonce quoted anyway —
// which verifies fine against an unbound policy and is exactly the replay the
// binding prevents. Here a connection that yields no binding yields no
// qualifying data.
//
// The nonce is not inspected: it is the verifier's value, and a quote over the
// wrong nonce is answered by the verifier's Nonce check.
func QualifyingDataFromTLS(state *tls.ConnectionState, nonce []byte) ([]byte, error) {
	binding, err := ChannelBinding(state)
	if err != nil {
		return nil, err
	}
	return QualifyingData(nonce, binding), nil
}
