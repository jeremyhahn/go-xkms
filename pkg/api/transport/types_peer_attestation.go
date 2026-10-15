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

package transport

import (
	"context"
	"time"
)

// PeerAttestationServicer is the server side of the attested-caller gate
// (pkg/attestation/peergate): a caller asks for a challenge and answers it
// with a TPM quote, and the gate admits its later requests on that evidence.
//
// Both methods identify the caller by the verified client certificate of the
// connection carrying the request, read from the context (auth.WithTLSState),
// and bind the evidence to that connection. They are server verbs only:
// XKMSServicer does not embed this interface and no client transport carries
// it, because a caller answers over the connection it is attesting.
type PeerAttestationServicer interface {
	// PeerAttestationChallenge issues a fresh nonce to the caller. A caller
	// holds one outstanding challenge; a new one replaces the last.
	PeerAttestationChallenge(ctx context.Context) (*PeerAttestationChallenge, error)

	// SubmitPeerAttestation stores the caller's quote over its outstanding
	// challenge. The quote is judged by the gate on every gated request, not
	// here, so a wrong quote is stored and refused there.
	SubmitPeerAttestation(ctx context.Context, req *SubmitPeerAttestationRequest) error
}

// PeerAttestationChallenge is a nonce issued to one caller.
type PeerAttestationChallenge struct {
	// Nonce is the value the caller's TPM quotes over, combined with the
	// connection's TLS exporter value (peer.QualifyingDataFromTLS).
	Nonce []byte `json:"nonce"`

	// ExpiresAt is the last instant a submission answering it is accepted.
	ExpiresAt time.Time `json:"expires_at"`
}

// SubmitPeerAttestationRequest is a caller's TPM quote answering its
// outstanding challenge.
type SubmitPeerAttestationRequest struct {
	// Quote is the TPMS_ATTEST the attestation key signed.
	Quote []byte `json:"quote"`

	// Signature is the attestation key's signature over Quote.
	Signature []byte `json:"signature"`

	// Nonce is the challenge nonce being answered.
	Nonce []byte `json:"nonce"`

	// PCRs are the quoted PCR values, by index.
	PCRs map[int][]byte `json:"pcrs"`

	// AKCertificatePEM is the attestation key's certificate chain, leaf
	// first, in PEM.
	AKCertificatePEM []byte `json:"ak_certificate_pem"`
}
