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

package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

var _ transport.PeerAttestationServicer = (*XKMSService)(nil)

// SetPeerEvidenceCollector wires the attested-caller gate's collector
// (peergate.Gate.Collector) the PeerAttestation methods delegate to. A
// server without a gate wires none, and both methods return ErrNotConfigured.
func (s *XKMSService) SetPeerEvidenceCollector(c *peergate.Collector) { s.peerEvidence.store(c) }

// PeerAttestationChallenge issues a fresh nonce to the caller identified by
// the verified client certificate on the context's TLS state.
//
// It returns ErrNotConfigured when no gate is wired, and the collector's
// *peergate.PeerCertificateError when the request carries no verified client
// certificate (a unix-socket caller has none).
func (s *XKMSService) PeerAttestationChallenge(ctx context.Context) (*transport.PeerAttestationChallenge, error) {
	collector := s.peerEvidence.load()
	if collector == nil {
		return nil, ErrNotConfigured
	}
	challenge, err := collector.Challenge(ctx, auth.TLSStateFromContext(ctx))
	if err != nil {
		return nil, err
	}
	return &transport.PeerAttestationChallenge{
		Nonce:     challenge.Nonce,
		ExpiresAt: challenge.ExpiresAt,
	}, nil
}

// SubmitPeerAttestation stores the caller's quote over its outstanding
// challenge, bound to the connection on the context's TLS state.
//
// It returns ErrNotConfigured when no gate is wired, ErrNilRequest for a nil
// request, and the collector's typed errors otherwise (peergate.Collector.Submit).
func (s *XKMSService) SubmitPeerAttestation(ctx context.Context, req *transport.SubmitPeerAttestationRequest) error {
	collector := s.peerEvidence.load()
	if collector == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return collector.Submit(ctx, auth.TLSStateFromContext(ctx), peer.Evidence{
		Quote:            req.Quote,
		Signature:        req.Signature,
		Nonce:            req.Nonce,
		PCRs:             req.PCRs,
		AKCertificatePEM: req.AKCertificatePEM,
	})
}
