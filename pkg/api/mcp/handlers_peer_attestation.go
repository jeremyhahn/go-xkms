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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The peer.attestation.* handlers are the MCP server side of the
// attested-caller verbs (pkg/attestation/peergate). Both delegate to
// XKMSService, which identifies the caller by the verified client
// certificate on the TLS state go-qrdb's MCP transport puts on the context;
// they gate on the peer_attestation:* pairs in server.go's rpcMethods table.

// handlePeerAttestationChallenge handles peer.attestation.challenge. It
// takes no parameters.
func (s *Server) handlePeerAttestationChallenge(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	const op = "peer attestation challenge"
	if s.xkmsService == nil {
		return nil, mapPeerAttestationError(xkms.ErrNotConfigured, op)
	}
	challenge, err := s.xkmsService.PeerAttestationChallenge(ctx)
	if err != nil {
		return nil, mapPeerAttestationError(err, op)
	}
	return challenge, nil
}

// handlePeerAttestationSubmit handles peer.attestation.submit, whose
// parameters are a transport.SubmitPeerAttestationRequest. It answers with an
// empty object.
func (s *Server) handlePeerAttestationSubmit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return servicerCall(s, ctx, req, "peer attestation submit", mapPeerAttestationError,
		func(ctx context.Context, params *transport.SubmitPeerAttestationRequest) (struct{}, error) {
			return struct{}{}, s.xkmsService.SubmitPeerAttestation(ctx, params)
		})
}
