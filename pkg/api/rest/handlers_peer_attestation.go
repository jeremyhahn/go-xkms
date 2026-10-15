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

package rest

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// PeerAttestationHandlers serves the attested-caller verbs
// (pkg/attestation/peergate) over REST: a caller asks for a challenge at
// POST /api/v1/peer-attestation/challenge and answers it with a TPM quote at
// POST /api/v1/peer-attestation/evidence.
//
// Both identify the caller by the verified client certificate of the
// request's connection and bind the evidence to it, so they answer only over
// mutual TLS. Request and response bodies are the pkg/api/transport types.
type PeerAttestationHandlers struct {
	servicer transport.PeerAttestationServicer
}

// NewPeerAttestationHandlers returns the attested-caller handlers over
// servicer.
func NewPeerAttestationHandlers(servicer transport.PeerAttestationServicer) *PeerAttestationHandlers {
	return &PeerAttestationHandlers{servicer: servicer}
}

// ChallengeHandler handles POST /api/v1/peer-attestation/challenge.
func (h *PeerAttestationHandlers) ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.PeerAttestationChallenge(peerTLSContext(r))
	respondClassified(w, resp, err, http.StatusOK, apierrors.PeerAttestationClassOf)
}

// EvidenceHandler handles POST /api/v1/peer-attestation/evidence.
func (h *PeerAttestationHandlers) EvidenceHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.SubmitPeerAttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if err := h.servicer.SubmitPeerAttestation(peerTLSContext(r), &req); err != nil {
		writeClassifiedError(w, err, apierrors.PeerAttestationClassOf)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// peerTLSContext returns the request's context carrying the connection's TLS
// state, the carrier the service reads the caller's certificate from. A
// context that already carries one keeps it.
func peerTLSContext(r *http.Request) context.Context {
	ctx := r.Context()
	if auth.TLSStateFromContext(ctx) == nil && r.TLS != nil {
		ctx = auth.WithTLSState(ctx, r.TLS)
	}
	return ctx
}
