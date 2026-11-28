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
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// AttestationVerdictHandlers serves the continuous attestation verdict
// verbs. Every verb is bound to the caller's tenant by the servicer; the
// device is named in the device query parameter or the request body.
type AttestationVerdictHandlers struct {
	servicer transport.AttestationVerdictServicer
}

// NewAttestationVerdictHandlers returns the verdict handlers over servicer.
func NewAttestationVerdictHandlers(servicer transport.AttestationVerdictServicer) *AttestationVerdictHandlers {
	return &AttestationVerdictHandlers{servicer: servicer}
}

func respondVerdict[R any](w http.ResponseWriter, resp R, err error, status int) {
	respondClassified(w, resp, err, status, apierrors.VerdictClassOf)
}

func deviceQuery(r *http.Request) *transport.AttestationVerdictRequest {
	return &transport.AttestationVerdictRequest{DeviceID: r.URL.Query().Get("device")}
}

// pageQuery reads the optional limit and offset query parameters of the
// list route; an absent one is zero. A value that is not a 32-bit integer
// is refused.
func pageQuery(r *http.Request) (limit, offset int32, err error) {
	parse := func(name string) (int32, error) {
		raw := r.URL.Query().Get(name)
		if raw == "" {
			return 0, nil
		}
		n, err := strconv.ParseInt(raw, 10, 32)
		return int32(n), err
	}
	if limit, err = parse("limit"); err != nil {
		return 0, 0, err
	}
	offset, err = parse("offset")
	return limit, offset, err
}

// ListHandler serves GET /attestation/verdicts?device=&limit=&offset=, one
// page of the device's history.
func (h *AttestationVerdictHandlers) ListHandler(w http.ResponseWriter, r *http.Request) {
	req := deviceQuery(r)
	var err error
	if req.Limit, req.Offset, err = pageQuery(r); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	resp, err := h.servicer.ListAttestationVerdicts(r.Context(), req)
	respondVerdict(w, resp, err, http.StatusOK)
}

// LatestHandler serves GET /attestation/verdicts/latest?device=.
func (h *AttestationVerdictHandlers) LatestHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.GetLatestAttestationVerdict(r.Context(), deviceQuery(r))
	respondVerdict(w, resp, err, http.StatusOK)
}

// ReattestHandler serves POST /attestation/verdicts with a body
// {"device_id": ...}.
func (h *AttestationVerdictHandlers) ReattestHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.AttestationVerdictRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	resp, err := h.servicer.ReattestDevice(r.Context(), &req)
	respondVerdict(w, resp, err, http.StatusOK)
}
