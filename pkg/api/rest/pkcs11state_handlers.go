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

package rest

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// pkcs11StateServicer is the slice of the XKMSService the PKCS#11 remote-state
// handlers need. Defining it locally keeps the handlers testable and avoids a
// hard dependency on the concrete service type.
type pkcs11StateServicer interface {
	PKCS11StatePut(ctx context.Context, req *transport.PKCS11StatePutRequest) (*transport.PKCS11StatePutResponse, error)
	PKCS11StatePutIfAbsent(ctx context.Context, req *transport.PKCS11StatePutIfAbsentRequest) (*transport.PKCS11StatePutIfAbsentResponse, error)
	PKCS11StateCAS(ctx context.Context, req *transport.PKCS11StateCASRequest) (*transport.PKCS11StateCASResponse, error)
	PKCS11StateCAD(ctx context.Context, req *transport.PKCS11StateCADRequest) (*transport.PKCS11StateCADResponse, error)
	PKCS11StateGet(ctx context.Context, req *transport.PKCS11StateGetRequest) (*transport.PKCS11StateGetResponse, error)
	PKCS11StateDelete(ctx context.Context, req *transport.PKCS11StateDeleteRequest) (*transport.PKCS11StateDeleteResponse, error)
	PKCS11StateList(ctx context.Context, req *transport.PKCS11StateListRequest) (*transport.PKCS11StateListResponse, error)
}

// PKCS11StateHandlers serves the remote-mode PKCS#11 module's persistence over
// REST. Records are opaque; the handlers only move bytes between the JSON body
// and the servicer. Per-route authorization is applied by the router
// (RequirePermission on the keys resource).
type PKCS11StateHandlers struct {
	servicer pkcs11StateServicer
}

// NewPKCS11StateHandlers builds the handlers over a servicer.
func NewPKCS11StateHandlers(servicer pkcs11StateServicer) *PKCS11StateHandlers {
	return &PKCS11StateHandlers{servicer: servicer}
}

func (h *PKCS11StateHandlers) ready(w http.ResponseWriter) bool {
	if h.servicer == nil {
		pkcs11StateWriteError(w, "pkcs11 state service not available", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (h *PKCS11StateHandlers) decode(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		pkcs11StateWriteError(w, "Invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func (h *PKCS11StateHandlers) respond(w http.ResponseWriter, resp interface{}, err error) {
	if err != nil {
		pkcs11StateWriteError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// pkcs11StateWriteError writes a JSON error body, mirroring the password
// handlers' error shape ({"error": message}).
func pkcs11StateWriteError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// PutHandler stores a record.
func (h *PKCS11StateHandlers) PutHandler(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	var req transport.PKCS11StatePutRequest
	if !h.decode(w, r, &req) {
		return
	}
	resp, err := h.servicer.PKCS11StatePut(r.Context(), &req)
	h.respond(w, resp, err)
}

// PutIfAbsentHandler atomically stores a record only if the key is absent.
func (h *PKCS11StateHandlers) PutIfAbsentHandler(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	var req transport.PKCS11StatePutIfAbsentRequest
	if !h.decode(w, r, &req) {
		return
	}
	resp, err := h.servicer.PKCS11StatePutIfAbsent(r.Context(), &req)
	h.respond(w, resp, err)
}

// CASHandler atomically stores New only if the current value equals Expected.
// ExpectAbsent is a legacy field now redefined as "PutIfAbsent with New as the
// value" rather than "require absent" (#186); see
// transport.PKCS11StateCASRequest's doc comment for the full contract.
func (h *PKCS11StateHandlers) CASHandler(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	var req transport.PKCS11StateCASRequest
	if !h.decode(w, r, &req) {
		return
	}
	resp, err := h.servicer.PKCS11StateCAS(r.Context(), &req)
	h.respond(w, resp, err)
}

// CADHandler atomically removes a record only if its current value equals
// Expected; an absent key or a different value answers deleted=false.
func (h *PKCS11StateHandlers) CADHandler(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	var req transport.PKCS11StateCADRequest
	if !h.decode(w, r, &req) {
		return
	}
	resp, err := h.servicer.PKCS11StateCAD(r.Context(), &req)
	h.respond(w, resp, err)
}

// GetHandler retrieves a record.
func (h *PKCS11StateHandlers) GetHandler(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	var req transport.PKCS11StateGetRequest
	if !h.decode(w, r, &req) {
		return
	}
	resp, err := h.servicer.PKCS11StateGet(r.Context(), &req)
	h.respond(w, resp, err)
}

// DeleteHandler removes a record.
func (h *PKCS11StateHandlers) DeleteHandler(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	var req transport.PKCS11StateDeleteRequest
	if !h.decode(w, r, &req) {
		return
	}
	resp, err := h.servicer.PKCS11StateDelete(r.Context(), &req)
	h.respond(w, resp, err)
}

// ListHandler lists namespace-relative keys under a prefix.
func (h *PKCS11StateHandlers) ListHandler(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	var req transport.PKCS11StateListRequest
	if !h.decode(w, r, &req) {
		return
	}
	resp, err := h.servicer.PKCS11StateList(r.Context(), &req)
	h.respond(w, resp, err)
}
