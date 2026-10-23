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
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The crypto utility handlers decode the transport request, take the key ID
// from the path and the tenant from the caller, and hand the request to the
// service. A tenant in the body is ignored.

// decodeCryptoUtility decodes the JSON body into req. It writes the error
// response and reports false when the body is malformed or the service is
// not initialized.
func (h *HandlerContext) decodeCryptoUtility(w http.ResponseWriter, r *http.Request, req any) bool {
	if err := decodeOptionalJSON(r, req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return false
	}
	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return false
	}
	return true
}

// pathKeyID returns the key ID route parameter, writing ErrMissingKeyID when
// it is empty.
func pathKeyID(w http.ResponseWriter, r *http.Request) (string, bool) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return "", false
	}
	return keyID, true
}

// RewrapHandler handles POST /api/v1/keys/rewrap.
func (h *HandlerContext) RewrapHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.RewrapRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	if req.Source == nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	req.Source.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.Rewrap(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// EncryptBatchHandler handles POST /api/v1/keys/{id}/encrypt-batch.
func (h *HandlerContext) EncryptBatchHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return
	}
	var req transport.EncryptBatchRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.EncryptBatch(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// DecryptBatchHandler handles POST /api/v1/keys/{id}/decrypt-batch.
func (h *HandlerContext) DecryptBatchHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return
	}
	var req transport.DecryptBatchRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.DecryptBatch(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// dataKeyRequest decodes a data key request for the key in the path.
func (h *HandlerContext) dataKeyRequest(w http.ResponseWriter, r *http.Request) (*transport.GenerateDataKeyRequest, bool) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return nil, false
	}
	var req transport.GenerateDataKeyRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return nil, false
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	return &req, true
}

// GenerateDataKeyHandler handles POST /api/v1/keys/{id}/data-key.
func (h *HandlerContext) GenerateDataKeyHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := h.dataKeyRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.GenerateDataKey(r.Context(), req)
	respondKeyOp(w, resp, err)
}

// GenerateWrappedDataKeyHandler handles POST
// /api/v1/keys/{id}/wrapped-data-key.
func (h *HandlerContext) GenerateWrappedDataKeyHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := h.dataKeyRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.GenerateWrappedDataKey(r.Context(), req)
	respondKeyOp(w, resp, err)
}

// GenerateHMACHandler handles POST /api/v1/keys/{id}/hmac.
func (h *HandlerContext) GenerateHMACHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return
	}
	var req transport.GenerateHMACRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.GenerateHMAC(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// VerifyHMACHandler handles POST /api/v1/keys/{id}/hmac/verify.
func (h *HandlerContext) VerifyHMACHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return
	}
	var req transport.VerifyHMACRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.VerifyHMAC(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// GenerateRandomHandler handles POST /api/v1/random.
func (h *HandlerContext) GenerateRandomHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.GenerateRandomRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	resp, err := h.xkmsService.GenerateRandom(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// HashHandler handles POST /api/v1/hash.
func (h *HandlerContext) HashHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.HashRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	resp, err := h.xkmsService.Hash(r.Context(), &req)
	respondKeyOp(w, resp, err)
}
