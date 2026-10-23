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
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The key management handlers take the key ID from the path, the backend
// from the query or the body, and the tenant from the caller. A tenant in
// the body is ignored. Reads take no body.

// keyManagementReady writes the not-initialized error and reports false when
// the service is missing.
func (h *HandlerContext) keyManagementReady(w http.ResponseWriter) bool {
	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return false
	}
	return true
}

// keyManagementRequest builds the request for a bodiless route on the key in
// the path.
func (h *HandlerContext) keyManagementRequest(w http.ResponseWriter, r *http.Request) (*transport.KeyManagementRequest, bool) {
	keyID, ok := pathKeyID(w, r)
	if !ok || !h.keyManagementReady(w) {
		return nil, false
	}
	return &transport.KeyManagementRequest{
		Backend:  backendFromRequest(r, ""),
		KeyID:    keyID,
		TenantID: callerTenantID(r.Context()),
	}, true
}

// backendRequest builds the request for a bodiless backend route.
func (h *HandlerContext) backendRequest(w http.ResponseWriter, r *http.Request) (*transport.BackendRequest, bool) {
	if !h.keyManagementReady(w) {
		return nil, false
	}
	return &transport.BackendRequest{
		Backend:  backendFromRequest(r, ""),
		TenantID: callerTenantID(r.Context()),
	}, true
}

// GetPublicKeyHandler handles GET /api/v1/keys/{id}/public-key.
func (h *HandlerContext) GetPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok || !h.keyManagementReady(w) {
		return
	}
	req := transport.GetPublicKeyRequest{
		Backend:  backendFromRequest(r, ""),
		KeyID:    keyID,
		TenantID: callerTenantID(r.Context()),
	}
	if v := r.URL.Query().Get("version"); v != "" {
		version, err := strconv.ParseUint(v, 10, 64)
		if err != nil || version == 0 {
			writeError(w, ErrInvalidKeyVersion, http.StatusBadRequest)
			return
		}
		req.Version = version
	}
	resp, err := h.xkmsService.GetPublicKey(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// RevokeKeyHandler handles POST /api/v1/keys/{id}/revoke.
func (h *HandlerContext) RevokeKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return
	}
	var req transport.RevokeKeyRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.RevokeKey(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// UpdateKeyStatusHandler handles POST /api/v1/keys/{id}/status.
func (h *HandlerContext) UpdateKeyStatusHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return
	}
	var req transport.UpdateKeyStatusRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.UpdateKeyStatus(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// GetKeyMetadataHandler handles GET /api/v1/keys/{id}/metadata.
func (h *HandlerContext) GetKeyMetadataHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := h.keyManagementRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.GetKeyMetadata(r.Context(), req)
	respondKeyOp(w, resp, err)
}

// UpdateKeyMetadataHandler handles PUT /api/v1/keys/{id}/metadata.
func (h *HandlerContext) UpdateKeyMetadataHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return
	}
	var req transport.UpdateKeyMetadataRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.UpdateKeyMetadata(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// SetKeyPolicyHandler handles PUT /api/v1/keys/{id}/policy.
func (h *HandlerContext) SetKeyPolicyHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return
	}
	var req transport.SetKeyPolicyRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.SetKeyPolicy(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// GetKeyPolicyHandler handles GET /api/v1/keys/{id}/policy.
func (h *HandlerContext) GetKeyPolicyHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := h.keyManagementRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.GetKeyPolicy(r.Context(), req)
	respondKeyOp(w, resp, err)
}

// DeleteKeyPolicyHandler handles DELETE /api/v1/keys/{id}/policy.
func (h *HandlerContext) DeleteKeyPolicyHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := h.keyManagementRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.DeleteKeyPolicy(r.Context(), req)
	respondKeyOp(w, resp, err)
}

// SetKeyRotationPolicyHandler handles PUT /api/v1/keys/{id}/rotation-policy.
func (h *HandlerContext) SetKeyRotationPolicyHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return
	}
	var req transport.SetKeyRotationPolicyRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.SetKeyRotationPolicy(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// GetKeyRotationPolicyHandler handles GET /api/v1/keys/{id}/rotation-policy.
func (h *HandlerContext) GetKeyRotationPolicyHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := h.keyManagementRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.GetKeyRotationPolicy(r.Context(), req)
	respondKeyOp(w, resp, err)
}

// DeleteKeyRotationPolicyHandler handles DELETE
// /api/v1/keys/{id}/rotation-policy.
func (h *HandlerContext) DeleteKeyRotationPolicyHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := h.keyManagementRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.DeleteKeyRotationPolicy(r.Context(), req)
	respondKeyOp(w, resp, err)
}

// GetSupportedAlgorithmsHandler handles GET /api/v1/backend/algorithms.
func (h *HandlerContext) GetSupportedAlgorithmsHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := h.backendRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.GetSupportedAlgorithms(r.Context(), req)
	respondKeyOp(w, resp, err)
}

// BackendStatusHandler handles GET /api/v1/backend/status.
func (h *HandlerContext) BackendStatusHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := h.backendRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.BackendStatus(r.Context(), req)
	respondKeyOp(w, resp, err)
}

// BackendTestHandler handles POST /api/v1/backend/test.
func (h *HandlerContext) BackendTestHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.BackendRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.BackendTest(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// SetKeySafetyHandler handles PUT /api/v1/keys/{id}/safety.
func (h *HandlerContext) SetKeySafetyHandler(w http.ResponseWriter, r *http.Request) {
	keyID, ok := pathKeyID(w, r)
	if !ok {
		return
	}
	var req transport.SetKeySafetyRequest
	if !h.decodeCryptoUtility(w, r, &req) {
		return
	}
	req.KeyID = keyID
	req.Backend = backendFromRequest(r, req.Backend)
	req.TenantID = callerTenantID(r.Context())
	resp, err := h.xkmsService.SetKeySafety(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// ClearKeySafetyHandler handles DELETE /api/v1/keys/{id}/safety.
func (h *HandlerContext) ClearKeySafetyHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := h.keyManagementRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.ClearKeySafety(r.Context(), req)
	respondKeyOp(w, resp, err)
}

// SafetyCheckHandler handles GET /api/v1/safety/check.
func (h *HandlerContext) SafetyCheckHandler(w http.ResponseWriter, r *http.Request) {
	if !h.keyManagementReady(w) {
		return
	}
	req := transport.SafetyCheckRequest{TenantID: callerTenantID(r.Context())}
	resp, err := h.xkmsService.SafetyCheck(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// SafetyReportHandler handles GET /api/v1/safety/report.
func (h *HandlerContext) SafetyReportHandler(w http.ResponseWriter, r *http.Request) {
	if !h.keyManagementReady(w) {
		return
	}
	req := transport.SafetyReportRequest{
		Format:   r.URL.Query().Get("format"),
		TenantID: callerTenantID(r.Context()),
	}
	resp, err := h.xkmsService.SafetyReport(r.Context(), &req)
	respondKeyOp(w, resp, err)
}
