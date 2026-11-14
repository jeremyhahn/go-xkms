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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// OTAImageKeyRequest creates or rotates a board's OTA image-signing key. The
// board id is the {board} path parameter.
type OTAImageKeyRequest struct {
	Backend string `json:"backend,omitempty"`
	// Algorithm must be "ES256"; empty selects it.
	Algorithm string `json:"algorithm,omitempty"`
}

// OTAImageSignRequest signs an OTA image, or its SHA-256 digest, with the
// current version of a board's OTA image-signing key.
type OTAImageSignRequest struct {
	Backend string `json:"backend,omitempty"`
	Data    []byte `json:"data"`
	// DataIsDigest states that Data is already the image's SHA-256 digest.
	DataIsDigest bool `json:"data_is_digest,omitempty"`
}

// otaRequest is an OTA image-key request body.
type otaRequest interface {
	bodyBackend() string
}

func (req *OTAImageKeyRequest) bodyBackend() string  { return req.Backend }
func (req *OTAImageSignRequest) bodyBackend() string { return req.Backend }

// decodeOTARequest decodes r's JSON body into req and returns the backend
// named by the query or the body. It writes the error response and returns
// false when the service is not initialized or the body or backend is
// missing or malformed.
func (h *HandlerContext) decodeOTARequest(w http.ResponseWriter, r *http.Request, req otaRequest) (string, bool) {
	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return "", false
	}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return "", false
	}
	backendID := backendFromRequest(r, req.bodyBackend())
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return "", false
	}
	return backendID, true
}

// CreateOTAImageKeyHandler handles POST /api/v1/ota-image-keys/{board}. It
// creates the board's ES256 OTA image-signing key.
func (h *HandlerContext) CreateOTAImageKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req OTAImageKeyRequest
	backendID, ok := h.decodeOTARequest(w, r, &req)
	if !ok {
		return
	}

	resp, err := h.xkmsService.CreateOTAImageKey(r.Context(), &transport.OTAImageKeyRequest{
		Backend:   backendID,
		BoardID:   chi.URLParam(r, "board"),
		Algorithm: req.Algorithm,
		TenantID:  callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, GenerateKeyResponse{
		KeyID:        resp.KeyID,
		KeyType:      resp.KeyType,
		PublicKeyPEM: resp.PublicKeyPEM,
		Message:      fmt.Sprintf("Key %s generated successfully", resp.KeyID),
	}, http.StatusCreated)
}

// RotateOTAImageKeyHandler handles POST /api/v1/ota-image-keys/{board}/rotate.
// The new version becomes current; earlier versions keep verifying.
func (h *HandlerContext) RotateOTAImageKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req OTAImageKeyRequest
	backendID, ok := h.decodeOTARequest(w, r, &req)
	if !ok {
		return
	}

	resp, err := h.xkmsService.RotateOTAImageKey(r.Context(), &transport.OTAImageKeyRequest{
		Backend:   backendID,
		BoardID:   chi.URLParam(r, "board"),
		Algorithm: req.Algorithm,
		TenantID:  callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, RotateKeyResponse{
		Success:                    true,
		KeyID:                      resp.KeyID,
		KeyType:                    resp.KeyType,
		PublicKeyPEM:               resp.PublicKeyPEM,
		KeyVersion:                 resp.KeyVersion,
		Message:                    fmt.Sprintf("Key %s rotated successfully", resp.KeyID),
		CertificateReissueRequired: resp.CertificateReissueRequired,
	}, http.StatusOK)
}

// SignOTAImageHandler handles POST /api/v1/ota-image-keys/{board}/sign. The
// response's key_version names the board key version that signed.
func (h *HandlerContext) SignOTAImageHandler(w http.ResponseWriter, r *http.Request) {
	var req OTAImageSignRequest
	backendID, ok := h.decodeOTARequest(w, r, &req)
	if !ok {
		return
	}

	resp, err := h.xkmsService.SignOTAImage(r.Context(), &transport.OTAImageSignRequest{
		Backend:      backendID,
		BoardID:      chi.URLParam(r, "board"),
		Data:         req.Data,
		DataIsDigest: req.DataIsDigest,
		TenantID:     callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, SignResponse{
		Signature:  resp.Signature,
		Algorithm:  resp.Algorithm,
		KeyVersion: resp.KeyVersion,
	}, http.StatusOK)
}

// ExportOTAImageKeyHandler handles POST /api/v1/ota-image-keys/{board}/export:
// the public half of the current version of the board's key.
func (h *HandlerContext) ExportOTAImageKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req OTAImageKeyRequest
	backendID, ok := h.decodeOTARequest(w, r, &req)
	if !ok {
		return
	}

	resp, err := h.xkmsService.ExportOTAImageKey(r.Context(), &transport.OTAImageKeyRequest{
		Backend:   backendID,
		BoardID:   chi.URLParam(r, "board"),
		Algorithm: req.Algorithm,
		TenantID:  callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}
