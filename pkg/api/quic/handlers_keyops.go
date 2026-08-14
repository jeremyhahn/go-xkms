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

package quic

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ErrTenantIDNotAccepted is returned when a request body carries a tenant_id.
//
// The tenant an operation runs under is the authenticated caller's own, never
// a value the caller names: a key ID is only unique within a tenant, so a
// body-supplied tenant would let any caller address another tenant's keys.
// The field is refused rather than ignored, because a caller that believes it
// is acting on one tenant and is quietly served another has no way to tell.
var ErrTenantIDNotAccepted = errors.New("tenant_id is not accepted in the request body; the tenant is taken from the authenticated identity")

// tenantForRequest returns the tenant the operation must run under, which is
// the one carried by the authenticated identity. It refuses a request that
// supplied a tenant of its own, sending this transport's validation error and
// reporting false so the handler returns without delegating.
//
// This mirrors the gRPC transport, where the tenant has only ever come from
// callerTenantID and the wire format has no field for the caller to set.
func (s *Server) tenantForRequest(w http.ResponseWriter, r *http.Request, supplied string) (string, bool) {
	if supplied != "" {
		s.sendError(w, http.StatusBadRequest, ErrTenantIDNotAccepted.Error())
		return "", false
	}
	return callerTenantID(r.Context()), true
}

// This file exposes the five hardware-capability key operations
// (attestation, ECDH key agreement, raw key-material export, and
// wrap/unwrap by key ID) over the QUIC/HTTP3 transport. Every handler
// follows the same shape: method check -> authorize -> decode -> delegate to
// the xkms service layer -> map errors -> encode. None of them reach into a
// backend.ImportExportBackend, types.AttestingKeyProvider, or
// types.KeyAgreementProvider directly; that capability resolution lives in
// pkg/xkms and is exercised there.

// handleAttestKey handles POST /api/v1/attest, delegating to
// XKMSService.AttestKey to produce a cryptographic attestation statement
// proving a key was created in hardware (TPM 2.0, PKCS#11, Android
// TEE/StrongBox) and never left the secure boundary.
func (s *Server) handleAttestKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionGet) {
		return
	}

	if s.xkmsService == nil {
		s.sendKeyOpError(r.Context(), w, xkms.ErrNotInitialized)
		return
	}

	var req transport.AttestKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	tenantID, ok := s.tenantForRequest(w, r, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = tenantID

	resp, err := s.xkmsService.AttestKey(r.Context(), &req)
	if err != nil {
		s.sendKeyOpError(r.Context(), w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleDeriveKeyECDH handles POST /api/v1/keys/derive-ecdh, delegating to
// XKMSService.DeriveKeyECDH to perform ECDH key agreement against a peer
// public key and run the resulting shared secret through a KDF to produce a
// symmetric key.
func (s *Server) handleDeriveKeyECDH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionDerive) {
		return
	}

	if s.xkmsService == nil {
		s.sendKeyOpError(r.Context(), w, xkms.ErrNotInitialized)
		return
	}

	var req transport.DeriveKeyECDHRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	tenantID, ok := s.tenantForRequest(w, r, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = tenantID

	resp, err := s.xkmsService.DeriveKeyECDH(r.Context(), &req)
	if err != nil {
		s.sendKeyOpError(r.Context(), w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleWrapKeyByID handles POST /api/v1/keys/wrap-by-id, delegating to
// XKMSService.WrapKeyByID to wrap a server-side target key with a
// server-side wrapping key, both identified by key ID and backend. This is
// the transport-level primitive behind PKCS#11 C_WrapKey.
func (s *Server) handleWrapKeyByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionWrap) {
		return
	}

	if s.xkmsService == nil {
		s.sendKeyOpError(r.Context(), w, xkms.ErrNotInitialized)
		return
	}

	var req transport.WrapKeyByIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	tenantID, ok := s.tenantForRequest(w, r, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = tenantID

	resp, err := s.xkmsService.WrapKeyByID(r.Context(), &req)
	if err != nil {
		s.sendKeyOpError(r.Context(), w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleUnwrapKeyByID handles POST /api/v1/keys/unwrap-by-id, delegating to
// XKMSService.UnwrapKeyByID to unwrap key material with a server-side
// unwrapping key and import the recovered material as a new key. This is
// the transport-level primitive behind PKCS#11 C_UnwrapKey.
func (s *Server) handleUnwrapKeyByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionUnwrap) {
		return
	}

	if s.xkmsService == nil {
		s.sendKeyOpError(r.Context(), w, xkms.ErrNotInitialized)
		return
	}

	var req transport.UnwrapKeyByIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	tenantID, ok := s.tenantForRequest(w, r, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = tenantID

	resp, err := s.xkmsService.UnwrapKeyByID(r.Context(), &req)
	if err != nil {
		s.sendKeyOpError(r.Context(), w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleExportKeyMaterial handles POST /api/v1/keys/{keyID}/export-material,
// delegating to XKMSService.ExportKeyMaterial to release raw symmetric key
// bytes for extractable keys. The request carries no body; keyID comes from
// the path and the target backend from the "backend" query parameter,
// matching handleKeyOperations' existing routing convention for the sibling
// "sign"/"encrypt"/"export" operations.
//
// SECURITY WARNING: this returns plaintext key material without any
// cryptographic protection. It only succeeds for symmetric keys created
// with exportable=true.
func (s *Server) handleExportKeyMaterial(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionExport) {
		return
	}

	if s.xkmsService == nil {
		s.sendKeyOpError(r.Context(), w, xkms.ErrNotInitialized)
		return
	}

	req := &transport.ExportKeyMaterialRequest{
		KeyID:    keyID,
		Backend:  backendParam,
		TenantID: callerTenantID(r.Context()),
	}

	resp, err := s.xkmsService.ExportKeyMaterial(r.Context(), req)
	if err != nil {
		s.sendKeyOpError(r.Context(), w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}
