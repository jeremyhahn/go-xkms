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
	"fmt"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// SealRequest represents a request to seal data
type SealRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Data    []byte `json:"data"`
	AAD     []byte `json:"aad,omitempty"`
}

// SealResponse represents the response from a seal operation
type SealResponse struct {
	Backend    string            `json:"backend"`
	Ciphertext []byte            `json:"ciphertext"`
	Nonce      []byte            `json:"nonce,omitempty"`
	Tag        []byte            `json:"tag,omitempty"`
	Metadata   map[string][]byte `json:"metadata,omitempty"`
}

// UnsealRequest represents a request to unseal data
type UnsealRequest struct {
	Backend    string `json:"backend"`
	KeyID      string `json:"key_id"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
	AAD        []byte `json:"aad,omitempty"`
}

// UnsealResponse represents the response from an unseal operation
type UnsealResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// CanSealRequest represents a request to check sealing capability
type CanSealRequest struct {
	Backend string `json:"backend"`
}

// CanSealResponse represents the response from a can seal check
type CanSealResponse struct {
	CanSeal bool `json:"can_seal"`
}

// handleSeal handles seal data requests
func (s *Server) handleSeal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "seal", "use") {
		return
	}

	var req SealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if req.Backend == "" {
		s.sendError(w, http.StatusBadRequest, "backend is required")
		return
	}

	if len(req.Data) == 0 {
		s.sendError(w, http.StatusBadRequest, "data is required")
		return
	}

	// Build seal options
	opts := &types.SealOptions{
		AAD: req.AAD,
	}

	// If KeyID is provided, look up the key to get its actual attributes
	if req.KeyID != "" {
		// Get the backend to look up the key
		ks, err := xkms.GetBackend(req.Backend)
		if err != nil {
			s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %v", err))
			return
		}

		// Find the key by CN to get its full attributes
		keyAttrs, err := ks.ListKeys()
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list keys: %v", err))
			return
		}

		var targetAttr *types.KeyAttributes
		for _, attr := range keyAttrs {
			if attr.CN == req.KeyID {
				targetAttr = attr
				break
			}
		}

		if targetAttr == nil {
			s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %s", req.KeyID))
			return
		}

		opts.KeyAttributes = targetAttr
	}

	// Seal the data using the xkms service
	ctx := r.Context()
	sealed, err := xkms.SealWithBackend(ctx, req.Backend, req.Data, opts)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to seal data: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, SealResponse{
		Backend:    string(sealed.Backend),
		Ciphertext: sealed.Ciphertext,
		Nonce:      sealed.Nonce,
		Tag:        sealed.Tag,
		Metadata:   sealed.Metadata,
	})
}

// handleUnseal handles unseal data requests
func (s *Server) handleUnseal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "seal", "use") {
		return
	}

	var req UnsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if req.Backend == "" {
		s.sendError(w, http.StatusBadRequest, "backend is required")
		return
	}

	if len(req.Ciphertext) == 0 {
		s.sendError(w, http.StatusBadRequest, "ciphertext is required")
		return
	}

	// Get backend to determine backend type for sealed data
	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %v", err))
		return
	}

	// Build sealed data from request
	sealed := &types.SealedData{
		Backend:    ks.KeyProvider().Type(),
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
	}

	// Build unseal options
	opts := &types.UnsealOptions{
		AAD: req.AAD,
	}

	// If KeyID is provided, look up the key to get its actual attributes
	if req.KeyID != "" {
		// Find the key by CN to get its full attributes
		keyAttrs, err := ks.ListKeys()
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list keys: %v", err))
			return
		}

		var targetAttr *types.KeyAttributes
		for _, attr := range keyAttrs {
			if attr.CN == req.KeyID {
				targetAttr = attr
				break
			}
		}

		if targetAttr == nil {
			s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %s", req.KeyID))
			return
		}

		opts.KeyAttributes = targetAttr
		sealed.KeyID = targetAttr.ID() // Use storage format to match what Seal stores
	}

	// Unseal the data using the xkms service
	ctx := r.Context()
	plaintext, err := xkms.UnsealWithBackend(ctx, req.Backend, sealed, opts)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to unseal data: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, UnsealResponse{
		Plaintext: plaintext,
	})
}

// handleCanSeal handles can seal capability check requests
func (s *Server) handleCanSeal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "seal", "read") {
		return
	}

	var backendName string

	// Support both GET with query param and POST with body
	if r.Method == http.MethodGet {
		backendName = r.URL.Query().Get("backend")
	} else {
		var req CanSealRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
			return
		}
		backendName = req.Backend
	}

	var canSeal bool
	if backendName != "" {
		canSeal = xkms.CanSeal(backendName)
	} else {
		canSeal = xkms.CanSeal()
	}

	s.sendJSON(w, http.StatusOK, CanSealResponse{
		CanSeal: canSeal,
	})
}
