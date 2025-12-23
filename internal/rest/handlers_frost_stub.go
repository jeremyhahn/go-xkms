// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !frost

package rest

import (
	"errors"
	"net/http"
)

var errFrostNotCompiled = errors.New("FROST support not compiled - rebuild with '-tags frost'")

// FrostGenerateKeyHandler handles POST /api/v1/frost/keys requests
func (h *HandlerContext) FrostGenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
	writeError(w, errFrostNotCompiled, http.StatusNotImplemented)
}

// FrostImportKeyHandler handles POST /api/v1/frost/keys/import requests
func (h *HandlerContext) FrostImportKeyHandler(w http.ResponseWriter, r *http.Request) {
	writeError(w, errFrostNotCompiled, http.StatusNotImplemented)
}

// FrostListKeysHandler handles GET /api/v1/frost/keys requests
func (h *HandlerContext) FrostListKeysHandler(w http.ResponseWriter, r *http.Request) {
	writeError(w, errFrostNotCompiled, http.StatusNotImplemented)
}

// FrostGetKeyHandler handles GET /api/v1/frost/keys/{id} requests
func (h *HandlerContext) FrostGetKeyHandler(w http.ResponseWriter, r *http.Request) {
	writeError(w, errFrostNotCompiled, http.StatusNotImplemented)
}

// FrostDeleteKeyHandler handles DELETE /api/v1/frost/keys/{id} requests
func (h *HandlerContext) FrostDeleteKeyHandler(w http.ResponseWriter, r *http.Request) {
	writeError(w, errFrostNotCompiled, http.StatusNotImplemented)
}

// FrostGenerateNoncesHandler handles POST /api/v1/frost/keys/{id}/nonces requests
func (h *HandlerContext) FrostGenerateNoncesHandler(w http.ResponseWriter, r *http.Request) {
	writeError(w, errFrostNotCompiled, http.StatusNotImplemented)
}

// FrostSignRoundHandler handles POST /api/v1/frost/keys/{id}/sign requests
func (h *HandlerContext) FrostSignRoundHandler(w http.ResponseWriter, r *http.Request) {
	writeError(w, errFrostNotCompiled, http.StatusNotImplemented)
}

// FrostAggregateHandler handles POST /api/v1/frost/aggregate requests
func (h *HandlerContext) FrostAggregateHandler(w http.ResponseWriter, r *http.Request) {
	writeError(w, errFrostNotCompiled, http.StatusNotImplemented)
}

// FrostVerifyHandler handles POST /api/v1/frost/verify requests
func (h *HandlerContext) FrostVerifyHandler(w http.ResponseWriter, r *http.Request) {
	writeError(w, errFrostNotCompiled, http.StatusNotImplemented)
}
