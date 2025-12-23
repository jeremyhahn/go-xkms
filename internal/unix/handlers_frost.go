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

package unix

import (
	"net/http"
)

// FrostGenerateKeyHandler handles POST /api/v1/frost/keys requests.
func (h *HandlerContext) FrostGenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.FrostGenerateKeyHandler(w, r)
}

// FrostImportKeyHandler handles POST /api/v1/frost/keys/import requests.
func (h *HandlerContext) FrostImportKeyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.FrostImportKeyHandler(w, r)
}

// FrostListKeysHandler handles GET /api/v1/frost/keys requests.
func (h *HandlerContext) FrostListKeysHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.FrostListKeysHandler(w, r)
}

// FrostGetKeyHandler handles GET /api/v1/frost/keys/{id} requests.
func (h *HandlerContext) FrostGetKeyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.FrostGetKeyHandler(w, r)
}

// FrostDeleteKeyHandler handles DELETE /api/v1/frost/keys/{id} requests.
func (h *HandlerContext) FrostDeleteKeyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.FrostDeleteKeyHandler(w, r)
}

// FrostGenerateNoncesHandler handles POST /api/v1/frost/keys/{id}/nonces requests.
func (h *HandlerContext) FrostGenerateNoncesHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.FrostGenerateNoncesHandler(w, r)
}

// FrostSignRoundHandler handles POST /api/v1/frost/keys/{id}/sign requests.
func (h *HandlerContext) FrostSignRoundHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.FrostSignRoundHandler(w, r)
}

// FrostAggregateHandler handles POST /api/v1/frost/aggregate requests.
func (h *HandlerContext) FrostAggregateHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.FrostAggregateHandler(w, r)
}

// FrostVerifyHandler handles POST /api/v1/frost/verify requests.
func (h *HandlerContext) FrostVerifyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.FrostVerifyHandler(w, r)
}
