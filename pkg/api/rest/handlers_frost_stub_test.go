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

//go:build !frost

package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFrostHandlers tests FROST stub handlers
func TestFrostHandlers(t *testing.T) {
	ctx := newTestHandlerContext()

	t.Run("FrostGenerateKeyHandler returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/keys", nil)
		w := httptest.NewRecorder()

		ctx.FrostGenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	t.Run("FrostImportKeyHandler returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/keys/import", nil)
		w := httptest.NewRecorder()

		ctx.FrostImportKeyHandler(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	t.Run("FrostListKeysHandler returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/frost/keys", nil)
		w := httptest.NewRecorder()

		ctx.FrostListKeysHandler(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	t.Run("FrostGetKeyHandler returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/frost/keys/test", nil)
		w := httptest.NewRecorder()

		ctx.FrostGetKeyHandler(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	t.Run("FrostDeleteKeyHandler returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/frost/keys/test", nil)
		w := httptest.NewRecorder()

		ctx.FrostDeleteKeyHandler(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	t.Run("FrostGenerateNoncesHandler returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/keys/test/nonces", nil)
		w := httptest.NewRecorder()

		ctx.FrostGenerateNoncesHandler(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	t.Run("FrostSignRoundHandler returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/keys/test/sign", nil)
		w := httptest.NewRecorder()

		ctx.FrostSignRoundHandler(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	t.Run("FrostAggregateHandler returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/aggregate", nil)
		w := httptest.NewRecorder()

		ctx.FrostAggregateHandler(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	t.Run("FrostVerifyHandler returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/verify", nil)
		w := httptest.NewRecorder()

		ctx.FrostVerifyHandler(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})
}
