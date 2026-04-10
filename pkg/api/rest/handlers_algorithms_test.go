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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlgorithmsHandler_ReturnsJSON(t *testing.T) {
	h := newTestHandlerContext()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/algorithms", nil)
	w := httptest.NewRecorder()

	h.AlgorithmsHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp types.AlgorithmsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
}

func TestSetPINManager(t *testing.T) {
	h := newTestHandlerContext()
	assert.Nil(t, h.PINManager)

	mock := &mockPINManager{strategy: "software"}
	h.SetPINManager(mock)
	assert.NotNil(t, h.PINManager)
}
