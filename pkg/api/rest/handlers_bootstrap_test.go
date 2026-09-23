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

// handlers_bootstrap_test.go covers the read-only trust-bootstrap listener
// key endpoint (go-xkms#632): the success pass-through and the "not enabled"
// failure mode. Permission enforcement itself (bootstrap:read, admin-only) is
// exercised at the RBAC-middleware and apimodule-scope layers, not here — see
// pkg/apimodule's TestModuleDeclaresOnlyItsOwnScopes and the REST route table
// in routes.go, which gates GET /api/v1/bootstrap/keys on that permission.
package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// stubBootstrapService returns a canned response or error.
type stubBootstrapService struct {
	resp *transport.BootstrapListenerKeysResponse
	err  error
}

func (s *stubBootstrapService) BootstrapListenerKeys(_ context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return s.resp, s.err
}

func showBootstrapKeys(t *testing.T, svc bootstrapServicer) *httptest.ResponseRecorder {
	t.Helper()
	h := NewBootstrapHandlers(svc, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/keys", nil)
	rec := httptest.NewRecorder()
	h.ShowKeysHandler(rec, req)
	return rec
}

// TestBootstrapShowKeys_Success proves the servicer's response is returned
// verbatim as JSON.
func TestBootstrapShowKeys_Success(t *testing.T) {
	svc := &stubBootstrapService{resp: &transport.BootstrapListenerKeysResponse{
		NoisePublicKey: "aa",
	}}

	rec := showBootstrapKeys(t, svc)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"noise_public_key":"aa"`)
}

// TestBootstrapShowKeys_NotEnabled proves the typed "not enabled" error maps
// to 503, not a generic 500 — the same deployment-shape-not-caller-mistake
// treatment ErrAuditNotConfigured gets.
func TestBootstrapShowKeys_NotEnabled(t *testing.T) {
	svc := &stubBootstrapService{err: xkms.ErrBootstrapListenerNotEnabled}

	rec := showBootstrapKeys(t, svc)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestBootstrapShowKeys_UnexpectedError proves an error the handler does not
// specifically recognize still fails closed rather than leaking detail.
func TestBootstrapShowKeys_UnexpectedError(t *testing.T) {
	svc := &stubBootstrapService{err: assert.AnError}

	rec := showBootstrapKeys(t, svc)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
