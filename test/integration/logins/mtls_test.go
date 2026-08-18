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

//go:build integration && logins

package logins

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMTLS_AdminCredentialAuthenticates proves any client certificate bound
// via SPKI (here, the first-boot admin credential) authenticates a
// session-gated REST route with no bearer token at all, and that the same
// route denies an anonymous caller.
func TestMTLS_AdminCredentialAuthenticates(t *testing.T) {
	for _, tgt := range targets() {
		t.Run(tgt.Name, func(t *testing.T) {
			admin := loadAdminCredential(t, tgt)

			ctx, cancel := context.WithTimeout(context.Background(), defaultLoginTestTimeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, tgt.BaseURL+"/api/v1/auth/me", nil)
			require.NoError(t, err)

			resp, err := httpClient(t, tgt, &admin).Do(req)
			require.NoError(t, err, "mTLS request to %s", tgt.BaseURL)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode, "the admin mTLS credential must authenticate /api/v1/auth/me")
		})
	}
}

// TestMTLS_AnonymousCallDenied proves the same permission route rejects a
// caller presenting no credential at all.
func TestMTLS_AnonymousCallDenied(t *testing.T) {
	for _, tgt := range targets() {
		t.Run(tgt.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultLoginTestTimeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, tgt.BaseURL+"/api/v1/auth/me", nil)
			require.NoError(t, err)

			resp, err := httpClient(t, tgt, nil).Do(req)
			require.NoError(t, err, "anonymous request to %s", tgt.BaseURL)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "an anonymous caller must be denied")
		})
	}
}
