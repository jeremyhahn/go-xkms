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
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// oidcTargets filters the matrix to targets that carry an OIDC session
// plane. Only quicbaas adds OIDC/OAuth2 to the stack (docs/08), so the leg
// applies exactly to the quicbaasd rows — this is matrix shape, not a skip:
// the xkmsd target has no OIDC surface to test.
func oidcTargets() []target {
	var out []target
	for _, tgt := range targets() {
		if tgt.Name == "quicbaasd" {
			out = append(out, tgt)
		}
	}
	return out
}

// oidcTokenResponse is the wire shape quicbaas's IAM PIV login returns: the
// platform OIDC session vehicle (access/ID/refresh token triple).
type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// TestOIDCLogin_HardwareSessionMinted proves quicbaas's OIDC leg of the
// matrix: the first-boot admin's mTLS credential (the hardware-bound
// identity) exchanges for a platform OIDC session at the IAM login plane,
// and the minted access token authenticates a real API call.
func TestOIDCLogin_HardwareSessionMinted(t *testing.T) {
	for _, tgt := range oidcTargets() {
		t.Run(tgt.Name, func(t *testing.T) {
			admin := loadAdminCredential(t, tgt)
			ensureAdminCertBinding(t, tgt, admin)

			ctx, cancel := context.WithTimeout(context.Background(), defaultLoginTestTimeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodPost,
				tgt.BaseURL+"/api/v1/iam/login/piv", nil)
			require.NoError(t, err)

			resp, err := httpClient(t, tgt, &admin).Do(req)
			require.NoError(t, err, "OIDC PIV login request")
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode, "OIDC PIV login must mint a session")

			var tokens oidcTokenResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokens))
			require.NotEmpty(t, tokens.AccessToken, "access token must be minted")
			require.NotEmpty(t, tokens.IDToken, "ID token must be minted")
			require.NotEmpty(t, tokens.TokenType, "token type must be set")
			require.Len(t, strings.Split(tokens.AccessToken, "."), 3,
				"access token must be a JWT")

			// The minted session must authenticate a real call on the
			// quicbaas surface (the admin reads its own tenant's audit
			// chain — the same lane the platform's one-audit-plane serves).
			authed, err := http.NewRequestWithContext(ctx, http.MethodGet,
				tgt.BaseURL+"/api/v1/iam/audit", nil)
			require.NoError(t, err)
			authed.Header.Set("Authorization", tokens.TokenType+" "+tokens.AccessToken)

			authedResp, err := httpClient(t, tgt, nil).Do(authed)
			require.NoError(t, err)
			defer func() { _ = authedResp.Body.Close() }()
			require.Equal(t, http.StatusOK, authedResp.StatusCode,
				"the OIDC session must authenticate an API call")
		})
	}
}

// TestOIDCLogin_NoClientCertificateRejected proves fail-closed: the OIDC
// PIV login refuses to mint a session for a caller presenting no client
// certificate.
func TestOIDCLogin_NoClientCertificateRejected(t *testing.T) {
	for _, tgt := range oidcTargets() {
		t.Run(tgt.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultLoginTestTimeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodPost,
				tgt.BaseURL+"/api/v1/iam/login/piv", nil)
			require.NoError(t, err)

			resp, err := httpClient(t, tgt, nil).Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
				"anonymous OIDC PIV login must be rejected")
		})
	}
}
