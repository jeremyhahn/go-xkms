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
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPIVLogin_AdminCredential drives POST /api/v1/auth/login/piv over mTLS
// using the first-boot admin credential, then exercises the full session
// lifecycle the pair supports: an authenticated call with the access token,
// a refresh rotation, and a logout revoke.
//
// The admin credential is the minimal honest fixture for this route: it
// already exists on a fresh deployment, so there is no separate PIV
// enrollment ceremony to fake. Its SPKI thumbprint is NOT bound to the
// admin user by qrdb's firstboot ceremony on this deployment, though (see
// ensureAdminCertBinding's doc comment - a real gap, not a test artifact),
// so the test performs that binding itself via the same admin API an
// operator would use.
func TestPIVLogin_AdminCredential(t *testing.T) {
	for _, tgt := range targets() {
		t.Run(tgt.Name, func(t *testing.T) {
			admin := loadAdminCredential(t, tgt)
			ensureAdminCertBinding(t, tgt, admin)

			client, err := xkms.NewLoginClient(xkms.LoginClientConfig{
				BaseURL:           tgt.BaseURL,
				ClientCertificate: &admin,
				RootCAs:           loadCAPool(t, tgt),
				Timeout:           defaultLoginTestTimeout,
			})
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), defaultLoginTestTimeout)
			defer cancel()

			pair, err := client.PIVLogin(ctx)
			require.NoError(t, err, "PIV login over mTLS")
			require.NotEmpty(t, pair.AccessToken)
			require.NotEmpty(t, pair.RefreshToken)

			require.NoError(t, client.Validate(ctx, pair.AccessToken), "the minted access token must validate")

			rotated, err := client.Refresh(ctx, pair.RefreshToken)
			require.NoError(t, err, "refresh must rotate the pair")
			assert.NotEmpty(t, rotated.AccessToken)
			assert.NotEmpty(t, rotated.RefreshToken)
			assert.NotEqual(t, pair.AccessToken, rotated.AccessToken, "refresh must mint a new access token")

			// The pre-rotation access token remains valid until its own
			// expiry (refresh rotates the refresh token's family, not the
			// still-live access token), so validate the rotated one.
			require.NoError(t, client.Validate(ctx, rotated.AccessToken))

			require.NoError(t, client.Logout(ctx, rotated.AccessToken, rotated.RefreshToken), "logout must revoke the pair")

			// A revoked refresh token must not mint another pair.
			_, err = client.Refresh(ctx, rotated.RefreshToken)
			assert.Error(t, err, "a revoked refresh token must not rotate again")
		})
	}
}

// TestPIVLogin_NoClientCertificate proves the route rejects a caller that
// presents no TLS client certificate at all: possession of the key IS the
// credential, so there is nothing else to fall back to.
func TestPIVLogin_NoClientCertificate(t *testing.T) {
	for _, tgt := range targets() {
		t.Run(tgt.Name, func(t *testing.T) {
			client, err := xkms.NewLoginClient(xkms.LoginClientConfig{
				BaseURL: tgt.BaseURL,
				RootCAs: loadCAPool(t, tgt),
				Timeout: defaultLoginTestTimeout,
			})
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), defaultLoginTestTimeout)
			defer cancel()

			_, err = client.PIVLogin(ctx)
			require.Error(t, err)

			var lce *xkms.LoginClientError
			require.ErrorAs(t, err, &lce)
			assert.Equal(t, 401, lce.Status)
		})
	}
}
