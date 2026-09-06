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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// authenticateMinted runs a token the adapter minted back through the JWT
// authenticator a host composes over the same issuer.
func authenticateMinted(t *testing.T, issuerKeyed *WebAuthnTokenAdapter, accessToken string) *auth.Identity {
	t.Helper()

	jwtAuth, err := auth.NewJWTAuthenticator(&auth.JWTConfig{
		PublicKey:  issuerKeyed.issuer.PublicKey(),
		Issuer:     issuerKeyed.issuer.IssuerName(),
		Audience:   issuerKeyed.issuer.Audience(),
		HeaderName: "Authorization",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	id, err := jwtAuth.AuthenticateHTTP(req)
	require.NoError(t, err)
	return id
}

// TestWebAuthnTokenAdapter_IdentityCarriesEmail proves a WebAuthn user's
// email — the key the ceremony itself is keyed by — reaches the identity the
// minted token authenticates as.
func TestWebAuthnTokenAdapter_IdentityCarriesEmail(t *testing.T) {
	adapter := NewWebAuthnTokenAdapter(newTestTokenIssuer(t), "tenant-a")
	user := webauthn.NewDefaultUser([]byte("user-1"), "alice@example.com", "Alice")

	id := adapter.identityFor(user)
	assert.Equal(t, "alice@example.com", id.Metadata["email"])
	assert.Equal(t, "tenant-a", id.TenantID)

	accessToken, err := adapter.GenerateToken(context.Background(), user)
	require.NoError(t, err)
	authenticated := authenticateMinted(t, adapter, accessToken)
	assert.Equal(t, "alice@example.com", authenticated.Metadata["email"])
	assert.Equal(t, id.Subject, authenticated.Subject)
}

// TestWebAuthnTokenAdapter_IdentityOmitsEmptyEmail proves a user without an
// email yields no key at all, on the identity and in the minted token.
func TestWebAuthnTokenAdapter_IdentityOmitsEmptyEmail(t *testing.T) {
	adapter := NewWebAuthnTokenAdapter(newTestTokenIssuer(t), "")
	user := webauthn.NewDefaultUser([]byte("user-2"), "", "Nameless")

	id := adapter.identityFor(user)
	_, present := id.Metadata["email"]
	assert.False(t, present, "an empty email must not be recorded: %v", id.Metadata)
	assert.Equal(t, DefaultWebAuthnTenant, id.TenantID)

	accessToken, err := adapter.GenerateToken(context.Background(), user)
	require.NoError(t, err)
	authenticated := authenticateMinted(t, adapter, accessToken)
	_, present = authenticated.Metadata["email"]
	assert.False(t, present, "the token must not carry an empty email claim: %v", authenticated.Metadata)
}
