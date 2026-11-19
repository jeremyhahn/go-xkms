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
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

// TestWebAuthnTokenAdapter_IdentityDeclaresUserHandleSubjectKind proves a
// WebAuthn-minted identity declares its Subject as a WebAuthn user handle
// (go-xkms#1297 review), on the identity itself and in the sub_kind claim
// both halves of the minted pair carry, so QRDBUserResolver -- which reads
// the claim straight off the refresh token via identityFromClaims, not
// through JWTAuthenticator's own narrower claim-to-metadata mapping -- never
// has to guess the encoding at refresh time.
func TestWebAuthnTokenAdapter_IdentityDeclaresUserHandleSubjectKind(t *testing.T) {
	adapter := NewWebAuthnTokenAdapter(newTestTokenIssuer(t), "tenant-a")
	user := webauthn.NewDefaultUser([]byte("user-1"), "alice@example.com", "Alice")

	id := adapter.identityFor(user)
	assert.Equal(t, auth.SubjectKindUserHandle, id.Metadata[auth.SubjectKindMetadataKey])

	access, refresh, err := adapter.GenerateTokenPair(context.Background(), user)
	require.NoError(t, err)
	assert.Equal(t, auth.SubjectKindUserHandle, accessClaims(t, access)["sub_kind"])
	assert.Equal(t, auth.SubjectKindUserHandle, accessClaims(t, refresh)["sub_kind"])
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

// failingSaveStore refuses every Save, so Issuer.Mint fails after signing.
type failingSaveStore struct {
	token.RefreshStore
}

func (failingSaveStore) Save(context.Context, *token.Record) error {
	return errors.New("refresh store unavailable")
}

// TestWebAuthnTokenAdapter_MintFailureReachesConfiguredLogger pins the
// Codex round 4 P2 on #2293: a mint failure is logged through the logger
// the host configured, not slog.Default(), so xkmsd's debug level and a
// host's own log sink both see it.
func TestWebAuthnTokenAdapter_MintFailureReachesConfiguredLogger(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuer, err := token.NewIssuer(&token.Config{
		Signer: key,
		KeyAttributes: &types.KeyAttributes{
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			Hash:               stdcrypto.SHA256,
		},
		RefreshStore: failingSaveStore{RefreshStore: token.NewMemoryRefreshStore()},
	})
	require.NoError(t, err)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	adapter := NewWebAuthnTokenAdapter(issuer, "tenant-a", logger)

	_, _, err = adapter.GenerateTokenPair(context.Background(),
		webauthn.NewDefaultUser([]byte("user-1"), "alice@example.com", "Alice"))
	require.Error(t, err)
	assert.Contains(t, buf.String(), "webauthn login: token mint failed")
	assert.Contains(t, buf.String(), "refresh store unavailable")
}
