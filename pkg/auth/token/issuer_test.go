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

package token

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// testKeyAttrs describe the software ECDSA P-256 signing key used in tests.
func testKeyAttrs() *types.KeyAttributes {
	return &types.KeyAttributes{
		KeyAlgorithm:       x509.ECDSA,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Hash:               stdcrypto.SHA256,
	}
}

// newTestIssuer builds an issuer over a fresh software ECDSA P-256 key and an
// in-memory refresh store.
func newTestIssuer(t *testing.T, opts ...func(*Config)) *Issuer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cfg := &Config{
		Signer:        key,
		KeyAttributes: testKeyAttrs(),
		RefreshStore:  NewMemoryRefreshStore(),
	}
	for _, o := range opts {
		o(cfg)
	}

	issuer, err := NewIssuer(cfg)
	require.NoError(t, err)
	return issuer
}

// testIdentity returns a fully populated identity.
func testIdentity() *auth.Identity {
	return &auth.Identity{
		Subject:  "user-123",
		TenantID: "tenant-a",
		Roles:    []string{"admin", "operator"},
		Metadata: map[string]string{
			"username":     "alice",
			"display_name": "Alice Admin",
			"email":        "alice@example.com",
		},
	}
}

// unverifiedClaims decodes a token's claims without verifying it, so a test
// can inspect exactly which claims were minted.
func unverifiedClaims(t *testing.T, tokenString string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	require.NoError(t, err)
	return claims
}

func TestNewIssuer_Validation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name string
		cfg  *Config
	}{
		{"nil config", nil},
		{"missing signer", &Config{KeyAttributes: testKeyAttrs(), RefreshStore: NewMemoryRefreshStore()}},
		{"missing key attributes", &Config{Signer: key, RefreshStore: NewMemoryRefreshStore()}},
		{"missing refresh store", &Config{Signer: key, KeyAttributes: testKeyAttrs()}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewIssuer(tc.cfg)
			var nilErr *NilInputError
			assert.ErrorAs(t, err, &nilErr)
		})
	}
}

// TestIssuer_AccessTTL pins the accessor's contract: an unset Config.AccessTTL
// falls back to DefaultAccessTTL, and an explicit positive value is returned
// verbatim.
func TestIssuer_AccessTTL(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		issuer := newTestIssuer(t)
		assert.Equal(t, DefaultAccessTTL, issuer.AccessTTL())
	})

	t.Run("explicit", func(t *testing.T) {
		issuer := newTestIssuer(t, func(c *Config) { c.AccessTTL = 5 * time.Minute })
		assert.Equal(t, 5*time.Minute, issuer.AccessTTL())
	})
}

// TestMint_AccessTokenVerifiesThroughJWTAuthenticator is the load-bearing
// compatibility test: the minted access token must authenticate through the
// production auth.JWTAuthenticator with all identity fields intact.
func TestMint_AccessTokenVerifiesThroughJWTAuthenticator(t *testing.T) {
	issuer := newTestIssuer(t)

	pair, err := issuer.Mint(context.Background(), testIdentity())
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)
	require.NotEmpty(t, pair.RefreshToken)
	assert.Equal(t, "Bearer", pair.TokenType)
	assert.Equal(t, int64(DefaultAccessTTL.Seconds()), pair.ExpiresIn)

	authn, err := auth.NewJWTAuthenticator(&auth.JWTConfig{
		PublicKey:  issuer.PublicKey(),
		Issuer:     issuer.IssuerName(),
		Audience:   issuer.Audience(),
		HeaderName: "Authorization",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)

	id, err := authn.AuthenticateHTTP(req)
	require.NoError(t, err)
	assert.Equal(t, "user-123", id.Subject)
	assert.Equal(t, "tenant-a", id.TenantID)
	assert.ElementsMatch(t, []string{"admin", "operator"}, id.Roles)
	assert.Equal(t, "alice", id.Metadata["username"])
	assert.Equal(t, "Alice Admin", id.Metadata["display_name"])
	assert.Equal(t, "alice@example.com", id.Metadata["email"])
}

// TestMint_CarriesEmailClaimOnBothTokens proves the login key rides on the
// access token (what /auth/me reads) and on the refresh token (what a
// rotation rebuilds the identity from).
func TestMint_CarriesEmailClaimOnBothTokens(t *testing.T) {
	issuer := newTestIssuer(t)

	pair, err := issuer.Mint(context.Background(), testIdentity())
	require.NoError(t, err)

	assert.Equal(t, "alice@example.com", unverifiedClaims(t, pair.AccessToken)["email"])
	assert.Equal(t, "alice@example.com", unverifiedClaims(t, pair.RefreshToken)["email"])
}

// TestMint_OmitsEmailClaimForPrincipalWithoutOne proves a principal with no
// login key mints tokens without an email claim, not with an empty one.
func TestMint_OmitsEmailClaimForPrincipalWithoutOne(t *testing.T) {
	issuer := newTestIssuer(t)
	id := testIdentity()
	delete(id.Metadata, "email")

	pair, err := issuer.Mint(context.Background(), id)
	require.NoError(t, err)

	for name, tok := range map[string]string{"access": pair.AccessToken, "refresh": pair.RefreshToken} {
		claims := unverifiedClaims(t, tok)
		_, present := claims["email"]
		assert.False(t, present, "%s token must not carry an email claim: %v", name, claims)
		assert.Equal(t, "alice", claims["username"], "%s token keeps the other identity claims", name)
	}
}

func TestMint_RequiresSubject(t *testing.T) {
	issuer := newTestIssuer(t)

	_, err := issuer.Mint(context.Background(), &auth.Identity{})
	var nilErr *NilInputError
	assert.ErrorAs(t, err, &nilErr)

	_, err = issuer.Mint(context.Background(), nil)
	assert.ErrorAs(t, err, &nilErr)
}

func TestRefresh_RotatesAndPreservesIdentity(t *testing.T) {
	issuer := newTestIssuer(t)
	ctx := context.Background()

	first, err := issuer.Mint(ctx, testIdentity())
	require.NoError(t, err)

	second, err := issuer.Refresh(ctx, first.RefreshToken)
	require.NoError(t, err)
	assert.NotEqual(t, first.RefreshToken, second.RefreshToken)
	assert.NotEmpty(t, second.AccessToken)

	// The rotated pair still authenticates with the same identity.
	authn, err := auth.NewJWTAuthenticator(&auth.JWTConfig{
		PublicKey: issuer.PublicKey(),
		Issuer:    issuer.IssuerName(),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+second.AccessToken)
	id, err := authn.AuthenticateHTTP(req)
	require.NoError(t, err)
	assert.Equal(t, "user-123", id.Subject)
	assert.Equal(t, "tenant-a", id.TenantID)
	assert.Equal(t, "alice@example.com", id.Metadata["email"], "the login key must survive rotation")
}

func TestRefresh_ReuseRevokesFamily(t *testing.T) {
	issuer := newTestIssuer(t)
	ctx := context.Background()

	first, err := issuer.Mint(ctx, testIdentity())
	require.NoError(t, err)

	second, err := issuer.Refresh(ctx, first.RefreshToken)
	require.NoError(t, err)

	// Replaying the rotated token is reuse: it must fail and revoke the family.
	_, err = issuer.Refresh(ctx, first.RefreshToken)
	var reuseErr *RefreshReuseError
	require.ErrorAs(t, err, &reuseErr)

	// The whole lineage — including the fresh successor — is now dead.
	_, err = issuer.Refresh(ctx, second.RefreshToken)
	var revokedErr *RefreshRevokedError
	assert.ErrorAs(t, err, &revokedErr)
}

func TestRefresh_RejectsAccessToken(t *testing.T) {
	issuer := newTestIssuer(t)

	pair, err := issuer.Mint(context.Background(), testIdentity())
	require.NoError(t, err)

	// An access token must never be exchangeable as a refresh token.
	_, err = issuer.Refresh(context.Background(), pair.AccessToken)
	var invalidErr *InvalidTokenError
	assert.ErrorAs(t, err, &invalidErr)
}

func TestRefresh_RejectsGarbageAndForeignTokens(t *testing.T) {
	issuer := newTestIssuer(t)

	var invalidErr *InvalidTokenError

	_, err := issuer.Refresh(context.Background(), "")
	assert.ErrorAs(t, err, &invalidErr)

	_, err = issuer.Refresh(context.Background(), "not-a-jwt")
	assert.ErrorAs(t, err, &invalidErr)

	// A refresh token signed by a different issuer key fails verification.
	other := newTestIssuer(t)
	foreign, err := other.Mint(context.Background(), testIdentity())
	require.NoError(t, err)

	_, err = issuer.Refresh(context.Background(), foreign.RefreshToken)
	assert.ErrorAs(t, err, &invalidErr)
}

func TestRefresh_ExpiredRecordReadsAsRevoked(t *testing.T) {
	// NewIssuer clamps non-positive TTLs to the default, so build the expiry
	// scenario through the store: mint normally, age the record out, and
	// verify the token is treated as revoked.
	ctx := context.Background()
	store := NewMemoryRefreshStore()
	issuer := newTestIssuer(t, func(c *Config) { c.RefreshStore = store })

	pair, err := issuer.Mint(ctx, testIdentity())
	require.NoError(t, err)

	// Force-expire every record in the store.
	store.mu.Lock()
	for _, rec := range store.records {
		rec.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	}
	store.mu.Unlock()

	_, err = issuer.Refresh(ctx, pair.RefreshToken)
	var revokedErr *RefreshRevokedError
	assert.ErrorAs(t, err, &revokedErr)
}

func TestRevoke_KillsFamilyAndIsIdempotent(t *testing.T) {
	issuer := newTestIssuer(t)
	ctx := context.Background()

	pair, err := issuer.Mint(ctx, testIdentity())
	require.NoError(t, err)

	require.NoError(t, issuer.Revoke(ctx, pair.RefreshToken))

	_, err = issuer.Refresh(ctx, pair.RefreshToken)
	var revokedErr *RefreshRevokedError
	assert.ErrorAs(t, err, &revokedErr)

	// Revoking again — or revoking garbage — is a no-op, not an error.
	assert.NoError(t, issuer.Revoke(ctx, pair.RefreshToken))
	assert.NoError(t, issuer.Revoke(ctx, "not-a-jwt"))
	assert.NoError(t, issuer.Revoke(ctx, ""))
}

func TestMemoryRefreshStore_Lifecycle(t *testing.T) {
	store := NewMemoryRefreshStore()
	ctx := context.Background()

	rec := &Record{
		JTI:       "jti-1",
		Family:    "fam-1",
		Subject:   "user-123",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	require.NoError(t, store.Save(ctx, rec))

	got, err := store.Get(ctx, "fam-1", "jti-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "user-123", got.Subject)
	assert.False(t, got.Rotated)

	require.NoError(t, store.MarkRotated(ctx, "fam-1", "jti-1"))
	got, err = store.Get(ctx, "fam-1", "jti-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Rotated)

	require.NoError(t, store.RevokeFamily(ctx, "fam-1"))
	got, err = store.Get(ctx, "fam-1", "jti-1")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestMemoryRefreshStore_ErrorPaths(t *testing.T) {
	store := NewMemoryRefreshStore()
	ctx := context.Background()

	var nilErr *NilInputError
	assert.ErrorAs(t, store.Save(ctx, nil), &nilErr)

	// Missing records are nil, not errors (fail closed = treated as revoked).
	got, err := store.Get(ctx, "no-such-family", "no-such-jti")
	require.NoError(t, err)
	assert.Nil(t, got)

	// Rotating what is not there must fail closed. Reporting success would let
	// a refresh mint a successor against a record the store never had.
	var revoked *RefreshRevokedError
	assert.ErrorAs(t, store.MarkRotated(ctx, "no-such-family", "no-such-jti"), &revoked)

	// Revoking the non-existent stays a no-op: logout is idempotent.
	assert.NoError(t, store.RevokeFamily(ctx, "no-such-family"))
}

func TestMemoryRefreshStore_ExpiryIsRevocation(t *testing.T) {
	store := NewMemoryRefreshStore()
	ctx := context.Background()

	require.NoError(t, store.Save(ctx, &Record{
		JTI:       "jti-old",
		Family:    "fam-old",
		Subject:   "user-123",
		ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	}))

	got, err := store.Get(ctx, "fam-old", "jti-old")
	require.NoError(t, err)
	assert.Nil(t, got, "expired records must read as absent")
}

// TestMint_CarriesAttestLevelClaimAndRefreshPreservesIt proves the PIV
// login's attestation level rides on both tokens and survives a rotation, so
// an unattested login stays representable for the token's whole lineage; a
// principal without one mints no attest_level claim at all.
func TestMint_CarriesAttestLevelClaimAndRefreshPreservesIt(t *testing.T) {
	issuer := newTestIssuer(t)
	ctx := context.Background()
	id := testIdentity()
	id.Metadata["attest_level"] = "hardware"

	pair, err := issuer.Mint(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "hardware", unverifiedClaims(t, pair.AccessToken)["attest_level"])
	assert.Equal(t, "hardware", unverifiedClaims(t, pair.RefreshToken)["attest_level"])

	rotated, err := issuer.Refresh(ctx, pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "hardware", unverifiedClaims(t, rotated.AccessToken)["attest_level"])
	assert.Equal(t, "hardware", identityFromClaims(unverifiedClaims(t, rotated.RefreshToken)).Metadata["attest_level"])

	plain, err := issuer.Mint(ctx, testIdentity())
	require.NoError(t, err)
	_, present := unverifiedClaims(t, plain.AccessToken)["attest_level"]
	assert.False(t, present, "a login that recorded no level must not mint an empty claim")
}

// TestMintedRefreshTokenIsNotABearerCredential proves the pair's two halves
// are not interchangeable in the other direction either: the refresh token
// the issuer mints is refused by the JWT authenticator that trusts the
// issuer's key, while the access token is accepted with its identity.
func TestMintedRefreshTokenIsNotABearerCredential(t *testing.T) {
	issuer := newTestIssuer(t)
	id := testIdentity()
	id.Metadata["attest_level"] = "hardware"
	pair, err := issuer.Mint(context.Background(), id)
	require.NoError(t, err)

	authenticator, err := auth.NewJWTAuthenticator(&auth.JWTConfig{PublicKey: issuer.PublicKey()})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer "+pair.RefreshToken)
	_, err = authenticator.AuthenticateHTTP(req)
	require.Error(t, err, "the refresh token must not authenticate a protected route")

	req = httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	got, err := authenticator.AuthenticateHTTP(req)
	require.NoError(t, err)
	assert.Equal(t, "user-123", got.Subject)
	assert.Equal(t, "hardware", got.Metadata["attest_level"])
}
