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

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/encoding/jwk"
)

func TestAccessTokenType(t *testing.T) {
	tests := []struct {
		name    string
		session *config.SessionConfig
		want    string
	}{
		{"no session config", nil, ""},
		{"unset", &config.SessionConfig{}, ""},
		{"at+jwt", &config.SessionConfig{AccessTokenType: token.ATJWTType}, token.ATJWTType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{config: &config.Config{Auth: config.AuthConfig{Session: tc.session}}}
			assert.Equal(t, tc.want, s.accessTokenType())
		})
	}
}

// The configured auth.session.access_token_type reaches the typ header of
// the access tokens the daemon's issuer mints (RFC 9068 §2.1); refresh
// tokens keep "JWT", and both carry the SPKI kid of the signing key.
func TestInitializeTokenIssuer_AccessTokenTypeReachesTheHeader(t *testing.T) {
	tests := []struct {
		name          string
		session       *config.SessionConfig
		wantAccessTyp string
	}{
		{"default", nil, "JWT"},
		{"at+jwt", &config.SessionConfig{AccessTokenType: token.ATJWTType, ClientID: "client-1"}, "at+jwt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			wantKid, err := jwk.SPKIKeyID(&key.PublicKey)
			require.NoError(t, err)

			s := newTokenIssuerServer(t, &signingKeyBackend{signer: key}, &config.Config{
				Auth: config.AuthConfig{Session: tc.session},
			})
			require.NoError(t, s.initializeTokenIssuer())
			require.NotNil(t, s.tokenIssuer)

			pair, err := s.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "user-1"})
			require.NoError(t, err)

			access := verifiedHeader(t, pair.AccessToken, key)
			assert.Equal(t, tc.wantAccessTyp, access["typ"])
			assert.Equal(t, wantKid, access["kid"])

			refresh := verifiedHeader(t, pair.RefreshToken, key)
			assert.Equal(t, "JWT", refresh["typ"])
			assert.Equal(t, wantKid, refresh["kid"])
		})
	}
}

// TestInitializeTokenIssuer_ClientIDReachesTheAccessToken proves
// auth.session.client_id becomes the client_id claim of at+jwt access
// tokens (RFC 9068 §2.2).
func TestInitializeTokenIssuer_ClientIDReachesTheAccessToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	s := newTokenIssuerServer(t, &signingKeyBackend{signer: key}, &config.Config{
		Auth: config.AuthConfig{Session: &config.SessionConfig{
			AccessTokenType: token.ATJWTType,
			ClientID:        "client-1",
		}},
	})
	require.NoError(t, s.initializeTokenIssuer())

	pair, err := s.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "user-1"})
	require.NoError(t, err)

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(pair.AccessToken, claims, func(*jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	require.NoError(t, err)
	assert.Equal(t, "client-1", claims["client_id"])
}

// TestInitializeTokenIssuer_ATJWTWithoutClientIDFails proves an at+jwt
// session without a client ID fails issuer construction rather than
// minting tokens that lack the claim.
func TestInitializeTokenIssuer_ATJWTWithoutClientIDFails(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	s := newTokenIssuerServer(t, &signingKeyBackend{signer: key}, &config.Config{
		Auth: config.AuthConfig{Session: &config.SessionConfig{AccessTokenType: token.ATJWTType}},
	})

	var want *token.ATJWTClientIDRequiredError
	require.ErrorAs(t, s.initializeTokenIssuer(), &want)
}

// verifiedHeader verifies tokenString against key and returns its header.
func verifiedHeader(t *testing.T, tokenString string, key *ecdsa.PrivateKey) map[string]interface{} {
	t.Helper()
	parsed, err := jwt.Parse(tokenString, func(*jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	require.NoError(t, err)
	return parsed.Header
}
