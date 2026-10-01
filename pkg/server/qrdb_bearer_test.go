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
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// signedSessionToken returns a JWT for subject signed by key, as the token
// issuer mints one.
func signedSessionToken(t *testing.T, key *ecdsa.PrivateKey, subject string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": subject, "iss": "xkms", "tenant_id": "system",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}).SignedString(key)
	require.NoError(t, err)
	return tok
}

// bearerFixture returns a bearer authenticator whose live delegate verifies
// tokens signed by the returned key.
func bearerFixture(t *testing.T) (*bearerAuthenticator, *ecdsa.PrivateKey, *auth.LiveAuthenticator) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwtAuth, err := auth.NewJWTAuthenticator(&auth.JWTConfig{PublicKey: &key.PublicKey, Issuer: "xkms"})
	require.NoError(t, err)
	live := auth.NewLiveAuthenticator(jwtAuth)
	return &bearerAuthenticator{live: live}, key, live
}

// grpcBearer is an incoming gRPC context carrying an authorization value.
func grpcBearer(value string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", value))
}

func TestBearerAuthenticator_AcceptsAValidSessionTokenOnGRPC(t *testing.T) {
	b, key, _ := bearerFixture(t)
	id, err := b.Authenticate(grpcBearer("Bearer " + signedSessionToken(t, key, "alice")))
	require.NoError(t, err)
	assert.Equal(t, "alice", id.Subject)
	assert.Equal(t, "jwt", b.Name(), "the method the account's permitted-method policy sees")
}

func TestBearerAuthenticator_NoBearerFallsThrough(t *testing.T) {
	b, _, _ := bearerFixture(t)
	for _, ctx := range []context.Context{context.Background(), grpcBearer(""), grpcBearer("Basic dXNlcjpwdw==")} {
		_, err := b.Authenticate(ctx)
		assert.ErrorIs(t, err, ErrNoBearerToken)
	}
}

func TestBearerAuthenticator_RejectsAForeignToken(t *testing.T) {
	b, _, _ := bearerFixture(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = b.Authenticate(grpcBearer("Bearer " + signedSessionToken(t, other, "mallory")))
	assert.Error(t, err, "a token the issuer did not sign is refused")
}

func TestBearerAuthenticator_NeverAdmitsThroughNoOpOrNoAuthenticator(t *testing.T) {
	b, key, live := bearerFixture(t)
	token := grpcBearer("Bearer " + signedSessionToken(t, key, "alice"))

	live.Store(auth.NewNoOpAuthenticator())
	_, err := b.Authenticate(token)
	assert.ErrorIs(t, err, ErrBearerNotAccepted, "disabled xkms auth must not turn a bearer into a qrdb identity")

	live.Store(nil)
	_, err = b.Authenticate(token)
	assert.ErrorIs(t, err, ErrBearerNotAccepted)
}

func TestBearerAuthenticator_FollowsAReload(t *testing.T) {
	b, key, live := bearerFixture(t)
	token := grpcBearer("Bearer " + signedSessionToken(t, key, "alice"))
	_, err := b.Authenticate(token)
	require.NoError(t, err)

	rotated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwtAuth, err := auth.NewJWTAuthenticator(&auth.JWTConfig{PublicKey: &rotated.PublicKey, Issuer: "xkms"})
	require.NoError(t, err)
	live.Store(jwtAuth)
	_, err = b.Authenticate(token)
	assert.Error(t, err, "the reloaded authenticator decides")
}
