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

package auth

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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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

// authorizationKey carries a request's Authorization value in the tests,
// standing in for qrdb's carrier, which its transports set.
type authorizationKey struct{}

// testAuthorization reads the value withAuthorization stored.
func testAuthorization(ctx context.Context) string {
	v, _ := ctx.Value(authorizationKey{}).(string)
	return v
}

// bearerFixture returns a bearer authenticator whose live delegate verifies
// tokens signed by the returned key.
func bearerFixture(t *testing.T) (*QRDBBearerAuthenticator, *ecdsa.PrivateKey, *LiveAuthenticator) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwtAuth, err := NewJWTAuthenticator(&JWTConfig{PublicKey: &key.PublicKey, Issuer: "xkms"})
	require.NoError(t, err)
	live := NewLiveAuthenticator(jwtAuth)
	b := NewQRDBBearerAuthenticator(live)
	b.authorization = testAuthorization
	return b, key, live
}

// grpcBearer is a request context carrying an Authorization value, as qrdb
// hands one to an authenticator on any transport.
func grpcBearer(value string) context.Context {
	return context.WithValue(context.Background(), authorizationKey{}, value)
}

func TestQRDBBearerAuthenticator_AcceptsAValidSessionToken(t *testing.T) {
	b, key, _ := bearerFixture(t)
	id, err := b.Authenticate(grpcBearer("Bearer " + signedSessionToken(t, key, "alice")))
	require.NoError(t, err)
	assert.Equal(t, "alice", id.Subject)
	assert.True(t, b.MethodUnobservable(), "a session token says who, not how: its issuer enforced the method policy")
}

func TestNewQRDBBearerAuthenticator_ReadsQRDBsAccessor(t *testing.T) {
	b := NewQRDBBearerAuthenticator(NewLiveAuthenticator(nil))
	require.NotNil(t, b.authorization)
	assert.Empty(t, b.authorization(context.Background()), "qrdb's accessor reads nothing from a context qrdb did not fill")
	_, err := b.Authenticate(context.Background())
	assert.ErrorIs(t, err, qrdbsdk.ErrUnauthenticated)
}

func TestQRDBBearerAuthenticator_NoBearerFallsThrough(t *testing.T) {
	b, _, _ := bearerFixture(t)
	for _, ctx := range []context.Context{context.Background(), grpcBearer(""), grpcBearer("Basic dXNlcjpwdw==")} {
		_, err := b.Authenticate(ctx)
		assert.ErrorIs(t, err, qrdbsdk.ErrUnauthenticated, "declined, so the next authenticator decides")
	}
}

func TestQRDBBearerAuthenticator_RejectsAForeignToken(t *testing.T) {
	b, _, _ := bearerFixture(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = b.Authenticate(grpcBearer("Bearer " + signedSessionToken(t, other, "mallory")))
	assert.Error(t, err, "a token the issuer did not sign is refused")
}

func TestQRDBBearerAuthenticator_NeverAdmitsThroughNoOpOrNoAuthenticator(t *testing.T) {
	b, key, live := bearerFixture(t)
	token := grpcBearer("Bearer " + signedSessionToken(t, key, "alice"))

	live.Store(NewNoOpAuthenticator())
	_, err := b.Authenticate(token)
	assert.ErrorIs(t, err, ErrBearerNotAccepted, "disabled xkms auth must not turn a bearer into a qrdb identity")

	live.Store(nil)
	_, err = b.Authenticate(token)
	assert.ErrorIs(t, err, ErrBearerNotAccepted)

	unsourced := NewQRDBBearerAuthenticator(nil)
	unsourced.authorization = testAuthorization
	_, err = unsourced.Authenticate(token)
	assert.ErrorIs(t, err, ErrBearerNotAccepted, "a bridge with no source admits nothing")
}

func TestQRDBBearerAuthenticator_FollowsAReload(t *testing.T) {
	b, key, live := bearerFixture(t)
	token := grpcBearer("Bearer " + signedSessionToken(t, key, "alice"))
	_, err := b.Authenticate(token)
	require.NoError(t, err)

	rotated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwtAuth, err := NewJWTAuthenticator(&JWTConfig{PublicKey: &rotated.PublicKey, Issuer: "xkms"})
	require.NoError(t, err)
	live.Store(jwtAuth)
	_, err = b.Authenticate(token)
	assert.Error(t, err, "the reloaded authenticator decides")
}
