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

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestServiceModuleSessionSigningJWK_ComposerFlow walks the composer's
// sequence through this SDK's re-exports only: before the module's REST
// surface exists there is no key to publish, and once it is up the JWK is
// the ES256 key under the CN the composer passed to WithServiceModuleSession.
func TestServiceModuleSessionSigningJWK_ComposerFlow(t *testing.T) {
	ctx := context.Background()
	svc := hostdeps.NewService(t)
	session := &ServiceModuleSessionOptions{SigningKeyCN: "composer-session-key"}

	module, err := NewServiceModule(func() *pkgxkms.XKMSService { return svc },
		WithServiceModuleSession(session))
	require.NoError(t, err)

	_, err = ServiceModuleSessionSigningJWK(ctx, svc, session)
	var missing *ServiceModuleSessionSigningKeyMissingError
	require.ErrorAs(t, err, &missing, "the key is not provisioned before the surface is built")
	assert.Equal(t, "composer-session-key", missing.CN)

	// The first authentication attempt builds the module's REST surface,
	// which provisions the session signing key.
	_, authErr := module.AuthenticateHTTP(httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil))
	require.Error(t, authErr, "a request with no credentials must not authenticate")

	var key *JWK
	key, err = ServiceModuleSessionSigningJWK(ctx, svc, session)
	require.NoError(t, err)
	assert.Equal(t, "ES256", key.Alg)
	pub, err := key.ToPublicKey()
	require.NoError(t, err)
	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P256(), ecPub.Curve)

	// The kid is the SPKI key ID the session tokens carry (go-xkms#1724),
	// not the key's CN.
	wantKid, err := JWKSPKIKeyID(ecPub)
	require.NoError(t, err)
	assert.Equal(t, wantKid, key.Kid)
}

func TestJWKSPKIKeyID_RefusesAKeyWithoutSPKI(t *testing.T) {
	kid, err := JWKSPKIKeyID(struct{}{})
	var kidErr *JWKKeyIDError
	require.ErrorAs(t, err, &kidErr)
	assert.Empty(t, kid)
}

func TestServiceModuleSessionSigningJWK_NilService(t *testing.T) {
	_, err := ServiceModuleSessionSigningJWK(context.Background(), nil, nil)
	require.Error(t, err)
}
