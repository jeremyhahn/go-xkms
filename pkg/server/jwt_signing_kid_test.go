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
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/encoding/jwk"
)

// The daemon's issuer stamps the SPKI kid of its signing key on both token
// kinds, and both keep the default "JWT" typ header.
func TestInitializeTokenIssuer_SPKIKeyIDReachesTheHeader(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wantKid, err := jwk.SPKIKeyID(&key.PublicKey)
	require.NoError(t, err)

	s := newTokenIssuerServer(t, &signingKeyBackend{signer: key}, &config.Config{})
	require.NoError(t, s.initializeTokenIssuer())
	require.NotNil(t, s.tokenIssuer)

	pair, err := s.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "user-1"})
	require.NoError(t, err)

	for name, tok := range map[string]string{"access": pair.AccessToken, "refresh": pair.RefreshToken} {
		header := verifiedHeader(t, tok, key)
		assert.Equal(t, "JWT", header["typ"], name)
		assert.Equal(t, wantKid, header["kid"], name)
	}
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
