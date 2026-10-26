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

package rest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// newSessionJWKService initializes the xkms singleton over backend as the
// default backend "test" and returns it.
func newSessionJWKService(t *testing.T, backend xkms.Backend) *xkms.XKMSService {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": backend},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	return svc
}

// fixedSigner is a crypto.Signer reporting a chosen public key; it never
// signs, since SessionSigningJWK only reads the public half.
type fixedSigner struct{ pub crypto.PublicKey }

func (s fixedSigner) Public() crypto.PublicKey { return s.pub }

func (s fixedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("fixedSigner: not a signing key")
}

// backendWithSigner returns a mock backend whose session signing key exists
// and whose Signer reports pub.
func backendWithSigner(pub crypto.PublicKey) *xkmsmocks.MockKeyStore {
	backend := xkmsmocks.NewMockKeyStore()
	backend.SetKey(DefaultJWTSigningKeyCN, struct{}{})
	backend.SignerFunc = func(*types.KeyAttributes) (crypto.Signer, error) {
		return fixedSigner{pub: pub}, nil
	}
	return backend
}

func TestSessionSigningJWK_VerifiesTheHostSurfaceTokens(t *testing.T) {
	cases := []struct {
		name    string
		opts    *SessionOptions
		wantKid string
	}{
		{name: "default signing CN", opts: nil, wantKid: DefaultJWTSigningKeyCN},
		{name: "custom signing CN", opts: &SessionOptions{SigningKeyCN: "composer-session-key"}, wantKid: "composer-session-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc := newSessionJWKService(t, xkmsmocks.NewMockKeyStore())
			srv, err := NewHostServer(ctx, &HostConfig{XKMSService: svc, Session: tc.opts})
			require.NoError(t, err)
			require.NotNil(t, srv.tokenIssuer, "the host surface must build its token issuer")

			pair, err := srv.tokenIssuer.Mint(ctx, &auth.Identity{Subject: "alice"})
			require.NoError(t, err)

			key, err := SessionSigningJWK(ctx, svc, tc.opts)
			require.NoError(t, err)
			assert.Equal(t, tc.wantKid, key.Kid)
			assert.Equal(t, "EC", key.Kty)
			assert.Equal(t, "P-256", key.Crv)
			assert.Equal(t, "ES256", key.Alg)
			assert.Equal(t, "sig", key.Use)
			assert.True(t, key.IsPublic(), "the JWK must carry no private member")

			pub, err := key.ToPublicKey()
			require.NoError(t, err)
			parsed, err := jwt.Parse(pair.AccessToken, func(tok *jwt.Token) (any, error) {
				assert.Equal(t, key.Kid, tok.Header["kid"], "the JWK kid must select the token's key")
				return pub, nil
			}, jwt.WithValidMethods([]string{"ES256"}))
			require.NoError(t, err)
			assert.True(t, parsed.Valid)

			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			_, err = jwt.Parse(pair.AccessToken, func(*jwt.Token) (any, error) {
				return &other.PublicKey, nil
			}, jwt.WithValidMethods([]string{"ES256"}))
			assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid, "another key must not verify the token")
		})
	}
}

func TestSessionSigningJWK_PadsShortCoordinates(t *testing.T) {
	// A P-256 key whose X coordinate has a leading zero octet: RFC 7518
	// §6.2.1.2 still requires the full 32-octet encoding.
	var key *ecdsa.PrivateKey
	for key == nil || len(key.X.Bytes()) == 32 { //nolint:staticcheck // the test inspects the raw coordinate length
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
	}
	svc := newSessionJWKService(t, backendWithSigner(&key.PublicKey))

	got, err := SessionSigningJWK(context.Background(), svc, nil)
	require.NoError(t, err)
	x, err := base64.RawURLEncoding.DecodeString(got.X)
	require.NoError(t, err)
	y, err := base64.RawURLEncoding.DecodeString(got.Y)
	require.NoError(t, err)
	assert.Len(t, x, 32)
	assert.Len(t, y, 32)
	assert.Equal(t, key.X, new(big.Int).SetBytes(x)) //nolint:staticcheck // compares the raw coordinate
}

func TestSessionSigningJWK_NilService(t *testing.T) {
	_, err := SessionSigningJWK(context.Background(), nil, nil)
	var target *HostXKMSServiceRequiredError
	assert.ErrorAs(t, err, &target)
}

func TestSessionSigningJWK_KeyNotProvisioned(t *testing.T) {
	svc := newSessionJWKService(t, xkmsmocks.NewMockKeyStore())

	_, err := SessionSigningJWK(context.Background(), svc, &SessionOptions{SigningKeyCN: "never-provisioned"})
	var target *SessionSigningKeyMissingError
	require.ErrorAs(t, err, &target)
	assert.Equal(t, "never-provisioned", target.CN)
	assert.Equal(t, "test", target.Backend)
	assert.Contains(t, err.Error(), "never-provisioned")
}

func TestSessionSigningJWK_NoDefaultBackend(t *testing.T) {
	// Zero-value XKMSService: no backends, so no default backend.
	_, err := SessionSigningJWK(context.Background(), &xkms.XKMSService{}, nil)
	var target *SessionSigningKeyMissingError
	require.ErrorAs(t, err, &target)
	assert.Equal(t, DefaultJWTSigningKeyCN, target.CN)
}

func TestSessionSigningJWK_BackendCannotExport(t *testing.T) {
	sentinel := errors.New("hsm: public key not extractable")
	backend := xkmsmocks.NewMockKeyStore()
	backend.SetKey(DefaultJWTSigningKeyCN, struct{}{})
	backend.SignerFunc = func(*types.KeyAttributes) (crypto.Signer, error) { return nil, sentinel }
	svc := newSessionJWKService(t, backend)

	_, err := SessionSigningJWK(context.Background(), svc, nil)
	var target *SessionSigningKeyExportError
	require.ErrorAs(t, err, &target)
	assert.ErrorIs(t, err, sentinel)
	assert.Equal(t, "test", target.Backend)
	assert.Contains(t, err.Error(), DefaultJWTSigningKeyCN)
}

func TestSessionSigningJWK_SignerWithoutPublicKey(t *testing.T) {
	svc := newSessionJWKService(t, backendWithSigner(nil))

	_, err := SessionSigningJWK(context.Background(), svc, nil)
	var target *SessionSigningKeyExportError
	require.ErrorAs(t, err, &target)
	assert.ErrorIs(t, err, ErrSessionSigningKeyNoPublicKey)
}

func TestSessionSigningJWK_UnsupportedKeyType(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name     string
		pub      crypto.PublicKey
		wantType string
	}{
		{name: "Ed25519", pub: edPub, wantType: "ed25519.PublicKey"},
		{name: "ECDSA P-384", pub: &p384.PublicKey, wantType: "ECDSA P-384"},
		{name: "invalid P-256 point", pub: &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, wantType: "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newSessionJWKService(t, backendWithSigner(tc.pub))

			_, err := SessionSigningJWK(context.Background(), svc, nil)
			var target *SessionSigningKeyTypeError
			require.ErrorAs(t, err, &target)
			assert.Contains(t, target.KeyType, tc.wantType)
			assert.Contains(t, err.Error(), "ES256")
		})
	}
}
