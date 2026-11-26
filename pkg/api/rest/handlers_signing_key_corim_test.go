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
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// signingXKMS returns a key service with a software backend holding the
// acme tenant's release signing key, and that key's public half.
func signingXKMS(t *testing.T) (*xkms.XKMSService, crypto.PublicKey) {
	t.Helper()
	backend, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	ks, err := xkms.New(&xkms.BackendConfig{Backend: backend, CertStorage: storage.New()})
	require.NoError(t, err)
	svc, err := xkms.NewService(&xkms.ServiceConfig{Backends: map[string]xkms.Backend{"software": ks}, DefaultBackend: "software"})
	require.NoError(t, err)
	svc.SetAttestationAppraiser(signingKeyXKMS(t).AttestationAppraiser())

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "release-manager", TenantID: "acme"})
	key, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: appraisal.ReleaseSigningKeyID, Backend: "software", KeyType: "signing", Algorithm: "ecdsa", Curve: "P-256", TenantID: "acme",
	})
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(key.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return svc, pub
}

// TestSigningKeyREST_SignCoRIM proves POST sign-corim returns a CoRIM signed
// with the tenant release key, draft-ietf-rats-corim-11 §4.2.
func TestSigningKeyREST_SignCoRIM(t *testing.T) {
	svc, pub := signingXKMS(t)
	c := signingKeyClient(t, signingKeyRouter(svc))
	unsigned, err := appraisaltest.UnsignedCoRIM(map[uint32][]byte{0: make([]byte, 32)})
	require.NoError(t, err)

	signed, err := c.SignCoRIM(context.Background(), &transport.SignCoRIMRequest{Repository: "acme/app", CoRIM: unsigned, SignerName: "Acme"})
	require.NoError(t, err)
	assert.Equal(t, appraisal.ReleaseSigningKeyID, signed.Key.KeyID)
	assert.True(t, signed.Key.Default)
	m, err := refvalue.VerifySigned(signed.CoRIM, refvalue.VerifyOptions{PublicKey: pub})
	require.NoError(t, err)
	assert.Equal(t, "Acme", m.Signer)
}

// TestSigningKeyREST_SignCoRIMErrors proves a bad body, a malformed CoRIM, a
// service without an appraiser and a nil request each fail with their class.
func TestSigningKeyREST_SignCoRIMErrors(t *testing.T) {
	svc, _ := signingXKMS(t)
	router := signingKeyRouter(svc)
	serve := func(body string) int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, wire.SigningKeySignCoRIMPath, strings.NewReader(body)))
		return w.Code
	}
	assert.Equal(t, http.StatusBadRequest, serve("{"))
	assert.Equal(t, http.StatusBadRequest, serve(`{"repository":"acme/app","corim":"/w==","signer_name":"Acme"}`))
	assert.Equal(t, http.StatusBadRequest, serve(`{"repository":"Acme/App"}`))

	c := signingKeyClient(t, signingKeyRouter(&xkms.XKMSService{}))
	_, err := c.SignCoRIM(context.Background(), &transport.SignCoRIMRequest{Repository: "acme/app", CoRIM: []byte{0xd9}, SignerName: "Acme"})
	assert.Equal(t, &errSigningKeyStatus{code: http.StatusServiceUnavailable}, err)
	_, err = wire.SigningKeyClient{}.SignCoRIM(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)

	// SignCoRIM and SignImage admit the release key as Sign does.
	denied := httptest.NewRecorder()
	respondSigningKey[any](denied, nil, &keypolicy.PolicyDeniedError{KeyID: "release-signing", Operation: keypolicy.OpSign}, http.StatusOK)
	assert.Equal(t, http.StatusForbidden, denied.Code)
	revoked := httptest.NewRecorder()
	respondSigningKey[any](revoked, nil, &keypolicy.KeyUnavailableError{KeyID: "release-signing", Status: keypolicy.StatusRevoked}, http.StatusOK)
	assert.Equal(t, http.StatusConflict, revoked.Code)
}
