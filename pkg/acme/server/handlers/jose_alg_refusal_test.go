//go:build codec_json

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

package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
)

// signedJWS returns a flattened JSON JWS over payload, signed with key under
// alg and carrying the given protected headers.
func signedJWS(t *testing.T, alg jose.SignatureAlgorithm, key interface{}, headers map[jose.HeaderKey]interface{}, payload []byte) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, &jose.SignerOptions{ExtraHeaders: headers})
	require.NoError(t, err)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	return obj.FullSerialize()
}

// hmacJWS returns a JWS signed with HS256, an algorithm that is not in
// server.AllowedJOSEAlgorithms.
func hmacJWS(t *testing.T, headers map[jose.HeaderKey]interface{}, payload []byte) string {
	t.Helper()
	for _, alg := range server.AllowedJOSEAlgorithms {
		require.NotEqual(t, jose.HS256, alg, "HS256 must stay outside the ACME allow-list for this test to mean anything")
	}
	return signedJWS(t, jose.HS256, make([]byte, 32), headers, payload)
}

// TestPeekJWSKeyID_RefusesAnAlgorithmOutsideTheAllowList proves that the
// tenant-auth parse path reports no kid for a JWS whose "alg" is outside
// server.AllowedJOSEAlgorithms, while the same headers under ES256 are read.
func TestPeekJWSKeyID_RefusesAnAlgorithmOutsideTheAllowList(t *testing.T) {
	kid := "https://acme.example/acme/account/42"
	headers := map[jose.HeaderKey]interface{}{"kid": kid}

	_, ok := peekJWSKeyID([]byte(hmacJWS(t, headers, []byte("{}"))))
	require.False(t, ok, "an HS256 JWS must never report a kid")

	got, ok := peekJWSKeyID([]byte(signedJWS(t, jose.ES256, generateTestKey(t).PrivateKey, headers, []byte("{}"))))
	require.True(t, ok)
	require.Equal(t, kid, got)
}

// TestParseSignedRequest_RefusesAnAlgorithmOutsideTheAllowList proves that
// the request parse path every kid- and jwk-authenticated handler goes
// through refuses an HS256 JWS, while an ES256 one parses.
func TestParseSignedRequest_RefusesAnAlgorithmOutsideTheAllowList(t *testing.T) {
	headers := map[jose.HeaderKey]interface{}{"url": "https://acme.example/acme/new-order"}
	post := func(body string) *http.Request {
		return httptest.NewRequest(http.MethodPost, "/acme/new-order", strings.NewReader(body))
	}

	_, err := parseSignedRequest(post(hmacJWS(t, headers, []byte("{}"))))
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse JWS")

	jws, err := parseSignedRequest(post(signedJWS(t, jose.ES256, generateTestKey(t).PrivateKey, headers, []byte("{}"))))
	require.NoError(t, err)
	require.Len(t, jws.Signatures, 1)
}

// TestKeyChangeHandler_RefusesAnInnerJWSOutsideTheAllowList proves that the
// key-change handler refuses an inner JWS signed with HS256 as malformed, at
// the inner parse step, even though the outer JWS is valid.
func TestKeyChangeHandler_RefusesAnInnerJWSOutsideTheAllowList(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)
	keyChangeURL := service.baseRESTURI + "/acme/key-change"
	accountURL := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)

	inner := hmacJWS(t, map[jose.HeaderKey]interface{}{"url": keyChangeURL},
		[]byte(fmt.Sprintf(`{"account":%q,"oldKey":{}}`, accountURL)))

	nonce, err := service.GetNonceService().Generate()
	require.NoError(t, err)
	outerSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: oldKey.PrivateKey}, &jose.SignerOptions{
		NonceSource:  &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{"url": keyChangeURL, "kid": accountURL},
	})
	require.NoError(t, err)
	outer, err := outerSigner.Sign([]byte(inner))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, keyChangeURL, strings.NewReader(outer.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")
	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	problem := parseErrorResponse(t, resp)
	require.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeMalformedError, problem.Type)
	require.Equal(t, "Invalid inner JWS", problem.Detail)
}
