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
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// oaepNoneHashRefusal is the service layer's verbatim refusal of hash "NONE"
// for RSA-OAEP (pkg/xkms/servicer_crypto.go). The handlers must report exactly
// this, not a paraphrase: it is the one definition of the refusal, and a
// transport that words it differently is a transport that decided for itself.
const oaepNoneHashRefusal = `RSA-OAEP requires a hash algorithm; hash "NONE" is not valid`

// TestEncryptAsymHandler_HashNONERefusedNotPanic is a regression test for a
// remote denial of service.
//
// xkms.ResolveOAEPHash answers (crypto.Hash(0), nil) for the name "NONE" -- a
// legal, non-error answer meaning "no digest". The handler took that answer and
// called hashFunc.New() on it, and crypto.Hash(0).New() panics with
// "crypto: requested hash function #0 is unavailable". An unauthenticated
// request body of {"hash":"NONE"} therefore crashed the serving goroutine.
//
// The test runs the handler through a router with no recovery middleware, so a
// panic propagates and fails the test rather than being rendered as a 500. It
// asserts the exact refusal text, and then issues a second, valid request
// through the same handler to prove the first one returned normally.
func TestEncryptAsymHandler_HashNONERefusedNotPanic(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("none-hash-key", rsaKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

	// "NONE" is the spelling xkms.ResolveHash recognizes, case-insensitively.
	for _, spelling := range []string{"NONE", "none", "None"} {
		body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data"), Hash: spelling})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/keys/none-hash-key/encrypt-asym?backend=test-backend",
			strings.NewReader(string(body)))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code,
			"hash %q must be refused as a client error", spelling)

		var errResp ErrorResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
		assert.Equal(t, oaepNoneHashRefusal, errResp.Message,
			"the refusal must be the service layer's, verbatim")
		assert.NotContains(t, w.Body.String(), "ciphertext",
			"a refused request must return no ciphertext")
	}

	// The handler is still serving: the refusals returned, they did not unwind
	// the goroutine.
	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data"), Hash: "SHA-256"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/none-hash-key/encrypt-asym?backend=test-backend",
		strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp EncryptAsymResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Ciphertext)
}

// TestDecryptHandler_RoundTripsWithEncryptHandler is the regression test for
// the halves of REST asymmetric encryption disagreeing on padding.
//
// EncryptHandler delegates to the service, which produces PKCS#1 v1.5 for an
// RSA key. DecryptHandler hard-wired rsa.OAEPOptions{Hash: crypto.SHA256}, so
// the ciphertext one REST call produced could not be read back by the next --
// asymmetric encrypt/decrypt over REST could not round-trip at all.
func TestDecryptHandler_RoundTripsWithEncryptHandler(t *testing.T) {
	// EncryptHandler's asymmetric fallback is PKCS#1 v1.5 and is refused
	// unless crypto.allow_legacy_key_wrap is set (pkg/xkms/servicer_crypto.go
	// Encrypt); this test's whole premise is exercising that construction, so
	// it must opt in explicitly.
	previous := types.AllowLegacyKeyWrap()
	types.SetAllowLegacyKeyWrap(true)
	t.Cleanup(func() { types.SetAllowLegacyKeyWrap(previous) })

	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("rt-key", rsaKey)

	ctx := newTestHandlerContext()
	plaintext := []byte("rest encrypt then rest decrypt")

	encRouter := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)
	encBody, _ := json.Marshal(EncryptRequest{Plaintext: plaintext})
	encReq := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/rt-key/encrypt?backend=test-backend", strings.NewReader(string(encBody)))
	encW := httptest.NewRecorder()
	encRouter.ServeHTTP(encW, encReq)

	if fips140.Enforced() {
		// SetAllowLegacyKeyWrap(true) above is a deliberate no-op under
		// GODEBUG=fips140=only (pkg/types/wrappolicy.go): the Go
		// Cryptographic Module's approved-mechanism boundary is a ceiling
		// this repository's own policy switch must never re-open. The
		// service layer's crypto.allow_legacy_key_wrap gate therefore still
		// refuses PKCS#1 v1.5 with a 400, before rsa.EncryptPKCS1v15 (which
		// also refuses it under FIPS) is ever reached.
		require.Equal(t, http.StatusBadRequest, encW.Code, encW.Body.String())
		return
	}

	require.Equal(t, http.StatusOK, encW.Code, encW.Body.String())
	var encResp EncryptResponse
	require.NoError(t, json.Unmarshal(encW.Body.Bytes(), &encResp))
	require.NotEmpty(t, encResp.Ciphertext)

	decRouter := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)
	decBody, _ := json.Marshal(DecryptRequest{Ciphertext: encResp.Ciphertext})
	decReq := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/rt-key/decrypt?backend=test-backend", strings.NewReader(string(decBody)))
	decW := httptest.NewRecorder()
	decRouter.ServeHTTP(decW, decReq)

	require.Equal(t, http.StatusOK, decW.Code, decW.Body.String())
	var decResp DecryptResponse
	require.NoError(t, json.Unmarshal(decW.Body.Bytes(), &decResp))
	assert.Equal(t, plaintext, decResp.Plaintext)
}

// TestDecryptHandler_PKCS1v15RefusedByDefault is the REST refusal test for
// go-xkms#1283: DecryptHandler's asymmetric fallback must refuse PKCS#1 v1.5
// -- named explicitly or left unnamed -- unless crypto.allow_legacy_key_wrap
// is set, mirroring EncryptHandler's own default refusal. Before this fix
// Decrypt performed PKCS#1 v1.5 unconditionally.
func TestDecryptHandler_PKCS1v15RefusedByDefault(t *testing.T) {
	previous := types.AllowLegacyKeyWrap()
	types.SetAllowLegacyKeyWrap(false)
	t.Cleanup(func() { types.SetAllowLegacyKeyWrap(previous) })

	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("v15-refused", rsaKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

	for _, padding := range []string{"", "pkcs1v15"} {
		body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("irrelevant"), Padding: padding})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/keys/v15-refused/decrypt?backend=test-backend", strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code, "padding %q: %s", padding, w.Body.String())
		assert.Contains(t, w.Body.String(), "allow_legacy_key_wrap", "padding %q", padding)
	}
}

// TestDecryptHandler_OAEPCiphertextWithoutPaddingFails is the bad-input
// companion: an OAEP ciphertext offered without naming its padding must not
// give the plaintext back, because an unnamed padding means PKCS#1 v1.5.
//
// The property is about the PLAINTEXT, not the status code, and the two are
// not the same claim (go-xkms#101).
//
// This used to require a non-200, which is a probabilistic assertion, and one
// that fails far more often than it looks.
//
// PKCS#1 v1.5 type-2 unpadding accepts any block beginning 0x00 0x02 with at
// least eight non-zero bytes and then a 0x00. RSA-decrypting an OAEP
// ciphertext yields the OAEP-encoded message, and the tempting estimate is to
// treat that block as uniformly random, which puts the 0x00 0x02 prefix at
// 2^-16.
//
// That is wrong, and the error is not small. An OAEP encoded message is
// 0x00 || maskedSeed || maskedDB, so its leading byte is 0x00 BY
// CONSTRUCTION. Half the prefix test is satisfied before any randomness is
// considered, leaving 1/256 for the second byte and the delimiter condition
// on top.
//
// Measured end to end rather than modelled -- 40,000 real OAEP ciphertexts
// decrypted with rsa.DecryptPKCS1v15 -- v1.5 accepted 92 of them: 1 in 435.
// (An earlier estimate here said 1 in 103,627, from simulating fully random
// blocks. It understated the rate by a factor of about 240 precisely by
// missing that fixed leading byte.)
//
// Each run draws a fresh key and fresh OAEP randomness, so each run is an
// independent trial at roughly 1-in-435 -- which is a frequent flake, not a
// freak one. That is v1.5 behaving as specified, not the handler misbehaving;
// malleability of exactly this kind is why OAEP exists.
//
// So the status code is deliberately not asserted here. What is asserted is
// that the OAEP plaintext never comes back, which holds in both branches: when
// v1.5 unpads by accident it recovers unrelated bytes, not this plaintext.
func TestDecryptHandler_OAEPCiphertextWithoutPaddingFails(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("oaep-key", rsaKey)

	plaintext := []byte("oaep payload")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, plaintext, nil)
	require.NoError(t, err)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

	body, _ := json.Marshal(DecryptRequest{Ciphertext: ciphertext})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/oaep-key/decrypt?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	requirePlaintextNotReturned(t, w, plaintext)

	// Naming the padding reads the very same ciphertext back.
	body, _ = json.Marshal(DecryptRequest{Ciphertext: ciphertext, Padding: "oaep", Hash: "SHA-256"})
	req = httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/oaep-key/decrypt?backend=test-backend", strings.NewReader(string(body)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp DecryptResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, plaintext, resp.Plaintext)
}

// requirePlaintextNotReturned asserts that a decrypt response does not carry
// the given plaintext, whatever its status code.
//
// Three checks, because the plaintext can reach a caller three ways.
//
// The base64 rendering, because that is how a SUCCESS body carries it:
// DecryptResponse.Plaintext is a []byte, and encoding/json renders []byte as
// base64, so a handler leaking this very plaintext produces
//
//	{"plaintext":"b2FlcCBwYXlsb2Fk"}
//
// which does not contain "oaep payload". A raw-body search alone therefore
// passes while the exact leak it names is happening (measured, go-xkms#101).
//
// The RAW bytes, because an ERROR body is not built from that field: a
// regression rendering {"message":"oaep payload"} would slip past a
// base64-only check. Both forms are checked on every status rather than one
// per branch -- replacing the raw search instead of supplementing it would
// have traded one blind spot for another.
//
// And the decoded plaintext on a 200, which is the claim itself rather than a
// guess at how it might be spelled on the wire.
func requirePlaintextNotReturned(t *testing.T, w *httptest.ResponseRecorder, plaintext []byte) {
	t.Helper()

	if b64 := base64.StdEncoding.EncodeToString(plaintext); strings.Contains(w.Body.String(), b64) {
		t.Fatalf("the response carries the plaintext (as base64) under a padding the caller "+
			"did not name; status was %d", w.Code)
	}

	if bytes.Contains(w.Body.Bytes(), plaintext) {
		t.Fatalf("the response carries the plaintext verbatim under a padding the caller "+
			"did not name; status was %d", w.Code)
	}

	if w.Code != http.StatusOK {
		return
	}

	// A 200 here is the rare accidental v1.5 unpad. It must have recovered
	// something other than this plaintext.
	var resp DecryptResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp),
		"a 200 response must still be a decodable DecryptResponse")
	if bytes.Equal(resp.Plaintext, plaintext) {
		t.Fatal("the handler returned the OAEP plaintext for a request that named no padding")
	}
}

// TestKeyTypeRenderedAsName pins the wire rendering of KeyAttributes.KeyType.
//
// types.KeyType is a uint8, so string(attr.KeyType) is an integer-to-rune
// conversion: KeyTypeSigning is 10, so the wire carried "\n" (and KeyTypeCA
// carried "\x02", and so on) instead of the type's name. go vet's stringintconv
// analyzer does not flag it, because it exempts byte-width integer types.
func TestKeyTypeRenderedAsName(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "sig", KeyType: types.KeyTypeSigning, StoreType: types.StoreSoftware},
			{CN: "tls", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	ks.SetKey("sig", rsaKey)
	ks.SetKey("tls", rsaKey)

	ctx := newTestHandlerContext()

	listRouter := createRouterWithHandler(http.MethodGet, "/api/v1/keys", ctx.ListKeysHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=test-backend", nil)
	w := httptest.NewRecorder()
	listRouter.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var listResp ListKeysResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
	require.Len(t, listResp.Keys, 2)

	byID := map[string]string{}
	for _, k := range listResp.Keys {
		byID[k.KeyID] = k.KeyType
	}
	assert.Equal(t, types.KeyTypeSigning.String(), byID["sig"])
	assert.Equal(t, types.KeyTypeTLS.String(), byID["tls"])
	for id, rendered := range byID {
		for _, r := range rendered {
			assert.False(t, unicode.IsControl(r),
				"key %s: key_type %q carries a control character, so the uint8 was converted to a rune", id, rendered)
		}
	}

	// GetKey renders it the same way.
	getRouter := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/keys/sig?backend=test-backend", nil)
	w = httptest.NewRecorder()
	getRouter.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var getResp GetKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &getResp))
	assert.Equal(t, types.KeyTypeSigning.String(), getResp.KeyType)
}

// TestKeyTypeRenderedAsName_UnknownKeyType is the bad-input companion: a
// KeyType outside the defined range must still render as a name, not as a
// control character.
func TestKeyTypeRenderedAsName_UnknownKeyType(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "weird", KeyType: types.KeyType(200), StoreType: types.StoreSoftware},
		}, nil
	}
	ks.SetKey("weird", rsaKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys", ctx.ListKeysHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp ListKeysResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Keys, 1)
	assert.Equal(t, types.KeyType(200).String(), resp.Keys[0].KeyType)
	assert.NotEmpty(t, resp.Keys[0].KeyType)
}
