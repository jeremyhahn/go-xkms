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

package quic

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	backendmocks "github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file holds the tests that prove a crypto parameter sent over the QUIC
// transport ARRIVES at the signing/encrypting primitive, rather than merely
// that the call succeeded.
//
// That distinction is the whole point. This transport used to decode
// {data, hash} and nothing else, then call signer.Sign with the bare
// crypto.Hash as its opts -- which is PKCS#1 v1.5 for an RSA key. A caller
// asking for RSASSA-PSS received a perfectly valid signature under the wrong
// scheme and a 200 response. Every assertion below is therefore paired with a
// negative: a test that only checks "it verified" cannot tell the two schemes
// apart, because both produce a valid signature.

// rsaSigningServer builds a QUIC server whose "software" backend holds one
// real RSA key, returning the server and the key's private half so tests can
// verify signatures independently of the server.
func rsaSigningServer(t *testing.T, keyID string) (*Server, *rsa.PrivateKey) {
	t.Helper()

	server, mockKS := createTestServer(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: keyID, KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	mockKS.SetKey(keyID, priv)

	return server, priv
}

// postSign issues a sign request against keyID and returns the recorder.
func postSign(t *testing.T, server *Server, keyID string, req SignRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleSign(rec, r, keyID, "software")
	return rec
}

// decodeSignatureResponse extracts the raw signature bytes from a sign
// response body.
func decodeSignatureResponse(t *testing.T, rec *httptest.ResponseRecorder) []byte {
	t.Helper()
	var resp struct {
		Signature []byte `json:"signature"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotEmpty(t, resp.Signature)
	return resp.Signature
}

// ============================================================================
// RSA-PSS
// ============================================================================

// TestHandleSign_PSSIsNotDowngradedToPKCS1v15 is the regression test for the
// silent downgrade. It asserts both halves: the signature verifies as PSS at
// the requested salt length, AND it does not verify as PKCS#1 v1.5.
//
// The negative is the load-bearing half. A PKCS#1 v1.5 signature over the same
// digest is still a valid signature, so "VerifyPSS failed" would be the only
// symptom of the old behaviour -- and a test that merely asserted a 200 and a
// non-empty signature passed against it.
func TestHandleSign_PSSIsNotDowngradedToPKCS1v15(t *testing.T) {
	const keyID = "rsa-pss-key"
	server, priv := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	message := []byte("payload to sign under PSS")
	digest := sha256.Sum256(message)

	for _, saltLength := range []int{32, rsa.PSSSaltLengthAuto} {
		rec := postSign(t, server, keyID, SignRequest{
			Data:       message,
			Hash:       "SHA-256",
			Padding:    "pss",
			SaltLength: saltLength,
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		signature := decodeSignatureResponse(t, rec)

		assert.NoError(t,
			rsa.VerifyPSS(&priv.PublicKey, crypto.SHA256, digest[:], signature,
				&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: saltLength}),
			"signature must verify as RSASSA-PSS at the requested salt length %d", saltLength)

		assert.Error(t,
			rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], signature),
			"a PSS request must not be answered with a PKCS#1 v1.5 signature (salt length %d)", saltLength)
	}
}

// TestHandleSign_PSSSaltLengthArrives proves SaltLength is not merely accepted
// but used: a signature made at a 32-byte salt must fail verification when
// checked against a different fixed salt length.
func TestHandleSign_PSSSaltLengthArrives(t *testing.T) {
	const keyID = "rsa-pss-salt"
	server, priv := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	message := []byte("salt length must survive the wire")
	digest := sha256.Sum256(message)

	rec := postSign(t, server, keyID, SignRequest{
		Data:       message,
		Hash:       "SHA-256",
		Padding:    "pss",
		SaltLength: 32,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	signature := decodeSignatureResponse(t, rec)

	require.NoError(t, rsa.VerifyPSS(&priv.PublicKey, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}))

	assert.Error(t, rsa.VerifyPSS(&priv.PublicKey, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 20}),
		"a signature made with a 32-byte salt must not verify at a 20-byte salt")
}

// TestHandleSign_DefaultPaddingRemainsPKCS1v15 pins the backward-compatible
// default: an absent Padding field still means PKCS#1 v1.5, so existing
// clients are unaffected by the field's introduction.
func TestHandleSign_DefaultPaddingRemainsPKCS1v15(t *testing.T) {
	const keyID = "rsa-default-padding"
	server, priv := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	message := []byte("no padding field at all")
	digest := sha256.Sum256(message)

	rec := postSign(t, server, keyID, SignRequest{Data: message, Hash: "SHA-256"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	signature := decodeSignatureResponse(t, rec)

	assert.NoError(t, rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], signature))
	assert.Error(t, rsa.VerifyPSS(&priv.PublicKey, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthAuto}))
}

// TestHandleSign_DataIsDigestNotHashedTwice proves DataIsDigest arrives: a
// caller-supplied digest must be signed as-is rather than hashed again.
//
// Without the flag the same bytes are treated as a message and hashed, which
// produces a signature over SHA-256(digest) -- valid-looking, and verifiable
// only against this implementation.
func TestHandleSign_DataIsDigestNotHashedTwice(t *testing.T) {
	const keyID = "rsa-prehashed"
	server, priv := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	message := []byte("pre-hashed input")
	digest := sha256.Sum256(message)

	rec := postSign(t, server, keyID, SignRequest{
		Data:         digest[:],
		Hash:         "SHA-256",
		Padding:      "pss",
		SaltLength:   32,
		DataIsDigest: true,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	signature := decodeSignatureResponse(t, rec)

	assert.NoError(t, rsa.VerifyPSS(&priv.PublicKey, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}),
		"the supplied digest must be signed directly")

	doubleHashed := sha256.Sum256(digest[:])
	assert.Error(t, rsa.VerifyPSS(&priv.PublicKey, crypto.SHA256, doubleHashed[:], signature,
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}),
		"the digest must not be hashed a second time")
}

// TestHandleSign_PSSRejectedForNonRSAKey proves the padding request is refused
// rather than silently falling back to the key's native scheme.
func TestHandleSign_PSSRejectedForNonRSAKey(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "ecdsa-pss", KeyAlgorithm: x509.ECDSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	mockKS.SetKey("ecdsa-pss", priv)

	rec := postSign(t, server, "ecdsa-pss", SignRequest{
		Data:    []byte("data"),
		Hash:    "SHA-256",
		Padding: "pss",
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "PSS")
}

// TestHandleSign_UnknownPaddingRefused proves a misspelled padding scheme is
// an error rather than a silent fallback to the default.
func TestHandleSign_UnknownPaddingRefused(t *testing.T) {
	const keyID = "rsa-bad-padding"
	server, _ := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	rec := postSign(t, server, keyID, SignRequest{
		Data:    []byte("data"),
		Hash:    "SHA-256",
		Padding: "pss1",
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "pss1")
}

// TestHandleVerify_PSSRoundTrip proves the verify handler honours the same
// parameters: a PSS signature produced independently must verify only when
// the request names PSS, and must be reported invalid when it does not.
func TestHandleVerify_PSSRoundTrip(t *testing.T) {
	const keyID = "rsa-pss-verify"
	server, priv := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	message := []byte("verify me under PSS")
	digest := sha256.Sum256(message)
	signature, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:],
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32})
	require.NoError(t, err)

	verify := func(req VerifyRequest) VerifyResponse {
		body, mErr := json.Marshal(req)
		require.NoError(t, mErr)
		r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		server.handleVerify(rec, r, keyID, "software")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp VerifyResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		return resp
	}

	assert.True(t, verify(VerifyRequest{
		Data: message, Signature: signature, Hash: "SHA-256",
		Padding: "pss", SaltLength: 32,
	}).Valid, "a PSS signature must verify when the request names PSS")

	assert.False(t, verify(VerifyRequest{
		Data: message, Signature: signature, Hash: "SHA-256",
	}).Valid, "a PSS signature must not verify as PKCS#1 v1.5")
}

// ============================================================================
// RSA-OAEP
// ============================================================================

// TestHandleDecrypt_OAEPHashArrives proves the OAEP digest travels: a
// ciphertext built with SHA-256 decrypts only when the request names SHA-256,
// and a request naming a different digest fails.
//
// This handler used to hard-wire rsa.OAEPOptions{Hash: crypto.SHA256} for
// every asymmetric key, so no other digest could be used over this transport
// at all -- and PKCS#1 v1.5 ciphertexts were undecryptable.
func TestHandleDecrypt_OAEPHashArrives(t *testing.T) {
	const keyID = "rsa-oaep-decrypt"
	server, priv := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	plaintext := []byte("oaep secret")
	ciphertext, err := rsa.EncryptOAEP(sha512.New384(), rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	decrypt := func(req DecryptRequest) *httptest.ResponseRecorder {
		body, mErr := json.Marshal(req)
		require.NoError(t, mErr)
		r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		server.handleDecrypt(rec, r, keyID, "software")
		return rec
	}

	rec := decrypt(DecryptRequest{Ciphertext: ciphertext, Padding: "oaep", Hash: "SHA-384"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp DecryptResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, plaintext, resp.Plaintext)

	// A different digest must fail rather than return some other plaintext.
	assert.NotEqual(t, http.StatusOK,
		decrypt(DecryptRequest{Ciphertext: ciphertext, Padding: "oaep", Hash: "SHA-256"}).Code,
		"a SHA-384 OAEP ciphertext must not decrypt under SHA-256")

	// And the wrong padding scheme entirely must fail too.
	assert.NotEqual(t, http.StatusOK,
		decrypt(DecryptRequest{Ciphertext: ciphertext}).Code,
		"an OAEP ciphertext must not decrypt as PKCS#1 v1.5")
}

// TestHandleDecrypt_OAEPLabelArrives proves the OAEP label reaches the
// primitive: a ciphertext built with a label decrypts only when the same label
// is supplied, and the label is part of the ciphertext's authentication.
func TestHandleDecrypt_OAEPLabelArrives(t *testing.T) {
	const keyID = "rsa-oaep-label"
	server, priv := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	label := []byte("tenant-42")
	plaintext := []byte("labelled secret")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, plaintext, label)
	require.NoError(t, err)

	decrypt := func(req DecryptRequest) *httptest.ResponseRecorder {
		body, mErr := json.Marshal(req)
		require.NoError(t, mErr)
		r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		server.handleDecrypt(rec, r, keyID, "software")
		return rec
	}

	rec := decrypt(DecryptRequest{Ciphertext: ciphertext, Padding: "oaep", Hash: "SHA-256", Label: label})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp DecryptResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, plaintext, resp.Plaintext)

	assert.NotEqual(t, http.StatusOK,
		decrypt(DecryptRequest{Ciphertext: ciphertext, Padding: "oaep", Hash: "SHA-256"}).Code,
		"a labelled OAEP ciphertext must not decrypt without the label")
}

// TestHandleDecrypt_PKCS1v15Supported proves the padding default is honoured
// and that a PKCS#1 v1.5 ciphertext -- previously undecryptable over this
// transport -- now works.
func TestHandleDecrypt_PKCS1v15Supported(t *testing.T) {
	const keyID = "rsa-v15-decrypt"
	server, priv := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	plaintext := []byte("v15 secret")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, plaintext)
	require.NoError(t, err)

	body, err := json.Marshal(DecryptRequest{Ciphertext: ciphertext})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, r, keyID, "software")

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp DecryptResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, plaintext, resp.Plaintext)
}

// TestHandleDecrypt_UnknownPaddingRefused proves a misspelled padding scheme
// is refused rather than silently treated as the default.
func TestHandleDecrypt_UnknownPaddingRefused(t *testing.T) {
	const keyID = "rsa-bad-decrypt-padding"
	server, _ := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	body, err := json.Marshal(DecryptRequest{Ciphertext: []byte("blob"), Padding: "oeap"})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, r, keyID, "software")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "oeap")
}

// TestHandleAsymmetricEncrypt_HashArrives proves the OAEP digest selected on
// the encrypt side is the one used. The handler used to force SHA-256 and
// ignore the field entirely.
func TestHandleAsymmetricEncrypt_HashArrives(t *testing.T) {
	const keyID = "rsa-asym-hash"
	server, priv := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	plaintext := []byte("choose my digest")
	body, err := json.Marshal(AsymmetricEncryptRequest{Plaintext: plaintext, Hash: "SHA-384"})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAsymmetricEncrypt(rec, r, keyID, "software")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp EncryptResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	recovered, err := rsa.DecryptOAEP(sha512.New384(), rand.Reader, priv, resp.Ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)

	_, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, resp.Ciphertext, nil)
	assert.Error(t, err, "a SHA-384 OAEP ciphertext must not open under SHA-256")
}

// TestHandleAsymmetricEncrypt_WeakHashRefused proves the weak-hash policy is
// enforced on this transport too: SHA-1 OAEP is refused rather than performed.
func TestHandleAsymmetricEncrypt_WeakHashRefused(t *testing.T) {
	const keyID = "rsa-asym-weak"
	server, _ := rsaSigningServer(t, keyID)
	defer xkms.Reset()

	body, err := json.Marshal(AsymmetricEncryptRequest{Plaintext: []byte("data"), Hash: "SHA-1"})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAsymmetricEncrypt(rec, r, keyID, "software")

	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "SHA-256 or stronger")
}

// ============================================================================
// AEAD
// ============================================================================

// aeadServer builds a QUIC server whose "software" backend holds one real
// AES-256 symmetric key.
func aeadServer(t *testing.T, keyID string) *Server {
	t.Helper()

	server, mockKS, ext := createTestServerWithExtended(t)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	ext.StoreSymmetricKey(keyID, key)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:                 keyID,
				KeyType:            types.KeyTypeSecret,
				StoreType:          types.StoreSoftware,
				KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
		}, nil
	}
	mockKS.SetKey(keyID, nil)

	return server
}

// TestHandleEncryptDecrypt_AADAuthenticated proves the additional
// authenticated data reaches the AEAD on both legs: the tag must fail to
// authenticate when the AAD is omitted or altered on decrypt.
//
// Succeeding at the round trip alone would not prove anything -- a handler
// that dropped AdditionalData on both sides would round-trip just as happily.
func TestHandleEncryptDecrypt_AADAuthenticated(t *testing.T) {
	const keyID = "aes-aad"
	server := aeadServer(t, keyID)
	defer xkms.Reset()

	aad := []byte("bound-context")
	plaintext := []byte("aead payload")

	encBody, err := json.Marshal(EncryptRequest{Plaintext: plaintext, AdditionalData: aad})
	require.NoError(t, err)
	encReq := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(encBody))
	encRec := httptest.NewRecorder()
	server.handleEncrypt(encRec, encReq, keyID, "software")
	require.Equal(t, http.StatusOK, encRec.Code, encRec.Body.String())

	var enc EncryptResponse
	require.NoError(t, json.NewDecoder(encRec.Body).Decode(&enc))

	decrypt := func(req DecryptRequest) *httptest.ResponseRecorder {
		body, mErr := json.Marshal(req)
		require.NoError(t, mErr)
		r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		server.handleDecrypt(rec, r, keyID, "software")
		return rec
	}

	rec := decrypt(DecryptRequest{
		Ciphertext: enc.Ciphertext, Nonce: enc.Nonce, Tag: enc.Tag, AdditionalData: aad,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var dec DecryptResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&dec))
	assert.Equal(t, plaintext, dec.Plaintext)

	assert.NotEqual(t, http.StatusOK,
		decrypt(DecryptRequest{Ciphertext: enc.Ciphertext, Nonce: enc.Nonce, Tag: enc.Tag}).Code,
		"decryption must fail when the AAD the tag authenticates is omitted")

	assert.NotEqual(t, http.StatusOK,
		decrypt(DecryptRequest{
			Ciphertext: enc.Ciphertext, Nonce: enc.Nonce, Tag: enc.Tag,
			AdditionalData: []byte("different-context"),
		}).Code,
		"decryption must fail when the AAD is altered")
}

// capturingEncrypter records the options a handler assembled and forwards to
// the real AEAD underneath, so a test can assert on what actually reached the
// primitive.
//
// It exists because the shared MockSymmetricEncrypter honours only the
// additional authenticated data: it generates its own nonce and always
// produces a full-length AES-GCM tag, so a nonce, tag size, cipher mode or IV
// that the handler dropped would be indistinguishable from one it forwarded.
// Capturing the options is the direct evidence that they arrived.
type capturingEncrypter struct {
	inner types.SymmetricEncrypter

	encryptOpts *types.EncryptOptions
	decryptOpts *types.DecryptOptions
}

func (c *capturingEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	c.encryptOpts = opts
	return c.inner.Encrypt(plaintext, opts)
}

func (c *capturingEncrypter) Decrypt(encrypted *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	c.decryptOpts = opts
	return c.inner.Decrypt(encrypted, opts)
}

var _ types.SymmetricEncrypter = (*capturingEncrypter)(nil)

// TestHandleEncrypt_SymmetricOptionsReachThePrimitive proves the nonce, cipher
// mode, IV and tag size a caller sends are the ones the symmetric primitive
// receives. Only Nonce was entirely absent from this transport's request type;
// the others were decoded but are asserted here so a future handler edit
// cannot quietly stop forwarding them.
func TestHandleEncrypt_SymmetricOptionsReachThePrimitive(t *testing.T) {
	const keyID = "aes-opts"
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	ext.StoreSymmetricKey(keyID, key)
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{
			CN: keyID, KeyType: types.KeyTypeSecret, StoreType: types.StoreSoftware,
			KeyAlgorithm: x509.UnknownPublicKeyAlgorithm, SymmetricAlgorithm: types.SymmetricAES256GCM,
		}}, nil
	}
	mockKS.SetKey(keyID, nil)

	capture := &capturingEncrypter{inner: &backendmocks.MockSymmetricEncrypter{
		KeyMaterial: key, Algorithm: string(types.SymmetricAES256GCM),
	}}
	ext.SymmetricEncrypterFunc = func(*types.KeyAttributes) (types.SymmetricEncrypter, error) {
		return capture, nil
	}

	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	body, err := json.Marshal(EncryptRequest{
		Plaintext:      []byte("payload"),
		AdditionalData: []byte("aad"),
		Nonce:          nonce,
		Mode:           "cbc-pad",
		IV:             iv,
		TagSize:        12,
	})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleEncrypt(rec, r, keyID, "software")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.NotNil(t, capture.encryptOpts, "the handler must reach the symmetric primitive")
	assert.Equal(t, nonce, capture.encryptOpts.Nonce, "nonce must arrive")
	assert.Equal(t, []byte("aad"), capture.encryptOpts.AdditionalData, "additional data must arrive")
	assert.Equal(t, types.CipherMode("cbc-pad"), capture.encryptOpts.Mode, "cipher mode must arrive")
	assert.Equal(t, iv, capture.encryptOpts.IV, "IV must arrive")
	assert.Equal(t, 12, capture.encryptOpts.TagSize, "tag size must arrive")
}

// TestHandleEncrypt_AbsentOptionsStayAbsent is the counterpart: a request that
// omits every optional parameter must reach the primitive with them empty, so
// the backend applies its own defaults rather than values the transport
// invented.
func TestHandleEncrypt_AbsentOptionsStayAbsent(t *testing.T) {
	const keyID = "aes-no-opts"
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	ext.StoreSymmetricKey(keyID, key)
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{
			CN: keyID, KeyType: types.KeyTypeSecret, StoreType: types.StoreSoftware,
			KeyAlgorithm: x509.UnknownPublicKeyAlgorithm, SymmetricAlgorithm: types.SymmetricAES256GCM,
		}}, nil
	}
	mockKS.SetKey(keyID, nil)

	capture := &capturingEncrypter{inner: &backendmocks.MockSymmetricEncrypter{
		KeyMaterial: key, Algorithm: string(types.SymmetricAES256GCM),
	}}
	ext.SymmetricEncrypterFunc = func(*types.KeyAttributes) (types.SymmetricEncrypter, error) {
		return capture, nil
	}

	body, err := json.Marshal(EncryptRequest{Plaintext: []byte("payload")})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleEncrypt(rec, r, keyID, "software")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.NotNil(t, capture.encryptOpts)
	assert.Empty(t, capture.encryptOpts.Nonce)
	assert.Empty(t, capture.encryptOpts.AdditionalData)
	assert.Equal(t, types.CipherMode(""), capture.encryptOpts.Mode)
	assert.Empty(t, capture.encryptOpts.IV)
	assert.Zero(t, capture.encryptOpts.TagSize)
}

// TestHandleDecrypt_SymmetricOptionsReachThePrimitive proves the decrypt leg
// forwards the cipher mode, IV and tag size that must match the ones used to
// encrypt. A tag size that does not arrive makes every short tag look like a
// forgery (NIST SP 800-38D section 5.2.2).
func TestHandleDecrypt_SymmetricOptionsReachThePrimitive(t *testing.T) {
	const keyID = "aes-dec-opts"
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	ext.StoreSymmetricKey(keyID, key)
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{
			CN: keyID, KeyType: types.KeyTypeSecret, StoreType: types.StoreSoftware,
			KeyAlgorithm: x509.UnknownPublicKeyAlgorithm, SymmetricAlgorithm: types.SymmetricAES256GCM,
		}}, nil
	}
	mockKS.SetKey(keyID, nil)

	inner := &backendmocks.MockSymmetricEncrypter{
		KeyMaterial: key, Algorithm: string(types.SymmetricAES256GCM),
	}
	encrypted, err := inner.Encrypt([]byte("payload"), &types.EncryptOptions{AdditionalData: []byte("aad")})
	require.NoError(t, err)

	capture := &capturingEncrypter{inner: inner}
	ext.SymmetricEncrypterFunc = func(*types.KeyAttributes) (types.SymmetricEncrypter, error) {
		return capture, nil
	}

	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	body, err := json.Marshal(DecryptRequest{
		Ciphertext:     encrypted.Ciphertext,
		Nonce:          encrypted.Nonce,
		Tag:            encrypted.Tag,
		AdditionalData: []byte("aad"),
		Mode:           "cbc-pad",
		IV:             iv,
		TagSize:        12,
	})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, r, keyID, "software")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.NotNil(t, capture.decryptOpts, "the handler must reach the symmetric primitive")
	assert.Equal(t, []byte("aad"), capture.decryptOpts.AdditionalData, "additional data must arrive")
	assert.Equal(t, types.CipherMode("cbc-pad"), capture.decryptOpts.Mode, "cipher mode must arrive")
	assert.Equal(t, 12, capture.decryptOpts.TagSize, "tag size must arrive")
}

// ============================================================================
// Tenant scoping
// ============================================================================

// TestHandleSign_TenantIDForwarded proves the caller's tenant reaches the
// service layer and selects which key signs. It was dropped entirely: every
// operation resolved against the untenanted backend regardless of who asked.
//
// The oracle is key identity, not the presence of an error. Two tenants own a
// key of the same name, and each request's signature must verify under its own
// tenant's key and not the other's. An assertion that a tenant-scoped call
// merely fails is satisfied by a wholly broken tenant path, which is what this
// test used to assert.
func TestHandleSign_TenantIDForwarded(t *testing.T) {
	const keyID = "tenant-sign"
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: keyID, TenantID: "tenant-a", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
			{CN: keyID, TenantID: "tenant-b", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
			{CN: "shared-sign", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	// The signer is chosen by the attributes the service resolved, so the
	// signature says which tenant's key the request actually reached.
	mockKS.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
		if attrs.TenantID == "tenant-b" {
			return keyB, nil
		}
		return keyA, nil
	}

	body, err := json.Marshal(SignRequest{Data: []byte("data"), Hash: "SHA-256"})
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("data"))

	signAs := func(cn, tenantID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
		if tenantID != "" {
			r = r.WithContext(auth.WithIdentity(r.Context(),
				&auth.Identity{Subject: "svc", TenantID: tenantID}))
		}
		rec := httptest.NewRecorder()
		server.handleSign(rec, r, cn, "software")
		return rec
	}

	recA := signAs(keyID, "tenant-a")
	require.Equal(t, http.StatusOK, recA.Code, recA.Body.String())
	sigA := decodeSignatureResponse(t, recA)
	require.NoError(t, rsa.VerifyPKCS1v15(&keyA.PublicKey, crypto.SHA256, digest[:], sigA),
		"tenant-a must sign with its own key")

	recB := signAs(keyID, "tenant-b")
	require.Equal(t, http.StatusOK, recB.Code, recB.Body.String())
	sigB := decodeSignatureResponse(t, recB)
	require.NoError(t, rsa.VerifyPKCS1v15(&keyB.PublicKey, crypto.SHA256, digest[:], sigB),
		"tenant-b must sign with its own key")
	assert.Error(t, rsa.VerifyPKCS1v15(&keyA.PublicKey, crypto.SHA256, digest[:], sigB),
		"tenant-b reached tenant-a's key")

	// Positive control: an unauthenticated caller still reaches the unscoped
	// view, so single-tenant deployments are unaffected.
	require.Equal(t, http.StatusOK, signAs("shared-sign", "").Code)

	// A tenant that owns no key of that name must not be served one.
	assert.NotEqual(t, http.StatusOK, signAs("shared-sign", "tenant-a").Code,
		"a tenant must not be served the untenanted key")
}

// TestCallerTenantID covers the helper directly, including the unauthenticated
// case where no identity is present.
func TestCallerTenantID(t *testing.T) {
	assert.Equal(t, "", callerTenantID(t.Context()),
		"a request with no identity carries no tenant")

	ctx := auth.WithIdentity(t.Context(), &auth.Identity{Subject: "svc", TenantID: "tenant-b"})
	assert.Equal(t, "tenant-b", callerTenantID(ctx))
}

// ============================================================================
// decodeSignature
// ============================================================================

// TestDecodeSignature covers every encoding this transport accepts and proves
// the malformed cases are refused rather than decoded to an empty signature,
// which would be reported as a verification failure.
func TestDecodeSignature(t *testing.T) {
	raw := []byte{0x01, 0x02, 0xFF}

	t.Run("bytes", func(t *testing.T) {
		got, err := decodeSignature(raw)
		require.NoError(t, err)
		assert.Equal(t, raw, got)
	})

	t.Run("base64 string", func(t *testing.T) {
		got, err := decodeSignature("AQL/")
		require.NoError(t, err)
		assert.Equal(t, raw, got)
	})

	t.Run("raw string", func(t *testing.T) {
		got, err := decodeSignature("not base64 !!")
		require.NoError(t, err)
		assert.Equal(t, []byte("not base64 !!"), got)
	})

	t.Run("byte array", func(t *testing.T) {
		got, err := decodeSignature([]interface{}{float64(1), float64(2), float64(255)})
		require.NoError(t, err)
		assert.Equal(t, raw, got)
	})

	t.Run("nil is refused", func(t *testing.T) {
		_, err := decodeSignature(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})

	t.Run("non-byte array is refused", func(t *testing.T) {
		_, err := decodeSignature([]interface{}{"not a number"})
		require.Error(t, err)
	})

	t.Run("object is refused", func(t *testing.T) {
		_, err := decodeSignature(map[string]interface{}{"foo": "bar"})
		require.Error(t, err)
	})
}
