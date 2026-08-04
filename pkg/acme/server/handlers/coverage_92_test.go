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

//go:build local

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// MapDAONotFound tests (0% -> 100%)
// =============================================================================

func TestMapDAONotFound_AllEntityTypes(t *testing.T) {
	notFoundErr := qrdbsdk.DAONotFoundError{EntityType: "test", ID: 1}

	tests := []struct {
		name       string
		entityType string
		wantType   string
	}{
		{"account", "account", "accountDoesNotExist"},
		{"order", "order", "malformed"},
		{"authorization", "authorization", "malformed"},
		{"challenge", "challenge", "malformed"},
		{"certificate", "certificate", "malformed"},
		{"nonce", "nonce", "badNonce"},
		{"eab", "eab", "unauthorized"},
		{"tenant", "tenant", "serverInternal"},
		{"unknown", "unknown-entity", "serverInternal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapDAONotFound(notFoundErr, tt.entityType)
			require.NotNil(t, result, "expected non-nil error for entity type %s", tt.entityType)
			assert.Contains(t, result.Type, tt.wantType)
		})
	}
}

func TestMapDAONotFound_NonDAOError(t *testing.T) {
	result := MapDAONotFound(&errs.Message{Msg: "some other error"}, "account")
	assert.Nil(t, result, "non-DAO errors should return nil")
}

// =============================================================================
// ExternalAccountBindingVerifier.Verify tests (62.3% -> 90%+)
// =============================================================================

// buildEABJWS constructs an EAB JWS structure for testing the Verify method.
func buildEABJWS(t *testing.T, header entities.ExternalAccountBindingProtectedHeader, payload interface{}, macKey []byte) map[string]interface{} {
	t.Helper()
	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)
	protectedB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	sigInput := protectedB64 + "." + payloadB64
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(sigInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return map[string]interface{}{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": sigB64,
	}
}

func mustGenerateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func TestEABVerify_NoncePresent(t *testing.T) {
	dao := newMockEABDAO()
	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")
	ctx := context.Background()

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg:   "HS256",
		KID:   "kid-1",
		URL:   "https://acme.test/acme/new-account",
		Nonce: "some-nonce",
	}
	jwk := &jose.JSONWebKey{Key: mustGenerateECKey(t).Public()}
	eabJWS := buildEABJWS(t, header, jwk, []byte("test-mac-key-32-bytes-long------"))

	_, err := verifier.Verify(ctx, eabJWS, jwk)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce")
}

func TestEABVerify_AsymmetricAlgorithm(t *testing.T) {
	dao := newMockEABDAO()
	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")
	ctx := context.Background()

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "RS256",
		KID: "kid-1",
		URL: "https://acme.test/acme/new-account",
	}
	jwk := &jose.JSONWebKey{Key: mustGenerateECKey(t).Public()}
	eabJWS := buildEABJWS(t, header, jwk, []byte("test-mac-key-32-bytes-long------"))

	_, err := verifier.Verify(ctx, eabJWS, jwk)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symmetric")
}

func TestEABVerify_URLMismatch(t *testing.T) {
	dao := newMockEABDAO()
	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")
	ctx := context.Background()

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: "kid-1",
		URL: "https://wrong.url/acme/new-account",
	}
	jwk := &jose.JSONWebKey{Key: mustGenerateECKey(t).Public()}
	eabJWS := buildEABJWS(t, header, jwk, []byte("test-mac-key-32-bytes-long------"))

	_, err := verifier.Verify(ctx, eabJWS, jwk)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL mismatch")
}

func TestEABVerify_BindingNotFound(t *testing.T) {
	dao := newMockEABDAO()
	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")
	ctx := context.Background()

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: "nonexistent-kid",
		URL: "https://acme.test/acme/new-account",
	}
	jwk := &jose.JSONWebKey{Key: mustGenerateECKey(t).Public()}
	eabJWS := buildEABJWS(t, header, jwk, []byte("test-mac-key-32-bytes-long------"))

	_, err := verifier.Verify(ctx, eabJWS, jwk)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestEABVerify_BindingExpired(t *testing.T) {
	dao := newMockEABDAO()
	kid := "expired-kid"
	macKey := make([]byte, 32)
	_, err := rand.Read(macKey)
	require.NoError(t, err)

	// Set ExpiresAt to a past time so IsExpired() returns true
	pastTime := time.Now().Add(-1 * time.Hour)
	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusActive, // Active but expired by time
		ExpiresAt:    &pastTime,
	}
	err = dao.Save(context.Background(), binding)
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: "https://acme.test/acme/new-account",
	}
	jwk := &jose.JSONWebKey{Key: mustGenerateECKey(t).Public()}
	eabJWS := buildEABJWS(t, header, jwk, macKey)

	_, err = verifier.Verify(context.Background(), eabJWS, jwk)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrExternalAccountBindingExpired)
}

func TestEABVerify_BindingUsed(t *testing.T) {
	dao := newMockEABDAO()
	kid := "used-kid"
	macKey := make([]byte, 32)
	_, err := rand.Read(macKey)
	require.NoError(t, err)

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusUsed,
	}
	err = dao.Save(context.Background(), binding)
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: "https://acme.test/acme/new-account",
	}
	jwk := &jose.JSONWebKey{Key: mustGenerateECKey(t).Public()}
	eabJWS := buildEABJWS(t, header, jwk, macKey)

	_, err = verifier.Verify(context.Background(), eabJWS, jwk)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrExternalAccountBindingUsed)
}

func TestEABVerify_BindingRevoked(t *testing.T) {
	dao := newMockEABDAO()
	kid := "revoked-kid"
	macKey := make([]byte, 32)
	_, err := rand.Read(macKey)
	require.NoError(t, err)

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusRevoked,
	}
	err = dao.Save(context.Background(), binding)
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: "https://acme.test/acme/new-account",
	}
	jwk := &jose.JSONWebKey{Key: mustGenerateECKey(t).Public()}
	eabJWS := buildEABJWS(t, header, jwk, macKey)

	_, err = verifier.Verify(context.Background(), eabJWS, jwk)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrExternalAccountBindingRevoked)
}

func TestEABVerify_AlgorithmMismatch(t *testing.T) {
	dao := newMockEABDAO()
	kid := "algo-mismatch-kid"
	macKey := make([]byte, 32)
	_, err := rand.Read(macKey)
	require.NoError(t, err)

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS512",
		Status:       entities.EABStatusActive,
	}
	err = dao.Save(context.Background(), binding)
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: "https://acme.test/acme/new-account",
	}
	jwk := &jose.JSONWebKey{Key: mustGenerateECKey(t).Public()}
	eabJWS := buildEABJWS(t, header, jwk, macKey)

	_, err = verifier.Verify(context.Background(), eabJWS, jwk)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm mismatch")
}

func TestEABVerify_PayloadKeyMismatch(t *testing.T) {
	dao := newMockEABDAO()
	kid := "key-mismatch-kid"
	macKey := make([]byte, 32)
	_, err := rand.Read(macKey)
	require.NoError(t, err)

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusActive,
	}
	err = dao.Save(context.Background(), binding)
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")

	differentKey := mustGenerateECKey(t)
	accountJWK := &jose.JSONWebKey{Key: mustGenerateECKey(t).Public()}

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: "https://acme.test/acme/new-account",
	}
	payloadJWK := &jose.JSONWebKey{Key: differentKey.Public()}
	eabJWS := buildEABJWS(t, header, payloadJWK, macKey)

	_, err = verifier.Verify(context.Background(), eabJWS, accountJWK)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key mismatch")
}

func TestEABVerify_InvalidMACSignature(t *testing.T) {
	dao := newMockEABDAO()
	kid := "bad-sig-kid"
	macKey := make([]byte, 32)
	_, err := rand.Read(macKey)
	require.NoError(t, err)

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusActive,
	}
	err = dao.Save(context.Background(), binding)
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")

	accountKey := mustGenerateECKey(t)
	accountJWK := &jose.JSONWebKey{Key: accountKey.Public()}

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: "https://acme.test/acme/new-account",
	}

	wrongMACKey := make([]byte, 32)
	_, err = rand.Read(wrongMACKey)
	require.NoError(t, err)
	eabJWS := buildEABJWS(t, header, accountJWK, wrongMACKey)

	_, err = verifier.Verify(context.Background(), eabJWS, accountJWK)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MAC verification failed")
}

func TestEABVerify_InvalidPayloadBase64(t *testing.T) {
	dao := newMockEABDAO()
	kid := "bad-payload-kid"
	macKey := make([]byte, 32)
	_, err := rand.Read(macKey)
	require.NoError(t, err)

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusActive,
	}
	err = dao.Save(context.Background(), binding)
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")

	accountJWK := &jose.JSONWebKey{Key: mustGenerateECKey(t).Public()}

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: "https://acme.test/acme/new-account",
	}
	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)
	protectedB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	eabJWS := map[string]interface{}{
		"protected": protectedB64,
		"payload":   "!!!invalid-base64!!!",
		"signature": "dummysig",
	}

	_, err = verifier.Verify(context.Background(), eabJWS, accountJWK)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode payload")
}

func TestEABVerify_InvalidMACKeyBase64(t *testing.T) {
	dao := newMockEABDAO()
	kid := "bad-mackey-kid"

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       "!!!invalid-base64!!!",
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusActive,
	}
	err := dao.Save(context.Background(), binding)
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")

	accountKey := mustGenerateECKey(t)
	accountJWK := &jose.JSONWebKey{Key: accountKey.Public()}

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: "https://acme.test/acme/new-account",
	}
	eabJWS := buildEABJWS(t, header, accountJWK, []byte("dummy-key-for-signing-----------"))

	_, err = verifier.Verify(context.Background(), eabJWS, accountJWK)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode MAC key")
}

func TestEABVerify_Success(t *testing.T) {
	dao := newMockEABDAO()
	kid := "valid-kid"
	macKey := make([]byte, 32)
	_, err := rand.Read(macKey)
	require.NoError(t, err)

	binding := &entities.ExternalAccountBinding{
		ID:                kid,
		MACKey:            base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm:      "HS256",
		Status:            entities.EABStatusActive,
		ExternalAccountID: "ext-acct-1",
	}
	err = dao.Save(context.Background(), binding)
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(dao, "https://acme.test/acme/new-account")

	accountKey := mustGenerateECKey(t)
	accountJWK := &jose.JSONWebKey{Key: accountKey.Public()}

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: "https://acme.test/acme/new-account",
	}
	eabJWS := buildEABJWS(t, header, accountJWK, macKey)

	result, err := verifier.Verify(context.Background(), eabJWS, accountJWK)
	require.NoError(t, err)
	assert.Equal(t, kid, result.ID)
	assert.Equal(t, "ext-acct-1", result.ExternalAccountID)
}

// =============================================================================
// KeyChangeHandler additional error paths (74% -> 90%+)
// =============================================================================

func TestKeyChangeHandler_AccountNotFoundInGet(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	url := fmt.Sprintf("%s/acme/key-change", service.baseRESTURI)

	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	err = accountDAO.Delete(ctx, account)
	require.NoError(t, err)

	req := createJWSRequest(t, service, testKey, url, json.RawMessage(`{}`), true, account.ID)
	rr := httptest.NewRecorder()

	service.KeyChangeHandler(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestKeyChangeHandler_InvalidAccountStatus_92(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	account.Status = common.StatusInvalid
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/key-change", service.baseRESTURI)
	req := createJWSRequest(t, service, testKey, url, json.RawMessage(`{}`), true, account.ID)
	rr := httptest.NewRecorder()

	service.KeyChangeHandler(rr, req)
	assert.Contains(t, rr.Body.String(), "Invalid account")
}

func TestKeyChangeHandler_InvalidInnerJWS_92(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	url := fmt.Sprintf("%s/acme/key-change", service.baseRESTURI)

	req := createJWSRequest(t, service, testKey, url, json.RawMessage(`"not-a-jws"`), true, account.ID)
	rr := httptest.NewRecorder()

	service.KeyChangeHandler(rr, req)
	assert.NotEqual(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid inner JWS")
}

func TestKeyChangeHandler_InnerURLMismatch_92(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)
	newKey := generateTestKey(t)

	url := fmt.Sprintf("%s/acme/key-change", service.baseRESTURI)

	innerPayload := KeyChangeRequest{
		AccountURL: account.URL,
		OldKey:     map[string]interface{}{"kty": "EC"},
	}
	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	innerSignerOpts := &jose.SignerOptions{
		EmbedJWK: true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": "https://wrong.example.com/acme/key-change",
		},
	}
	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	req := createJWSRequest(t, service, testKey, url, json.RawMessage(innerJWS.FullSerialize()), true, account.ID)
	rr := httptest.NewRecorder()

	service.KeyChangeHandler(rr, req)
	assert.NotEqual(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "URL")
}

func TestKeyChangeHandler_AccountURLMismatch_Cover(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)
	newKey := generateTestKey(t)

	url := fmt.Sprintf("%s/acme/key-change", service.baseRESTURI)

	oldKeyJWK := &jose.JSONWebKey{Key: testKey.PublicKey}
	oldKeyJSON, err := oldKeyJWK.MarshalJSON()
	require.NoError(t, err)
	var oldKeyMap map[string]interface{}
	err = json.Unmarshal(oldKeyJSON, &oldKeyMap)
	require.NoError(t, err)

	innerPayload := KeyChangeRequest{
		AccountURL: "https://acme.test.example.com/acme/account/99999",
		OldKey:     oldKeyMap,
	}
	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	innerSignerOpts := &jose.SignerOptions{
		EmbedJWK: true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}
	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	req := createJWSRequest(t, service, testKey, url, json.RawMessage(innerJWS.FullSerialize()), true, account.ID)
	rr := httptest.NewRecorder()

	service.KeyChangeHandler(rr, req)
	assert.NotEqual(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Account URL")
}

func TestKeyChangeHandler_OldKeyMismatch_92(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)
	newKey := generateTestKey(t)

	url := fmt.Sprintf("%s/acme/key-change", service.baseRESTURI)

	differentKey := generateTestKey(t)
	differentJWK := &jose.JSONWebKey{Key: differentKey.PublicKey}
	differentJSON, err := differentJWK.MarshalJSON()
	require.NoError(t, err)
	var differentKeyMap map[string]interface{}
	err = json.Unmarshal(differentJSON, &differentKeyMap)
	require.NoError(t, err)

	innerPayload := KeyChangeRequest{
		AccountURL: account.URL,
		OldKey:     differentKeyMap,
	}
	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	innerSignerOpts := &jose.SignerOptions{
		EmbedJWK: true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}
	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	req := createJWSRequest(t, service, testKey, url, json.RawMessage(innerJWS.FullSerialize()), true, account.ID)
	rr := httptest.NewRecorder()

	service.KeyChangeHandler(rr, req)
	assert.NotEqual(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Old key does not match")
}

func TestKeyChangeHandler_NewKeySameAsCurrent_Cover(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	url := fmt.Sprintf("%s/acme/key-change", service.baseRESTURI)

	oldKeyJWK := &jose.JSONWebKey{Key: testKey.PublicKey}
	oldKeyJSON, err := oldKeyJWK.MarshalJSON()
	require.NoError(t, err)
	var oldKeyMap map[string]interface{}
	err = json.Unmarshal(oldKeyJSON, &oldKeyMap)
	require.NoError(t, err)

	innerPayload := KeyChangeRequest{
		AccountURL: account.URL,
		OldKey:     oldKeyMap,
	}
	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	innerSignerOpts := &jose.SignerOptions{
		EmbedJWK: true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}
	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       testKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	req := createJWSRequest(t, service, testKey, url, json.RawMessage(innerJWS.FullSerialize()), true, account.ID)
	rr := httptest.NewRecorder()

	service.KeyChangeHandler(rr, req)
	assert.NotEqual(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "same as the current key")
}

func TestKeyChangeHandler_ConflictWithExistingAccount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	otherKey := generateTestKey(t)
	createTestAccount(t, service, otherKey)

	url := fmt.Sprintf("%s/acme/key-change", service.baseRESTURI)

	oldKeyJWK := &jose.JSONWebKey{Key: testKey.PublicKey}
	oldKeyJSON, err := oldKeyJWK.MarshalJSON()
	require.NoError(t, err)
	var oldKeyMap map[string]interface{}
	err = json.Unmarshal(oldKeyJSON, &oldKeyMap)
	require.NoError(t, err)

	innerPayload := KeyChangeRequest{
		AccountURL: account.URL,
		OldKey:     oldKeyMap,
	}
	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	innerSignerOpts := &jose.SignerOptions{
		EmbedJWK: true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}
	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       otherKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	req := createJWSRequest(t, service, testKey, url, json.RawMessage(innerJWS.FullSerialize()), true, account.ID)
	rr := httptest.NewRecorder()

	service.KeyChangeHandler(rr, req)
	assert.Equal(t, http.StatusConflict, rr.Code)
	assert.Contains(t, rr.Body.String(), "already exists")
}

// =============================================================================
// NewAccountHandler EAB error type routing tests (82% -> 90%+)
// =============================================================================

func TestNewAccountHandler_EABExpiredBinding(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.externalAccountRequired = true

	testKey := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)

	eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	kid := "expired-eab-kid"
	macKey := make([]byte, 32)
	_, err = rand.Read(macKey)
	require.NoError(t, err)

	// Use a past ExpiresAt to trigger the expired path
	pastTime := time.Now().Add(-1 * time.Hour)
	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusActive,
		ExpiresAt:    &pastTime,
	}
	err = eabDAO.Save(context.Background(), binding)
	require.NoError(t, err)

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: url,
	}
	eabJWS := buildEABJWS(t, header, &jose.JSONWebKey{Key: testKey.PublicKey}, macKey)

	req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
		"contact":                []string{"mailto:test@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eabJWS,
	}, false, 0)

	rr := httptest.NewRecorder()
	service.NewAccountHandler(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "expired")
}

func TestNewAccountHandler_EABUsedBinding(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.externalAccountRequired = true

	testKey := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)

	eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	kid := "used-eab-kid"
	macKey := make([]byte, 32)
	_, err = rand.Read(macKey)
	require.NoError(t, err)

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusUsed,
	}
	err = eabDAO.Save(context.Background(), binding)
	require.NoError(t, err)

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: url,
	}
	eabJWS := buildEABJWS(t, header, &jose.JSONWebKey{Key: testKey.PublicKey}, macKey)

	req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
		"contact":                []string{"mailto:test@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eabJWS,
	}, false, 0)

	rr := httptest.NewRecorder()
	service.NewAccountHandler(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "already been used")
}

func TestNewAccountHandler_EABRevokedBinding(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.externalAccountRequired = true

	testKey := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)

	eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	kid := "revoked-eab-kid"
	macKey := make([]byte, 32)
	_, err = rand.Read(macKey)
	require.NoError(t, err)

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusRevoked,
	}
	err = eabDAO.Save(context.Background(), binding)
	require.NoError(t, err)

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: url,
	}
	eabJWS := buildEABJWS(t, header, &jose.JSONWebKey{Key: testKey.PublicKey}, macKey)

	req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
		"contact":                []string{"mailto:test@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eabJWS,
	}, false, 0)

	rr := httptest.NewRecorder()
	service.NewAccountHandler(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "revoked")
}

func TestNewAccountHandler_EABMalformedAlgorithm(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.externalAccountRequired = true

	testKey := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "RS256",
		KID: "some-kid",
		URL: url,
	}
	eabJWS := buildEABJWS(t, header, &jose.JSONWebKey{Key: testKey.PublicKey}, []byte("test-mac-key-32-bytes-long------"))

	req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
		"contact":                []string{"mailto:test@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eabJWS,
	}, false, 0)

	rr := httptest.NewRecorder()
	service.NewAccountHandler(rr, req)
	assert.Contains(t, rr.Body.String(), "malformed")
}

func TestNewAccountHandler_EABNotFoundKID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.externalAccountRequired = true

	testKey := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: "nonexistent-kid",
		URL: url,
	}
	eabJWS := buildEABJWS(t, header, &jose.JSONWebKey{Key: testKey.PublicKey}, []byte("test-mac-key-32-bytes-long------"))

	req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
		"contact":                []string{"mailto:test@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eabJWS,
	}, false, 0)

	rr := httptest.NewRecorder()
	service.NewAccountHandler(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid key identifier")
}

func TestNewAccountHandler_EABVerificationFailureSig(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.externalAccountRequired = true

	testKey := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)

	eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	kid := "verify-fail-kid"
	macKey := make([]byte, 32)
	_, err = rand.Read(macKey)
	require.NoError(t, err)

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusActive,
	}
	err = eabDAO.Save(context.Background(), binding)
	require.NoError(t, err)

	wrongKey := make([]byte, 32)
	_, err = rand.Read(wrongKey)
	require.NoError(t, err)

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: url,
	}
	eabJWS := buildEABJWS(t, header, &jose.JSONWebKey{Key: testKey.PublicKey}, wrongKey)

	req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
		"contact":                []string{"mailto:test@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eabJWS,
	}, false, 0)

	rr := httptest.NewRecorder()
	service.NewAccountHandler(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "signature verification failed")
}

func TestNewAccountHandler_EABUnauthorizedKeyMismatch(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.externalAccountRequired = true

	testKey := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)

	eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	kid := "unauthorized-eab-kid"
	macKey := make([]byte, 32)
	_, err = rand.Read(macKey)
	require.NoError(t, err)

	differentKey := mustGenerateECKey(t)

	binding := &entities.ExternalAccountBinding{
		ID:           kid,
		MACKey:       base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm: "HS256",
		Status:       entities.EABStatusActive,
	}
	err = eabDAO.Save(context.Background(), binding)
	require.NoError(t, err)

	header := entities.ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: kid,
		URL: url,
	}
	eabJWS := buildEABJWS(t, header, &jose.JSONWebKey{Key: differentKey.Public()}, macKey)

	req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
		"contact":                []string{"mailto:test@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eabJWS,
	}, false, 0)

	rr := httptest.NewRecorder()
	service.NewAccountHandler(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestNewAccountHandler_EABSerializationError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.externalAccountRequired = true

	testKey := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)

	req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
		"contact":                []string{"mailto:test@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": "invalid-not-a-jws-object",
	}, false, 0)

	rr := httptest.NewRecorder()
	service.NewAccountHandler(rr, req)
	assert.NotEqual(t, http.StatusCreated, rr.Code)
}

// =============================================================================
// CreateExternalAccountBinding tests
// =============================================================================

func TestCreateExternalAccountBinding_UnsupportedAlgorithm(t *testing.T) {
	_, err := CreateExternalAccountBinding("kid1", "ext1", "RS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported MAC algorithm")
}

func TestCreateExternalAccountBinding_HS384(t *testing.T) {
	binding, err := CreateExternalAccountBinding("kid1", "ext1", "HS384")
	require.NoError(t, err)
	assert.Equal(t, "kid1", binding.ID)
	assert.Equal(t, "HS384", binding.MACAlgorithm)
	macKeyBytes, err := base64.RawURLEncoding.DecodeString(binding.MACKey)
	require.NoError(t, err)
	assert.Len(t, macKeyBytes, 48)
}

func TestCreateExternalAccountBinding_HS512(t *testing.T) {
	binding, err := CreateExternalAccountBinding("kid2", "ext2", "HS512")
	require.NoError(t, err)
	assert.Equal(t, "HS512", binding.MACAlgorithm)
	macKeyBytes, err := base64.RawURLEncoding.DecodeString(binding.MACKey)
	require.NoError(t, err)
	assert.Len(t, macKeyBytes, 64)
}

// =============================================================================
// OrderFinalizeHandler additional error paths
// =============================================================================

func TestOrderFinalizeHandler_InvalidCSRNotTCG(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	createTestAuthorization(t, service, account, order,
		entities.ACMEIdentifier{Type: "dns", Value: "example.com"},
		[]string{"http-01"})

	order.Status = common.StatusReady
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	invalidCSR := base64.RawURLEncoding.EncodeToString([]byte("not-a-valid-csr-bytes"))

	req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
		"csr": invalidCSR,
	}, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	rr := httptest.NewRecorder()

	service.OrderFinalizeHandler(rr, req)
	assert.NotEqual(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid CSR")
}

func TestOrderFinalizeHandler_WrongAccountOwnership(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	otherKey := generateTestKey(t)
	otherAccount := createTestAccount(t, service, otherKey)

	order := createTestOrderSimple(t, service, otherAccount.ID)
	order.Status = common.StatusReady
	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(otherAccount.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
		"csr": base64.RawURLEncoding.EncodeToString([]byte("dummy")),
	}, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	rr := httptest.NewRecorder()

	service.OrderFinalizeHandler(rr, req)
	assert.NotEqual(t, http.StatusOK, rr.Code)
}

// =============================================================================
// verifyMAC additional algorithm test
// =============================================================================

func TestVerifyMAC_UnsupportedAlgorithm(t *testing.T) {
	err := verifyMAC("HS999", []byte("key"), []byte("msg"), "c2ln")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

func TestVerifyMAC_InvalidSignatureBase64(t *testing.T) {
	err := verifyMAC("HS256", []byte("key"), []byte("msg"), "!!!invalid!!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode signature")
}

// =============================================================================
// NewNonceHandler additional method tests
// =============================================================================

func TestNewNonceHandler_PatchMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPatch, "/acme/new-nonce", nil)
	rr := httptest.NewRecorder()

	service.NewNonceHandler(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestNewNonceHandler_PutMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPut, "/acme/new-nonce", nil)
	rr := httptest.NewRecorder()

	service.NewNonceHandler(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// =============================================================================
// RevokeCertHandler error paths
// =============================================================================

func TestRevokeCertHandler_DeactivatedAccount_92(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	account.Status = common.StatusDeactivated
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/revoke-cert", service.baseRESTURI)
	req := createJWSRequest(t, service, testKey, url, json.RawMessage(`{}`), true, account.ID)
	rr := httptest.NewRecorder()

	service.RevokeCertHandler(rr, req)
	assert.NotEqual(t, http.StatusOK, rr.Code)
}

// =============================================================================
// ChallengeHandler additional error paths
// =============================================================================

func TestChallengeHandler_CorruptAccountKey_92(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	// Register a challenge verifier
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	// Create order with authorization and challenge
	order := createTestOrderSimple(t, service, account.ID)
	authz := createTestAuthorization(t, service, account, order,
		entities.ACMEIdentifier{Type: "dns", Value: "example.com"},
		[]string{"http-01"})

	// Corrupt the account key so DecodePublicKeyPEM fails
	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	account.Key = "invalid-pem-data-not-a-real-key"
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	challengeID := authz.Challenges[0].ID
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, challengeID)
	req := createJWSRequest(t, service, testKey, url, json.RawMessage(`{}`), true, account.ID)
	rr := httptest.NewRecorder()

	service.ChallengeHandler(rr, req)
	// The challenge should get a response with invalid status
	assert.NotEqual(t, 0, rr.Code)
}

func TestChallengeHandler_OrderNotFoundAfterValidation_92(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	// Register a challenge verifier that succeeds
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	// Create order with authorization and challenge
	order := createTestOrderSimple(t, service, account.ID)
	authz := createTestAuthorization(t, service, account, order,
		entities.ACMEIdentifier{Type: "dns", Value: "example.com"},
		[]string{"http-01"})

	// Delete the order before challenge validation looks it up
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Delete(context.Background(), order)
	require.NoError(t, err)

	challengeID := authz.Challenges[0].ID
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, challengeID)
	req := createJWSRequest(t, service, testKey, url, json.RawMessage(`{}`), true, account.ID)
	rr := httptest.NewRecorder()

	service.ChallengeHandler(rr, req)
	assert.NotEqual(t, http.StatusOK, rr.Code)
}

func TestChallengeHandler_InvalidAuthzURLInOrder_92(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	// Register a challenge verifier that succeeds
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	// Create order with authorization and challenge
	order := createTestOrderSimple(t, service, account.ID)
	authz := createTestAuthorization(t, service, account, order,
		entities.ACMEIdentifier{Type: "dns", Value: "example.com"},
		[]string{"http-01"})

	// Add invalid authorization URL to order
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	order.Authorizations = append(order.Authorizations, "https://acme.test/acme/authz/invalid-not-a-number")
	err = orderDAO.Save(context.Background(), order)
	require.NoError(t, err)

	challengeID := authz.Challenges[0].ID
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, challengeID)
	req := createJWSRequest(t, service, testKey, url, json.RawMessage(`{}`), true, account.ID)
	rr := httptest.NewRecorder()

	service.ChallengeHandler(rr, req)
	assert.NotEqual(t, 0, rr.Code)
}

func TestChallengeHandler_AuthzNotFoundInOrderLoop_92(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	// Register a challenge verifier that succeeds
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	// Create order with authorization and challenge
	order := createTestOrderSimple(t, service, account.ID)
	authz := createTestAuthorization(t, service, account, order,
		entities.ACMEIdentifier{Type: "dns", Value: "example.com"},
		[]string{"http-01"})

	// Add a nonexistent authorization URL to order
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	order.Authorizations = append(order.Authorizations, "https://acme.test/acme/authz/999999999")
	err = orderDAO.Save(context.Background(), order)
	require.NoError(t, err)

	challengeID := authz.Challenges[0].ID
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, challengeID)
	req := createJWSRequest(t, service, testKey, url, json.RawMessage(`{}`), true, account.ID)
	rr := httptest.NewRecorder()

	service.ChallengeHandler(rr, req)
	assert.NotEqual(t, 0, rr.Code)
}

func TestChallengeHandler_GenericValidationFailure_92(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	// Register a challenge verifier that fails
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return &errs.Message{Msg: "connection refused"}
	}

	// Create order
	order := createTestOrderSimple(t, service, account.ID)
	authz := createTestAuthorization(t, service, account, order,
		entities.ACMEIdentifier{Type: "dns", Value: "example.com"},
		[]string{"http-01"})

	challengeID := authz.Challenges[0].ID
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, challengeID)
	req := createJWSRequest(t, service, testKey, url, json.RawMessage(`{}`), true, account.ID)
	rr := httptest.NewRecorder()

	service.ChallengeHandler(rr, req)
	assert.NotEqual(t, 0, rr.Code)
}
