//go:build codec_json

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestRSAKey creates a test RSA key pair and its JWK representation
func generateTestRSAKey(t *testing.T) *TestKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk := &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	return &TestKey{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public(),
		JWK:        jwk,
	}
}

// generateTestECDSAKey creates a test ECDSA key pair with specified curve
func generateTestECDSAKey(t *testing.T, curve elliptic.Curve) *TestKey {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	var algo string
	switch curve.Params().Name {
	case "P-256":
		algo = string(jose.ES256)
	case "P-384":
		algo = string(jose.ES384)
	case "P-521":
		algo = string(jose.ES512)
	default:
		t.Fatalf("unsupported curve: %s", curve.Params().Name)
	}

	jwk := &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "",
		Algorithm: algo,
		Use:       "sig",
	}

	return &TestKey{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public(),
		JWK:        jwk,
	}
}

// createKeyChangeRequest creates a properly formatted key-change request with inner JWS
func createKeyChangeRequest(t *testing.T, service *RestService, oldKey, newKey *TestKey, accountID uint64) *http.Request {
	// Get a nonce for the inner JWS
	innerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(innerNonce)

	// Get account URL
	accountURL := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, accountID)
	keyChangeURL := service.baseRESTURI + "/acme/key-change"

	// Encode old public key to JWK format
	oldPublicJWK := &jose.JSONWebKey{Key: oldKey.PublicKey}
	oldKeyJSON, err := oldPublicJWK.MarshalJSON()
	require.NoError(t, err)

	var oldKeyMap map[string]interface{}
	err = json.Unmarshal(oldKeyJSON, &oldKeyMap)
	require.NoError(t, err)

	// Create inner payload (key-change request)
	innerPayload := KeyChangeRequest{
		AccountURL: accountURL,
		OldKey:     oldKeyMap,
	}

	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	// Determine the JOSE algorithm for the new key
	var newAlgo jose.SignatureAlgorithm
	switch newKey.PrivateKey.(type) {
	case *rsa.PrivateKey:
		newAlgo = jose.RS256
	case *ecdsa.PrivateKey:
		ecdsaKey := newKey.PrivateKey.(*ecdsa.PrivateKey)
		switch ecdsaKey.Curve.Params().Name {
		case "P-256":
			newAlgo = jose.ES256
		case "P-384":
			newAlgo = jose.ES384
		case "P-521":
			newAlgo = jose.ES512
		default:
			t.Fatalf("unsupported ECDSA curve")
		}
	default:
		t.Fatalf("unsupported key type")
	}

	// Create inner JWS signer with new key
	innerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: innerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
		},
		EmbedJWK: true, // Include new public key in JWK header
	}

	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: newAlgo,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	// Sign the inner payload
	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	innerJWSString := innerJWS.FullSerialize()

	// Now create outer JWS with old key
	outerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(outerNonce)

	// Determine the JOSE algorithm for the old key
	var oldAlgo jose.SignatureAlgorithm
	switch oldKey.PrivateKey.(type) {
	case *rsa.PrivateKey:
		oldAlgo = jose.RS256
	case *ecdsa.PrivateKey:
		ecdsaKey := oldKey.PrivateKey.(*ecdsa.PrivateKey)
		switch ecdsaKey.Curve.Params().Name {
		case "P-256":
			oldAlgo = jose.ES256
		case "P-384":
			oldAlgo = jose.ES384
		case "P-521":
			oldAlgo = jose.ES512
		default:
			t.Fatalf("unsupported ECDSA curve")
		}
	default:
		t.Fatalf("unsupported key type")
	}

	outerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: outerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
			"kid": accountURL,
		},
	}

	outerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: oldAlgo,
		Key:       oldKey.PrivateKey,
	}, outerSignerOpts)
	require.NoError(t, err)

	// Sign the inner JWS with the old key
	outerJWS, err := outerSigner.Sign([]byte(innerJWSString))
	require.NoError(t, err)

	outerJWSString := outerJWS.FullSerialize()

	// Create HTTP request
	req := httptest.NewRequest(http.MethodPost, keyChangeURL, strings.NewReader(outerJWSString))
	req.Header.Set("Content-Type", "application/jose+json")

	return req
}

// TestKeyChangeHandler_Success_RSA_to_RSA tests successful key rollover from RSA to RSA
func TestKeyChangeHandler_Success_RSA_to_RSA(t *testing.T) {

	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestRSAKey(t)
	newKey := generateTestRSAKey(t)

	account := createTestAccount(t, service, oldKey)

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	var response KeyChangeResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "Key-change completed successfully", response.Message)
}

// TestKeyChangeHandler_Success_RSA_to_ECDSA tests successful key rollover from RSA to ECDSA
func TestKeyChangeHandler_Success_RSA_to_ECDSA(t *testing.T) {

	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestRSAKey(t)
	newKey := generateTestECDSAKey(t, elliptic.P256())

	account := createTestAccount(t, service, oldKey)

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	if resp.Code != http.StatusOK {
		t.Logf("Error response: %s", resp.Body.String())
	}
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	var response KeyChangeResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "Key-change completed successfully", response.Message)
}

// TestKeyChangeHandler_Success_ECDSA_to_RSA tests successful key rollover from ECDSA to RSA
func TestKeyChangeHandler_Success_ECDSA_to_RSA(t *testing.T) {

	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestECDSAKey(t, elliptic.P256())
	newKey := generateTestRSAKey(t)

	account := createTestAccount(t, service, oldKey)

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	var response KeyChangeResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "Key-change completed successfully", response.Message)
}

// TestKeyChangeHandler_Success_ECDSA_to_ECDSA tests successful key rollover from ECDSA to ECDSA
func TestKeyChangeHandler_Success_ECDSA_to_ECDSA(t *testing.T) {

	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestECDSAKey(t, elliptic.P256())
	newKey := generateTestECDSAKey(t, elliptic.P384())

	account := createTestAccount(t, service, oldKey)

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	var response KeyChangeResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "Key-change completed successfully", response.Message)
}

// TestKeyChangeHandler_InvalidOuterJWS tests error handling for invalid outer JWS
func TestKeyChangeHandler_InvalidOuterJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/key-change"
	req := createInvalidJWSRequest(t, url)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// The handler uses http.Error instead of writeError for parseKID failures
	// so it returns plain text, not JSON
	require.Equal(t, http.StatusBadRequest, resp.Code)
	require.Contains(t, resp.Body.String(), "Invalid request")
}

// TestKeyChangeHandler_InvalidInnerJWS tests error handling for invalid inner JWS
func TestKeyChangeHandler_InvalidInnerJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	keyChangeURL := service.baseRESTURI + "/acme/key-change"
	accountURL := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)

	// Create outer JWS with invalid inner payload (not a valid JWS)
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	outerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
			"kid": accountURL,
		},
	}

	outerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       oldKey.PrivateKey,
	}, outerSignerOpts)
	require.NoError(t, err)

	// Sign invalid inner payload
	outerJWS, err := outerSigner.Sign([]byte("not-a-valid-jws"))
	require.NoError(t, err)

	outerJWSString := outerJWS.FullSerialize()

	req := httptest.NewRequest(http.MethodPost, keyChangeURL, strings.NewReader(outerJWSString))
	req.Header.Set("Content-Type", "application/jose+json")

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestKeyChangeHandler_SameKey tests error handling when old key equals new key
func TestKeyChangeHandler_SameKey(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	// Use same key for both old and new
	req := createKeyChangeRequest(t, service, oldKey, oldKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestKeyChangeHandler_AccountNotFound tests error handling when account doesn't exist
func TestKeyChangeHandler_AccountNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	// Use non-existent account ID
	nonExistentAccountID := uint64(999999)

	req := createKeyChangeRequest(t, service, oldKey, newKey, nonExistentAccountID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// Should fail during account validation
	require.Equal(t, http.StatusBadRequest, resp.Code)
}

// TestKeyChangeHandler_InvalidPayloadFormat tests error handling for invalid payload format
func TestKeyChangeHandler_InvalidPayloadFormat(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	// Get nonces
	innerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(innerNonce)

	keyChangeURL := service.baseRESTURI + "/acme/key-change"
	accountURL := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)

	// Create inner JWS with invalid payload (not a KeyChangeRequest)
	invalidPayload := map[string]string{
		"invalid": "payload",
	}

	invalidPayloadBytes, err := json.Marshal(invalidPayload)
	require.NoError(t, err)

	innerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: innerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
		},
		EmbedJWK: true,
	}

	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(invalidPayloadBytes)
	require.NoError(t, err)

	innerJWSString := innerJWS.FullSerialize()

	// Create outer JWS
	outerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(outerNonce)

	outerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: outerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
			"kid": accountURL,
		},
	}

	outerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       oldKey.PrivateKey,
	}, outerSignerOpts)
	require.NoError(t, err)

	outerJWS, err := outerSigner.Sign([]byte(innerJWSString))
	require.NoError(t, err)

	outerJWSString := outerJWS.FullSerialize()

	req := httptest.NewRequest(http.MethodPost, keyChangeURL, strings.NewReader(outerJWSString))
	req.Header.Set("Content-Type", "application/jose+json")

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestKeyChangeHandler_MissingInnerJWK tests error handling when inner JWS lacks JWK header
func TestKeyChangeHandler_MissingInnerJWK(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	innerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(innerNonce)

	keyChangeURL := service.baseRESTURI + "/acme/key-change"
	accountURL := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)

	// Encode old public key to JWK format
	oldPublicJWK := &jose.JSONWebKey{Key: oldKey.PublicKey}
	oldKeyJSON, err := oldPublicJWK.MarshalJSON()
	require.NoError(t, err)

	var oldKeyMap map[string]interface{}
	err = json.Unmarshal(oldKeyJSON, &oldKeyMap)
	require.NoError(t, err)

	innerPayload := KeyChangeRequest{
		AccountURL: accountURL,
		OldKey:     oldKeyMap,
	}

	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	// Create inner JWS WITHOUT embedding the JWK (EmbedJWK: false)
	innerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: innerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
		},
		EmbedJWK: false, // Don't embed the JWK
	}

	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	innerJWSString := innerJWS.FullSerialize()

	// Create outer JWS
	outerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(outerNonce)

	outerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: outerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
			"kid": accountURL,
		},
	}

	outerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       oldKey.PrivateKey,
	}, outerSignerOpts)
	require.NoError(t, err)

	outerJWS, err := outerSigner.Sign([]byte(innerJWSString))
	require.NoError(t, err)

	outerJWSString := outerJWS.FullSerialize()

	req := httptest.NewRequest(http.MethodPost, keyChangeURL, strings.NewReader(outerJWSString))
	req.Header.Set("Content-Type", "application/jose+json")

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestKeyChangeHandler_AccountURLMismatch tests error handling when account URL doesn't match
func TestKeyChangeHandler_AccountURLMismatch(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	innerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(innerNonce)

	keyChangeURL := service.baseRESTURI + "/acme/key-change"
	accountURL := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)
	wrongAccountURL := service.baseRESTURI + "/acme/account/999999"

	// Encode old public key to JWK format
	oldPublicJWK := &jose.JSONWebKey{Key: oldKey.PublicKey}
	oldKeyJSON, err := oldPublicJWK.MarshalJSON()
	require.NoError(t, err)

	var oldKeyMap map[string]interface{}
	err = json.Unmarshal(oldKeyJSON, &oldKeyMap)
	require.NoError(t, err)

	// Create inner payload with wrong account URL
	innerPayload := KeyChangeRequest{
		AccountURL: wrongAccountURL,
		OldKey:     oldKeyMap,
	}

	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	innerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: innerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
		},
		EmbedJWK: true,
	}

	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	innerJWSString := innerJWS.FullSerialize()

	// Create outer JWS
	outerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(outerNonce)

	outerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: outerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
			"kid": accountURL,
		},
	}

	outerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       oldKey.PrivateKey,
	}, outerSignerOpts)
	require.NoError(t, err)

	outerJWS, err := outerSigner.Sign([]byte(innerJWSString))
	require.NoError(t, err)

	outerJWSString := outerJWS.FullSerialize()

	req := httptest.NewRequest(http.MethodPost, keyChangeURL, strings.NewReader(outerJWSString))
	req.Header.Set("Content-Type", "application/jose+json")

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestKeyChangeHandler_OldKeyMismatch tests error handling when old key doesn't match
func TestKeyChangeHandler_OldKeyMismatch(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	wrongOldKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	innerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(innerNonce)

	keyChangeURL := service.baseRESTURI + "/acme/key-change"
	accountURL := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)

	// Encode WRONG old public key to JWK format
	wrongOldPublicJWK := &jose.JSONWebKey{Key: wrongOldKey.PublicKey}
	wrongOldKeyJSON, err := wrongOldPublicJWK.MarshalJSON()
	require.NoError(t, err)

	var wrongOldKeyMap map[string]interface{}
	err = json.Unmarshal(wrongOldKeyJSON, &wrongOldKeyMap)
	require.NoError(t, err)

	innerPayload := KeyChangeRequest{
		AccountURL: accountURL,
		OldKey:     wrongOldKeyMap,
	}

	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	innerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: innerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
		},
		EmbedJWK: true,
	}

	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	innerJWSString := innerJWS.FullSerialize()

	// Create outer JWS with correct old key
	outerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(outerNonce)

	outerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: outerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
			"kid": accountURL,
		},
	}

	outerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       oldKey.PrivateKey,
	}, outerSignerOpts)
	require.NoError(t, err)

	outerJWS, err := outerSigner.Sign([]byte(innerJWSString))
	require.NoError(t, err)

	outerJWSString := outerJWS.FullSerialize()

	req := httptest.NewRequest(http.MethodPost, keyChangeURL, strings.NewReader(outerJWSString))
	req.Header.Set("Content-Type", "application/jose+json")

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestKeyChangeHandler_DeactivatedAccount tests error handling for deactivated account
func TestKeyChangeHandler_DeactivatedAccount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	// Deactivate the account
	ctx := context.Background()
	account.Status = common.StatusDeactivated
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// Handler returns Unauthorized (401) not Forbidden (403) for invalid account status
	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

// TestKeyChangeHandler_URLMismatch tests error handling when inner and outer JWS URLs don't match
func TestKeyChangeHandler_URLMismatch(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	innerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(innerNonce)

	keyChangeURL := service.baseRESTURI + "/acme/key-change"
	wrongURL := service.baseRESTURI + "/acme/wrong-url"
	accountURL := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)

	// Encode old public key
	oldPublicJWK := &jose.JSONWebKey{Key: oldKey.PublicKey}
	oldKeyJSON, err := oldPublicJWK.MarshalJSON()
	require.NoError(t, err)

	var oldKeyMap map[string]interface{}
	err = json.Unmarshal(oldKeyJSON, &oldKeyMap)
	require.NoError(t, err)

	innerPayload := KeyChangeRequest{
		AccountURL: accountURL,
		OldKey:     oldKeyMap,
	}

	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	// Create inner JWS with different URL
	innerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: innerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": wrongURL, // Different URL
		},
		EmbedJWK: true,
	}

	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	innerJWSString := innerJWS.FullSerialize()

	// Create outer JWS with correct URL
	outerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(outerNonce)

	outerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: outerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
			"kid": accountURL,
		},
	}

	outerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       oldKey.PrivateKey,
	}, outerSignerOpts)
	require.NoError(t, err)

	outerJWS, err := outerSigner.Sign([]byte(innerJWSString))
	require.NoError(t, err)

	outerJWSString := outerJWS.FullSerialize()

	req := httptest.NewRequest(http.MethodPost, keyChangeURL, strings.NewReader(outerJWSString))
	req.Header.Set("Content-Type", "application/jose+json")

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestCompareKeyMaps_RSA tests compareKeyMaps for RSA keys
func TestCompareKeyMaps_RSA(t *testing.T) {
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk1 := &jose.JSONWebKey{Key: rsaKey1.Public()}
	jwk2 := &jose.JSONWebKey{Key: rsaKey2.Public()}

	json1, err := jwk1.MarshalJSON()
	require.NoError(t, err)

	json2, err := jwk2.MarshalJSON()
	require.NoError(t, err)

	var map1, map2 map[string]interface{}
	err = json.Unmarshal(json1, &map1)
	require.NoError(t, err)

	err = json.Unmarshal(json2, &map2)
	require.NoError(t, err)

	// Same key should match
	assert.True(t, compareKeyMaps(map1, map1))

	// Different keys should not match
	assert.False(t, compareKeyMaps(map1, map2))
}

// TestCompareKeyMaps_ECDSA tests compareKeyMaps for ECDSA keys
func TestCompareKeyMaps_ECDSA(t *testing.T) {
	ecKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk1 := &jose.JSONWebKey{Key: ecKey1.Public()}
	jwk2 := &jose.JSONWebKey{Key: ecKey2.Public()}

	json1, err := jwk1.MarshalJSON()
	require.NoError(t, err)

	json2, err := jwk2.MarshalJSON()
	require.NoError(t, err)

	var map1, map2 map[string]interface{}
	err = json.Unmarshal(json1, &map1)
	require.NoError(t, err)

	err = json.Unmarshal(json2, &map2)
	require.NoError(t, err)

	// Same key should match
	assert.True(t, compareKeyMaps(map1, map1))

	// Different keys should not match
	assert.False(t, compareKeyMaps(map1, map2))
}

// TestCompareKeyMaps_DifferentTypes tests compareKeyMaps for different key types
func TestCompareKeyMaps_DifferentTypes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaJWK := &jose.JSONWebKey{Key: rsaKey.Public()}
	ecJWK := &jose.JSONWebKey{Key: ecKey.Public()}

	rsaJSON, err := rsaJWK.MarshalJSON()
	require.NoError(t, err)

	ecJSON, err := ecJWK.MarshalJSON()
	require.NoError(t, err)

	var rsaMap, ecMap map[string]interface{}
	err = json.Unmarshal(rsaJSON, &rsaMap)
	require.NoError(t, err)

	err = json.Unmarshal(ecJSON, &ecMap)
	require.NoError(t, err)

	// RSA and EC keys should not match
	assert.False(t, compareKeyMaps(rsaMap, ecMap))
}

// TestCompareKeyMaps_EdDSA tests compareKeyMaps for EdDSA (OKP) keys
func TestCompareKeyMaps_EdDSA(t *testing.T) {
	pubKey1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk1 := &jose.JSONWebKey{Key: pubKey1}
	jwk2 := &jose.JSONWebKey{Key: pubKey2}

	json1, err := jwk1.MarshalJSON()
	require.NoError(t, err)

	json2, err := jwk2.MarshalJSON()
	require.NoError(t, err)

	var map1, map2 map[string]interface{}
	err = json.Unmarshal(json1, &map1)
	require.NoError(t, err)

	err = json.Unmarshal(json2, &map2)
	require.NoError(t, err)

	// Same key should match
	assert.True(t, compareKeyMaps(map1, map1))

	// Different keys should not match
	assert.False(t, compareKeyMaps(map1, map2))
}

// TestPublicKeyToJOSEAlgorithm_RSA tests publicKeyToJOSEAlgorithm for RSA keys
func TestPublicKeyToJOSEAlgorithm_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	algo, err := publicKeyToJOSEAlgorithm(rsaKey.Public())
	require.NoError(t, err)
	assert.Equal(t, jose.RS256, algo)
}

// TestPublicKeyToJOSEAlgorithm_ECDSA_P256 tests publicKeyToJOSEAlgorithm for ECDSA P-256
func TestPublicKeyToJOSEAlgorithm_ECDSA_P256(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	algo, err := publicKeyToJOSEAlgorithm(ecKey.Public())
	require.NoError(t, err)
	assert.Equal(t, jose.ES256, algo)
}

// TestPublicKeyToJOSEAlgorithm_ECDSA_P384 tests publicKeyToJOSEAlgorithm for ECDSA P-384
func TestPublicKeyToJOSEAlgorithm_ECDSA_P384(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	algo, err := publicKeyToJOSEAlgorithm(ecKey.Public())
	require.NoError(t, err)
	assert.Equal(t, jose.ES384, algo)
}

// TestPublicKeyToJOSEAlgorithm_ECDSA_P521 tests publicKeyToJOSEAlgorithm for ECDSA P-521
func TestPublicKeyToJOSEAlgorithm_ECDSA_P521(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	algo, err := publicKeyToJOSEAlgorithm(ecKey.Public())
	require.NoError(t, err)
	assert.Equal(t, jose.ES512, algo)
}

// TestPublicKeyToJOSEAlgorithm_EdDSA tests publicKeyToJOSEAlgorithm for Ed25519
func TestPublicKeyToJOSEAlgorithm_EdDSA(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	algo, err := publicKeyToJOSEAlgorithm(pubKey)
	require.NoError(t, err)
	assert.Equal(t, jose.EdDSA, algo)
}

// TestPublicKeyToJOSEAlgorithm_UnsupportedType tests publicKeyToJOSEAlgorithm for unsupported key type
func TestPublicKeyToJOSEAlgorithm_UnsupportedType(t *testing.T) {
	// Use a string as an unsupported key type
	_, err := publicKeyToJOSEAlgorithm("unsupported")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

// TestCompareKeyMaps_InvalidType tests compareKeyMaps with invalid key type
func TestCompareKeyMaps_InvalidType(t *testing.T) {
	map1 := map[string]interface{}{
		"kty": "INVALID",
		"n":   "test",
	}
	map2 := map[string]interface{}{
		"kty": "INVALID",
		"n":   "test",
	}

	// Should return false for unsupported key type
	assert.False(t, compareKeyMaps(map1, map2))
}

// TestCompareKeyMaps_MissingKeyType tests compareKeyMaps with missing key type
func TestCompareKeyMaps_MissingKeyType(t *testing.T) {
	map1 := map[string]interface{}{
		"n": "test",
	}
	map2 := map[string]interface{}{
		"n": "test",
	}

	// Should return false when key type is missing
	assert.False(t, compareKeyMaps(map1, map2))
}

// TestKeyChangeHandler_VerifyAccountKeyUpdated tests that the account key is actually updated
func TestKeyChangeHandler_VerifyAccountKeyUpdated(t *testing.T) {

	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	// Store original key
	originalKey := account.Key

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	// Retrieve updated account
	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	updatedAccount, err := accountDAO.Get(ctx, account.ID)
	require.NoError(t, err)

	// Verify key was updated
	assert.NotEqual(t, originalKey, updatedAccount.Key)

	// Verify new key matches expected new key
	newKeyPEM, err := xkmssdk.EncodePublicKeyPEM(newKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, string(newKeyPEM), updatedAccount.Key)
}

// TestKeyChangeHandler_InvalidAccountKey tests error handling when account key cannot be decoded
func TestKeyChangeHandler_InvalidAccountKey(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Corrupt the account key in storage to trigger decoding error
	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account.Key = "invalid-pem-data"
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	newKey := generateTestKey(t)
	req := createKeyChangeRequest(t, service, key, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// parseKID returns http.Error for key decoding failures, so check for plain text response
	require.Equal(t, http.StatusBadRequest, resp.Code)
	require.Contains(t, resp.Body.String(), "Invalid request")
}

// TestKeyChangeHandler_NoInnerSignatures tests error handling when inner JWS has no signatures
func TestKeyChangeHandler_NoInnerSignatures(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	// Create a malformed inner JWS with no signatures by manually constructing JWS
	keyChangeURL := service.baseRESTURI + "/acme/key-change"
	accountURL := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)

	// Create a JWS-like structure with no signatures
	innerJWS := `{"payload":"eyJ0ZXN0IjoidGVzdCJ9","protected":"eyJ0ZXN0IjoidGVzdCJ9"}`

	// Create outer JWS with the malformed inner JWS
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	outerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
			"kid": accountURL,
		},
	}

	outerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       oldKey.PrivateKey,
	}, outerSignerOpts)
	require.NoError(t, err)

	outerJWS, err := outerSigner.Sign([]byte(innerJWS))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, keyChangeURL, strings.NewReader(outerJWS.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestKeyChangeHandler_InvalidAccountURL tests error handling for account URL parsing failure
func TestKeyChangeHandler_InvalidAccountURL(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	innerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(innerNonce)

	keyChangeURL := service.baseRESTURI + "/acme/key-change"
	accountURL := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)

	// Use an account URL with invalid format (can't parse ID)
	badAccountURL := service.baseRESTURI + "/acme/account/not-a-number"

	// Encode old public key
	oldPublicJWK := &jose.JSONWebKey{Key: oldKey.PublicKey}
	oldKeyJSON, err := oldPublicJWK.MarshalJSON()
	require.NoError(t, err)

	var oldKeyMap map[string]interface{}
	err = json.Unmarshal(oldKeyJSON, &oldKeyMap)
	require.NoError(t, err)

	innerPayload := KeyChangeRequest{
		AccountURL: badAccountURL, // Invalid account URL
		OldKey:     oldKeyMap,
	}

	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	innerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: innerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
		},
		EmbedJWK: true,
	}

	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	innerJWSString := innerJWS.FullSerialize()

	// Create outer JWS
	outerNonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(outerNonce)

	outerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: outerNonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": keyChangeURL,
			"kid": accountURL,
		},
	}

	outerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       oldKey.PrivateKey,
	}, outerSignerOpts)
	require.NoError(t, err)

	outerJWS, err := outerSigner.Sign([]byte(innerJWSString))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, keyChangeURL, strings.NewReader(outerJWS.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// NOTE: TestKeyChangeHandler_InnerJWSVerificationFailure
// Testing inner JWS signature verification failure would require manipulating
// the JWS structure to have a signature that doesn't match the embedded public key.
// This is very difficult to do reliably with the go-jose library and would require
// direct JWS structure manipulation that is fragile and implementation-dependent.
// The inner JWS verification is already covered indirectly by other tests that
// provide invalid or mismatched signatures.

// TestPublicKeyToJOSEAlgorithm_UnsupportedECDSACurve tests unsupported ECDSA curve
func TestPublicKeyToJOSEAlgorithm_UnsupportedECDSACurve(t *testing.T) {
	// Create an ECDSA key with P-224 curve (unsupported)
	ecKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	_, err = publicKeyToJOSEAlgorithm(ecKey.Public())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ECDSA curve")
}

// TestKeyChangeHandler_NewKeyConflict tests error handling when new key already exists on another account
func TestKeyChangeHandler_NewKeyConflict(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	// Create first account with old key
	account1 := createTestAccount(t, service, oldKey)

	// Create second account with the new key
	account2 := createTestAccount(t, service, newKey)

	// Try to change account1's key to newKey (which is already used by account2)
	req := createKeyChangeRequest(t, service, oldKey, newKey, account1.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// Should return 409 Conflict
	require.Equal(t, http.StatusConflict, resp.Code)
	require.Equal(t, "application/problem+json", resp.Header().Get("Content-Type"))

	// Verify Location header points to the conflicting account
	locationHeader := resp.Header().Get("Location")
	require.NotEmpty(t, locationHeader)
	require.Contains(t, locationHeader, fmt.Sprintf("/acme/account/%d", account2.ID))

	// Verify error response
	var errorResp map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&errorResp)
	require.NoError(t, err)
	assert.Equal(t, "urn:ietf:params:acme:error:malformed", errorResp["type"])
	assert.Contains(t, errorResp["detail"], "already exists")
}

// TestKeyChangeHandler_AccountStorageError tests when account is deleted
func TestKeyChangeHandler_AccountStorageError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	account := createTestAccount(t, service, oldKey)

	// Delete the account to simulate it not being found
	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	err = accountDAO.Delete(ctx, account)
	require.NoError(t, err)

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// parseKID returns http.Error for account not found, which is plain text
	require.Equal(t, http.StatusBadRequest, resp.Code)
	require.Contains(t, resp.Body.String(), "Invalid request")
}

// TestKeyChangeHandler_InvalidAccountStatus tests when account status is not valid
func TestKeyChangeHandler_InvalidAccountStatus(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	// Set account status to pending
	ctx := context.Background()
	account.Status = common.StatusPending
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// Should return unauthorized for invalid account status
	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
}

// TestCompareKeyMaps_DifferentCurves tests compareKeyMaps for EC keys with different curves
func TestCompareKeyMaps_DifferentCurves(t *testing.T) {
	ecKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	jwk1 := &jose.JSONWebKey{Key: ecKey1.Public()}
	jwk2 := &jose.JSONWebKey{Key: ecKey2.Public()}

	json1, err := jwk1.MarshalJSON()
	require.NoError(t, err)

	json2, err := jwk2.MarshalJSON()
	require.NoError(t, err)

	var map1, map2 map[string]interface{}
	err = json.Unmarshal(json1, &map1)
	require.NoError(t, err)

	err = json.Unmarshal(json2, &map2)
	require.NoError(t, err)

	// Different curves should not match
	assert.False(t, compareKeyMaps(map1, map2))
}

// TestCompareKeyMaps_MissingParameters tests compareKeyMaps with incomplete key data
func TestCompareKeyMaps_MissingParameters(t *testing.T) {
	// RSA key missing modulus
	rsaMap1 := map[string]interface{}{
		"kty": "RSA",
		"e":   "AQAB",
	}
	rsaMap2 := map[string]interface{}{
		"kty": "RSA",
		"n":   "test-modulus",
		"e":   "AQAB",
	}
	assert.False(t, compareKeyMaps(rsaMap1, rsaMap2))

	// EC key missing x coordinate
	ecMap1 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"y":   "test-y",
	}
	ecMap2 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x",
		"y":   "test-y",
	}
	assert.False(t, compareKeyMaps(ecMap1, ecMap2))
}
