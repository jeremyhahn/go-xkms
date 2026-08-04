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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRestService_Success tests successful creation of RestService
func TestNewRestService_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	assert.NotNil(t, service)
	assert.Equal(t, "https://acme.test.example.com", service.baseRESTURI)
	assert.NotNil(t, service.ca)
	assert.NotNil(t, service.logger)
	assert.NotNil(t, service.storageFactory)
	assert.NotNil(t, service.nonceStore)
	assert.NotNil(t, service.challengeMap)
}

// TestNewRestService_NilParams tests error when params is nil
func TestNewRestService_NilParams(t *testing.T) {
	service, err := NewRestService(nil)
	assert.Nil(t, service)
	assert.EqualError(t, err, "handlers: params cannot be nil")
}

// TestNewRestService_MissingBaseRESTURI tests error when BaseRESTURI is missing
func TestNewRestService_MissingBaseRESTURI(t *testing.T) {
	params := &Params{
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
	}

	service, err := NewRestService(params)
	assert.Nil(t, service)
	assert.EqualError(t, err, "handlers: BaseRESTURI is required")
}

// TestNewRestService_MissingCA tests error when CA is missing
func TestNewRestService_MissingCA(t *testing.T) {
	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
	}

	service, err := NewRestService(params)
	assert.Nil(t, service)
	assert.EqualError(t, err, "handlers: CA is required")
}

// TestNewRestService_MissingLogger tests error when Logger is missing
func TestNewRestService_MissingLogger(t *testing.T) {
	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		StorageFactory: setupTestStorage(t),
	}

	service, err := NewRestService(params)
	assert.Nil(t, service)
	assert.EqualError(t, err, "handlers: Logger is required")
}

// TestNewRestService_MissingStorageFactory tests error when StorageFactory is missing
func TestNewRestService_MissingStorageFactory(t *testing.T) {
	params := &Params{
		BaseRESTURI: "https://acme.test.example.com",
		CA:          &MockCA{},
		Logger:      setupTestLogger(),
	}

	service, err := NewRestService(params)
	assert.Nil(t, service)
	assert.EqualError(t, err, "handlers: StorageFactory is required")
}

// TestNewRestService_DefaultChallengeMap tests that ChallengeMap is initialized if nil
func TestNewRestService_DefaultChallengeMap(t *testing.T) {
	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
		ChallengeMap:   nil, // Explicitly nil
	}

	service, err := NewRestService(params)
	require.NoError(t, err)
	require.NotNil(t, service)

	restService := service.(*RestService)
	assert.NotNil(t, restService.challengeMap)
	assert.Empty(t, restService.challengeMap)
}

// TestKeyToID_Success tests successful conversion of key to ID
func TestKeyToID_Success(t *testing.T) {
	testCases := []struct {
		name string
		key  interface{}
	}{
		{
			name: "map key",
			key:  map[string]string{"test": "value"},
		},
		{
			name: "string key",
			key:  "test-string",
		},
		{
			name: "int key",
			key:  12345,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := keyToID(tc.key)
			assert.NoError(t, err)
			assert.NotEmpty(t, id)
			// Verify it's a valid base64url encoded string
			assert.NotContains(t, id, "+")
			assert.NotContains(t, id, "/")
			assert.NotContains(t, id, "=")
		})
	}
}

// TestKeyToID_Consistency tests that same key produces same ID
func TestKeyToID_Consistency(t *testing.T) {
	key := map[string]string{"test": "value"}

	id1, err := keyToID(key)
	require.NoError(t, err)

	id2, err := keyToID(key)
	require.NoError(t, err)

	assert.Equal(t, id1, id2, "Same key should produce same ID")
}

// TestKeyToID_InvalidKey tests error handling with unmarshalable key
func TestKeyToID_InvalidKey(t *testing.T) {
	// Channel cannot be marshaled to JSON
	invalidKey := make(chan int)

	id, err := keyToID(invalidKey)
	assert.Empty(t, id)
	assert.Error(t, err)
}

// TestKeyToString_Success tests successful conversion of key to string
func TestKeyToString_Success(t *testing.T) {
	testCases := []struct {
		name string
		key  interface{}
	}{
		{
			name: "map key",
			key:  map[string]string{"test": "value"},
		},
		{
			name: "string key",
			key:  "test-string",
		},
		{
			name: "struct key",
			key:  struct{ Name string }{Name: "test"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := keyToString(tc.key)
			assert.NotEmpty(t, result)
			// Verify it's a valid base64url encoded string
			assert.NotContains(t, result, "+")
			assert.NotContains(t, result, "/")
			assert.NotContains(t, result, "=")
		})
	}
}

// TestKeyToString_InvalidKey tests error handling with unmarshalable key
func TestKeyToString_InvalidKey(t *testing.T) {
	// Channel cannot be marshaled to JSON
	invalidKey := make(chan int)

	// keyToString ignores errors and returns empty string
	result := keyToString(invalidKey)
	assert.Empty(t, result)
}

// TestParseNextLinkHeaderFromRequest_Success tests successful parsing of next link
func TestParseNextLinkHeaderFromRequest_Success(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://acme.example.com/acme/orders", nil)
	req.Header.Set("Link", `<https://acme.example.com/acme/orders/12345>; rel="next"`)

	id, err := parseNextLinkHeaderFromRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, 12345, id)
}

// TestParseNextLinkHeaderFromRequest_MultipleLinks tests parsing when multiple links present
func TestParseNextLinkHeaderFromRequest_MultipleLinks(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://acme.example.com/acme/orders", nil)
	req.Header.Set("Link", `<https://acme.example.com/acme/directory>; rel="index", <https://acme.example.com/acme/orders/99999>; rel="next"`)

	id, err := parseNextLinkHeaderFromRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, 99999, id)
}

// TestParseNextLinkHeaderFromRequest_NoNextLink tests error when no next link present
func TestParseNextLinkHeaderFromRequest_NoNextLink(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://acme.example.com/acme/orders", nil)
	req.Header.Set("Link", `<https://acme.example.com/acme/directory>; rel="index"`)

	id, err := parseNextLinkHeaderFromRequest(req)
	assert.Error(t, err)
	assert.Equal(t, 0, id)
	assert.Contains(t, err.Error(), "next link not found")
}

// TestParseNextLinkHeaderFromRequest_InvalidURL tests error with invalid URL in link
func TestParseNextLinkHeaderFromRequest_InvalidURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://acme.example.com/acme/orders", nil)
	req.Header.Set("Link", `<://invalid-url>; rel="next"`)

	id, err := parseNextLinkHeaderFromRequest(req)
	assert.Error(t, err)
	assert.Equal(t, 0, id)
	assert.Contains(t, err.Error(), "invalid URL")
}

// TestParseNextLinkHeaderFromRequest_InvalidID tests error with non-numeric ID
func TestParseNextLinkHeaderFromRequest_InvalidID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://acme.example.com/acme/orders", nil)
	req.Header.Set("Link", `<https://acme.example.com/acme/orders/not-a-number>; rel="next"`)

	id, err := parseNextLinkHeaderFromRequest(req)
	assert.Error(t, err)
	assert.Equal(t, 0, id)
	assert.Contains(t, err.Error(), "invalid ID")
}

// TestOrderResponse_Success tests successful order response
func TestOrderResponse_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	order := &entities.ACMEOrder{
		ID:     12345,
		Status: common.StatusPending,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Authorizations: []string{"https://acme.example.com/authz/1"},
		Finalize:       "https://acme.example.com/finalize/12345",
	}

	w := httptest.NewRecorder()
	service.orderResponse(w, order)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.NotEmpty(t, w.Header().Get("Replay-Nonce"))

	var response struct {
		Status         string                    `json:"status"`
		Identifiers    []entities.ACMEIdentifier `json:"identifiers"`
		Authorizations []string                  `json:"authorizations"`
		Finalize       string                    `json:"finalize"`
	}
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, common.StatusPending, response.Status)
	assert.Len(t, response.Identifiers, 1)
	assert.Equal(t, "example.com", response.Identifiers[0].Value)
}

// TestOrderResponse_WithCertificate tests order response with certificate
func TestOrderResponse_WithCertificate(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	order := &entities.ACMEOrder{
		ID:          12345,
		Status:      common.StatusValid,
		Certificate: "https://acme.example.com/cert/12345",
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		Authorizations: []string{"https://acme.example.com/authz/1"},
		Finalize:       "https://acme.example.com/finalize/12345",
	}

	w := httptest.NewRecorder()
	service.orderResponse(w, order)

	assert.Equal(t, http.StatusOK, w.Code)

	var response struct {
		Status      string `json:"status"`
		Certificate string `json:"certificate"`
	}
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, response.Status)
	assert.Equal(t, "https://acme.example.com/cert/12345", response.Certificate)
}

// TestKeyAuthorization_RSA tests key authorization with RSA key
func TestKeyAuthorization_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := "test-token-12345"
	keyAuth, err := KeyAuthorization(token, privateKey.Public())
	assert.NoError(t, err)
	assert.NotEmpty(t, keyAuth)
	assert.True(t, strings.HasPrefix(keyAuth, token+"."))
}

// TestKeyAuthorization_ECDSA tests key authorization with ECDSA key
func TestKeyAuthorization_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := "test-token-54321"
	keyAuth, err := KeyAuthorization(token, privateKey.Public())
	assert.NoError(t, err)
	assert.NotEmpty(t, keyAuth)
	assert.True(t, strings.HasPrefix(keyAuth, token+"."))
}

// TestKeyAuthorization_Ed25519 tests key authorization with Ed25519 key
func TestKeyAuthorization_Ed25519(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	token := "test-token-ed25519"
	keyAuth, err := KeyAuthorization(token, publicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, keyAuth)
	assert.True(t, strings.HasPrefix(keyAuth, token+"."))
}

// TestKeyAuthorization_InvalidKeyType tests error with unsupported key type
func TestKeyAuthorization_InvalidKeyType(t *testing.T) {
	invalidKey := "not-a-crypto-key"

	token := "test-token"
	keyAuth, err := KeyAuthorization(token, invalidKey)
	assert.Empty(t, keyAuth)
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)
}

// TestGenerateID_Success tests successful ID generation
func TestGenerateID_Success(t *testing.T) {
	id, err := GenerateID()
	assert.NoError(t, err)
	assert.NotZero(t, id)
}

// TestGenerateID_Uniqueness tests that generated IDs are unique
func TestGenerateID_Uniqueness(t *testing.T) {
	ids := make(map[uint64]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		id, err := GenerateID()
		require.NoError(t, err)
		assert.False(t, ids[id], "Generated duplicate ID")
		ids[id] = true
	}

	assert.Len(t, ids, iterations)
}

// TestGenerateToken_Success tests successful token generation
func TestGenerateToken_Success(t *testing.T) {
	token, err := GenerateToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	// Verify it's a valid base64url encoded string
	assert.NotContains(t, token, "+")
	assert.NotContains(t, token, "/")
	assert.NotContains(t, token, "=")
}

// TestGenerateToken_Uniqueness tests that generated tokens are unique
func TestGenerateToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		token, err := GenerateToken()
		require.NoError(t, err)
		assert.False(t, tokens[token], "Generated duplicate token")
		tokens[token] = true
	}

	assert.Len(t, tokens, iterations)
}

// TestWriteError_WithStatus tests writeError with explicit status
func TestWriteError_WithStatus(t *testing.T) {
	w := httptest.NewRecorder()
	acmeErr := &entities.Error{
		Type:   "urn:ietf:params:acme:error:malformed",
		Detail: "Request was malformed",
		Status: http.StatusBadRequest,
	}

	writeError(w, acmeErr)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))

	var response entities.Error
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, acmeErr.Type, response.Type)
	assert.Equal(t, acmeErr.Detail, response.Detail)
}

// TestWriteError_WithoutStatus tests writeError defaults to 500 when status is 0
func TestWriteError_WithoutStatus(t *testing.T) {
	w := httptest.NewRecorder()
	acmeErr := &entities.Error{
		Type:   "urn:ietf:params:acme:error:serverInternal",
		Detail: "Internal server error",
		Status: 0, // No status set
	}

	writeError(w, acmeErr)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))

	var response entities.Error
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, acmeErr.Type, response.Type)
	assert.Equal(t, acmeErr.Detail, response.Detail)
}

// TestParseAccountID_Success tests successful account ID parsing
func TestParseAccountID_Success(t *testing.T) {
	testCases := []struct {
		name       string
		accountURL string
		expectedID uint64
	}{
		{
			name:       "simple URL",
			accountURL: "https://acme.example.com/acme/account/12345",
			expectedID: 12345,
		},
		{
			name:       "large ID",
			accountURL: "https://acme.example.com/acme/account/18446744073709551615",
			expectedID: 18446744073709551615,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := ParseAccountID(tc.accountURL)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedID, id)
		})
	}
}

// TestParseAccountID_InvalidID tests error with invalid account ID
func TestParseAccountID_InvalidID(t *testing.T) {
	testCases := []struct {
		name       string
		accountURL string
	}{
		{
			name:       "non-numeric ID",
			accountURL: "https://acme.example.com/acme/account/not-a-number",
		},
		{
			name:       "negative ID",
			accountURL: "https://acme.example.com/acme/account/-123",
		},
		{
			name:       "float ID",
			accountURL: "https://acme.example.com/acme/account/123.45",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := ParseAccountID(tc.accountURL)
			assert.Zero(t, id)
			assert.ErrorIs(t, err, ErrInvalidAccountID)
		})
	}
}

// TestAccountIDFromPublicKey_RSA tests account ID generation from RSA key
func TestAccountIDFromPublicKey_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	id, err := AccountIDFromPublicKey(privateKey.Public())
	assert.NoError(t, err)
	assert.NotZero(t, id)
}

// TestAccountIDFromPublicKey_ECDSA tests account ID generation from ECDSA key
func TestAccountIDFromPublicKey_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	id, err := AccountIDFromPublicKey(privateKey.Public())
	assert.NoError(t, err)
	assert.NotZero(t, id)
}

// TestAccountIDFromPublicKey_Ed25519 tests account ID generation from Ed25519 key
func TestAccountIDFromPublicKey_Ed25519(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	id, err := AccountIDFromPublicKey(publicKey)
	assert.NoError(t, err)
	assert.NotZero(t, id)
}

// TestAccountIDFromPublicKey_Deterministic tests that same key produces same ID
func TestAccountIDFromPublicKey_Deterministic(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	id1, err := AccountIDFromPublicKey(privateKey.Public())
	require.NoError(t, err)

	id2, err := AccountIDFromPublicKey(privateKey.Public())
	require.NoError(t, err)

	assert.Equal(t, id1, id2, "Same key should produce same account ID")
}

// TestAccountIDFromPublicKey_InvalidKeyType tests error with unsupported key type
func TestAccountIDFromPublicKey_InvalidKeyType(t *testing.T) {
	invalidKey := "not-a-crypto-key"

	id, err := AccountIDFromPublicKey(invalidKey)
	assert.Zero(t, id)
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)
}

// TestJWKThumbprint_RSA tests JWK thumbprint for RSA key
func TestJWKThumbprint_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	thumbprint, err := JWKThumbprint(privateKey.Public())
	assert.NoError(t, err)
	assert.NotEmpty(t, thumbprint)
	// Verify it's a valid base64url encoded string
	assert.NotContains(t, thumbprint, "+")
	assert.NotContains(t, thumbprint, "/")
	assert.NotContains(t, thumbprint, "=")
}

// TestJWKThumbprint_ECDSA_P256 tests JWK thumbprint for ECDSA P-256 key
func TestJWKThumbprint_ECDSA_P256(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	thumbprint, err := JWKThumbprint(privateKey.Public())
	assert.NoError(t, err)
	assert.NotEmpty(t, thumbprint)
}

// TestJWKThumbprint_ECDSA_P384 tests JWK thumbprint for ECDSA P-384 key
func TestJWKThumbprint_ECDSA_P384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	thumbprint, err := JWKThumbprint(privateKey.Public())
	assert.NoError(t, err)
	assert.NotEmpty(t, thumbprint)
}

// TestJWKThumbprint_Ed25519 tests JWK thumbprint for Ed25519 key
func TestJWKThumbprint_Ed25519(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	thumbprint, err := JWKThumbprint(publicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, thumbprint)
}

// TestJWKThumbprint_Deterministic tests that same key produces same thumbprint
func TestJWKThumbprint_Deterministic(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	thumbprint1, err := JWKThumbprint(privateKey.Public())
	require.NoError(t, err)

	thumbprint2, err := JWKThumbprint(privateKey.Public())
	require.NoError(t, err)

	assert.Equal(t, thumbprint1, thumbprint2, "Same key should produce same thumbprint")
}

// TestJWKThumbprint_InvalidKeyType tests error with unsupported key type
func TestJWKThumbprint_InvalidKeyType(t *testing.T) {
	invalidKey := "not-a-crypto-key"

	thumbprint, err := JWKThumbprint(invalidKey)
	assert.Empty(t, thumbprint)
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)
}

// TestParseKID_Success tests successful KID parsing with valid signature
func TestParseKID_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create request with KID
	payload := map[string]interface{}{"test": "data"}
	url := service.baseRESTURI + "/acme/account/" + fmt.Sprintf("%d", account.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Parse KID
	ctx := context.Background()
	parsedAccount, parsedPayload, err := service.parseKID(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, parsedAccount)
	assert.Equal(t, account.ID, parsedAccount.ID)
	assert.NotNil(t, parsedPayload)
}

// TestParseKID_InvalidJWS tests error with invalid JWS
func TestParseKID_InvalidJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()
	req := httptest.NewRequest(http.MethodPost, "/acme/account/123", bytes.NewBufferString("invalid-jws"))

	account, payload, err := service.parseKID(ctx, req)
	assert.Nil(t, account)
	assert.Nil(t, payload)
	assert.Error(t, err)
}

// TestParseKID_MissingKID tests error when KID is missing
func TestParseKID_MissingKID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create request without KID (JWK instead)
	payload := map[string]interface{}{"test": "data"}
	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	ctx := context.Background()
	account, parsedPayload, err := service.parseKID(ctx, req)
	assert.Nil(t, account)
	assert.Nil(t, parsedPayload)
	assert.Error(t, err)
}

// TestParseKID_InvalidAccountID tests error with invalid account ID in KID
func TestParseKID_InvalidAccountID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Get a valid nonce
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	// Create JWS with invalid KID (non-numeric ID)
	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/account/123",
			"kid": service.baseRESTURI + "/acme/account/invalid-id",
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/account/123", strings.NewReader(jws.FullSerialize()))

	ctx := context.Background()
	account, parsedPayload, err := service.parseKID(ctx, req)
	assert.Nil(t, account)
	assert.Nil(t, parsedPayload)
	assert.ErrorIs(t, err, ErrInvalidAccountID)
}

// TestParseKID_AccountNotFound tests error when account doesn't exist
func TestParseKID_AccountNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create request with KID for non-existent account
	nonExistentID := uint64(99999)
	payload := map[string]interface{}{"test": "data"}
	url := service.baseRESTURI + "/acme/account/99999"
	req := createJWSRequest(t, service, key, url, payload, true, nonExistentID)

	ctx := context.Background()
	account, parsedPayload, err := service.parseKID(ctx, req)
	assert.Nil(t, account)
	assert.Nil(t, parsedPayload)
	assert.ErrorIs(t, err, ErrAccountNotFound)
}

// TestParseJWS_Success tests successful JWS parsing with JWK
func TestParseJWS_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create request with JWK
	payload := map[string]interface{}{"test": "data"}
	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	jwk, parsedPayload, err := service.parseJWS(req)
	assert.NoError(t, err)
	assert.NotNil(t, jwk)
	assert.NotNil(t, parsedPayload)
}

// TestParseJWS_InvalidJWS tests error with invalid JWS
func TestParseJWS_InvalidJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/acme/new-account", bytes.NewBufferString("invalid-jws"))

	jwk, payload, err := service.parseJWS(req)
	assert.Nil(t, jwk)
	assert.Nil(t, payload)
	assert.Error(t, err)
}

// TestParseJWS_MissingJWK tests error when JWK is missing
func TestParseJWS_MissingJWK(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create request with KID instead of JWK
	payload := map[string]interface{}{"test": "data"}
	url := service.baseRESTURI + "/acme/account/" + fmt.Sprintf("%d", account.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	jwk, parsedPayload, err := service.parseJWS(req)
	assert.Nil(t, jwk)
	assert.Nil(t, parsedPayload)
	assert.Error(t, err)
}

// TestParseJWS_InvalidNonce tests error with invalid nonce
func TestParseJWS_InvalidNonce(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create JWS with invalid nonce (not in store)
	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: "invalid-nonce"},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/new-account",
		},
		EmbedJWK: true,
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/new-account", strings.NewReader(jws.FullSerialize()))

	jwk, parsedPayload, err := service.parseJWS(req)
	assert.Nil(t, jwk)
	assert.Nil(t, parsedPayload)
	assert.Error(t, err)
}

// TestParseJWS_InvalidSignature tests error with invalid signature
func TestParseJWS_InvalidSignature(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Get a valid nonce
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	// Create JWS with valid key
	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/new-account",
		},
		EmbedJWK: true,
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	jwsStr := jws.FullSerialize()

	// Modify the payload to corrupt the signature validation
	// This keeps the signature but changes what it should validate against
	modifiedPayload := []byte(`{"test":"modified"}`)
	var jwsObj map[string]interface{}
	err = json.Unmarshal([]byte(jwsStr), &jwsObj)
	require.NoError(t, err)

	// Replace payload with modified one (base64url encoded)
	jwsObj["payload"] = base64.RawURLEncoding.EncodeToString(modifiedPayload)

	modifiedJWS, err := json.Marshal(jwsObj)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/new-account", bytes.NewReader(modifiedJWS))

	jwk, parsedPayload, err := service.parseJWS(req)
	assert.Nil(t, jwk)
	assert.Nil(t, parsedPayload)
	assert.ErrorIs(t, err, ErrInvalidJWSSignature)
}

// TestParseKID_URLMismatch tests RFC 8555 Section 6.3 URL validation in parseKID
func TestParseKID_URLMismatch(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Get a valid nonce
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	// Create JWS with URL pointing to a different endpoint than the request
	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/new-order", // Wrong URL
			"kid": fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID),
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	// Send the JWS to a DIFFERENT endpoint than what's in the URL header
	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/account/"+fmt.Sprintf("%d", account.ID), strings.NewReader(jws.FullSerialize()))

	ctx := context.Background()
	acct, parsedPayload, err := service.parseKID(ctx, req)
	assert.Nil(t, acct)
	assert.Nil(t, parsedPayload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWS url header does not match request URL")
}

// TestParseKID_MissingURL tests RFC 8555 Section 6.3 URL validation when URL header is missing
func TestParseKID_MissingURL(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Get a valid nonce
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	// Create JWS WITHOUT the url header
	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID),
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/account/"+fmt.Sprintf("%d", account.ID), strings.NewReader(jws.FullSerialize()))

	ctx := context.Background()
	acct, parsedPayload, err := service.parseKID(ctx, req)
	assert.Nil(t, acct)
	assert.Nil(t, parsedPayload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWS url header does not match request URL")
}

// TestParseJWS_URLMismatch tests RFC 8555 Section 6.3 URL validation in parseJWS
func TestParseJWS_URLMismatch(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Get a valid nonce
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	// Create JWS with URL pointing to a different endpoint
	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/revoke-cert", // Wrong URL
		},
		EmbedJWK: true,
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	// Send the JWS to /acme/new-account but the URL header says /acme/revoke-cert
	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/new-account", strings.NewReader(jws.FullSerialize()))

	jwk, parsedPayload, err := service.parseJWS(req)
	assert.Nil(t, jwk)
	assert.Nil(t, parsedPayload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWS url header does not match request URL")
}

// TestParseJWS_MissingURL tests RFC 8555 Section 6.3 URL validation when URL header is missing
func TestParseJWS_MissingURL(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Get a valid nonce
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	// Create JWS WITHOUT the url header
	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		EmbedJWK:    true,
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/new-account", strings.NewReader(jws.FullSerialize()))

	jwk, parsedPayload, err := service.parseJWS(req)
	assert.Nil(t, jwk)
	assert.Nil(t, parsedPayload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWS url header does not match request URL")
}

// Helper functions

func setupTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
}

func setupTestStorage(t *testing.T) storage.Factory {
	tmpDir, err := os.MkdirTemp("", "acme-service-test-*")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = os.RemoveAll(tmpDir)
	})

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)

	factory, err := objstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	return factory
}

// TestGenerateID tests GenerateID function
func TestGenerateID(t *testing.T) {
	id1, err := GenerateID()
	require.NoError(t, err)
	assert.NotZero(t, id1)

	id2, err := GenerateID()
	require.NoError(t, err)
	assert.NotZero(t, id2)

	// IDs should be unique
	assert.NotEqual(t, id1, id2)

	// Generate many IDs and verify uniqueness
	ids := make(map[uint64]bool)
	for i := 0; i < 1000; i++ {
		id, err := GenerateID()
		require.NoError(t, err)
		assert.False(t, ids[id], "ID should be unique")
		ids[id] = true
	}
}

// TestGenerateToken tests GenerateToken function
func TestGenerateToken(t *testing.T) {
	token1, err := GenerateToken()
	require.NoError(t, err)
	assert.NotEmpty(t, token1)

	token2, err := GenerateToken()
	require.NoError(t, err)
	assert.NotEmpty(t, token2)

	// Tokens should be unique
	assert.NotEqual(t, token1, token2)

	// Generate many tokens and verify uniqueness
	tokens := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		token, err := GenerateToken()
		require.NoError(t, err)
		assert.False(t, tokens[token], "Token should be unique")
		tokens[token] = true
	}

	// Verify token format (should be base64url encoded)
	token, err := GenerateToken()
	require.NoError(t, err)
	_, err = base64.RawURLEncoding.DecodeString(token)
	assert.NoError(t, err, "Token should be valid base64url")
}
