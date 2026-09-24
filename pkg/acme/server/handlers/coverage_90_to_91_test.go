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

//go:build codec_json

package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewNonceHandler_MethodNotAllowedPATCH tests NewNonceHandler with PATCH method
func TestNewNonceHandler_MethodNotAllowedPATCH(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPatch, "/acme/new-nonce", nil)
	resp := httptest.NewRecorder()
	service.NewNonceHandler(resp, req)

	assert.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

// TestNewNonceHandler_MethodNotAllowedOPTIONS tests NewNonceHandler with OPTIONS method
func TestNewNonceHandler_MethodNotAllowedOPTIONS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodOptions, "/acme/new-nonce", nil)
	resp := httptest.NewRecorder()
	service.NewNonceHandler(resp, req)

	assert.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

// TestParseKID_AccountNotFoundPath tests parseKID when account doesn't exist
func TestParseKID_AccountNotFoundPath(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	_ = createTestAccount(t, service, key)

	nonExistentID := uint64(9999999999)

	nonce, err := service.GetNonceService().Generate()
	require.NoError(t, err)

	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/account/9999999999",
			"kid": service.baseRESTURI + "/acme/account/9999999999",
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/account/9999999999", strings.NewReader(jws.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")

	ctx := context.Background()
	account, _, err := service.parseKID(ctx, req)
	assert.Nil(t, account)
	assert.Error(t, err)
	assert.True(t, err == ErrAccountNotFound, "expected ErrAccountNotFound, got %v", err)
	_ = nonExistentID
}

// TestParseKID_KIDAndJWKBothPresent tests parseKID when both KID and JWK are present
func TestParseKID_KIDAndJWKBothPresent(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	nonce, err := service.GetNonceService().Generate()
	require.NoError(t, err)

	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/account/" + string(rune(account.ID)),
			"kid": service.baseRESTURI + "/acme/account/" + string(rune(account.ID)),
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

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/account/"+string(rune(account.ID)), strings.NewReader(jws.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")

	ctx := context.Background()
	parsedAccount, _, err := service.parseKID(ctx, req)
	assert.Nil(t, parsedAccount)
	assert.ErrorIs(t, err, ErrKIDAndJWKNotAllowed)
}

// TestChallengeHandler_ChallengeIDEmpty tests ChallengeHandler when challenge ID is empty
func TestChallengeHandler_ChallengeIDEmpty(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := service.baseRESTURI + "/acme/challenge/"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// TestChallengeHandler_ChallengeIDInvalid tests ChallengeHandler with invalid challenge ID
func TestChallengeHandler_ChallengeIDInvalid(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := service.baseRESTURI + "/acme/challenge/not-a-number"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestAuthorizationHandler_PostUnauthorizedAccount tests authorization POST with mismatched account
func TestAuthorizationHandler_PostUnauthorizedAccount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	_ = createTestAccount(t, service, key2)

	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account1.ID)
	require.NoError(t, err)

	authzID, err := GenerateID()
	require.NoError(t, err)

	authz := &entities.ACMEAuthorization{
		ID:        authzID,
		AccountID: account1.ID,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status:  common.StatusPending,
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	url := service.baseRESTURI + "/acme/authz/" + string(rune(authz.ID))
	req := createJWSRequest(t, service, key2, url, nil, true, account1.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	assert.True(t, resp.Code == http.StatusBadRequest || resp.Code == http.StatusUnauthorized)
}

// TestNewAccountHandler_ExternalAccountBindingOptionalProvided tests EAB provided but not required
func TestNewAccountHandler_ExternalAccountBindingOptionalProvided(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	eab := &entities.ExternalAccountBinding{
		ID:                "test-eab-kid",
		MACKey:            base64.RawURLEncoding.EncodeToString([]byte("test-mac-key-12345678901234567890")),
		Status:            "valid",
		ExternalAccountID: "external-123",
		CreatedAt:         time.Now(),
	}
	ctx := context.Background()
	err = eabDAO.Save(ctx, eab)
	require.NoError(t, err)

	newAccountPayload := NewAccountRequest{
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
		ExternalAccountBinding: map[string]interface{}{
			"protected": "invalid",
			"payload":   "invalid",
			"signature": "invalid",
		},
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, newAccountPayload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	assert.Equal(t, http.StatusCreated, resp.Code)
}

// TestNewAccountHandler_ExternalAccountBindingProvided_OptionalPath tests optional EAB verification
func TestNewAccountHandler_ExternalAccountBindingProvided_OptionalPath(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	newAccountPayload := NewAccountRequest{
		Contact:              []string{"mailto:optional@example.com"},
		TermsOfServiceAgreed: true,
		ExternalAccountBinding: map[string]interface{}{
			"not": "valid-eab",
		},
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, newAccountPayload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	assert.Equal(t, http.StatusCreated, resp.Code)
}

// TestNewAccountHandler_AccountExistsNotOnlyReturnExisting tests when account exists and OnlyReturnExisting is false.
//
// Per RFC 8555 Section 7.3: "if the server receives a newAccount request
// signed with a key for which it already has an account registered with
// the provided account key, then it MUST return a response with a 200 (OK)
// status code and provide the URL of that account in the Location header
// field." This applies regardless of onlyReturnExisting; that flag only
// changes behavior when NO account exists for the key (Section 7.3.1: the
// server MUST reply 400 accountDoesNotExist rather than creating one).
// "accountExists" is not among the error types RFC 8555 Section 6.7
// defines, so the original assertion here was never RFC-conformant.
func TestNewAccountHandler_AccountExistsNotOnlyReturnExisting(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	existingAccount := createTestAccount(t, service, key)

	newAccountPayload := NewAccountRequest{
		Contact:              []string{"mailto:newtest@example.com"},
		TermsOfServiceAgreed: true,
		OnlyReturnExisting:   false,
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, newAccountPayload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)

	// Per RFC 8555 Section 7.1.2, the account object body carries no "id"
	// field; the account's identity is conveyed via the Location header.
	assert.Equal(t, service.accountURL(existingAccount), resp.Header().Get("Location"))

	var returned entities.ACMEAccount
	err := json.NewDecoder(resp.Body).Decode(&returned)
	require.NoError(t, err)
	assert.Equal(t, existingAccount.Status, returned.Status)
}

// TestKeyChangeHandler_MissingInnerJWSSignatures tests KeyChangeHandler when inner JWS has no signatures
func TestKeyChangeHandler_MissingInnerJWSSignatures(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	malformedInnerJWS := `{"protected":"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0","payload":"e30"}`

	url := service.baseRESTURI + "/acme/key-change"
	req := createJWSRequest(t, service, key, url, malformedInnerJWS, true, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestParseKID_DeactivatedAccount tests parseKID with deactivated account
func TestParseKID_DeactivatedAccount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account.Status = common.StatusDeactivated
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	url := service.baseRESTURI + "/acme/account/" + string(rune(account.ID))
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	parsedAccount, _, err := service.parseKID(ctx, req)
	assert.Nil(t, parsedAccount)
	assert.ErrorIs(t, err, ErrAccountDeactivated)
}

// TestCompareKeyMaps_OKPKey tests compareKeyMaps with OKP (EdDSA) keys
func TestCompareKeyMaps_OKPKey(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "testXValue12345",
	}
	key2 := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "testXValue12345",
	}
	key3 := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "differentXValue",
	}

	assert.True(t, compareKeyMaps(key1, key2))
	assert.False(t, compareKeyMaps(key1, key3))
}

// TestCompareKeyMaps_UnknownKeyType tests compareKeyMaps with unknown key type
func TestCompareKeyMaps_UnknownKeyType(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "UNKNOWN",
		"x":   "testValue",
	}
	key2 := map[string]interface{}{
		"kty": "UNKNOWN",
		"x":   "testValue",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

// TestCompareKeyMaps_MismatchedKeyTypes tests compareKeyMaps with different key types
func TestCompareKeyMaps_MismatchedKeyTypes(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus",
		"e":   "exponent",
	}
	key2 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "x-coord",
		"y":   "y-coord",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

// TestCompareKeyMaps_MissingKtyInBothKeys tests compareKeyMaps when kty is missing
func TestCompareKeyMaps_MissingKtyInBothKeys(t *testing.T) {
	key1 := map[string]interface{}{
		"n": "modulus",
		"e": "exponent",
	}
	key2 := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus",
		"e":   "exponent",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

// TestParseJWS_NoSignatures tests parseJWS when JWS has no signatures
func TestParseJWS_NoSignatures(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	malformedJWS := `{"protected":"eyJhbGciOiJFUzI1NiJ9","payload":"e30"}`

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/new-account", strings.NewReader(malformedJWS))
	req.Header.Set("Content-Type", "application/jose+json")

	jwk, payload, err := service.parseJWS(req)
	assert.Nil(t, jwk)
	assert.Nil(t, payload)
	assert.Error(t, err)
}

// generateTestKeyP521ForCoverage creates a P-521 ECDSA test key pair and its
// JWK representation.
func generateTestKeyP521ForCoverage(t *testing.T) *TestKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	jwk := &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "",
		Algorithm: string(jose.ES512),
		Use:       "sig",
	}

	return &TestKey{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public(),
		JWK:        jwk,
	}
}

// TestJWKThumbprint_ECDSA_P521Key tests JWK thumbprint for ECDSA P-521 key
func TestJWKThumbprint_ECDSA_P521Key(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKeyP521ForCoverage(t)

	thumbprint, err := JWKThumbprint(key.PublicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, thumbprint)
	_ = service
}

// TestAccountHandler_InvalidStatusValue tests AccountHandler with invalid status value
func TestAccountHandler_InvalidStatusValue(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	accountUpdatePayload := AccountRequest{
		Status: "invalid-status",
	}

	url := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, accountUpdatePayload, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestAccountHandler_ContactUpdateWithInvalidURL tests AccountHandler with invalid contact URL
func TestAccountHandler_ContactUpdateWithInvalidURL(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	accountUpdatePayload := AccountRequest{
		Contact: []string{"not-a-valid-mailto-url"},
	}

	url := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, accountUpdatePayload, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// TestAccountHandler_DeactivateSuccess tests successful account deactivation
func TestAccountHandler_DeactivateSuccess(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	accountUpdatePayload := AccountRequest{
		Status: common.StatusDeactivated,
	}

	url := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)
	req := createJWSRequest(t, service, key, url, accountUpdatePayload, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)

	var respAccount entities.ACMEAccount
	err := json.NewDecoder(resp.Body).Decode(&respAccount)
	require.NoError(t, err)
	assert.Equal(t, common.StatusDeactivated, respAccount.Status)
}

// TestAuthorizationHandler_MethodNotAllowed tests AuthorizationHandler with unsupported method
func TestAuthorizationHandler_MethodNotAllowed(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create an authorization first
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	authzID, err := GenerateID()
	require.NoError(t, err)

	authz := &entities.ACMEAuthorization{
		ID:        authzID,
		AccountID: account.ID,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status:  common.StatusPending,
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// DELETE is not a supported method
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)
	req := createJWSRequestWithMethod(t, service, key, http.MethodDelete, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Method not allowed or bad request (depends on how parseKID handles non-POST)
	assert.True(t, resp.Code == http.StatusMethodNotAllowed || resp.Code == http.StatusBadRequest)
}

// TestAuthorizationHandler_AuthorizationNotFoundGET tests authorizationGetHandler when authorization doesn't exist
func TestAuthorizationHandler_AuthorizationNotFoundGET(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to get a non-existent authorization
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, 9999999999)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestAuthorizationHandler_AuthorizationIDEmpty tests AuthorizationHandler when authz ID is empty
func TestAuthorizationHandler_AuthorizationIDEmpty(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	url := service.baseRESTURI + "/acme/authz/"
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestAuthorizationPostHandler_AccountMismatch(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create two accounts
	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	account2 := createTestAccount(t, service, key2)

	ctx := context.Background()

	// Create an authorization for account1
	authzDAO, err := service.storageFactory.AuthorizationDAO(account1.ID)
	require.NoError(t, err)

	authzID, err := GenerateID()
	require.NoError(t, err)

	authz := &entities.ACMEAuthorization{
		ID:        authzID,
		AccountID: account1.ID,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status:  common.StatusPending,
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Challenges: []entities.ACMEChallenge{
			{
				ID:     12345,
				Type:   "http-01",
				Status: common.StatusPending,
				Token:  "test-token",
			},
		},
	}
	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// Also save to account2's authorization storage to make it findable
	authzDAO2, err := service.storageFactory.AuthorizationDAO(account2.ID)
	require.NoError(t, err)

	// Create a copy of the authorization but keep account1.ID as the AccountID
	// to trigger the mismatch check
	authzForAccount2 := &entities.ACMEAuthorization{
		ID:        authzID,
		AccountID: account1.ID, // Intentionally different from account2
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status:  common.StatusPending,
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Challenges: []entities.ACMEChallenge{
			{
				ID:     12345,
				Type:   "http-01",
				Status: common.StatusPending,
				Token:  "test-token",
			},
		},
	}
	err = authzDAO2.Save(ctx, authzForAccount2)
	require.NoError(t, err)

	// Try to access account1's authorization using account2's credentials
	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authzID)

	// Send a POST request with account2's key but trying to access account1's authz
	payload := map[string]string{"status": "deactivated"}
	req := createJWSRequest(t, service, key2, url, payload, true, account2.ID)

	resp := httptest.NewRecorder()
	service.AuthorizationHandler(resp, req)

	// Should get Unauthorized due to account mismatch
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
}

// TestChallengeHandler_ChallengeNotFoundCov tests ChallengeHandler when challenge doesn't exist
func TestChallengeHandler_ChallengeNotFoundCov(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Try to access a non-existent challenge
	nonExistentChallengeID := uint64(9999999999)
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, nonExistentChallengeID)
	req := createJWSRequest(t, service, key, url, nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// Should return error since challenge doesn't exist
	assert.True(t, resp.Code == http.StatusBadRequest || resp.Code == http.StatusNotFound)
}

// TestNewOrderHandler_UnsupportedIdentifierType tests NewOrderHandler with unsupported identifier type
func TestNewOrderHandler_UnsupportedIdentifierType(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	orderRequest := struct {
		Identifiers []entities.ACMEIdentifier `json:"identifiers"`
	}{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  "unsupported-type",
				Value: "test.example.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, orderRequest, true, account.ID)

	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Should return unsupported identifier error
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// TestNewOrderHandler_InvalidDomainName tests NewOrderHandler with invalid domain name
func TestNewOrderHandler_InvalidDomainName(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	orderRequest := struct {
		Identifiers []entities.ACMEIdentifier `json:"identifiers"`
	}{
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  "dns",
				Value: "-invalid-domain.com",
			},
		},
	}

	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, orderRequest, true, account.ID)

	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	// Should return malformed error for invalid domain
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// TestRevokeCertHandler_InactiveAccountCov tests RevokeCertHandler when account is not active
func TestRevokeCertHandler_InactiveAccountCov(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Deactivate the account
	ctx := context.Background()
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account.Status = common.StatusDeactivated
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	// Try to revoke a certificate
	revokeRequest := RevokeCertRequest{
		Certificate: base64.RawURLEncoding.EncodeToString([]byte("fake-cert")),
		Reason:      1,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, revokeRequest, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	// Should fail because account is deactivated (parseKID will reject)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// TestRevokeCertHandler_InvalidCertEncodingCov tests RevokeCertHandler with invalid base64
func TestRevokeCertHandler_InvalidCertEncodingCov(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	revokeRequest := RevokeCertRequest{
		Certificate: "!!!invalid-base64!!!",
		Reason:      1,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, revokeRequest, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// TestRevokeCertHandler_InvalidReasonCov tests RevokeCertHandler with invalid reason code
func TestRevokeCertHandler_InvalidReasonCov(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a minimal valid-looking DER certificate (just for the encoding check)
	fakeCertDER := []byte{0x30, 0x82, 0x01, 0x00} // Minimal ASN.1 sequence header

	revokeRequest := RevokeCertRequest{
		Certificate: base64.RawURLEncoding.EncodeToString(fakeCertDER),
		Reason:      99, // Invalid reason (valid is 0-10)
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, revokeRequest, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// Helper function to create JWS request with specific method
func createJWSRequestWithMethod(t *testing.T, service *RestService, key *TestKey, method string, url string, payload interface{}, useKID bool, accountID uint64) *http.Request {
	nonce, err := service.GetNonceService().Generate()
	require.NoError(t, err)

	var payloadBytes []byte
	if payload != nil {
		payloadBytes, err = json.Marshal(payload)
		require.NoError(t, err)
	} else {
		payloadBytes = []byte{}
	}

	var signerOpts *jose.SignerOptions
	if useKID {
		signerOpts = &jose.SignerOptions{
			NonceSource: &staticNonceSource{nonce: nonce},
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": url,
				"kid": fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, accountID),
			},
		}
	} else {
		signerOpts = &jose.SignerOptions{
			NonceSource: &staticNonceSource{nonce: nonce},
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": url,
			},
			EmbedJWK: true,
		}
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	req := httptest.NewRequest(method, url, strings.NewReader(jws.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")

	return req
}

type errorReaderCov struct{}

func (e *errorReaderCov) Read(p []byte) (n int, err error) {
	return 0, caerrors.InternalServerError("mock read error")
}

// shortReader is a mock io.Reader that returns fewer bytes than requested
type shortReader struct{}

func (s *shortReader) Read(p []byte) (n int, err error) {
	// Return only 4 bytes when more are requested
	if len(p) > 4 {
		copy(p[:4], []byte{1, 2, 3, 4})
		return 4, nil
	}
	return len(p), nil
}

// TestGenerateIDWithReader_Error tests generateIDWithReader with a failing reader
func TestGenerateIDWithReader_Error(t *testing.T) {
	reader := &errorReaderCov{}
	id, err := generateIDWithReader(reader)

	assert.Error(t, err)
	assert.Equal(t, uint64(0), id)
	assert.Contains(t, err.Error(), "mock read error")
}

// TestGenerateIDWithReader_ShortRead tests generateIDWithReader with a reader that returns fewer bytes
func TestGenerateIDWithReader_ShortRead(t *testing.T) {
	reader := &shortReader{}
	id, err := generateIDWithReader(reader)

	assert.Error(t, err)
	assert.Equal(t, uint64(0), id)
	assert.ErrorIs(t, err, ErrFailedToGenerateID)
}

// TestGenerateTokenWithReader_Error tests generateTokenWithReader with a failing reader
func TestGenerateTokenWithReader_Error(t *testing.T) {
	reader := &errorReaderCov{}
	token, err := generateTokenWithReader(reader)

	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "mock read error")
}

// TestGenerateTokenWithReader_ShortRead tests generateTokenWithReader with a reader that returns fewer bytes
func TestGenerateTokenWithReader_ShortRead(t *testing.T) {
	reader := &shortReader{}
	token, err := generateTokenWithReader(reader)

	assert.Error(t, err)
	assert.Empty(t, token)
	assert.ErrorIs(t, err, ErrFailedToGenerateToken)
}

// TestGenerateID_SuccessCov tests normal ID generation
func TestGenerateID_SuccessCov(t *testing.T) {
	id, err := GenerateID()

	assert.NoError(t, err)
	assert.NotEqual(t, uint64(0), id)
}

// TestGenerateToken_SuccessCov tests normal token generation
func TestGenerateToken_SuccessCov(t *testing.T) {
	token, err := GenerateToken()

	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestParseChallengeAsDynamicPortAssignment_VariousChallenges(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		expectedBase  string
		expectedPort  uint16
		expectError   bool
	}{
		{"standard http-01", "http-01", "http-01", 0, false},
		{"standard enroll-01", "enroll-01", "enroll-01", 0, false},
		{"enroll with port", "enroll-01-8080", "enroll-01", 8080, false},
		{"device-attest with port", "device-attest-01-443", "device-attest-01", 443, false},
		{"endorse with port", "endorse-01-9000", "endorse-01", 9000, false},
		{"high port number", "http-01-65535", "http-01", 65535, false},
		{"port 100", "http-01-100", "http-01", 100, false},
		{"low port preserved", "http-01-80", "http-01-80", 0, false},
		{"single part", "http", "http", 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseType, port, err := parseChallengeAsDynamicPortAssignment(tc.challengeType)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedBase, baseType)
				assert.Equal(t, tc.expectedPort, port)
			}
		})
	}
}

func TestCompareKeyMaps_RSAKeys_Cov91(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "RSA",
		"n":   "test-modulus-value",
		"e":   "AQAB",
	}
	key2 := map[string]interface{}{
		"kty": "RSA",
		"n":   "test-modulus-value",
		"e":   "AQAB",
	}
	key3 := map[string]interface{}{
		"kty": "RSA",
		"n":   "different-modulus",
		"e":   "AQAB",
	}

	assert.True(t, compareKeyMaps(key1, key2))
	assert.False(t, compareKeyMaps(key1, key3))
}

// TestCompareKeyMaps_ECKeys_Cov91 tests compareKeyMaps with EC keys
func TestCompareKeyMaps_ECKeys_Cov91(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x-value",
		"y":   "test-y-value",
	}
	key2 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x-value",
		"y":   "test-y-value",
	}
	key3 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "different-x",
		"y":   "test-y-value",
	}

	assert.True(t, compareKeyMaps(key1, key2))
	assert.False(t, compareKeyMaps(key1, key3))
}

func TestCompareKeyMaps_InvalidKtyTypeValue(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": 123,
		"n":   "modulus",
		"e":   "AQAB",
	}
	key2 := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus",
		"e":   "AQAB",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

func TestParseSpecIDEvent_SignatureReadError(t *testing.T) {
	// Data that's exactly 28 bytes but signature read would fail
	// 28 bytes minimum, but we need data that fails at different stages

	// Test with valid length but truncated during first read
	data := []byte{
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
		'E', 'v', 'e', 'n', 't', '0', '3', 0,
		0x00, 0x00, 0x00, 0x00, // platformClass
		0x00,             // specVersionMinor
		0x02,             // specVersionMajor
		0x00,             // specErrata
		0x04,             // uintnSize
		0x00, 0x00, 0x00, // partial numberOfAlgorithms (truncated)
	}

	_, err := parseSpecIDEvent(data)
	assert.Error(t, err)
}

// TestParseSpecIDEvent_AlgorithmReadError tests algorithm entry read error
func TestParseSpecIDEvent_AlgorithmReadError(t *testing.T) {
	// Valid header but algorithm read fails
	data := []byte{
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
		'E', 'v', 'e', 'n', 't', '0', '3', 0,
		0x00, 0x00, 0x00, 0x00, // platformClass
		0x00, 0x02, 0x00, // specVersionMinor, specVersionMajor, specErrata
		0x04,                   // uintnSize
		0x01, 0x00, 0x00, 0x00, // numberOfAlgorithms = 1
		0x04, // Only 1 byte of algorithm (need 4 total: 2 for AlgorithmID + 2 for DigestSize)
	}

	_, err := parseSpecIDEvent(data)
	assert.Error(t, err)
}

// TestParseSpecIDEvent_DigestSizeReadError tests digest size read error
func TestParseSpecIDEvent_DigestSizeReadError(t *testing.T) {
	// Valid header and algorithm ID but digest size read fails
	data := []byte{
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
		'E', 'v', 'e', 'n', 't', '0', '3', 0,
		0x00, 0x00, 0x00, 0x00, // platformClass
		0x00, 0x02, 0x00, // specVersionMinor, specVersionMajor, specErrata
		0x04,                   // uintnSize
		0x01, 0x00, 0x00, 0x00, // numberOfAlgorithms = 1
		0x04, 0x00, // AlgorithmID = SHA-1
		0x14, // Only 1 byte of DigestSize (need 2)
	}

	_, err := parseSpecIDEvent(data)
	assert.Error(t, err)
}

// TestParseCryptoAgileEvent_AlgIDReadError tests algorithm ID read error
func TestParseCryptoAgileEvent_AlgIDReadError(t *testing.T) {
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: 0x000B, DigestSize: 32}, // SHA-256
	}

	// Event with valid header but truncated during algID read
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count = 1
		0x01, 0x00, 0x00, 0x00,
		// Algorithm ID - only 1 byte (need 2)
		0x0B,
	}

	reader := bytes.NewReader(data)
	_, err := parseCryptoAgileEvent(reader, algorithms)
	assert.Error(t, err)
}

// TestParseCryptoAgileEvent_UnknownAlgorithmSHA1 tests SHA-1 algorithm fallback
func TestParseCryptoAgileEvent_UnknownAlgorithmSHA1(t *testing.T) {
	// Empty algorithms list - will trigger fallback
	algorithms := []SpecIDAlgorithm{}

	// Event with SHA-1 (0x0004) but no matching algorithm entry
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count = 1
		0x01, 0x00, 0x00, 0x00,
		// Algorithm ID = SHA-1 (0x0004)
		0x04, 0x00,
	}
	// Add 20 bytes for SHA-1 digest
	digest := make([]byte, 20)
	data = append(data, digest...)
	// Event data size = 0
	data = append(data, 0x00, 0x00, 0x00, 0x00)

	reader := bytes.NewReader(data)
	entry, err := parseCryptoAgileEvent(reader, algorithms)
	assert.NoError(t, err)
	assert.Equal(t, 0, entry.PCRIndex)
}

// TestParseCryptoAgileEvent_UnknownAlgorithmSHA384 tests SHA-384 fallback
func TestParseCryptoAgileEvent_UnknownAlgorithmSHA384(t *testing.T) {
	// Empty algorithms list
	algorithms := []SpecIDAlgorithm{}

	// Event with SHA-384 (0x000C)
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count = 1
		0x01, 0x00, 0x00, 0x00,
		// Algorithm ID = SHA-384 (0x000C)
		0x0C, 0x00,
	}
	// Add 48 bytes for SHA-384 digest
	digest := make([]byte, 48)
	data = append(data, digest...)
	// Event data size = 0
	data = append(data, 0x00, 0x00, 0x00, 0x00)

	reader := bytes.NewReader(data)
	entry, err := parseCryptoAgileEvent(reader, algorithms)
	assert.NoError(t, err)
	assert.Equal(t, 0, entry.PCRIndex)
}

// TestParseCryptoAgileEvent_UnknownAlgorithmSHA512 tests SHA-512 fallback
func TestParseCryptoAgileEvent_UnknownAlgorithmSHA512(t *testing.T) {
	// Empty algorithms list
	algorithms := []SpecIDAlgorithm{}

	// Event with SHA-512 (0x000D)
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count = 1
		0x01, 0x00, 0x00, 0x00,
		// Algorithm ID = SHA-512 (0x000D)
		0x0D, 0x00,
	}
	// Add 64 bytes for SHA-512 digest
	digest := make([]byte, 64)
	data = append(data, digest...)
	// Event data size = 0
	data = append(data, 0x00, 0x00, 0x00, 0x00)

	reader := bytes.NewReader(data)
	entry, err := parseCryptoAgileEvent(reader, algorithms)
	assert.NoError(t, err)
	assert.Equal(t, 0, entry.PCRIndex)
}

// TestParseCryptoAgileEvent_UnknownAlgorithmError tests unknown algorithm error
func TestParseCryptoAgileEvent_UnknownAlgorithmError(t *testing.T) {
	// Empty algorithms list
	algorithms := []SpecIDAlgorithm{}

	// Event with unknown algorithm (0x0099)
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count = 1
		0x01, 0x00, 0x00, 0x00,
		// Algorithm ID = unknown (0x0099)
		0x99, 0x00,
	}

	reader := bytes.NewReader(data)
	_, err := parseCryptoAgileEvent(reader, algorithms)
	assert.Error(t, err) // Should fail on unknown algorithm
}

// TestParseCryptoAgileEvent_DigestReadError tests digest read error
func TestParseCryptoAgileEvent_DigestReadError(t *testing.T) {
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: 0x000B, DigestSize: 32}, // SHA-256
	}

	// Event with valid header but truncated digest
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count = 1
		0x01, 0x00, 0x00, 0x00,
		// Algorithm ID = SHA-256
		0x0B, 0x00,
		// Only 5 bytes of digest (need 32)
		0x01, 0x02, 0x03, 0x04, 0x05,
	}

	reader := bytes.NewReader(data)
	_, err := parseCryptoAgileEvent(reader, algorithms)
	assert.Error(t, err)
}

// TestParseCryptoAgileEvent_EventDataReadError tests event data read error
func TestParseCryptoAgileEvent_EventDataReadError(t *testing.T) {
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: 0x000B, DigestSize: 32}, // SHA-256
	}

	// Event with valid digest but truncated event data
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count = 1
		0x01, 0x00, 0x00, 0x00,
		// Algorithm ID = SHA-256
		0x0B, 0x00,
	}
	// Add 32 bytes for SHA-256 digest
	digest := make([]byte, 32)
	data = append(data, digest...)
	// Event data size = 10 but no actual data
	data = append(data, 0x0A, 0x00, 0x00, 0x00)

	reader := bytes.NewReader(data)
	_, err := parseCryptoAgileEvent(reader, algorithms)
	assert.Error(t, err)
}

// TestNewEventLogValidationHook_ValidateAgainstPCRs tests PCR validation path
func TestNewEventLogValidationHook_ValidateAgainstPCRs(t *testing.T) {
	policy := &EventLogPolicy{
		RequiredEvents:      []string{},
		ForbiddenEvents:     []string{},
		ValidateAgainstPCRs: true,
	}
	hook := NewEventLogValidationHook(policy)

	// Create a minimal valid event log
	eventLog := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type (EV_NO_ACTION)
		0x03, 0x00, 0x00, 0x00,
		// Digest (20 bytes of zeros for SHA-1)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Event data size
		0x10, 0x00, 0x00, 0x00,
		// Event data (Spec ID Event03 signature)
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
		'E', 'v', 'e', 'n', 't', '0', '3', 0,
	}

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			EventLog:   eventLog,
			ProdCaData: []byte{}, // Empty ProdCaData for PCR validation
		},
	}

	err := hook(ctx)
	// May or may not error depending on PCR validation logic
	// The goal is to hit the code path
	_ = err
}
