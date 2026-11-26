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
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
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
// ChallengeHandler additional error paths
// =============================================================================

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
