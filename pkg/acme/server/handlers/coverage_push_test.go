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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Service Getters/Setters Tests (0% coverage -> target 100%)
// =============================================================================

func TestCoveragePush_GetStorageFactory(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	factory := service.GetStorageFactory()
	assert.NotNil(t, factory)
	assert.Equal(t, service.storageFactory, factory)
}

func TestCoveragePush_GetNonceService(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	nonceService := service.GetNonceService()
	assert.NotNil(t, nonceService)
	assert.Equal(t, service.nonceService, nonceService)
}

func TestCoveragePush_SetOrderFinalizeHooks(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	registry := NewOrderFinalizeHookRegistry()
	service.SetOrderFinalizeHooks(registry)

	assert.Equal(t, registry, service.orderFinalizeHooks)
	assert.Equal(t, registry, service.params.OrderFinalizeHooks)
}

func TestCoveragePush_GetOrderFinalizeHooks(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	registry := NewOrderFinalizeHookRegistry()
	service.orderFinalizeHooks = registry

	result := service.GetOrderFinalizeHooks()
	assert.Equal(t, registry, result)
}

func TestCoveragePush_SetPreIssuanceHooks(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	registry := NewPreIssuanceHookRegistry()
	service.SetPreIssuanceHooks(registry)

	assert.Equal(t, registry, service.preIssuanceHooks)
	assert.Equal(t, registry, service.params.PreIssuanceHooks)
}

func TestCoveragePush_GetPreIssuanceHooks(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	registry := NewPreIssuanceHookRegistry()
	service.preIssuanceHooks = registry

	result := service.GetPreIssuanceHooks()
	assert.Equal(t, registry, result)
}

func TestCoveragePush_SetGlobalComplianceConfig(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	config := &GlobalComplianceConfig{
		ComplianceConfig: ComplianceConfig{
			Enabled: true,
		},
	}
	service.SetGlobalComplianceConfig(config)

	assert.Equal(t, config, service.globalComplianceConfig)
	assert.Equal(t, config, service.params.GlobalComplianceConfig)
}

func TestCoveragePush_GetGlobalComplianceConfig_Nil(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.globalComplianceConfig = nil
	result := service.GetGlobalComplianceConfig()
	assert.Nil(t, result)
}

// mockCAAValidatorCovPush for testing CAA validation
type mockCAAValidatorCovPush struct {
	err error
}

func (m *mockCAAValidatorCovPush) Validate(_ context.Context, _ string, _ bool, _ string, _ string) error {
	return m.err
}

func TestCoveragePush_SetCAAValidator(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	validator := &mockCAAValidatorCovPush{}
	service.SetCAAValidator(validator)

	assert.Equal(t, validator, service.caaValidator)
}

func TestCoveragePush_GetCAAValidator_Nil(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.caaValidator = nil
	result := service.GetCAAValidator()
	assert.Nil(t, result)
}

func TestCoveragePush_SetNonceGenerator(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	customGen := func() (string, error) {
		return "custom-nonce", nil
	}
	service.SetNonceGenerator(customGen)

	// Verify by calling the generator
	nonce, err := service.nonceGenerator()
	assert.NoError(t, err)
	assert.Equal(t, "custom-nonce", nonce)
}

func TestCoveragePush_GetNonceGenerator(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	gen := service.GetNonceGenerator()
	assert.NotNil(t, gen)

	// Test that it works
	nonce, err := gen()
	assert.NoError(t, err)
	assert.NotEmpty(t, nonce)
}

// =============================================================================
// encodeJSONWithLogger Tests (25% coverage -> target 100%)
// =============================================================================

// =============================================================================
// jwkKeysMatch Tests (72.7% coverage -> target 100%)
// =============================================================================

func TestCoveragePush_JwkKeysMatch_RSA_Mismatch(t *testing.T) {
	a := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus123",
		"e":   "AQAB",
	}
	b := map[string]interface{}{
		"kty": "RSA",
		"n":   "different",
		"e":   "AQAB",
	}

	assert.False(t, jwkKeysMatch(a, b))
}

func TestCoveragePush_JwkKeysMatch_EC_Mismatch(t *testing.T) {
	a := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "x123",
		"y":   "y123",
	}
	b := map[string]interface{}{
		"kty": "EC",
		"crv": "P-384",
		"x":   "x123",
		"y":   "y123",
	}

	assert.False(t, jwkKeysMatch(a, b))
}

func TestCoveragePush_JwkKeysMatch_OKP_Mismatch(t *testing.T) {
	a := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "publickey123",
	}
	b := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "different",
	}

	assert.False(t, jwkKeysMatch(a, b))
}

// =============================================================================
// writeChallengeResponse Tests (75% coverage -> target 100%)
// =============================================================================

func TestCoveragePush_WriteChallengeResponse_WithValidated(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	challenge := &entities.ACMEChallenge{
		ID:        12345,
		Type:      "http-01",
		URL:       "https://acme.test.example.com/acme/challenge/12345",
		Status:    common.StatusValid,
		Token:     "test-token",
		Validated: time.Now().Format(time.RFC3339),
	}

	w := httptest.NewRecorder()
	service.writeChallengeResponse(w, challenge)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "valid", resp["status"])
	assert.NotEmpty(t, resp["validated"])
}

// =============================================================================
// resolveTenantComplianceConfig Tests (65.2% coverage -> target 100%)
// =============================================================================

// =============================================================================
// NewAccountHandler Additional Tests (57.4% coverage -> target 90%+)
// =============================================================================

func TestCoveragePush_NewAccountHandler_AccountExists_OnlyReturn(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// First create an account
	payload := map[string]interface{}{
		"contact":              []string{"mailto:test@example.com"},
		"termsOfServiceAgreed": true,
	}

	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-account", payload, false, 0)
	w := httptest.NewRecorder()
	service.NewAccountHandler(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Request existing with onlyReturnExisting
	payload2 := map[string]interface{}{
		"onlyReturnExisting": true,
	}
	req2 := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-account", payload2, false, 0)
	w2 := httptest.NewRecorder()
	service.NewAccountHandler(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
}

// =============================================================================
// NewOrderHandler Additional Tests (76.6% coverage -> target 90%+)
// =============================================================================

// =============================================================================
// KeyChangeHandler Additional Tests (71.1% coverage -> target 90%+)
// =============================================================================

// =============================================================================
// OrderFinalizeHandler Additional Tests (68.6% coverage -> target 90%+)
// =============================================================================

// =============================================================================
// ChallengeHandler Additional Tests
// =============================================================================

// =============================================================================
// isEnrollXChallenge Tests
// =============================================================================

// =============================================================================
// ValidateContactURLs Tests
// =============================================================================

func TestCoveragePush_ValidateContactURLs(t *testing.T) {
	testCases := []struct {
		name     string
		contacts []string
		wantErr  bool
	}{
		{"valid mailto", []string{"mailto:test@example.com"}, false},
		{"multiple valid", []string{"mailto:a@example.com", "mailto:b@example.com"}, false},
		{"empty", []string{}, false},
		{"mailto with hfields", []string{"mailto:test@example.com?subject=test"}, true},
		{"mailto with multiple addr", []string{"mailto:a@example.com,b@example.com"}, true},
		{"invalid email", []string{"mailto:not-an-email"}, true},
		{"unsupported scheme", []string{"tel:+1234567890"}, true},
		{"no scheme", []string{"test@example.com"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateContactURLs(tc.contacts)
			if tc.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

// =============================================================================
// generateIDWithReader and generateTokenWithReader Tests
// =============================================================================

// =============================================================================
// compareKeyMaps Tests (for KeyChangeHandler)
// =============================================================================

// =============================================================================
// verifyMAC Tests
// =============================================================================

func TestCoveragePush_VerifyMAC_HS256(t *testing.T) {
	// Create binding to verify MAC generation works
	binding, err := CreateExternalAccountBinding("kid", "external", "HS256")
	require.NoError(t, err)
	assert.NotNil(t, binding)
}

// =============================================================================
// CreateExternalAccountBinding Tests
// =============================================================================

func TestCoveragePush_CreateExternalAccountBinding_DefaultAlgorithm(t *testing.T) {
	binding, err := CreateExternalAccountBinding("kid", "external", "")
	require.NoError(t, err)
	assert.Equal(t, "HS256", binding.MACAlgorithm)
	assert.Equal(t, 32, len(mustDecodeBase64CovPush(t, binding.MACKey)))
}

func mustDecodeBase64CovPush(t *testing.T, s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

// =============================================================================
// isSymmetricAlgorithm Tests
// =============================================================================

func TestCoveragePush_IsSymmetricAlgorithm(t *testing.T) {
	assert.True(t, isSymmetricAlgorithm("HS256"))
	assert.True(t, isSymmetricAlgorithm("HS384"))
	assert.True(t, isSymmetricAlgorithm("HS512"))
	assert.False(t, isSymmetricAlgorithm("RS256"))
	assert.False(t, isSymmetricAlgorithm("ES256"))
	assert.False(t, isSymmetricAlgorithm(""))
}

// =============================================================================
// orderResponse Nonce Error Test
// =============================================================================

func TestCoveragePush_OrderResponse_NonceError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Set failing nonce generator
	service.SetNonceGenerator(func() (string, error) {
		return "", errors.New("nonce generation failed")
	})

	order := &entities.ACMEOrder{
		ID:     12345,
		Status: common.StatusPending,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
	}

	w := httptest.NewRecorder()
	service.orderResponse(w, order)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// =============================================================================
// respondWithAccount Nonce Error Test
// =============================================================================

func TestCoveragePush_RespondWithAccount_NonceError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Set failing nonce generator
	service.SetNonceGenerator(func() (string, error) {
		return "", errors.New("nonce generation failed")
	})

	account := &entities.ACMEAccount{
		ID:      12345,
		Status:  common.StatusValid,
		Contact: []string{"mailto:test@example.com"},
	}

	w := httptest.NewRecorder()
	service.respondWithAccount(w, account, http.StatusOK)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// =============================================================================
// parseKID Error Paths
// =============================================================================

func TestCoveragePush_ParseKID_InvalidNonce(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create JWS with invalid nonce (not in store)
	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: "invalid-nonce-not-in-store"},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/account/" + fmt.Sprintf("%d", account.ID),
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
	parsedAccount, parsedPayload, err := service.parseKID(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, parsedAccount)
	assert.Nil(t, parsedPayload)
}

func TestCoveragePush_ParseKID_InvalidSignature(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Get a valid nonce
	nonce, err := service.GetNonceService().Generate()
	require.NoError(t, err)

	// Create JWS with correct key
	payload := map[string]interface{}{"test": "data"}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/account/" + fmt.Sprintf("%d", account.ID),
			"kid": fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID),
		},
	}

	// Sign with a DIFFERENT key than what's stored in the account
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       wrongKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/account/"+fmt.Sprintf("%d", account.ID), strings.NewReader(jws.FullSerialize()))

	ctx := context.Background()
	parsedAccount, parsedPayload, err := service.parseKID(ctx, req)

	assert.ErrorIs(t, err, ErrInvalidJWSSignature)
	assert.Nil(t, parsedAccount)
	assert.Nil(t, parsedPayload)
}

// =============================================================================
// External Account Binding Verifier Tests
// =============================================================================

func TestCoveragePush_ExternalAccountBindingVerifier_InvalidJWSFormat(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create DAO mock
	eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(eabDAO, "https://example.com/acme/new-account")

	key := generateTestKey(t)

	// Pass an invalid EAB JWS (not a proper structure)
	invalidJWS := "invalid-jws-string"

	ctx := context.Background()
	binding, err := verifier.Verify(ctx, invalidJWS, key.JWK)

	assert.Error(t, err)
	assert.Nil(t, binding)
}

func TestCoveragePush_ExternalAccountBindingVerifier_InvalidProtectedHeader(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	verifier := NewExternalAccountBindingVerifier(eabDAO, "https://example.com/acme/new-account")

	key := generateTestKey(t)

	// Pass JWS with invalid base64 in protected header
	invalidJWS := map[string]string{
		"protected": "!!!invalid-base64!!!",
		"payload":   base64.RawURLEncoding.EncodeToString([]byte("{}")),
		"signature": base64.RawURLEncoding.EncodeToString([]byte("sig")),
	}

	ctx := context.Background()
	binding, err := verifier.Verify(ctx, invalidJWS, key.JWK)

	assert.Error(t, err)
	assert.Nil(t, binding)
}

// =============================================================================
// encodeCertificatePEM and encodeCSRToPEM Tests
// =============================================================================

// =============================================================================
// Tenant Signing CA Resolution Tests
// =============================================================================

// =============================================================================
// getTenantCASigner Tests
// =============================================================================

// =============================================================================
// matchesIdentifier Tests
// =============================================================================

// =============================================================================
// Account URL Generation Test
// =============================================================================

func TestCoveragePush_AccountURL(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	account := &entities.ACMEAccount{
		ID: 12345,
	}

	url := service.accountURL(account)
	assert.Equal(t, "https://acme.test.example.com/acme/account/12345", url)
}

// =============================================================================
// generateNonce Test
// =============================================================================

func TestCoveragePush_GenerateNonce(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	nonce, err := service.generateNonce()
	assert.NoError(t, err)
	assert.NotEmpty(t, nonce)
}

func TestCoveragePush_GenerateNonce_Error(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.SetNonceGenerator(func() (string, error) {
		return "", errors.New("generation failed")
	})

	nonce, err := service.generateNonce()
	assert.Error(t, err)
	assert.Empty(t, nonce)
}

// =============================================================================
// NewRestService with NonceGenerator Test
// =============================================================================

func TestCoveragePush_NewRestService_CustomNonceGenerator(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	customGen := func() (string, error) {
		return "custom-nonce", nil
	}

	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		StorageFactory: service.storageFactory,
		NonceGenerator: customGen,
	}

	newService, err := NewRestService(params)
	require.NoError(t, err)

	restService := newService.(*RestService)
	nonce, err := restService.generateNonce()
	assert.NoError(t, err)
	assert.Equal(t, "custom-nonce", nonce)
}

// =============================================================================
// challengeResponse Test (standalone function)
// =============================================================================

// =============================================================================
// parseJWS No Signatures Test
// =============================================================================

// =============================================================================
// parseKID No Signatures Test
// =============================================================================

// Suppress unused import warning
var _ = storage.Factory(nil)
