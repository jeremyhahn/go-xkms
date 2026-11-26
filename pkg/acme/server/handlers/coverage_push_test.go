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
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
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
// jwkKeysMatch Tests (72.7% coverage -> target 100%)
// =============================================================================

func TestCoveragePush_JwkKeysMatch_RSA(t *testing.T) {
	a := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus123",
		"e":   "AQAB",
	}
	b := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus123",
		"e":   "AQAB",
	}

	assert.True(t, jwkKeysMatch(a, b))
}

func TestCoveragePush_JwkKeysMatch_OKP(t *testing.T) {
	a := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "publickey123",
	}
	b := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "publickey123",
	}

	assert.True(t, jwkKeysMatch(a, b))
}

func TestCoveragePush_JwkKeysMatch_UnknownType_Mismatch(t *testing.T) {
	a := map[string]interface{}{
		"kty":  "UNKNOWN",
		"data": "value1",
	}
	b := map[string]interface{}{
		"kty":  "UNKNOWN",
		"data": "value2",
	}

	assert.False(t, jwkKeysMatch(a, b))
}

func TestCoveragePush_JwkKeysMatch_TypeMismatch(t *testing.T) {
	a := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus123",
	}
	b := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
	}

	assert.False(t, jwkKeysMatch(a, b))
}

// =============================================================================
// writeChallengeResponse Tests (75% coverage -> target 100%)
// =============================================================================

func TestCoveragePush_WriteChallengeResponse_NonceError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Set failing nonce generator
	service.SetNonceGenerator(func() (string, error) {
		return "", errors.New("nonce generation failed")
	})

	challenge := &entities.ACMEChallenge{
		ID:     12345,
		Type:   "http-01",
		URL:    "https://acme.test.example.com/acme/challenge/12345",
		Status: common.StatusPending,
		Token:  "test-token",
	}

	w := httptest.NewRecorder()
	service.writeChallengeResponse(w, challenge)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// =============================================================================
// NewAccountHandler Additional Tests (57.4% coverage -> target 90%+)
// =============================================================================

func TestCoveragePush_NewAccountHandler_ExternalAccountRequired_NotProvided(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Enable external account requirement
	service.externalAccountRequired = true

	key := generateTestKey(t)

	payload := map[string]interface{}{
		"contact":              []string{"mailto:test@example.com"},
		"termsOfServiceAgreed": true,
		// No externalAccountBinding provided
	}

	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-account", payload, false, 0)
	w := httptest.NewRecorder()

	service.NewAccountHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assertErrorType(t, w, "externalAccountRequired", http.StatusUnauthorized)
}

// =============================================================================
// generateIDWithReader and generateTokenWithReader Tests
// =============================================================================

// failingReaderCovPush always returns an error
type failingReaderCovPush struct{}

func (f *failingReaderCovPush) Read(_ []byte) (int, error) {
	return 0, errors.New("read failed")
}

// shortReaderCovPush reads less than requested
type shortReaderCovPush struct{}

func (s *shortReaderCovPush) Read(p []byte) (int, error) {
	if len(p) > 5 {
		return 5, nil // Only read 5 bytes
	}
	return len(p), nil
}

func TestCoveragePush_GenerateIDWithReader_Error(t *testing.T) {
	id, err := generateIDWithReader(&failingReaderCovPush{})
	assert.Error(t, err)
	assert.Zero(t, id)
}

func TestCoveragePush_GenerateIDWithReader_ShortRead(t *testing.T) {
	id, err := generateIDWithReader(&shortReaderCovPush{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFailedToGenerateID)
	assert.Zero(t, id)
}

func TestCoveragePush_GenerateTokenWithReader_Error(t *testing.T) {
	token, err := generateTokenWithReader(&failingReaderCovPush{})
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestCoveragePush_GenerateTokenWithReader_ShortRead(t *testing.T) {
	token, err := generateTokenWithReader(&shortReaderCovPush{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFailedToGenerateToken)
	assert.Empty(t, token)
}

// =============================================================================
// verifyMAC Tests
// =============================================================================

func TestCoveragePush_VerifyMAC_UnsupportedAlgorithm(t *testing.T) {
	err := verifyMAC("UNSUPPORTED", []byte("key"), []byte("message"), "signature")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

func TestCoveragePush_VerifyMAC_InvalidSignatureBase64(t *testing.T) {
	// 32 bytes: a real EAB key is never this short, and crypto/hmac refuses
	// any key under 112 bits (14 bytes) under GODEBUG=fips140=only, which
	// would otherwise report the wrong cause for this bad-base64 signature.
	key := []byte("32-byte-eab-hmac-key-for-tests!!")
	err := verifyMAC("HS256", key, []byte("message"), "invalid base64!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode signature")
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

func TestCoveragePush_CreateExternalAccountBinding_HS384(t *testing.T) {
	binding, err := CreateExternalAccountBinding("kid", "external", "HS384")
	require.NoError(t, err)
	assert.Equal(t, "HS384", binding.MACAlgorithm)
	assert.Equal(t, 48, len(mustDecodeBase64CovPush(t, binding.MACKey)))
}

func TestCoveragePush_CreateExternalAccountBinding_HS512(t *testing.T) {
	binding, err := CreateExternalAccountBinding("kid", "external", "HS512")
	require.NoError(t, err)
	assert.Equal(t, "HS512", binding.MACAlgorithm)
	assert.Equal(t, 64, len(mustDecodeBase64CovPush(t, binding.MACKey)))
}

func TestCoveragePush_CreateExternalAccountBinding_UnsupportedAlgorithm(t *testing.T) {
	binding, err := CreateExternalAccountBinding("kid", "external", "RS256")
	assert.Error(t, err)
	assert.Nil(t, binding)
	var caErr *caerrors.TrustedCAError
	assert.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Malformed, caErr.Type)
}

func mustDecodeBase64CovPush(t *testing.T, s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
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
// Tenant Signing CA Resolution Tests
// =============================================================================

func TestCoveragePush_ResolveTenantSigningCA_NonTenantAwareFactory(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	account := &entities.ACMEAccount{
		ID:       12345,
		TenantID: "tenant-123",
	}

	// Standard storage factory doesn't support TenantAwareFactory: a
	// tenant-bound account fails closed rather than using the global CA.
	result, err := service.resolveTenantSigningCA(context.Background(), account, "general")
	assert.ErrorIs(t, err, ErrTenantStorageUnsupported)
	assert.Nil(t, result)
}

// =============================================================================
// getTenantCASigner Tests
// =============================================================================

func TestCoveragePush_GetTenantCASigner_NoKMSService(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.kmsService = nil

	signingCAInfo := &entities.SigningCAInfo{
		UseGlobalDefault: false,
		TenantID:         "tenant-123",
		Type:             entities.SigningCATypeIntermediate,
	}

	signer, err := service.getTenantCASigner(context.Background(), signingCAInfo)
	assert.ErrorIs(t, err, ErrTenantSignerUnavailable)
	assert.Nil(t, signer)
}

// Suppress unused import warning
var _ = storage.Factory(nil)
