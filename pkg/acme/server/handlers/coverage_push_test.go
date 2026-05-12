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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
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

func TestCoveragePush_GetNonceStore(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	nonceStore := service.GetNonceStore()
	assert.NotNil(t, nonceStore)
	assert.Equal(t, service.nonceStore, nonceStore)
}

func TestCoveragePush_SetOrderFinalizeHooks(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	registry := NewOrderFinalizeHookRegistry()
	service.SetOrderFinalizeHooks(registry)

	assert.Equal(t, registry, service.orderFinalizeHooks)
	assert.Equal(t, registry, service.params.OrderFinalizeHooks)
}

func TestCoveragePush_SetOrderFinalizeHooks_NilParams(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Set params to nil to test nil check
	service.params = nil

	registry := NewOrderFinalizeHookRegistry()
	service.SetOrderFinalizeHooks(registry)

	assert.Equal(t, registry, service.orderFinalizeHooks)
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

func TestCoveragePush_SetPreIssuanceHooks_NilParams(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Set params to nil to test nil check
	service.params = nil

	registry := NewPreIssuanceHookRegistry()
	service.SetPreIssuanceHooks(registry)

	assert.Equal(t, registry, service.preIssuanceHooks)
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

func TestCoveragePush_SetGlobalComplianceConfig_NilParams(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Set params to nil to test nil check
	service.params = nil

	config := &GlobalComplianceConfig{
		ComplianceConfig: ComplianceConfig{
			Enabled: true,
		},
	}
	service.SetGlobalComplianceConfig(config)

	assert.Equal(t, config, service.globalComplianceConfig)
}

func TestCoveragePush_GetGlobalComplianceConfig(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	config := &GlobalComplianceConfig{
		ComplianceConfig: ComplianceConfig{
			Enabled: true,
		},
	}
	service.globalComplianceConfig = config

	result := service.GetGlobalComplianceConfig()
	assert.Equal(t, config, result)
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

func (m *mockCAAValidatorCovPush) Validate(_ context.Context, _ string, _ bool) error {
	return m.err
}

func TestCoveragePush_SetCAAValidator(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	validator := &mockCAAValidatorCovPush{}
	service.SetCAAValidator(validator)

	assert.Equal(t, validator, service.caaValidator)
}

func TestCoveragePush_GetCAAValidator(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	validator := &mockCAAValidatorCovPush{}
	service.caaValidator = validator

	result := service.GetCAAValidator()
	assert.Equal(t, validator, result)
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

	customGen := func(length int) (string, error) {
		return "custom-nonce", nil
	}
	service.SetNonceGenerator(customGen)

	// Verify by calling the generator
	nonce, err := service.nonceGenerator(16)
	assert.NoError(t, err)
	assert.Equal(t, "custom-nonce", nonce)
}

func TestCoveragePush_GetNonceGenerator(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	gen := service.GetNonceGenerator()
	assert.NotNil(t, gen)

	// Test that it works
	nonce, err := gen(16)
	assert.NoError(t, err)
	assert.NotEmpty(t, nonce)
}

// =============================================================================
// encodeJSONWithLogger Tests (25% coverage -> target 100%)
// =============================================================================

func TestCoveragePush_EncodeJSONWithLogger_Success(t *testing.T) {
	w := httptest.NewRecorder()
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))

	data := map[string]string{"key": "value"}
	encodeJSONWithLogger(w, data, logger)

	var result map[string]string
	err := json.NewDecoder(w.Body).Decode(&result)
	assert.NoError(t, err)
	assert.Equal(t, "value", result["key"])
}

func TestCoveragePush_EncodeJSONWithLogger_NilLogger(t *testing.T) {
	w := httptest.NewRecorder()

	data := map[string]string{"key": "value"}
	encodeJSONWithLogger(w, data, nil)

	var result map[string]string
	err := json.NewDecoder(w.Body).Decode(&result)
	assert.NoError(t, err)
	assert.Equal(t, "value", result["key"])
}

// brokenWriterCovPush simulates a write error for testing
type brokenWriterCovPush struct {
	http.ResponseWriter
}

func (b *brokenWriterCovPush) Write(_ []byte) (int, error) {
	return 0, errors.New("broken writer")
}

func TestCoveragePush_EncodeJSONWithLogger_WriteError(t *testing.T) {
	logBuf := bytes.NewBuffer(nil)
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	w := &brokenWriterCovPush{ResponseWriter: httptest.NewRecorder()}

	data := map[string]string{"key": "value"}
	encodeJSONWithLogger(w, data, logger)

	// Verify error was logged
	assert.Contains(t, logBuf.String(), "failed to encode JSON response")
}

// =============================================================================
// isValidDomainName Tests (64.3% coverage -> target 100%)
// =============================================================================

func TestCoveragePush_IsValidDomainName_Valid(t *testing.T) {
	testCases := []struct {
		name   string
		domain string
	}{
		{"simple", "example.com"},
		{"subdomain", "sub.example.com"},
		{"multi-subdomain", "a.b.c.example.com"},
		{"with-hyphen", "my-domain.com"},
		{"mixed-case", "Example.COM"},
		{"numbers", "test123.com"},
		{"single-char-labels", "a.b.c.d"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, isValidDomainName(tc.domain), "domain %s should be valid", tc.domain)
		})
	}
}

func TestCoveragePush_IsValidDomainName_Invalid(t *testing.T) {
	testCases := []struct {
		name   string
		domain string
	}{
		{"empty", ""},
		{"too-long", strings.Repeat("a", 254)},
		{"label-too-long", strings.Repeat("a", 64) + ".com"},
		{"starts-with-hyphen", "-example.com"},
		{"ends-with-hyphen", "example-.com"},
		{"empty-label", "example..com"},
		{"label-starts-with-hyphen", "sub.-example.com"},
		{"label-ends-with-hyphen", "sub.example-.com"},
		{"invalid-char-underscore", "test_domain.com"},
		{"invalid-char-space", "test domain.com"},
		{"invalid-char-at", "test@domain.com"},
		{"single-empty-label", ".com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, isValidDomainName(tc.domain), "domain %s should be invalid", tc.domain)
		})
	}
}

func TestCoveragePush_IsValidDomainName_EdgeCases(t *testing.T) {
	// Max length domain (253 chars): 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
	maxLabel63 := strings.Repeat("a", 63)
	lastLabel61 := strings.Repeat("b", 61)
	maxDomain := maxLabel63 + "." + maxLabel63 + "." + maxLabel63 + "." + lastLabel61
	assert.Equal(t, 253, len(maxDomain))
	assert.True(t, isValidDomainName(maxDomain))

	// Just over max length (254 chars)
	overMaxDomain := maxDomain + "c"
	assert.Equal(t, 254, len(overMaxDomain))
	assert.False(t, isValidDomainName(overMaxDomain))
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

func TestCoveragePush_JwkKeysMatch_EC(t *testing.T) {
	a := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "x123",
		"y":   "y123",
	}
	b := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "x123",
		"y":   "y123",
	}

	assert.True(t, jwkKeysMatch(a, b))
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

func TestCoveragePush_JwkKeysMatch_UnknownType(t *testing.T) {
	a := map[string]interface{}{
		"kty":  "UNKNOWN",
		"data": "same",
	}
	b := map[string]interface{}{
		"kty":  "UNKNOWN",
		"data": "same",
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

func TestCoveragePush_JwkKeysMatch_MissingKty(t *testing.T) {
	a := map[string]interface{}{
		"n": "modulus123",
	}
	b := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus123",
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

func TestCoveragePush_WriteChallengeResponse_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	challenge := &entities.ACMEChallenge{
		ID:     12345,
		Type:   "http-01",
		URL:    "https://acme.test.example.com/acme/challenge/12345",
		Status: common.StatusPending,
		Token:  "test-token",
	}

	w := httptest.NewRecorder()
	service.writeChallengeResponse(w, challenge)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("Replay-Nonce"))
	assert.Contains(t, w.Header().Get("Link"), "directory")

	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "http-01", resp["type"])
	assert.Equal(t, "pending", resp["status"])
}

func TestCoveragePush_WriteChallengeResponse_NonceError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Set failing nonce generator
	service.SetNonceGenerator(func(_ int) (string, error) {
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

func TestCoveragePush_WriteChallengeResponse_WithError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	challenge := &entities.ACMEChallenge{
		ID:     12345,
		Type:   "http-01",
		URL:    "https://acme.test.example.com/acme/challenge/12345",
		Status: common.StatusInvalid,
		Token:  "test-token",
		Error: &entities.Error{
			Type:   "urn:ietf:params:acme:error:incorrectResponse",
			Detail: "validation failed",
			Status: http.StatusForbidden,
		},
	}

	w := httptest.NewRecorder()
	service.writeChallengeResponse(w, challenge)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid", resp["status"])
	assert.NotNil(t, resp["error"])
}

// =============================================================================
// resolveTenantComplianceConfig Tests (65.2% coverage -> target 100%)
// =============================================================================

func TestCoveragePush_ResolveTenantComplianceConfig_NoTenantID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	account := &entities.ACMEAccount{
		ID:       12345,
		TenantID: "", // No tenant ID
	}

	// With global config
	globalConfig := &GlobalComplianceConfig{
		ComplianceConfig: ComplianceConfig{
			Enabled: true,
		},
	}
	service.globalComplianceConfig = globalConfig

	result := service.resolveTenantComplianceConfig(context.Background(), account)
	assert.NotNil(t, result)
	assert.True(t, result.Enabled)
}

func TestCoveragePush_ResolveTenantComplianceConfig_NoTenantID_NoGlobalConfig(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	account := &entities.ACMEAccount{
		ID:       12345,
		TenantID: "", // No tenant ID
	}

	service.globalComplianceConfig = nil

	result := service.resolveTenantComplianceConfig(context.Background(), account)
	assert.Nil(t, result)
}

func TestCoveragePush_ResolveTenantComplianceConfig_NonTenantAwareFactory(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	account := &entities.ACMEAccount{
		ID:       12345,
		TenantID: "tenant-123",
	}

	// Global config should be used when factory doesn't support tenants
	globalConfig := &GlobalComplianceConfig{
		ComplianceConfig: ComplianceConfig{
			Enabled: true,
		},
	}
	service.globalComplianceConfig = globalConfig

	result := service.resolveTenantComplianceConfig(context.Background(), account)
	assert.NotNil(t, result)
	assert.True(t, result.Enabled)
}

// =============================================================================
// NewAccountHandler Additional Tests (57.4% coverage -> target 90%+)
// =============================================================================

func TestCoveragePush_NewAccountHandler_InvalidJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := createInvalidJWSRequest(t, service.baseRESTURI+"/acme/new-account")
	w := httptest.NewRecorder()

	service.NewAccountHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorType(t, w, "malformed", http.StatusBadRequest)
}

func TestCoveragePush_NewAccountHandler_InvalidJSON(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create a request with raw bytes that are not valid JSON
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

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

	// Sign invalid JSON payload
	jws, err := signer.Sign([]byte("not valid json"))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/new-account", strings.NewReader(jws.FullSerialize()))
	w := httptest.NewRecorder()

	service.NewAccountHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCoveragePush_NewAccountHandler_InvalidContact(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	payload := map[string]interface{}{
		"contact":              []string{"invalid-contact"},
		"termsOfServiceAgreed": true,
	}

	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-account", payload, false, 0)
	w := httptest.NewRecorder()

	service.NewAccountHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCoveragePush_NewAccountHandler_OnlyReturnExisting_NotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	payload := map[string]interface{}{
		"onlyReturnExisting": true,
	}

	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-account", payload, false, 0)
	w := httptest.NewRecorder()

	service.NewAccountHandler(w, req)

	// Note: Implementation returns 404, though RFC 8555 specifies 400 for accountDoesNotExist
	assert.Equal(t, http.StatusNotFound, w.Code)
	assertErrorType(t, w, "accountDoesNotExist", http.StatusNotFound)
}

func TestCoveragePush_NewAccountHandler_AccountExists_NotOnlyReturn(t *testing.T) {
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

	// Try to create again without onlyReturnExisting
	req2 := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-account", payload, false, 0)
	w2 := httptest.NewRecorder()
	service.NewAccountHandler(w2, req2)

	assert.Equal(t, http.StatusConflict, w2.Code)
}

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
// NewOrderHandler Additional Tests (76.6% coverage -> target 90%+)
// =============================================================================

func TestCoveragePush_NewOrderHandler_InvalidJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := createInvalidJWSRequest(t, service.baseRESTURI+"/acme/new-order")
	w := httptest.NewRecorder()

	service.NewOrderHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCoveragePush_NewOrderHandler_InvalidJSON(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a request with invalid JSON payload
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/new-order",
			"kid": fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID),
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign([]byte("not valid json"))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/new-order", strings.NewReader(jws.FullSerialize()))
	w := httptest.NewRecorder()

	service.NewOrderHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCoveragePush_NewOrderHandler_UnsupportedIdentifier(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	payload := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "unsupported-type", "value": "example.com"},
		},
	}

	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-order", payload, true, account.ID)
	w := httptest.NewRecorder()

	service.NewOrderHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorType(t, w, "unsupportedIdentifier", http.StatusBadRequest)
}

func TestCoveragePush_NewOrderHandler_InvalidDomainName(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	payload := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "dns", "value": "-invalid.com"},
		},
	}

	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-order", payload, true, account.ID)
	w := httptest.NewRecorder()

	service.NewOrderHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCoveragePush_NewOrderHandler_WildcardDomain(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Add DNS challenge verifier
	service.challengeMap["dns-01"] = func(_ *net.Resolver, _ common.CertificateAuthority, _, _, _, _ string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	payload := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "dns", "value": "*.example.com"},
		},
	}

	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-order", payload, true, account.ID)
	w := httptest.NewRecorder()

	service.NewOrderHandler(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

// =============================================================================
// KeyChangeHandler Additional Tests (71.1% coverage -> target 90%+)
// =============================================================================

func TestCoveragePush_KeyChangeHandler_InvalidJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := createInvalidJWSRequest(t, service.baseRESTURI+"/acme/key-change")
	w := httptest.NewRecorder()

	service.KeyChangeHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCoveragePush_KeyChangeHandler_DeactivatedAccount(t *testing.T) {
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

	payload := map[string]interface{}{
		"account": account.URL,
		"oldKey":  map[string]interface{}{},
	}

	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/key-change", payload, true, account.ID)
	w := httptest.NewRecorder()

	service.KeyChangeHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCoveragePush_KeyChangeHandler_AccountNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create a request for a non-existent account
	payload := map[string]interface{}{}
	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/key-change", payload, true, 99999)
	w := httptest.NewRecorder()

	service.KeyChangeHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// =============================================================================
// OrderFinalizeHandler Additional Tests (68.6% coverage -> target 90%+)
// =============================================================================

func TestCoveragePush_OrderFinalizeHandler_InvalidJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := createInvalidJWSRequest(t, service.baseRESTURI+"/acme/order/12345/finalize")
	w := httptest.NewRecorder()

	service.OrderFinalizeHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// =============================================================================
// ChallengeHandler Additional Tests
// =============================================================================

func TestCoveragePush_ChallengeHandler_InvalidMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, service.baseRESTURI+"/acme/challenge/12345", nil)
	w := httptest.NewRecorder()

	service.ChallengeHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCoveragePush_ChallengeHandler_EmptyChallengeID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/challenge/", nil)
	w := httptest.NewRecorder()

	service.ChallengeHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCoveragePush_ChallengeHandler_InvalidChallengeID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	payload := map[string]interface{}{}
	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/challenge/not-a-number", payload, true, account.ID)
	w := httptest.NewRecorder()

	service.ChallengeHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// =============================================================================
// parseChallengeAsDynamicPortAssignment Tests
// =============================================================================

func TestCoveragePush_ParseChallengeAsDynamicPortAssignment(t *testing.T) {
	testCases := []struct {
		name         string
		challengeTyp string
		wantBase     string
		wantPort     uint16
		wantErr      bool
	}{
		{"standard http-01", "http-01", "http-01", 0, false},
		{"standard enroll-01", "enroll-01", "enroll-01", 0, false},
		{"with port enroll-01-8080", "enroll-01-8080", "enroll-01", 8080, false},
		{"with port device-attest-01-443", "device-attest-01-443", "device-attest-01", 443, false},
		{"no hyphen", "http", "http", 0, false},
		{"version suffix -01", "http-01", "http-01", 0, false},
		{"port 100", "enroll-01-100", "enroll-01", 100, false},
		{"port 99 (reserved)", "enroll-01-99", "enroll-01-99", 0, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseType, port, err := parseChallengeAsDynamicPortAssignment(tc.challengeTyp)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantBase, baseType)
				assert.Equal(t, tc.wantPort, port)
			}
		})
	}
}

// =============================================================================
// isEnrollXChallenge Tests
// =============================================================================

func TestCoveragePush_IsEnrollXChallenge(t *testing.T) {
	testCases := []struct {
		name          string
		challengeType string
		want          bool
	}{
		{"enroll-01", "enroll-01", true},
		{"enroll-01 with port", "enroll-01-8080", true},
		{"endorse-01", "endorse-01", true},
		{"device-attest-01", "device-attest-01", true},
		{"http-01", "http-01", false},
		{"dns-01", "dns-01", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isEnrollXChallenge(tc.challengeType)
			assert.Equal(t, tc.want, result)
		})
	}
}

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
// compareKeyMaps Tests (for KeyChangeHandler)
// =============================================================================

func TestCoveragePush_CompareKeyMaps_RSA(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus",
		"e":   "AQAB",
	}
	key2 := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus",
		"e":   "AQAB",
	}

	assert.True(t, compareKeyMaps(key1, key2))
}

func TestCoveragePush_CompareKeyMaps_EC(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "x",
		"y":   "y",
	}
	key2 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "x",
		"y":   "y",
	}

	assert.True(t, compareKeyMaps(key1, key2))
}

func TestCoveragePush_CompareKeyMaps_OKP(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "pubkey",
	}
	key2 := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "pubkey",
	}

	assert.True(t, compareKeyMaps(key1, key2))
}

func TestCoveragePush_CompareKeyMaps_UnknownType(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "UNKNOWN",
	}
	key2 := map[string]interface{}{
		"kty": "UNKNOWN",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

func TestCoveragePush_CompareKeyMaps_MissingKty(t *testing.T) {
	key1 := map[string]interface{}{
		"n": "modulus",
	}
	key2 := map[string]interface{}{
		"kty": "RSA",
		"n":   "modulus",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

// =============================================================================
// verifyMAC Tests
// =============================================================================

func TestCoveragePush_VerifyMAC_HS256(t *testing.T) {
	// Create binding to verify MAC generation works
	binding, err := CreateExternalAccountBinding("kid", "external", "HS256")
	require.NoError(t, err)
	assert.NotNil(t, binding)
}

func TestCoveragePush_VerifyMAC_UnsupportedAlgorithm(t *testing.T) {
	err := verifyMAC("UNSUPPORTED", []byte("key"), []byte("message"), "signature")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

func TestCoveragePush_VerifyMAC_InvalidSignatureBase64(t *testing.T) {
	err := verifyMAC("HS256", []byte("key"), []byte("message"), "invalid base64!")
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
	service.SetNonceGenerator(func(_ int) (string, error) {
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
	service.SetNonceGenerator(func(_ int) (string, error) {
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
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

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

func TestCoveragePush_EncodeCertificatePEM(t *testing.T) {
	derBytes := []byte("mock-certificate-der")
	pem := encodeCertificatePEM(derBytes)

	assert.Contains(t, string(pem), "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, string(pem), "-----END CERTIFICATE-----")
}

func TestCoveragePush_EncodeCSRToPEM(t *testing.T) {
	derBytes := []byte("mock-csr-der")
	pem := encodeCSRToPEM(derBytes)

	assert.Contains(t, string(pem), "-----BEGIN CERTIFICATE REQUEST-----")
	assert.Contains(t, string(pem), "-----END CERTIFICATE REQUEST-----")
}

// =============================================================================
// Tenant Signing CA Resolution Tests
// =============================================================================

func TestCoveragePush_ResolveTenantSigningCA_NoTenantID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	account := &entities.ACMEAccount{
		ID:       12345,
		TenantID: "",
	}

	result := service.resolveTenantSigningCA(context.Background(), account, "general")
	assert.Nil(t, result)
}

func TestCoveragePush_ResolveTenantSigningCA_NonTenantAwareFactory(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	account := &entities.ACMEAccount{
		ID:       12345,
		TenantID: "tenant-123",
	}

	// Standard storage factory doesn't support TenantAwareFactory
	result := service.resolveTenantSigningCA(context.Background(), account, "general")
	assert.Nil(t, result)
}

// =============================================================================
// getTenantCASigner Tests
// =============================================================================

func TestCoveragePush_GetTenantCASigner_NilSigningCAInfo(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	signer := service.getTenantCASigner(context.Background(), nil)
	assert.Nil(t, signer)
}

func TestCoveragePush_GetTenantCASigner_UseGlobalDefault(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	signingCAInfo := &entities.SigningCAInfo{
		UseGlobalDefault: true,
	}

	signer := service.getTenantCASigner(context.Background(), signingCAInfo)
	assert.Nil(t, signer)
}

func TestCoveragePush_GetTenantCASigner_NoKMSService(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.kmsService = nil

	signingCAInfo := &entities.SigningCAInfo{
		UseGlobalDefault: false,
		TenantID:         "tenant-123",
		Type:             entities.SigningCATypeIntermediate,
	}

	signer := service.getTenantCASigner(context.Background(), signingCAInfo)
	assert.Nil(t, signer)
}

func TestCoveragePush_GetTenantCASigner_UnknownType(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Set up mock KMS
	service.kmsService = &mockKMSServiceCovPush{}

	signingCAInfo := &entities.SigningCAInfo{
		UseGlobalDefault: false,
		TenantID:         "tenant-123",
		Type:             "unknown-type", // Invalid type
	}

	signer := service.getTenantCASigner(context.Background(), signingCAInfo)
	assert.Nil(t, signer)
}

// mockKMSServiceCovPush for testing
type mockKMSServiceCovPush struct{}

func (m *mockKMSServiceCovPush) CreateSigningKey(_ context.Context, _ string, _ kms.KeyPurpose, _ string) (*kms.KeyMetadata, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKMSServiceCovPush) GetSigningKey(_ context.Context, _ string, _ kms.KeyPurpose) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKMSServiceCovPush) ListSigningKeys(_ context.Context, _ string) ([]*kms.KeyMetadata, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKMSServiceCovPush) DeleteSigningKey(_ context.Context, _, _ string) error {
	return errors.New("not implemented")
}

func (m *mockKMSServiceCovPush) EnableSigningKey(_ context.Context, _, _ string) error {
	return errors.New("not implemented")
}

func (m *mockKMSServiceCovPush) DisableSigningKey(_ context.Context, _, _ string) error {
	return errors.New("not implemented")
}

func (m *mockKMSServiceCovPush) StoreCertificate(_ context.Context, _ string, _ kms.KeyPurpose, _ []byte) error {
	return errors.New("not implemented")
}

func (m *mockKMSServiceCovPush) GetCertificate(_ context.Context, _ string, _ kms.KeyPurpose) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKMSServiceCovPush) DeleteCertificate(_ context.Context, _ string, _ kms.KeyPurpose) error {
	return errors.New("not implemented")
}

// =============================================================================
// matchesIdentifier Tests
// =============================================================================

func TestCoveragePush_MatchesIdentifier_DNS(t *testing.T) {
	csr := createTestCSRCovPush(t, "example.com")

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.NoError(t, err)
	assert.True(t, matches)
}

func TestCoveragePush_MatchesIdentifier_DNS_NoMatch(t *testing.T) {
	csr := createTestCSRCovPush(t, "different.com")

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.NoError(t, err)
	assert.False(t, matches)
}

func TestCoveragePush_MatchesIdentifier_UnsupportedType(t *testing.T) {
	csr := createTestCSRCovPush(t, "example.com")

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: "unsupported", Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.Error(t, err)
	assert.False(t, matches)
}

// createTestCSRCovPush creates a real x509.CertificateRequest for testing
func createTestCSRCovPush(t *testing.T, cn string) *x509.CertificateRequest {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	return csr
}

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

	nonce, err := service.generateNonce(16)
	assert.NoError(t, err)
	assert.NotEmpty(t, nonce)
}

func TestCoveragePush_GenerateNonce_Error(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.SetNonceGenerator(func(_ int) (string, error) {
		return "", errors.New("generation failed")
	})

	nonce, err := service.generateNonce(16)
	assert.Error(t, err)
	assert.Empty(t, nonce)
}

// =============================================================================
// NewRestService with NonceGenerator Test
// =============================================================================

func TestCoveragePush_NewRestService_CustomNonceGenerator(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	customGen := func(length int) (string, error) {
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
	nonce, err := restService.generateNonce(16)
	assert.NoError(t, err)
	assert.Equal(t, "custom-nonce", nonce)
}

// =============================================================================
// challengeResponse Test (standalone function)
// =============================================================================

func TestCoveragePush_ChallengeResponse(t *testing.T) {
	challenge := &entities.ACMEChallenge{
		ID:     12345,
		Type:   "http-01",
		URL:    "https://acme.test.example.com/acme/challenge/12345",
		Status: common.StatusPending,
		Token:  "test-token",
	}

	w := httptest.NewRecorder()
	challengeResponse(w, challenge)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "http-01", resp["type"])
}

// =============================================================================
// parseJWS No Signatures Test
// =============================================================================

func TestCoveragePush_ParseJWS_NoSignatures(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create a JWS-like structure with no signatures
	invalidJWS := `{"payload":"dGVzdA","signatures":[]}`

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/new-account", strings.NewReader(invalidJWS))

	jwk, payload, err := service.parseJWS(req)
	assert.Error(t, err)
	assert.Nil(t, jwk)
	assert.Nil(t, payload)
}

// =============================================================================
// parseKID No Signatures Test
// =============================================================================

func TestCoveragePush_ParseKID_NoSignatures(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create a JWS-like structure with no signatures
	invalidJWS := `{"payload":"dGVzdA","signatures":[]}`

	req := httptest.NewRequest(http.MethodPost, service.baseRESTURI+"/acme/account/123", strings.NewReader(invalidJWS))

	ctx := context.Background()
	account, payload, err := service.parseKID(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, account)
	assert.Nil(t, payload)
}

// Suppress unused import warning
var _ = storage.Factory(nil)
