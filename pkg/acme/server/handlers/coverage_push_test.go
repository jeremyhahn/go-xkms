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

// =============================================================================
// writeChallengeResponse Tests (75% coverage -> target 100%)
// =============================================================================

// =============================================================================
// NewAccountHandler Additional Tests (57.4% coverage -> target 90%+)
// =============================================================================

// =============================================================================
// generateIDWithReader and generateTokenWithReader Tests
// =============================================================================

// =============================================================================
// verifyMAC Tests
// =============================================================================

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

// =============================================================================
// getTenantCASigner Tests
// =============================================================================

// Suppress unused import warning
var _ = storage.Factory(nil)
