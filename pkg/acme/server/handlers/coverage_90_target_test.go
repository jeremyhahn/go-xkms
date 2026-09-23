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
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test helper function
// =============================================================================

// setupTestServiceWithMockCAForCoverage creates a test service with a mock CA for coverage testing
func setupTestServiceWithMockCAForCoverage(t *testing.T) (*RestService, *MockCAForFinalize, func()) {
	return setupTestServiceWithMockCA(t)
}

// =============================================================================
// NewAccountHandler Coverage Tests - Unique paths not covered elsewhere
// =============================================================================

func TestNewAccountHandler_EABOptionalButProvidedCoverage(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create EAB - optional but provided
	ctx := context.Background()
	eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	// MACKey should be base64url-encoded
	macKeyRaw := []byte("test-hmac-key-32-bytes-long!!!!")
	macKeyEncoded := base64.RawURLEncoding.EncodeToString(macKeyRaw)

	eab := &entities.ExternalAccountBinding{
		ID:                "test-kid-optional",
		MACKey:            macKeyEncoded,
		MACAlgorithm:      "HS256",
		ExternalAccountID: "external-123",
		Status:            entities.EABStatusActive,
		CreatedAt:         time.Now(),
	}
	err = eabDAO.Save(ctx, eab)
	require.NoError(t, err)

	// Create the EAB JWS
	eabJWS := createTestEABJWSCoverage(t, service, key, eab, macKeyRaw)

	payload := NewAccountRequest{
		Contact:                []string{"mailto:test@example.com"},
		TermsOfServiceAgreed:   true,
		ExternalAccountBinding: json.RawMessage(eabJWS),
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should succeed since EAB is optional
	assert.Equal(t, http.StatusCreated, resp.Code)
}

// createTestEABJWSCoverage creates a test EAB JWS for testing
func createTestEABJWSCoverage(t *testing.T, service *RestService, key *TestKey, eab *entities.ExternalAccountBinding, macKeyRaw []byte) []byte {
	// Create the protected header
	protected := map[string]interface{}{
		"alg": "HS256",
		"kid": eab.ID,
		"url": service.baseRESTURI + "/acme/new-account",
	}

	protectedBytes, err := json.Marshal(protected)
	require.NoError(t, err)

	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)

	// Create payload with account key
	pubKeyJWK := jose.JSONWebKey{Key: key.PublicKey}
	pubKeyJSON, err := pubKeyJWK.MarshalJSON()
	require.NoError(t, err)

	payloadB64 := base64.RawURLEncoding.EncodeToString(pubKeyJSON)

	// Create signature
	signingInput := protectedB64 + "." + payloadB64
	mac := createHMACCoverage(t, []byte(signingInput), macKeyRaw)
	signatureB64 := base64.RawURLEncoding.EncodeToString(mac)

	// Build JWS
	eabJWS := map[string]interface{}{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": signatureB64,
	}

	jwsBytes, err := json.Marshal(eabJWS)
	require.NoError(t, err)

	return jwsBytes
}

// =============================================================================
// KeyChangeHandler Coverage Tests
// =============================================================================

func TestKeyChangeHandler_SuccessfulKeyChangeCoverage(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a new key
	newKey := generateTestKey(t)
	payload := createKeyChangePayload(t, service, account, key, newKey)

	url := service.baseRESTURI + "/acme/key-change"
	req := createJWSRequest(t, service, key, url, json.RawMessage(payload), true, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// Should succeed
	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestKeyChangeHandler_NoJWKInHeaderCoverage(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create inner JWS without embedded JWK
	newKey := generateTestKey(t)
	innerPayload := map[string]interface{}{
		"account": account.URL,
		"oldKey":  map[string]interface{}{"kty": "EC"},
	}
	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	// Create signer WITHOUT embedding JWK
	signerOpts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/key-change",
		},
	}
	// NOT embedding JWK: signerOpts.EmbedJWK = false (default)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	innerJWS, err := signer.Sign(innerPayloadBytes)
	require.NoError(t, err)

	url := service.baseRESTURI + "/acme/key-change"
	req := createJWSRequest(t, service, key, url, json.RawMessage(innerJWS.FullSerialize()), true, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)

	// Should fail because inner JWS has no JWK in header
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// =============================================================================
// OrderFinalizeHandler Coverage Tests
// =============================================================================

func TestOrderFinalizeHandler_InvalidOrderIDCoverage(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCAForCoverage(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString([]byte("test-csr")),
	}

	url := service.baseRESTURI + "/acme/order/invalid/finalize"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestOrderFinalizeHandler_InvalidPayloadJSONCoverage(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCAForCoverage(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	_ = mockCA

	// Create ready order
	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		ID:        12346,
		AccountID: account.ID,
		Status:    common.StatusReady,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
	}
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Invalid JSON payload
	url := service.baseRESTURI + "/acme/order/12346/finalize"

	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
			"kid": fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID),
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	// Send invalid JSON
	jws, err := signer.Sign([]byte("{invalid json"))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(jws.FullSerialize()))
	req = mux.SetURLVars(req, map[string]string{"id": "12346"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// =============================================================================
// Compliance Attestation Tests
// =============================================================================

func TestPCRMismatchErrorCoverage(t *testing.T) {
	t.Run("with custom message", func(t *testing.T) {
		err := &PCRMismatchError{
			PCRIndex: 7,
			Message:  "custom error message",
		}
		assert.Equal(t, "custom error message", err.Error())
		assert.True(t, errors.Is(err, ErrPCRMismatch))
	})

	t.Run("without custom message", func(t *testing.T) {
		err := &PCRMismatchError{
			PCRIndex:      7,
			ExpectedValue: []byte{0x01, 0x02, 0x03},
			ActualValue:   []byte{0x04, 0x05, 0x06},
		}
		errStr := err.Error()
		assert.Contains(t, errStr, "PCR[7]")
		assert.Contains(t, errStr, "mismatch")
	})
}

func TestAttestationErrorCoverage(t *testing.T) {
	innerErr := errors.New("inner error")
	err := &AttestationError{
		Op:  "test_operation",
		Err: innerErr,
	}

	assert.Contains(t, err.Error(), "test_operation")
	assert.Contains(t, err.Error(), "inner error")
	assert.ErrorIs(t, err, innerErr)
}

func TestEventLogErrorCoverage(t *testing.T) {
	err := &EventLogError{
		Message:     "event log error",
		MissingType: "EV_SEPARATOR",
	}

	assert.Equal(t, "event log error", err.Error())
	assert.True(t, errors.Is(err, ErrEventLogInvalid))
}

func TestEventLogPCRMismatchErrorCoverage(t *testing.T) {
	err := &EventLogPCRMismatchError{
		PCRIndex:      0,
		Algorithm:     "SHA256",
		ExpectedValue: []byte{0x01, 0x02},
		ActualValue:   []byte{0x03, 0x04},
	}

	errStr := err.Error()
	assert.Contains(t, errStr, "PCR[0]")
	assert.Contains(t, errStr, "SHA256")
	assert.True(t, errors.Is(err, ErrEventLogPCRMismatch))
	assert.True(t, errors.Is(err, ErrEventLogInvalid))
}

func TestQuoteValidationErrorCoverage(t *testing.T) {
	err := &QuoteValidationError{
		Reason: "test reason",
	}

	assert.Contains(t, err.Error(), "test reason")
	assert.True(t, errors.Is(err, ErrQuoteInvalid))
}

func TestDeviceProfileErrorCoverage(t *testing.T) {
	innerErr := errors.New("profile lookup failed")
	err := &DeviceProfileError{
		Op:  "lookup",
		Err: innerErr,
	}

	assert.Contains(t, err.Error(), "lookup")
	assert.Contains(t, err.Error(), "device profile")
	assert.ErrorIs(t, err, innerErr)
}

func TestBytesToBigIntCoverage(t *testing.T) {
	result := bytesToBigInt([]byte{0x01, 0x02, 0x03})
	expected := big.NewInt(0x010203)
	assert.Equal(t, 0, result.Cmp(expected))
}

func TestParseEventLog_EmptyLogCoverage(t *testing.T) {
	events, err := parseEventLog([]byte{})
	assert.NoError(t, err)
	assert.Empty(t, events)
}

func TestVerifyRSAQuoteSignatureCoverage(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	quoted := []byte("test quoted data")

	t.Run("invalid PKCS1v15 signature", func(t *testing.T) {
		err := verifyRSAQuoteSignature(quoted, TPMAlgRSASSA, []byte("invalid"), &rsaKey.PublicKey)
		assert.Error(t, err)
	})

	t.Run("invalid PSS signature", func(t *testing.T) {
		err := verifyRSAQuoteSignature(quoted, TPMAlgRSAPSS, []byte("invalid"), &rsaKey.PublicKey)
		assert.Error(t, err)
	})
}

func TestVerifyECDSAQuoteSignatureCoverage(t *testing.T) {
	t.Run("P-256 curve", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		quoted := []byte("test quoted data")

		// Invalid signature
		err = verifyECDSAQuoteSignature(quoted, 0, []byte("invalid"), &key.PublicKey)
		assert.Error(t, err)
	})

	t.Run("P-384 curve", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		quoted := []byte("test quoted data")
		err = verifyECDSAQuoteSignature(quoted, 0, []byte("invalid"), &key.PublicKey)
		assert.Error(t, err)
	})

	t.Run("P-521 curve", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		quoted := []byte("test quoted data")
		err = verifyECDSAQuoteSignature(quoted, 0, []byte("invalid"), &key.PublicKey)
		assert.Error(t, err)
	})
}

// =============================================================================
// Service Tests
// =============================================================================

func TestParseKID_NoSignaturesCoverage(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create request with JWS that has no signatures (invalid JWS)
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"signatures":[]}`))

	ctx := context.Background()
	_, _, err := service.parseKID(ctx, req)
	assert.Error(t, err)
}

func TestJWKThumbprint_RSACoverage(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	thumbprint, err := JWKThumbprint(&rsaKey.PublicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, thumbprint)
}

func TestJWKThumbprint_UnsupportedKeyTypeCoverage(t *testing.T) {
	_, err := JWKThumbprint("unsupported")
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)
}

// =============================================================================
// Tenant Resolution Tests
// =============================================================================

func TestResolveTenantSigningCA_NoTenantIDCoverage(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCAForCoverage(t)
	defer cleanup()

	ctx := context.Background()
	account := &entities.ACMEAccount{
		ID:       12345,
		TenantID: "",
	}

	result, err := service.resolveTenantSigningCA(ctx, account, "general")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestResolveTenantSigningCA_NonTenantAwareFactoryCoverage(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCAForCoverage(t)
	defer cleanup()

	ctx := context.Background()
	account := &entities.ACMEAccount{
		ID:       12345,
		TenantID: "tenant-1",
	}

	// Default storage factory is not tenant-aware: a tenant-bound account
	// fails closed rather than using the global CA.
	result, err := service.resolveTenantSigningCA(ctx, account, "general")
	assert.ErrorIs(t, err, ErrTenantStorageUnsupported)
	assert.Nil(t, result)
}

func TestGetTenantCASigner_NilSigningCAInfoCoverage(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCAForCoverage(t)
	defer cleanup()

	ctx := context.Background()
	result, err := service.getTenantCASigner(ctx, nil)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestGetTenantCASigner_UseGlobalDefaultCoverage(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCAForCoverage(t)
	defer cleanup()

	ctx := context.Background()
	signingCAInfo := &entities.SigningCAInfo{
		UseGlobalDefault: true,
	}

	result, err := service.getTenantCASigner(ctx, signingCAInfo)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestResolveTenantComplianceConfig_NoTenantIDCoverage(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCAForCoverage(t)
	defer cleanup()

	ctx := context.Background()
	account := &entities.ACMEAccount{
		ID:       12345,
		TenantID: "",
	}

	result := service.resolveTenantComplianceConfig(ctx, account)
	assert.Nil(t, result)
}

func TestResolveTenantComplianceConfig_WithGlobalConfigCoverage(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCAForCoverage(t)
	defer cleanup()

	service.globalComplianceConfig = &GlobalComplianceConfig{
		ComplianceConfig: ComplianceConfig{
			Enabled: true,
		},
	}

	ctx := context.Background()
	account := &entities.ACMEAccount{
		ID:       12345,
		TenantID: "",
	}

	result := service.resolveTenantComplianceConfig(ctx, account)
	assert.NotNil(t, result)
	assert.True(t, result.Enabled)
}

// =============================================================================
// Additional Service Method Tests
// =============================================================================

func TestAccountIDFromPublicKeyCoverage(t *testing.T) {
	key := generateTestKey(t)
	id, err := AccountIDFromPublicKey(key.PublicKey)
	assert.NoError(t, err)
	assert.NotZero(t, id)

	// Same key should generate same ID
	id2, err := AccountIDFromPublicKey(key.PublicKey)
	assert.NoError(t, err)
	assert.Equal(t, id, id2)
}

func TestParseAccountIDCoverage(t *testing.T) {
	t.Run("valid URL", func(t *testing.T) {
		id, err := ParseAccountID("https://example.com/acme/account/12345")
		assert.NoError(t, err)
		assert.Equal(t, uint64(12345), id)
	})

	t.Run("invalid URL", func(t *testing.T) {
		_, err := ParseAccountID("https://example.com/acme/account/invalid")
		assert.ErrorIs(t, err, ErrInvalidAccountID)
	})
}

func TestKeyAuthorizationCoverage(t *testing.T) {
	key := generateTestKey(t)
	auth, err := KeyAuthorization("test-token", key.PublicKey)
	assert.NoError(t, err)
	assert.Contains(t, auth, "test-token.")
}

// =============================================================================
// compareKeyMaps Tests
// =============================================================================

func TestCompareKeyMaps_RSAKeys(t *testing.T) {
	// Test RSA key comparison
	key1 := map[string]interface{}{
		"kty": "RSA",
		"n":   "test-modulus",
		"e":   "AQAB",
	}
	key2 := map[string]interface{}{
		"kty": "RSA",
		"n":   "test-modulus",
		"e":   "AQAB",
	}

	assert.True(t, compareKeyMaps(key1, key2))

	// Different modulus
	key3 := map[string]interface{}{
		"kty": "RSA",
		"n":   "different-modulus",
		"e":   "AQAB",
	}
	assert.False(t, compareKeyMaps(key1, key3))
}

func TestCompareKeyMaps_ECKeys(t *testing.T) {
	// Test EC key comparison
	key1 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x",
		"y":   "test-y",
	}
	key2 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x",
		"y":   "test-y",
	}

	assert.True(t, compareKeyMaps(key1, key2))

	// Different curve
	key3 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-384",
		"x":   "test-x",
		"y":   "test-y",
	}
	assert.False(t, compareKeyMaps(key1, key3))
}

func TestCompareKeyMaps_OKPKeys(t *testing.T) {
	// Test OKP (EdDSA) key comparison
	key1 := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "test-x",
	}
	key2 := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "test-x",
	}

	assert.True(t, compareKeyMaps(key1, key2))

	// Different x
	key3 := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "different-x",
	}
	assert.False(t, compareKeyMaps(key1, key3))
}

func TestCompareKeyMaps_UnsupportedKeyType(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "unsupported",
	}
	key2 := map[string]interface{}{
		"kty": "unsupported",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

func TestCompareKeyMaps_DifferentKeyTypes(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "RSA",
		"n":   "test",
		"e":   "AQAB",
	}
	key2 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test",
		"y":   "test",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

func TestCompareKeyMaps_MissingKty(t *testing.T) {
	key1 := map[string]interface{}{
		"n": "test",
		"e": "AQAB",
	}
	key2 := map[string]interface{}{
		"kty": "RSA",
		"n":   "test",
		"e":   "AQAB",
	}

	assert.False(t, compareKeyMaps(key1, key2))
}

// =============================================================================
// extendPCR Tests
// =============================================================================

func TestExtendPCR_SHA256Coverage(t *testing.T) {
	current := make([]byte, 32) // Zero initialized
	digest := make([]byte, 32)
	copy(digest, []byte("test event data 32 bytes!!!!!!!"))

	result, err := extendPCR(current, digest, TCGAlgSHA256)

	assert.NoError(t, err)
	// Result should be 32 bytes (SHA256 digest size)
	assert.Len(t, result, 32)
	// Result should be different from original
	assert.NotEqual(t, current, result)
}

func TestExtendPCR_SHA1Coverage(t *testing.T) {
	current := make([]byte, 20) // Zero initialized
	digest := make([]byte, 20)
	copy(digest, []byte("test event 20!!!"))

	result, err := extendPCR(current, digest, TCGAlgSHA1)

	if fips140.Enforced() {
		// See TestExtendPCR's "extends with SHA-1" subtest
		// (compliance_attestation_test.go) for why a SHA-1 PCR bank is
		// refused under GODEBUG=fips140=only rather than computed.
		assert.ErrorIs(t, err, ErrUnsupportedHashAlgorithm)
		assert.Nil(t, result)
		return
	}
	assert.NoError(t, err)
	// Result should be 20 bytes (SHA1 digest size)
	assert.Len(t, result, 20)
}

func TestExtendPCR_SHA384Coverage(t *testing.T) {
	current := make([]byte, 48) // Zero initialized
	digest := make([]byte, 48)
	copy(digest, []byte("test event data 48 bytes long digest value!!!!"))

	result, err := extendPCR(current, digest, TCGAlgSHA384)

	assert.NoError(t, err)
	// Result should be 48 bytes (SHA384 digest size)
	assert.Len(t, result, 48)
}

func TestExtendPCR_SHA512Coverage(t *testing.T) {
	current := make([]byte, 64) // Zero initialized
	digest := make([]byte, 64)
	copy(digest, []byte("test event data 64 bytes long digest value for sha512 test!!!!"))

	result, err := extendPCR(current, digest, TCGAlgSHA512)

	assert.NoError(t, err)
	// Result should be 64 bytes (SHA512 digest size)
	assert.Len(t, result, 64)
}

func TestExtendPCR_UnsupportedAlgorithmCoverage(t *testing.T) {
	current := make([]byte, 32)
	digest := make([]byte, 32)

	// Unsupported algorithm should return error
	_, err := extendPCR(current, digest, 0x9999)
	assert.Error(t, err)
}

// =============================================================================
// algorithmStringToID Tests
// =============================================================================

func TestAlgorithmStringToIDCoverage(t *testing.T) {
	tests := []struct {
		input    string
		expected uint16
	}{
		{"sha1", TCGAlgSHA1},
		{"SHA1", TCGAlgSHA1},
		{"sha256", TCGAlgSHA256},
		{"SHA256", TCGAlgSHA256},
		{"sha384", TCGAlgSHA384},
		{"SHA384", TCGAlgSHA384},
		{"sha512", TCGAlgSHA512},
		{"SHA512", TCGAlgSHA512},
		{"unknown", 0},
	}

	for _, tc := range tests {
		result := algorithmStringToID(tc.input)
		assert.Equal(t, tc.expected, result, "Algorithm: %s", tc.input)
	}
}

// =============================================================================
// eventTypeToString Tests - Target 90% coverage
// =============================================================================

func TestEventTypeToString_Handlers90(t *testing.T) {
	testCases := []struct {
		input    uint32
		expected string
	}{
		{EVPrebootCert, "EV_PREBOOT_CERT"},
		{EVPostCode, "EV_POST_CODE"},
		{EVUnused, "EV_UNUSED"},
		{EVNoAction, "EV_NO_ACTION"},
		{EVSeparator, "EV_SEPARATOR"},
		{EVAction, "EV_ACTION"},
		{EVEventTag, "EV_EVENT_TAG"},
		{EVSCRTMContents, "EV_S_CRTM_CONTENTS"},
		{EVSCRTMVersion, "EV_S_CRTM_VERSION"},
		{EVCPUMicrocode, "EV_CPU_MICROCODE"},
		{EVPlatformConfigFlags, "EV_PLATFORM_CONFIG_FLAGS"},
		{EVTableOfDevices, "EV_TABLE_OF_DEVICES"},
		{EVCompactHash, "EV_COMPACT_HASH"},
		{EVIPL, "EV_IPL"},
		{EVIPLPartitionData, "EV_IPL_PARTITION_DATA"},
		{EVNonhostCode, "EV_NONHOST_CODE"},
		{EVNonhostConfig, "EV_NONHOST_CONFIG"},
		{EVNonhostInfo, "EV_NONHOST_INFO"},
		{EVOmitBootDevEvents, "EV_OMIT_BOOT_DEVICE_EVENTS"},
		{EVEFIVariableDriverConfig, "EV_EFI_VARIABLE_DRIVER_CONFIG"},
		{EVEFIVariableBoot, "EV_EFI_VARIABLE_BOOT"},
		{EVEFIBootServicesApplication, "EV_EFI_BOOT_SERVICES_APPLICATION"},
		{EVEFIBootServicesDriver, "EV_EFI_BOOT_SERVICES_DRIVER"},
		{EVEFIRuntimeServicesDriver, "EV_EFI_RUNTIME_SERVICES_DRIVER"},
		{EVEFIGPTEvent, "EV_EFI_GPT_EVENT"},
		{EVEFIAction, "EV_EFI_ACTION"},
		{EVEFIPlatformFirmwareBlob, "EV_EFI_PLATFORM_FIRMWARE_BLOB"},
		{EVEFIHandoffTables, "EV_EFI_HANDOFF_TABLES"},
		{EVEFIHCRTMEvent, "EV_EFI_HCRTM_EVENT"},
		{EVEFIVariableAuthority, "EV_EFI_VARIABLE_AUTHORITY"},
		{0xFFFFFFFF, "EV_UNKNOWN_FFFFFFFF"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := eventTypeToString(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// parseLegacyEvent Tests - Target 90% coverage
// =============================================================================

func TestParseLegacyEvent_Handlers90(t *testing.T) {
	t.Run("valid legacy event", func(t *testing.T) {
		// Build a valid TCG_PCR_EVENT structure
		buf := make([]byte, 0, 100)

		// PCR index (4 bytes)
		pcrIndex := make([]byte, 4)
		binary.LittleEndian.PutUint32(pcrIndex, 0)
		buf = append(buf, pcrIndex...)

		// Event type (4 bytes)
		eventType := make([]byte, 4)
		binary.LittleEndian.PutUint32(eventType, EVSeparator)
		buf = append(buf, eventType...)

		// SHA-1 digest (20 bytes)
		digest := make([]byte, 20)
		buf = append(buf, digest...)

		// Event data size (4 bytes)
		dataSize := make([]byte, 4)
		binary.LittleEndian.PutUint32(dataSize, 4)
		buf = append(buf, dataSize...)

		// Event data
		buf = append(buf, []byte("test")...)

		events, err := parseEventLog(buf)
		assert.NoError(t, err)
		assert.NotEmpty(t, events)
		assert.Equal(t, 0, events[0].PCRIndex)
		assert.Equal(t, "EV_SEPARATOR", events[0].EventType)
	})

	t.Run("truncated PCR index", func(t *testing.T) {
		buf := make([]byte, 2) // Too short
		events, err := parseEventLog(buf)
		// Should not fail but should return empty
		assert.NoError(t, err)
		assert.Empty(t, events)
	})

	t.Run("truncated event type", func(t *testing.T) {
		buf := make([]byte, 6) // PCR index ok, event type truncated
		events, err := parseEventLog(buf)
		assert.NoError(t, err)
		assert.Empty(t, events)
	})

	t.Run("truncated digest", func(t *testing.T) {
		buf := make([]byte, 10) // PCR + event type ok, digest truncated
		events, err := parseEventLog(buf)
		assert.NoError(t, err)
		assert.Empty(t, events)
	})

	t.Run("event data too large", func(t *testing.T) {
		buf := make([]byte, 0, 32)
		pcrIndex := make([]byte, 4)
		eventType := make([]byte, 4)
		digest := make([]byte, 20)
		dataSize := make([]byte, 4)
		binary.LittleEndian.PutUint32(dataSize, 2<<20) // 2MB - too large

		buf = append(buf, pcrIndex...)
		buf = append(buf, eventType...)
		buf = append(buf, digest...)
		buf = append(buf, dataSize...)

		events, err := parseEventLog(buf)
		assert.NoError(t, err)
		assert.Empty(t, events)
	})
}

// =============================================================================
// parseTPMSignature Tests - Target 90% coverage
// =============================================================================

func TestParseTPMSignature_Handlers90(t *testing.T) {
	t.Run("RSA signature", func(t *testing.T) {
		buf := make([]byte, 0, 100)
		// Signature algorithm (2 bytes big-endian)
		sigAlg := make([]byte, 2)
		binary.BigEndian.PutUint16(sigAlg, TPMAlgRSASSA)
		buf = append(buf, sigAlg...)

		// Hash algorithm (2 bytes)
		hashAlg := make([]byte, 2)
		binary.BigEndian.PutUint16(hashAlg, TCGAlgSHA256)
		buf = append(buf, hashAlg...)

		// Signature size (2 bytes)
		sigSize := make([]byte, 2)
		binary.BigEndian.PutUint16(sigSize, 32)
		buf = append(buf, sigSize...)

		// Signature data
		sig := make([]byte, 32)
		buf = append(buf, sig...)

		alg, sigData, err := parseTPMSignature(buf)
		assert.NoError(t, err)
		assert.Equal(t, TPMAlgRSASSA, alg)
		assert.Len(t, sigData, 32)
	})

	t.Run("ECDSA signature", func(t *testing.T) {
		buf := make([]byte, 0, 100)
		// Signature algorithm
		sigAlg := make([]byte, 2)
		binary.BigEndian.PutUint16(sigAlg, TPMAlgECDSA)
		buf = append(buf, sigAlg...)

		// Hash algorithm
		hashAlg := make([]byte, 2)
		binary.BigEndian.PutUint16(hashAlg, TCGAlgSHA256)
		buf = append(buf, hashAlg...)

		// R size and value
		rSize := make([]byte, 2)
		binary.BigEndian.PutUint16(rSize, 32)
		buf = append(buf, rSize...)
		rBytes := make([]byte, 32)
		buf = append(buf, rBytes...)

		// S size and value
		sSize := make([]byte, 2)
		binary.BigEndian.PutUint16(sSize, 32)
		buf = append(buf, sSize...)
		sBytes := make([]byte, 32)
		buf = append(buf, sBytes...)

		alg, sigData, err := parseTPMSignature(buf)
		assert.NoError(t, err)
		assert.Equal(t, TPMAlgECDSA, alg)
		assert.Len(t, sigData, 64)
	})

	t.Run("too short", func(t *testing.T) {
		buf := make([]byte, 2)
		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint16(buf, 0xFFFF) // Unknown algorithm
		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})

	t.Run("RSA too short", func(t *testing.T) {
		buf := make([]byte, 5) // Need at least 6 for RSA
		binary.BigEndian.PutUint16(buf, TPMAlgRSASSA)
		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})

	t.Run("RSA signature data too short", func(t *testing.T) {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint16(buf, TPMAlgRSASSA)
		binary.BigEndian.PutUint16(buf[2:], TCGAlgSHA256)
		binary.BigEndian.PutUint16(buf[4:], 100) // Claim 100 bytes
		// But only have 2 more bytes
		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})

	t.Run("ECDSA R too short", func(t *testing.T) {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint16(buf, TPMAlgECDSA)
		binary.BigEndian.PutUint16(buf[2:], TCGAlgSHA256)
		binary.BigEndian.PutUint16(buf[4:], 100) // R claims 100 bytes
		// Not enough data
		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})

	t.Run("ECDSA S too short", func(t *testing.T) {
		buf := make([]byte, 0, 50)
		sigAlg := make([]byte, 2)
		binary.BigEndian.PutUint16(sigAlg, TPMAlgECDSA)
		buf = append(buf, sigAlg...)

		hashAlg := make([]byte, 2)
		buf = append(buf, hashAlg...)

		// R size and value (small)
		rSize := make([]byte, 2)
		binary.BigEndian.PutUint16(rSize, 2)
		buf = append(buf, rSize...)
		buf = append(buf, 0x01, 0x02)

		// S size claims large
		sSize := make([]byte, 2)
		binary.BigEndian.PutUint16(sSize, 100)
		buf = append(buf, sSize...)
		// No S data

		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})
}

// =============================================================================
// parseRawPublicKey Tests - Target 90% coverage
// =============================================================================

func TestParseRawPublicKey_Handlers90(t *testing.T) {
	t.Run("RSA PKCS1 public key", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		der := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)

		key, err := parseRawPublicKey(der)
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("from certificate", func(t *testing.T) {
		// Create a self-signed cert
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &ecKey.PublicKey, ecKey)
		require.NoError(t, err)

		key, err := parseRawPublicKey(certDER)
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("invalid data", func(t *testing.T) {
		key, err := parseRawPublicKey([]byte("not a key"))
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

// =============================================================================
// NewDeviceProfileHook Tests - Target 90% coverage
// =============================================================================

func TestNewDeviceProfileHook_Handlers90(t *testing.T) {
	t.Run("non-TCG enrollment skipped", func(t *testing.T) {
		hook := NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return nil, errors.New("should not be called")
		})

		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: false,
		})
		assert.NoError(t, err)
	})

	t.Run("nil TCGData skipped", func(t *testing.T) {
		hook := NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return nil, errors.New("should not be called")
		})

		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData:  nil,
		})
		assert.NoError(t, err)
	})

	t.Run("lookup error", func(t *testing.T) {
		hook := NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return nil, errors.New("database error")
		})

		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductSerial: "ABC123",
				ProductModel:  "Model-X",
			},
		})
		assert.Error(t, err)
		var profileErr *DeviceProfileError
		assert.True(t, errors.As(err, &profileErr))
	})

	t.Run("no profile found - allowed", func(t *testing.T) {
		hook := NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return nil, nil // No profile found
		})

		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductSerial: "ABC123",
				ProductModel:  "Model-X",
			},
		})
		assert.NoError(t, err)
	})

	t.Run("profile found with no expected PCRs", func(t *testing.T) {
		hook := NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return &DeviceProfile{
				ProductSerial: "ABC123",
				ProductModel:  "Model-X",
				// No ExpectedPCRs
			}, nil
		})

		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductSerial: "ABC123",
				ProductModel:  "Model-X",
			},
		})
		assert.NoError(t, err)
	})
}

// =============================================================================
// hasEventType Tests - Target 90% coverage
// =============================================================================

func TestHasEventType_Handlers90(t *testing.T) {
	events := []EventLogEntry{
		{PCRIndex: 0, EventType: "EV_SEPARATOR"},
		{PCRIndex: 1, EventType: "EV_POST_CODE"},
		{PCRIndex: 7, EventType: "EV_EFI_ACTION"},
	}

	assert.True(t, hasEventType(events, "EV_SEPARATOR"))
	assert.True(t, hasEventType(events, "EV_POST_CODE"))
	assert.True(t, hasEventType(events, "EV_EFI_ACTION"))
	assert.False(t, hasEventType(events, "EV_NO_ACTION"))
	assert.False(t, hasEventType(events, "EV_UNKNOWN"))

	// Empty events
	assert.False(t, hasEventType(nil, "EV_SEPARATOR"))
	assert.False(t, hasEventType([]EventLogEntry{}, "EV_SEPARATOR"))
}

// =============================================================================
// NewEventLogValidationHook Tests - Target 90% coverage
// =============================================================================

func TestNewEventLogValidationHook_Handlers90(t *testing.T) {
	t.Run("non-TCG enrollment skipped", func(t *testing.T) {
		hook := NewEventLogValidationHook(&EventLogPolicy{})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: false,
		})
		assert.NoError(t, err)
	})

	t.Run("empty event log allowed when no required events", func(t *testing.T) {
		hook := NewEventLogValidationHook(&EventLogPolicy{})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: nil,
			},
		})
		assert.NoError(t, err)
	})

	t.Run("empty event log error when required events specified", func(t *testing.T) {
		hook := NewEventLogValidationHook(&EventLogPolicy{
			RequiredEvents: []string{"EV_SEPARATOR"},
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: nil,
			},
		})
		assert.Error(t, err)
	})

	t.Run("max event count exceeded", func(t *testing.T) {
		// Build a simple event log with multiple events
		eventLog := buildLegacyEventLog(t, 5)

		hook := NewEventLogValidationHook(&EventLogPolicy{
			MaxEventCount: 2,
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: eventLog,
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max allowed")
	})

	t.Run("required event found", func(t *testing.T) {
		eventLog := buildLegacyEventLogWithTypes(t, []uint32{EVSeparator, EVPostCode})

		hook := NewEventLogValidationHook(&EventLogPolicy{
			RequiredEvents: []string{"EV_SEPARATOR"},
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: eventLog,
			},
		})
		assert.NoError(t, err)
	})

	t.Run("required event not found", func(t *testing.T) {
		eventLog := buildLegacyEventLogWithTypes(t, []uint32{EVPostCode})

		hook := NewEventLogValidationHook(&EventLogPolicy{
			RequiredEvents: []string{"EV_SEPARATOR"},
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: eventLog,
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required event")
	})

	t.Run("forbidden event found", func(t *testing.T) {
		eventLog := buildLegacyEventLogWithTypes(t, []uint32{EVSeparator, EVPostCode})

		hook := NewEventLogValidationHook(&EventLogPolicy{
			ForbiddenEvents: []string{"EV_POST_CODE"},
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: eventLog,
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "forbidden")
	})
}

// =============================================================================
// NewPCRValidationHook Tests - Target 90% coverage
// =============================================================================

func TestNewPCRValidationHook_Handlers90(t *testing.T) {
	t.Run("non-TCG enrollment skipped", func(t *testing.T) {
		hook := NewPCRValidationHook(&PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: {0x01}},
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: false,
		})
		assert.NoError(t, err)
	})

	t.Run("no prodcadata in non-strict mode", func(t *testing.T) {
		hook := NewPCRValidationHook(&PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: {0x01}},
			StrictMode:   false,
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProdCaData: nil,
			},
		})
		assert.NoError(t, err)
	})

	t.Run("no prodcadata in strict mode", func(t *testing.T) {
		hook := NewPCRValidationHook(&PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: {0x01}},
			StrictMode:   true,
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProdCaData: nil,
			},
		})
		assert.ErrorIs(t, err, ErrAttestationDataMissing)
	})
}

// =============================================================================
// NewQuoteValidationHook Tests - Target 90% coverage
// =============================================================================

func TestNewQuoteValidationHook_Handlers90(t *testing.T) {
	t.Run("non-TCG enrollment skipped", func(t *testing.T) {
		hook := NewQuoteValidationHook([]byte("nonce"))
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: false,
		})
		assert.NoError(t, err)
	})

	t.Run("no prodcadata skipped", func(t *testing.T) {
		hook := NewQuoteValidationHook([]byte("nonce"))
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProdCaData: nil,
			},
		})
		assert.NoError(t, err)
	})
}

// =============================================================================
// verifyQuoteSignature Tests - Target 90% coverage
// =============================================================================

func TestVerifyQuoteSignature_Handlers90(t *testing.T) {
	t.Run("empty quoted data", func(t *testing.T) {
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		err := verifyQuoteSignature(nil, []byte("sig"), &ecKey.PublicKey)
		assert.Error(t, err)
	})

	t.Run("empty signature", func(t *testing.T) {
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		err := verifyQuoteSignature([]byte("quoted"), nil, &ecKey.PublicKey)
		assert.Error(t, err)
	})

	t.Run("unsupported key type", func(t *testing.T) {
		err := verifyQuoteSignature([]byte("quoted"), []byte("sig"), "not a key")
		assert.Error(t, err)
	})
}

// =============================================================================
// parseCryptoAgileEvent Tests - Target 90% coverage
// =============================================================================

func TestParseCryptoAgileEvent_Handlers90(t *testing.T) {
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: TCGAlgSHA256, DigestSize: 32},
		{AlgorithmID: TCGAlgSHA1, DigestSize: 20},
	}

	t.Run("valid event with SHA256", func(t *testing.T) {
		buf := new(bytes.Buffer)
		// PCR index
		binary.Write(buf, binary.LittleEndian, uint32(0))
		// Event type
		binary.Write(buf, binary.LittleEndian, uint32(EVSeparator))
		// Digest count
		binary.Write(buf, binary.LittleEndian, uint32(1))
		// Algorithm ID
		binary.Write(buf, binary.LittleEndian, uint16(TCGAlgSHA256))
		// Digest (32 bytes for SHA256)
		buf.Write(make([]byte, 32))
		// Event data size
		binary.Write(buf, binary.LittleEndian, uint32(0))

		reader := bytes.NewReader(buf.Bytes())
		entry, err := parseCryptoAgileEvent(reader, algorithms)
		assert.NoError(t, err)
		assert.Equal(t, 0, entry.PCRIndex)
		assert.Equal(t, "EV_SEPARATOR", entry.EventType)
	})

	t.Run("truncated PCR index", func(t *testing.T) {
		buf := make([]byte, 2) // Too short
		reader := bytes.NewReader(buf)
		_, err := parseCryptoAgileEvent(reader, algorithms)
		assert.Error(t, err)
	})

	t.Run("truncated event type", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint32(0)) // PCR index only
		reader := bytes.NewReader(buf.Bytes())
		_, err := parseCryptoAgileEvent(reader, algorithms)
		assert.Error(t, err)
	})

	t.Run("truncated digest count", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint32(0)) // PCR index
		binary.Write(buf, binary.LittleEndian, uint32(EVSeparator))
		reader := bytes.NewReader(buf.Bytes())
		_, err := parseCryptoAgileEvent(reader, algorithms)
		assert.Error(t, err)
	})

	t.Run("unknown algorithm uses default sizes", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint32(0))
		binary.Write(buf, binary.LittleEndian, uint32(EVSeparator))
		binary.Write(buf, binary.LittleEndian, uint32(1))
		binary.Write(buf, binary.LittleEndian, uint16(TCGAlgSHA384)) // Not in algorithms list
		buf.Write(make([]byte, 48))                                  // SHA384 is 48 bytes
		binary.Write(buf, binary.LittleEndian, uint32(0))

		reader := bytes.NewReader(buf.Bytes())
		entry, err := parseCryptoAgileEvent(reader, []SpecIDAlgorithm{})
		assert.NoError(t, err)
		assert.Equal(t, "EV_SEPARATOR", entry.EventType)
	})

	t.Run("truly unknown algorithm fails", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint32(0))
		binary.Write(buf, binary.LittleEndian, uint32(EVSeparator))
		binary.Write(buf, binary.LittleEndian, uint32(1))
		binary.Write(buf, binary.LittleEndian, uint16(0x9999)) // Unknown algorithm
		reader := bytes.NewReader(buf.Bytes())
		_, err := parseCryptoAgileEvent(reader, []SpecIDAlgorithm{})
		assert.Error(t, err)
	})
}

// =============================================================================
// parseCryptoAgileEventLog Tests - Target 90% coverage
// =============================================================================

func TestParseCryptoAgileEventLog_Handlers90(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		buf := make([]byte, 10) // Less than 32 bytes
		_, err := parseCryptoAgileEventLog(buf)
		assert.Error(t, err)
	})

	t.Run("not crypto-agile format - wrong event type", func(t *testing.T) {
		buf := buildLegacyEventLogWithTypes(t, []uint32{EVSeparator})
		_, err := parseCryptoAgileEventLog(buf)
		assert.Error(t, err)
	})
}

// =============================================================================
// parseSpecIDEvent Tests - Target 90% coverage
// =============================================================================

func TestParseSpecIDEvent_Handlers90(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		buf := make([]byte, 10)
		_, err := parseSpecIDEvent(buf)
		assert.Error(t, err)
	})

	t.Run("invalid signature", func(t *testing.T) {
		buf := make([]byte, 32)
		copy(buf, []byte("Invalid Signature"))
		_, err := parseSpecIDEvent(buf)
		assert.Error(t, err)
	})

	t.Run("valid spec ID event", func(t *testing.T) {
		buf := new(bytes.Buffer)
		// Signature "Spec ID Event03"
		sig := make([]byte, 16)
		copy(sig, []byte("Spec ID Event03"))
		buf.Write(sig)
		// platformClass (4), minor (1), major (1), errata (1)
		buf.Write(make([]byte, 7))
		// uintnSize (1)
		buf.WriteByte(4)
		// numberOfAlgorithms (4)
		binary.Write(buf, binary.LittleEndian, uint32(2))
		// Algorithm 1: SHA1
		binary.Write(buf, binary.LittleEndian, uint16(TCGAlgSHA1))
		binary.Write(buf, binary.LittleEndian, uint16(20))
		// Algorithm 2: SHA256
		binary.Write(buf, binary.LittleEndian, uint16(TCGAlgSHA256))
		binary.Write(buf, binary.LittleEndian, uint16(32))

		algorithms, err := parseSpecIDEvent(buf.Bytes())
		assert.NoError(t, err)
		assert.Len(t, algorithms, 2)
	})

	t.Run("too many algorithms", func(t *testing.T) {
		buf := new(bytes.Buffer)
		sig := make([]byte, 16)
		copy(sig, []byte("Spec ID Event03"))
		buf.Write(sig)
		buf.Write(make([]byte, 7))
		buf.WriteByte(4)
		// numberOfAlgorithms > 16
		binary.Write(buf, binary.LittleEndian, uint32(20))

		_, err := parseSpecIDEvent(buf.Bytes())
		assert.Error(t, err)
	})
}

// =============================================================================
// validateDeviceAgainstProfile Tests - Target 90% coverage
// =============================================================================

func TestValidateDeviceAgainstProfile_Handlers90(t *testing.T) {
	t.Run("no expected PCRs", func(t *testing.T) {
		profile := &DeviceProfile{
			ExpectedPCRs: nil,
		}
		tcgData := &TCGEnrollmentData{}
		err := validateDeviceAgainstProfile(tcgData, profile)
		assert.NoError(t, err)
	})

	t.Run("no ProdCaData", func(t *testing.T) {
		profile := &DeviceProfile{
			ExpectedPCRs: map[int][]byte{0: {0xde, 0xad, 0xbe, 0xef}},
		}
		tcgData := &TCGEnrollmentData{
			ProdCaData: []byte("invalid-prodcadata"),
		}
		err := validateDeviceAgainstProfile(tcgData, profile)
		assert.Error(t, err)
	})
}

// =============================================================================
// Helper Functions for building test data
// =============================================================================

func createHMACCoverage(_ *testing.T, message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// buildLegacyEventLog creates a simple legacy event log with n events
func buildLegacyEventLog(t *testing.T, count int) []byte {
	types := make([]uint32, count)
	for i := range types {
		types[i] = EVSeparator
	}
	return buildLegacyEventLogWithTypes(t, types)
}

// buildLegacyEventLogWithTypes creates a legacy event log with specific event types
func buildLegacyEventLogWithTypes(t *testing.T, eventTypes []uint32) []byte {
	var buf []byte

	for i, evType := range eventTypes {
		// PCR index (4 bytes)
		pcrIndex := make([]byte, 4)
		binary.LittleEndian.PutUint32(pcrIndex, uint32(i%8))
		buf = append(buf, pcrIndex...)

		// Event type (4 bytes)
		eventType := make([]byte, 4)
		binary.LittleEndian.PutUint32(eventType, evType)
		buf = append(buf, eventType...)

		// SHA-1 digest (20 bytes)
		digest := make([]byte, 20)
		buf = append(buf, digest...)

		// Event data size (4 bytes) - 0 data
		dataSize := make([]byte, 4)
		buf = append(buf, dataSize...)
	}

	return buf
}

// createKeyChangePayload creates the inner JWS payload for key change
func createKeyChangePayload(t *testing.T, service *RestService, account *entities.ACMEAccount, oldKey, newKey *TestKey) []byte {
	// Create old key JWK
	oldKeyJWK := &jose.JSONWebKey{Key: oldKey.PublicKey}
	oldKeyJSON, err := oldKeyJWK.MarshalJSON()
	require.NoError(t, err)
	var oldKeyMap map[string]interface{}
	err = json.Unmarshal(oldKeyJSON, &oldKeyMap)
	require.NoError(t, err)

	// Create inner payload
	innerPayload := map[string]interface{}{
		"account": account.URL,
		"oldKey":  oldKeyMap,
	}
	innerPayloadBytes, err := json.Marshal(innerPayload)
	require.NoError(t, err)

	// Create inner JWS signed with new key
	innerSignerOpts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": service.baseRESTURI + "/acme/key-change",
		},
	}
	innerSignerOpts.EmbedJWK = true

	innerSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	require.NoError(t, err)

	innerJWS, err := innerSigner.Sign(innerPayloadBytes)
	require.NoError(t, err)

	return []byte(innerJWS.FullSerialize())
}
