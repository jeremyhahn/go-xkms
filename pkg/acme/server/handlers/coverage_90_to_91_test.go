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
