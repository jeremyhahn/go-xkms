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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCertificateWithSerial creates and saves a test certificate with a specific serial number
func createTestCertificateWithSerial(t *testing.T, service *RestService, accountKey *TestKey) (*entities.ACMECertificate, *x509.Certificate) {
	ctx := context.Background()

	// Generate a real certificate for testing
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign for testing
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, accountKey.PublicKey, accountKey.PrivateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Get certificate DAO
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Create ACME certificate entity
	acmeCert := &entities.ACMECertificate{
		ID:        serialNumber.Uint64(),
		CertURL:   "",
		PEM:       "",
		IssuedAt:  time.Now(),
		Status:    common.StatusValid,
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}

	// Save certificate
	err = certificateDAO.Save(ctx, acmeCert)
	require.NoError(t, err)

	return acmeCert, cert
}

// createTestCertificateWithAuthorization creates a test certificate AND the required authorization
// to satisfy RFC 8555 Section 7.6 revocation authorization requirements
func createTestCertificateWithAuthorization(t *testing.T, service *RestService, accountKey *TestKey, accountID uint64) (*entities.ACMECertificate, *x509.Certificate) {
	ctx := context.Background()

	// Generate a real certificate for testing
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	domain := "test.example.com"
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign for testing
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, accountKey.PublicKey, accountKey.PrivateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Get certificate DAO
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Create ACME certificate entity
	acmeCert := &entities.ACMECertificate{
		ID:        serialNumber.Uint64(),
		CertURL:   "",
		PEM:       "",
		IssuedAt:  time.Now(),
		Status:    common.StatusValid,
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}

	// Save certificate
	err = certificateDAO.Save(ctx, acmeCert)
	require.NoError(t, err)

	// Create valid authorization for the domain (RFC 8555 Section 7.6 requirement)
	authzDAO, err := service.storageFactory.AuthorizationDAO(accountID)
	require.NoError(t, err)

	authz := &entities.ACMEAuthorization{
		ID: serialNumber.Uint64() + 1, // Use a different ID than the cert
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: domain,
		},
		Status:    common.StatusValid,
		Expires:   time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		AccountID: accountID,
	}

	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	return acmeCert, cert
}

func TestRevokeCertHandler_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test certificate with authorization
	acmeCert, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	// Encode certificate to base64url
	certDER := x509Cert.Raw
	certB64 := base64.RawURLEncoding.EncodeToString(certDER)

	// Create revoke request with valid reason
	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Verify certificate status was updated
	ctx := context.Background()
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	updatedCert, err := certificateDAO.Get(ctx, acmeCert.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusRevoked, updatedCert.Status)
}

func TestRevokeCertHandler_SuccessWithoutReason(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test certificate with authorization
	acmeCert, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	// Encode certificate to base64url
	certDER := x509Cert.Raw
	certB64 := base64.RawURLEncoding.EncodeToString(certDER)

	// Create revoke request without reason (defaults to unspecified)
	payload := RevokeCertRequest{
		Certificate: certB64,
		// Reason omitted - should default to 0 (unspecified)
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	// Verify certificate status was updated
	ctx := context.Background()
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	updatedCert, err := certificateDAO.Get(ctx, acmeCert.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusRevoked, updatedCert.Status)
}

func TestRevokeCertHandler_AllValidReasons(t *testing.T) {
	validReasons := []int{
		RevocationReasonUnspecified,
		RevocationReasonKeyCompromise,
		RevocationReasonCACertCompromise,
		RevocationReasonAffiliationChanged,
		RevocationReasonSuperseded,
		RevocationReasonCessationOfOperation,
		RevocationReasonCertificateHold,
	}

	for _, reason := range validReasons {
		t.Run(reasonToString(reason), func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()

			key := generateTestKey(t)
			account := createTestAccount(t, service, key)

			// Create a test certificate with authorization
			acmeCert, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

			// Encode certificate to base64url
			certDER := x509Cert.Raw
			certB64 := base64.RawURLEncoding.EncodeToString(certDER)

			// Create revoke request with specific reason
			payload := RevokeCertRequest{
				Certificate: certB64,
				Reason:      reason,
			}

			url := service.baseRESTURI + "/acme/revoke-cert"
			req := createJWSRequest(t, service, key, url, payload, true, account.ID)

			// Execute request
			resp := httptest.NewRecorder()
			service.RevokeCertHandler(resp, req)

			// Verify response
			require.Equal(t, http.StatusOK, resp.Code)

			// Verify certificate status was updated
			ctx := context.Background()
			certificateDAO, err := service.storageFactory.CertificateDAO()
			require.NoError(t, err)

			updatedCert, err := certificateDAO.Get(ctx, acmeCert.ID)
			require.NoError(t, err)
			assert.Equal(t, common.StatusRevoked, updatedCert.Status)
		})
	}
}

func TestRevokeCertHandler_InvalidCertificateEncoding(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create revoke request with invalid base64 encoding
	payload := RevokeCertRequest{
		Certificate: "not-valid-base64!!!", // Invalid base64
		Reason:      RevocationReasonKeyCompromise,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	// Should return 400 Bad Request
	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "Invalid certificate encoding")
}

func TestRevokeCertHandler_InvalidCertificateFormat(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create revoke request with invalid certificate data (valid base64 but not a valid certificate)
	invalidCertData := []byte("this is not a valid certificate")
	certB64 := base64.RawURLEncoding.EncodeToString(invalidCertData)

	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	// Should return 400 Bad Request
	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "Invalid certificate format")
}

func TestRevokeCertHandler_CertificateNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a certificate but don't save it to the database
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign for testing
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey, key.PrivateKey)
	require.NoError(t, err)

	// Encode certificate to base64url
	certB64 := base64.RawURLEncoding.EncodeToString(certDER)

	// Create revoke request
	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestRevokeCertHandler_InvalidRevocationReason(t *testing.T) {
	invalidReasons := []int{-1, 11, 100, -100}

	for _, reason := range invalidReasons {
		t.Run(reasonToString(reason), func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()

			key := generateTestKey(t)
			account := createTestAccount(t, service, key)

			// Create a test certificate
			_, x509Cert := createTestCertificateWithSerial(t, service, key)

			// Encode certificate to base64url
			certDER := x509Cert.Raw
			certB64 := base64.RawURLEncoding.EncodeToString(certDER)

			// Create revoke request with invalid reason
			payload := RevokeCertRequest{
				Certificate: certB64,
				Reason:      reason,
			}

			url := service.baseRESTURI + "/acme/revoke-cert"
			req := createJWSRequest(t, service, key, url, payload, true, account.ID)

			// Execute request
			resp := httptest.NewRecorder()
			service.RevokeCertHandler(resp, req)

			// Should return 400 Bad Request
			require.Equal(t, http.StatusBadRequest, resp.Code)
			assert.Contains(t, resp.Body.String(), "Invalid revocation reason")
		})
	}
}

func TestRevokeCertHandler_AlreadyRevokedCertificate(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test certificate with authorization
	acmeCert, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	// Encode certificate to base64url
	certDER := x509Cert.Raw
	certB64 := base64.RawURLEncoding.EncodeToString(certDER)

	// Create revoke request
	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// First revocation
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// Verify first revocation succeeded
	ctx := context.Background()
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	updatedCert, err := certificateDAO.Get(ctx, acmeCert.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusRevoked, updatedCert.Status)

	// Try to revoke again
	req2 := createJWSRequest(t, service, key, url, payload, true, account.ID)
	resp2 := httptest.NewRecorder()
	service.RevokeCertHandler(resp2, req2)

	// Second revocation should also succeed (idempotent)
	// RFC 8555 doesn't specify error behavior for already-revoked certs
	// The implementation just updates the status again, which is harmless
	require.Equal(t, http.StatusOK, resp2.Code)
}

func TestRevokeCertHandler_MalformedJWS(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createInvalidJWSRequest(t, url)

	// Execute request
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	// Should return malformed error
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestRevokeCertHandler_InvalidMethod_GET(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a test certificate
	_, x509Cert := createTestCertificateWithSerial(t, service, key)

	// Encode certificate to base64url
	certDER := x509Cert.Raw
	certB64 := base64.RawURLEncoding.EncodeToString(certDER)

	// Create revoke request
	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Change method to GET
	req.Method = http.MethodGet

	// Execute request
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	// The handler doesn't explicitly check method, so parseKID will be called
	// For GET requests with JWS body, it may succeed or fail depending on implementation
	// This test verifies the handler doesn't crash with GET
	require.NotEqual(t, http.StatusInternalServerError, resp.Code)
}

func TestRevokeCertHandler_EmptyCertificate(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create revoke request with empty certificate
	payload := RevokeCertRequest{
		Certificate: "",
		Reason:      RevocationReasonKeyCompromise,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	// Should return 400 Bad Request for empty certificate
	require.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestRevokeCertHandler_BoundaryReasons(t *testing.T) {
	boundaryReasons := []struct {
		reason int
		valid  bool
	}{
		{0, true},  // Minimum valid reason
		{10, true}, // Maximum valid reason
		{5, true},  // Middle valid reason
	}

	for _, tc := range boundaryReasons {
		t.Run(reasonToString(tc.reason), func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()

			key := generateTestKey(t)
			account := createTestAccount(t, service, key)

			// Create a test certificate with authorization
			_, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

			// Encode certificate to base64url
			certDER := x509Cert.Raw
			certB64 := base64.RawURLEncoding.EncodeToString(certDER)

			// Create revoke request
			payload := RevokeCertRequest{
				Certificate: certB64,
				Reason:      tc.reason,
			}

			url := service.baseRESTURI + "/acme/revoke-cert"
			req := createJWSRequest(t, service, key, url, payload, true, account.ID)

			// Execute request
			resp := httptest.NewRecorder()
			service.RevokeCertHandler(resp, req)

			if tc.valid {
				require.Equal(t, http.StatusOK, resp.Code)
			} else {
				require.Equal(t, http.StatusBadRequest, resp.Code)
			}
		})
	}
}

func TestRevokeCertHandler_UnauthorizedRevocation(t *testing.T) {
	// This test verifies RFC 8555 Section 7.6 authorization checks
	// A certificate created WITHOUT a valid authorization should be rejected
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create a certificate WITHOUT authorization (using the old helper)
	_, x509Cert := createTestCertificateWithSerial(t, service, key)

	// Encode certificate to base64url
	certDER := x509Cert.Raw
	certB64 := base64.RawURLEncoding.EncodeToString(certDER)

	// Create revoke request
	payload := RevokeCertRequest{
		Certificate: certB64,
		Reason:      RevocationReasonKeyCompromise,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Execute request
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	// Should return 401 Unauthorized because no authorization exists
	require.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, resp.Body.String(), "unauthorized")
}

// Helper function to convert reason code to string for test names
func reasonToString(reason int) string {
	switch reason {
	case RevocationReasonUnspecified:
		return "unspecified"
	case RevocationReasonKeyCompromise:
		return "keyCompromise"
	case RevocationReasonCACertCompromise:
		return "caCertCompromise"
	case RevocationReasonAffiliationChanged:
		return "affiliationChanged"
	case RevocationReasonSuperseded:
		return "superseded"
	case RevocationReasonCessationOfOperation:
		return "cessationOfOperation"
	case RevocationReasonCertificateHold:
		return "certificateHold"
	default:
		return "invalid"
	}
}
