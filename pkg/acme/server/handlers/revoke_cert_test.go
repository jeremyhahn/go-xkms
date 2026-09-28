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
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
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

	// Create ACME certificate entity. PEM mirrors the certificate the "CA"
	// just issued: revocation now requires the submitted certificate to
	// byte-match the stored PEM record (see RevokeCertHandler), so a test
	// fixture with an empty PEM would make every revocation attempt fail as
	// an unauthorized mismatch regardless of what the test intends to check.
	acmeCert := &entities.ACMECertificate{
		Serial:    serialNumber.Text(16),
		CertURL:   "",
		PEM:       string(encodeCertificatePEM(certDER)),
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

	// Create ACME certificate entity with the stored PEM matching the
	// certificate under test (see createTestCertificateWithSerial for why).
	acmeCert := &entities.ACMECertificate{
		Serial:    serialNumber.Text(16),
		CertURL:   "",
		PEM:       string(encodeCertificatePEM(certDER)),
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

	updatedCert, err := certificateDAO.Get(ctx, acmeCert.EntityID())
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

	updatedCert, err := certificateDAO.Get(ctx, acmeCert.EntityID())
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

			updatedCert, err := certificateDAO.Get(ctx, acmeCert.EntityID())
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

	updatedCert, err := certificateDAO.Get(ctx, acmeCert.EntityID())
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

// mockRevokeCA wraps MockCA to observe and control RevokeCert behavior for
// regression tests covering H2 (CA revocation must actually be invoked).
type mockRevokeCA struct {
	MockCA
	revokeCertCalled bool
	revokeCertCert   *x509.Certificate
	revokeCertOpts   ca.RevokeOptions
	revokeCertErr    error
}

func (m *mockRevokeCA) RevokeCert(_ context.Context, cert *x509.Certificate, opts ca.RevokeOptions) error {
	m.revokeCertCalled = true
	m.revokeCertCert = cert
	m.revokeCertOpts = opts
	return m.revokeCertErr
}

// TestRevokeCertHandler_ForgedCertificateWithVictimSerial verifies H1: a
// self-signed certificate forged with a victim's serial number, carrying no
// authorized identifiers of its own, must not be able to revoke the
// victim's certificate merely because the serial numbers collide.
func TestRevokeCertHandler_ForgedCertificateWithVictimSerial(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	victimKey := generateTestKey(t)
	victimAccount := createTestAccount(t, service, victimKey)

	// The victim's real, issued certificate with a valid authorization.
	acmeCert, victimCert := createTestCertificateWithAuthorization(t, service, victimKey, victimAccount.ID)

	// The attacker has its own account and crafts a self-signed certificate
	// that reuses the victim's serial number. It carries no CN/SAN, so it
	// would previously satisfy the buggy "authorize from submitted cert"
	// logic (empty domain list => nothing to check).
	attackerKey := generateTestKey(t)
	attackerAccount := createTestAccount(t, service, attackerKey)

	forgedTemplate := &x509.Certificate{
		SerialNumber:          victimCert.SerialNumber,
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	forgedDER, err := x509.CreateCertificate(rand.Reader, forgedTemplate, forgedTemplate,
		attackerKey.PublicKey, attackerKey.PrivateKey)
	require.NoError(t, err)

	payload := RevokeCertRequest{
		Certificate: base64.RawURLEncoding.EncodeToString(forgedDER),
		Reason:      RevocationReasonKeyCompromise,
	}

	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, attackerKey, url, payload, true, attackerAccount.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	require.Equal(t, http.StatusUnauthorized, resp.Code)

	// The victim's stored certificate must remain untouched.
	ctx := context.Background()
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	stored, err := certificateDAO.Get(ctx, acmeCert.EntityID())
	require.NoError(t, err)
	assert.Equal(t, common.StatusValid, stored.Status)
}

// TestRevokeCertHandler_StoredCertificateWithNoIdentifiers verifies H1's
// "require at least one identity" rule: a stored certificate with neither a
// CommonName nor DNS SANs has nothing to authorize revocation against and
// must be rejected even though the submitted certificate byte-matches.
func TestRevokeCertHandler_StoredCertificateWithNoIdentifiers(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{}, // No CommonName
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey, key.PrivateKey)
	require.NoError(t, err)

	ctx := context.Background()
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	acmeCert := &entities.ACMECertificate{
		Serial:    serialNumber.Text(16),
		PEM:       string(encodeCertificatePEM(certDER)),
		IssuedAt:  time.Now(),
		Status:    common.StatusValid,
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
	require.NoError(t, certificateDAO.Save(ctx, acmeCert))

	payload := RevokeCertRequest{
		Certificate: base64.RawURLEncoding.EncodeToString(certDER),
		Reason:      RevocationReasonKeyCompromise,
	}
	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	require.Equal(t, http.StatusUnauthorized, resp.Code)
}

// TestRevokeCertHandler_InvokesCARevocation verifies H2: revoking a
// certificate through the ACME endpoint must call the canonical CA
// revocation entry point (ca.RevokeCert), not just flip the ACME DAO's
// status field.
func TestRevokeCertHandler_InvokesCARevocation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	mockCA := &mockRevokeCA{}
	service.ca = mockCA

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	acmeCert, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	payload := RevokeCertRequest{
		Certificate: base64.RawURLEncoding.EncodeToString(x509Cert.Raw),
		Reason:      RevocationReasonKeyCompromise,
	}
	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	require.True(t, mockCA.revokeCertCalled, "RevokeCertHandler must call the CA's RevokeCert")
	assert.Equal(t, x509Cert.SerialNumber, mockCA.revokeCertCert.SerialNumber)
	assert.Equal(t, RevocationReasonKeyCompromise, mockCA.revokeCertOpts.Reason)

	ctx := context.Background()
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	stored, err := certificateDAO.Get(ctx, acmeCert.EntityID())
	require.NoError(t, err)
	assert.Equal(t, common.StatusRevoked, stored.Status)
}

// TestRevokeCertHandler_CARevocationFailureBlocksACMERecord verifies that
// when the canonical CA revocation fails for a reason other than "already
// revoked", the ACME record is not updated to "revoked": the two stores
// must not be allowed to disagree about whether the certificate is actually
// revoked.
func TestRevokeCertHandler_CARevocationFailureBlocksACMERecord(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	mockCA := &mockRevokeCA{revokeCertErr: caerrors.InternalServerError("hardware key store unavailable")}
	service.ca = mockCA

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	acmeCert, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	payload := RevokeCertRequest{
		Certificate: base64.RawURLEncoding.EncodeToString(x509Cert.Raw),
		Reason:      RevocationReasonKeyCompromise,
	}
	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)

	ctx := context.Background()
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	stored, err := certificateDAO.Get(ctx, acmeCert.EntityID())
	require.NoError(t, err)
	assert.Equal(t, common.StatusValid, stored.Status)
}

// TestRevokeCertHandler_CAAlreadyRevokedIsSuccess verifies that a CA
// reporting ca.ErrAlreadyRevoked is treated as a successful revocation: the
// desired end state already holds, so the ACME record still moves to
// "revoked" rather than surfacing an error to the client.
func TestRevokeCertHandler_CAAlreadyRevokedIsSuccess(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	mockCA := &mockRevokeCA{revokeCertErr: ca.ErrAlreadyRevoked}
	service.ca = mockCA

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	acmeCert, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	payload := RevokeCertRequest{
		Certificate: base64.RawURLEncoding.EncodeToString(x509Cert.Raw),
		Reason:      RevocationReasonKeyCompromise,
	}
	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	ctx := context.Background()
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	stored, err := certificateDAO.Get(ctx, acmeCert.EntityID())
	require.NoError(t, err)
	assert.Equal(t, common.StatusRevoked, stored.Status)
}

// TestRevokeCertHandler_HashCollisionRefuses verifies that when the DAO row
// a requested serial's EntityID hashes to (entities.StringToEntityID, a
// 64-bit FNV-1a hash) actually holds a DIFFERENT certificate - simulating a
// genuine hash collision, which this test substitutes directly since one
// cannot be manufactured cheaply - RevokeCertHandler refuses with "not
// found" and never calls the CA to revoke the wrong certificate.
func TestRevokeCertHandler_HashCollisionRefuses(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	mockCA := &mockRevokeCA{}
	service.ca = mockCA

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// The certificate the client is trying to revoke.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "victim.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey, key.PrivateKey)
	require.NoError(t, err)

	// The row this serial's EntityID hashes to belongs to a DIFFERENT
	// certificate.
	otherCert := &entities.ACMECertificate{
		Serial: "deadbeef",
		PEM:    string(encodeCertificatePEM([]byte("not-the-requested-cert"))),
		Status: common.StatusValid,
	}
	service.storageFactory = &collidingCertificateFactory{
		Factory:   service.storageFactory,
		otherCert: otherCert,
	}

	payload := RevokeCertRequest{
		Certificate: base64.RawURLEncoding.EncodeToString(certDER),
		Reason:      RevocationReasonKeyCompromise,
	}
	url := service.baseRESTURI + "/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
	assert.False(t, mockCA.revokeCertCalled, "CA RevokeCert must never be called on a storage row collision")
	assert.NotEqual(t, common.StatusRevoked, otherCert.Status, "the other certificate must never be revoked either")
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
