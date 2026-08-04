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

package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

func TestAdminService_ListCertificates(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create test certificates
	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	cert1 := createTestACMECertificate(t, 1, "test1.example.com", "valid")
	cert2 := createTestACMECertificate(t, 2, "test2.example.com", "revoked")

	require.NoError(t, certDAO.Save(ctx, cert1))
	require.NoError(t, certDAO.Save(ctx, cert2))

	// Test listing all certificates
	req := ListCertificatesRequest{Page: 1, PerPage: 10}
	certs, pagination, err := service.ListCertificates(ctx, req)

	require.NoError(t, err)
	assert.Len(t, certs, 2)
	assert.Equal(t, 2, pagination.Total)
	assert.Equal(t, 1, pagination.Page)
	assert.Equal(t, 10, pagination.PerPage)
}

func TestAdminService_ListCertificates_WithFilters(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	cert1 := createTestACMECertificate(t, 1, "test1.example.com", "valid")
	cert2 := createTestACMECertificate(t, 2, "test2.example.com", "revoked")

	require.NoError(t, certDAO.Save(ctx, cert1))
	require.NoError(t, certDAO.Save(ctx, cert2))

	// Filter by status
	req := ListCertificatesRequest{Page: 1, PerPage: 10, Status: "valid"}
	certs, pagination, err := service.ListCertificates(ctx, req)

	require.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Equal(t, 1, pagination.Total)
	assert.Equal(t, "valid", certs[0].Status)
}

func TestAdminService_ListCertificates_Pagination(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Create 5 test certificates
	for i := 1; i <= 5; i++ {
		cert := createTestACMECertificate(t, uint64(i), "test.example.com", "valid")
		require.NoError(t, certDAO.Save(ctx, cert))
	}

	// Get first page
	req := ListCertificatesRequest{Page: 1, PerPage: 2}
	certs, pagination, err := service.ListCertificates(ctx, req)

	require.NoError(t, err)
	assert.Len(t, certs, 2)
	assert.Equal(t, 5, pagination.Total)

	// Get second page
	req = ListCertificatesRequest{Page: 2, PerPage: 2}
	certs, pagination, err = service.ListCertificates(ctx, req)

	require.NoError(t, err)
	assert.Len(t, certs, 2)
	assert.Equal(t, 5, pagination.Total)
}

func TestAdminService_GetCertificate(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	cert := createTestACMECertificate(t, 1, "test.example.com", "valid")
	require.NoError(t, certDAO.Save(ctx, cert))

	// Parse certificate to get serial number
	x509Cert, err := parsePEMCertificate(cert.PEM)
	require.NoError(t, err)

	// Get certificate by serial
	result, err := service.GetCertificate(ctx, x509Cert.SerialNumber.String())
	require.NoError(t, err)
	assert.Equal(t, x509Cert.SerialNumber.String(), result.SerialNumber)
}

func TestAdminService_GetCertificate_NotFound(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	_, err := service.GetCertificate(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

func TestAdminService_ListAccounts(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	// Create test accounts
	account1 := &entities.ACMEAccount{
		ID:        1,
		Status:    "valid",
		Contact:   []string{"mailto:test1@example.com"},
		CreatedAt: time.Now(),
	}
	account2 := &entities.ACMEAccount{
		ID:        2,
		Status:    "deactivated",
		Contact:   []string{"mailto:test2@example.com"},
		CreatedAt: time.Now(),
	}

	require.NoError(t, accountDAO.Save(ctx, account1))
	require.NoError(t, accountDAO.Save(ctx, account2))

	// List all accounts
	req := ListAccountsRequest{Page: 1, PerPage: 10}
	accounts, pagination, err := service.ListAccounts(ctx, req)

	require.NoError(t, err)
	assert.Len(t, accounts, 2)
	assert.Equal(t, 2, pagination.Total)
}

func TestAdminService_GetAccount(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{
		ID:        1,
		Status:    "valid",
		Contact:   []string{"mailto:test@example.com"},
		CreatedAt: time.Now(),
	}

	require.NoError(t, accountDAO.Save(ctx, account))

	// Get account
	result, err := service.GetAccount(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, FlexUint64(1), result.ID)
	assert.Equal(t, "valid", result.Status)
}

func TestAdminService_DisableAccount(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{
		ID:        1,
		Status:    "valid",
		Contact:   []string{"mailto:test@example.com"},
		CreatedAt: time.Now(),
	}

	require.NoError(t, accountDAO.Save(ctx, account))

	// Disable account
	err = service.DisableAccount(ctx, 1)
	require.NoError(t, err)

	// Verify account is disabled
	updated, err := accountDAO.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, "deactivated", updated.Status)
}

func TestAdminService_GetStatus(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	status, err := service.GetStatus(ctx)
	require.NoError(t, err)

	assert.NotEmpty(t, status.Identity)
	assert.True(t, status.Initialized)
	assert.NotEmpty(t, status.Version)
	assert.NotEmpty(t, status.RootCA)

	// Verify multi-key information is populated from the issuing identity
	require.NotNil(t, status.Keys, "Keys should be populated from CA config")
	require.GreaterOrEqual(t, len(status.Keys), 3, "should have at least 3 keys (ECDSA, RSA, Ed25519)")

	// The first key should be marked as default
	assert.True(t, status.Keys[0].Default, "first key should be the default signing key")

	// Verify all keys have required fields
	for i, key := range status.Keys {
		assert.NotEmpty(t, key.Algorithm, "key %d: algorithm must not be empty", i)
		assert.NotEmpty(t, key.SignatureAlgorithm, "key %d: signature algorithm must not be empty", i)
		assert.NotEmpty(t, key.Store, "key %d: store must not be empty", i)
		if i > 0 {
			assert.False(t, key.Default, "key %d: only Keys[0] should be default", i)
		}
	}

	// Backward compatibility: legacy single-key fields are still populated
	assert.NotEmpty(t, status.KeyAlgorithm)
	assert.NotEmpty(t, status.SignatureAlgo)
}

func TestAdminService_GetStatus_KeyDetails(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	status, err := service.GetStatus(ctx)
	require.NoError(t, err)
	require.NotNil(t, status.Keys)

	// Build a set of algorithm+store combinations for verification
	type keyID struct {
		algo  string
		store string
	}
	seen := make(map[keyID]bool)
	for _, key := range status.Keys {
		seen[keyID{key.Algorithm, key.Store}] = true

		// RSA keys must have a key size
		if key.Algorithm == "RSA" {
			assert.Greater(t, key.KeySize, 0, "RSA key must have key_size set")
		}
		// ECDSA keys must have a curve
		if key.Algorithm == "ECDSA" {
			assert.NotEmpty(t, key.Curve, "ECDSA key must have curve set")
		}
	}

	// The default config includes at least software ECDSA, RSA, and Ed25519
	assert.True(t, seen[keyID{"ECDSA", "software"}], "should include software ECDSA key")
	assert.True(t, seen[keyID{"RSA", "software"}], "should include software RSA key")
	assert.True(t, seen[keyID{"Ed25519", "software"}], "should include software Ed25519 key")
}

func TestAdminService_GetStats(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	stats, err := service.GetStats(ctx)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, stats.TotalCertificates, 0)
	assert.GreaterOrEqual(t, stats.TotalAccounts, 0)
	assert.GreaterOrEqual(t, stats.TotalOrders, 0)
}

func TestAdminService_ListExpiringCertificates(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Create certificate expiring in 15 days
	cert := createTestACMECertificate(t, 1, "test.example.com", "valid")
	// Update expiration to 15 days from now
	cert.ExpiresAt = time.Now().Add(15 * 24 * time.Hour)

	require.NoError(t, certDAO.Save(ctx, cert))

	// List certificates expiring in 30 days
	certs, pagination, err := service.ListExpiringCertificates(ctx, 30, 1, 10)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Equal(t, 1, pagination.Total)

	// List certificates expiring in 10 days (should be empty)
	certs, _, err = service.ListExpiringCertificates(ctx, 10, 1, 10)
	require.NoError(t, err)
	assert.Len(t, certs, 0)
}

// Helper functions

func TestAdminService_RevokeCertificate(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Create a valid certificate
	cert := createTestACMECertificate(t, 1, "test.example.com", "valid")
	require.NoError(t, certDAO.Save(ctx, cert))

	// Parse to get serial number
	x509Cert, err := parsePEMCertificate(cert.PEM)
	require.NoError(t, err)
	serial := x509Cert.SerialNumber.String()

	// Revoke the certificate
	err = service.RevokeCertificate(ctx, serial, "testing")
	require.NoError(t, err)

	// Verify certificate is now revoked
	updated, err := certDAO.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, "revoked", updated.Status)
}

func TestAdminService_RevokeCertificate_NotFound(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	err := service.RevokeCertificate(ctx, "nonexistent-serial", "testing")
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

func TestAdminService_ListOrders(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create test account first
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{
		ID:        1,
		Status:    "valid",
		Contact:   []string{"mailto:test@example.com"},
		CreatedAt: time.Now(),
	}
	require.NoError(t, accountDAO.Save(ctx, account))

	// Create test orders
	orderDAO, err := service.storageFactory.OrderDAO(1)
	require.NoError(t, err)

	order1 := &entities.ACMEOrder{
		ID:        1,
		AccountID: 1,
		Status:    "pending",
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	order2 := &entities.ACMEOrder{
		ID:        2,
		AccountID: 1,
		Status:    "valid",
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "test.com"},
		},
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	require.NoError(t, orderDAO.Save(ctx, order1))
	require.NoError(t, orderDAO.Save(ctx, order2))

	// List all orders
	req := ListOrdersRequest{Page: 1, PerPage: 10}
	orders, pagination, err := service.ListOrders(ctx, req)

	require.NoError(t, err)
	assert.Len(t, orders, 2)
	assert.Equal(t, 2, pagination.Total)
}

func TestAdminService_ListOrders_WithAccountID(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create test accounts
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account1 := &entities.ACMEAccount{ID: 1, Status: "valid", CreatedAt: time.Now()}
	account2 := &entities.ACMEAccount{ID: 2, Status: "valid", CreatedAt: time.Now()}
	require.NoError(t, accountDAO.Save(ctx, account1))
	require.NoError(t, accountDAO.Save(ctx, account2))

	// Create orders for account 1
	orderDAO1, err := service.storageFactory.OrderDAO(1)
	require.NoError(t, err)
	order1 := &entities.ACMEOrder{
		ID:          1,
		AccountID:   1,
		Status:      "pending",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "example.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	require.NoError(t, orderDAO1.Save(ctx, order1))

	// Create orders for account 2
	orderDAO2, err := service.storageFactory.OrderDAO(2)
	require.NoError(t, err)
	order2 := &entities.ACMEOrder{
		ID:          2,
		AccountID:   2,
		Status:      "valid",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "test.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	require.NoError(t, orderDAO2.Save(ctx, order2))

	// List orders for account 1 only
	req := ListOrdersRequest{Page: 1, PerPage: 10, AccountID: 1}
	orders, pagination, err := service.ListOrders(ctx, req)

	require.NoError(t, err)
	assert.Len(t, orders, 1)
	assert.Equal(t, 1, pagination.Total)
	assert.Equal(t, uint64(1), orders[0].AccountID)
}

func TestAdminService_ListOrders_WithStatus(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{ID: 1, Status: "valid", CreatedAt: time.Now()}
	require.NoError(t, accountDAO.Save(ctx, account))

	orderDAO, err := service.storageFactory.OrderDAO(1)
	require.NoError(t, err)

	order1 := &entities.ACMEOrder{
		ID:          1,
		AccountID:   1,
		Status:      "pending",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "example.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	order2 := &entities.ACMEOrder{
		ID:          2,
		AccountID:   1,
		Status:      "valid",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "test.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	require.NoError(t, orderDAO.Save(ctx, order1))
	require.NoError(t, orderDAO.Save(ctx, order2))

	// Filter by status "pending"
	req := ListOrdersRequest{Page: 1, PerPage: 10, Status: "pending"}
	orders, pagination, err := service.ListOrders(ctx, req)

	require.NoError(t, err)
	assert.Len(t, orders, 1)
	assert.Equal(t, 1, pagination.Total)
	assert.Equal(t, "pending", orders[0].Status)
}

func TestAdminService_GetOrder(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{ID: 1, Status: "valid", CreatedAt: time.Now()}
	require.NoError(t, accountDAO.Save(ctx, account))

	orderDAO, err := service.storageFactory.OrderDAO(1)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		ID:          1,
		AccountID:   1,
		Status:      "pending",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "example.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	require.NoError(t, orderDAO.Save(ctx, order))

	// Get order
	result, err := service.GetOrder(ctx, 1, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), result.ID)
	assert.Equal(t, "pending", result.Status)
}

func TestAdminService_GetOrder_NotFound(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{ID: 1, Status: "valid", CreatedAt: time.Now()}
	require.NoError(t, accountDAO.Save(ctx, account))

	_, err = service.GetOrder(ctx, 1, 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAdminService_ListAccounts_WithStatus(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account1 := &entities.ACMEAccount{
		ID:        1,
		Status:    "valid",
		Contact:   []string{"mailto:test1@example.com"},
		CreatedAt: time.Now(),
	}
	account2 := &entities.ACMEAccount{
		ID:        2,
		Status:    "deactivated",
		Contact:   []string{"mailto:test2@example.com"},
		CreatedAt: time.Now(),
	}
	require.NoError(t, accountDAO.Save(ctx, account1))
	require.NoError(t, accountDAO.Save(ctx, account2))

	// Filter by status "valid"
	req := ListAccountsRequest{Page: 1, PerPage: 10, Status: "valid"}
	accounts, pagination, err := service.ListAccounts(ctx, req)

	require.NoError(t, err)
	assert.Len(t, accounts, 1)
	assert.Equal(t, 1, pagination.Total)
	assert.Equal(t, "valid", accounts[0].Status)
}

func TestAdminService_GetAccount_NotFound(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	_, err := service.GetAccount(ctx, 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAdminService_DisableAccount_NotFound(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	err := service.DisableAccount(ctx, 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAdminService_ListCertificates_DefaultPagination(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Test with invalid pagination values (should default)
	req := ListCertificatesRequest{Page: 0, PerPage: 0}
	_, pagination, err := service.ListCertificates(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, 1, pagination.Page)
	assert.Equal(t, 20, pagination.PerPage)
}

func TestAdminService_ListCertificates_MaxPerPage(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Test with excessive per_page (should cap at 100)
	req := ListCertificatesRequest{Page: 1, PerPage: 500}
	_, pagination, err := service.ListCertificates(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, 100, pagination.PerPage)
}

func TestAdminService_GetStats_WithData(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create test data
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	account := &entities.ACMEAccount{ID: 1, Status: "valid", CreatedAt: time.Now()}
	require.NoError(t, accountDAO.Save(ctx, account))

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	cert := createTestACMECertificate(t, 1, "test.example.com", "valid")
	require.NoError(t, certDAO.Save(ctx, cert))

	orderDAO, err := service.storageFactory.OrderDAO(1)
	require.NoError(t, err)
	order := &entities.ACMEOrder{
		ID:          1,
		AccountID:   1,
		Status:      "pending",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "example.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	require.NoError(t, orderDAO.Save(ctx, order))

	// Get stats
	stats, err := service.GetStats(ctx)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, stats.TotalCertificates, 1)
	assert.GreaterOrEqual(t, stats.TotalAccounts, 1)
	assert.GreaterOrEqual(t, stats.TotalOrders, 1)
}

func createTestACMECertificate(t *testing.T, id uint64, cn string, status string) *entities.ACMECertificate {
	// Generate test certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &entities.ACMECertificate{
		ID:        id,
		PEM:       string(certPEM),
		Status:    status,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
		CertURL:   "https://example.com/cert/" + serialNumber.String(),
	}
}
