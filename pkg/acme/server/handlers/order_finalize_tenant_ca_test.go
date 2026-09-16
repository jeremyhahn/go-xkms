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
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the H3 fail-closed fix: tenant-bound certificate issuance must
// never fall back to the global CA when the tenant's own signing CA cannot
// be resolved, and a tenant signer must never be paired with a mismatched
// issuer certificate.

// setupTenantCAService builds a RestService whose storage factory is tenant
// aware (backed by tenantDAO) and whose CA is the MockCAForFinalize, so the
// full OrderFinalizeHandler flow can be exercised for tenant-bound accounts.
func setupTenantCAService(t *testing.T, tenantDAO *mockTenantDAOSimple) (*RestService, *MockCAForFinalize, func()) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	service.storageFactory = &mockTenantAwareFactory90{
		Factory:   service.storageFactory,
		tenantDAO: tenantDAO,
	}
	return service, mockCA, cleanup
}

// finalizeTenantOrder drives a full finalize request for a DNS identifier
// order and returns the HTTP response together with the order as persisted
// after the handler runs.
func finalizeTenantOrder(t *testing.T, service *RestService, key *TestKey, account *entities.ACMEAccount) (*httptest.ResponseRecorder, *entities.ACMEOrder) {
	ctx := context.Background()

	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	require.NoError(t, orderDAO.Save(ctx, order))

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	persisted, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)

	return resp, persisted
}

// selfSignedCertDER creates a minimal self-signed certificate DER for the
// given key, for use as a (possibly mismatched) tenant issuer certificate.
func selfSignedCertDER(t *testing.T, key *ecdsa.PrivateKey) []byte {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tenant issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	return der
}

func TestOrderFinalizeHandler_TenantLookupFailure_RejectsIssuance(t *testing.T) {
	tenantDAO := &mockTenantDAOSimple{getErr: errors.New("tenant store unavailable")}
	service, mockCA, cleanup := setupTenantCAService(t, tenantDAO)
	defer cleanup()

	// Confirm the typed error resolveTenantSigningCA surfaces, independent
	// of the HTTP-level assertions below.
	_, resolveErr := service.resolveTenantSigningCA(context.Background(),
		&entities.ACMEAccount{ID: 1, TenantID: "tenant-1"}, entities.CAPurposeGeneral)
	assert.ErrorIs(t, resolveErr, ErrTenantNotFound)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	account.TenantID = "tenant-1"
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	require.NoError(t, accountDAO.Save(context.Background(), account))

	resp, order := finalizeTenantOrder(t, service, key, account)

	require.Equal(t, http.StatusInternalServerError, resp.Code)
	assert.Equal(t, common.StatusInvalid, order.Status)
	require.NotNil(t, order.Error)
	assert.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeServerInternal, order.Error.Type)
	assert.False(t, mockCA.shouldFailSignCSR, "sanity: CA was never told to fail; it must simply never be reached")
}

func TestOrderFinalizeHandler_SuspendedTenant_Rejected(t *testing.T) {
	tenantDAO := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{
		"tenant-1": {ID: "tenant-1", Status: entities.TenantStatusSuspended},
	}}
	service, _, cleanup := setupTenantCAService(t, tenantDAO)
	defer cleanup()

	_, resolveErr := service.resolveTenantSigningCA(context.Background(),
		&entities.ACMEAccount{ID: 1, TenantID: "tenant-1"}, entities.CAPurposeGeneral)
	assert.ErrorIs(t, resolveErr, ErrTenantInactive)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	account.TenantID = "tenant-1"
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	require.NoError(t, accountDAO.Save(context.Background(), account))

	resp, order := finalizeTenantOrder(t, service, key, account)

	require.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Equal(t, common.StatusInvalid, order.Status)
	require.NotNil(t, order.Error)
	assert.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeUnauthorized, order.Error.Type)
}

func TestOrderFinalizeHandler_TenantSignerFailure_Rejected(t *testing.T) {
	tenantDAO := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{
		"tenant-1": {
			ID:     "tenant-1",
			Status: entities.TenantStatusActive,
			IntermediateCAs: []*entities.TenantIntermediateCA{
				{ID: "ca1", Status: entities.CAStatusActive},
			},
		},
	}}
	service, _, cleanup := setupTenantCAService(t, tenantDAO)
	defer cleanup()

	service.kmsService = &mockKMSService90{getSignerErr: errors.New("kms unreachable")}

	_, signerErr := service.getTenantCASigner(context.Background(), &entities.SigningCAInfo{
		Type: entities.SigningCATypeIntermediate, TenantID: "tenant-1",
	})
	assert.ErrorIs(t, signerErr, ErrTenantSignerUnavailable)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	account.TenantID = "tenant-1"
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	require.NoError(t, accountDAO.Save(context.Background(), account))

	resp, order := finalizeTenantOrder(t, service, key, account)

	require.Equal(t, http.StatusInternalServerError, resp.Code)
	assert.Equal(t, common.StatusInvalid, order.Status)
	require.NotNil(t, order.Error)
	assert.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeServerInternal, order.Error.Type)
}

func TestGetTenantCASigner_UnknownCAType_Rejects(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()
	service.kmsService = &mockKMSService90{}

	signer, err := service.getTenantCASigner(context.Background(), &entities.SigningCAInfo{
		Type: "bogus-type", TenantID: "tenant-1",
	})
	assert.ErrorIs(t, err, ErrTenantCATypeUnsupported)
	assert.Nil(t, signer)
}

func TestOrderFinalizeHandler_TenantExplicitGlobalDefault_StillIssues(t *testing.T) {
	// A tenant with no root or intermediate CA configured at all resolves
	// to SigningCAInfo.UseGlobalDefault == true - the tenant's own explicit
	// configuration to use the global CA, not a resolution failure - and
	// issuance must proceed normally through the global CA.
	tenantDAO := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{
		"tenant-1": {ID: "tenant-1", Status: entities.TenantStatusActive},
	}}
	service, mockCA, cleanup := setupTenantCAService(t, tenantDAO)
	defer cleanup()
	mockCA.returnedSerialNum = big.NewInt(424242)

	signingCAInfo, resolveErr := service.resolveTenantSigningCA(context.Background(),
		&entities.ACMEAccount{ID: 1, TenantID: "tenant-1"}, entities.CAPurposeGeneral)
	require.NoError(t, resolveErr)
	require.NotNil(t, signingCAInfo)
	assert.True(t, signingCAInfo.UseGlobalDefault)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	account.TenantID = "tenant-1"
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	require.NoError(t, accountDAO.Save(context.Background(), account))

	resp, order := finalizeTenantOrder(t, service, key, account)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, common.StatusValid, order.Status)
	assert.Nil(t, order.Error)

	var orderResp entities.ACMEOrder
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&orderResp))
	assert.NotEmpty(t, orderResp.Certificate)
}

func TestOrderFinalizeHandler_SignerIssuerMismatch_Refused(t *testing.T) {
	tenantDAO := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{
		"tenant-1": {
			ID:     "tenant-1",
			Status: entities.TenantStatusActive,
			IntermediateCAs: []*entities.TenantIntermediateCA{
				{ID: "ca1", Status: entities.CAStatusActive},
			},
		},
	}}
	service, _, cleanup := setupTenantCAService(t, tenantDAO)
	defer cleanup()

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	purposeKey := "tenant-1-" + string(kms.KeyPurposeTenantIntermediateCA)
	mockKMS := &mockKMSService90{
		signers:      map[string]crypto.Signer{purposeKey: signerKey},
		certificates: map[string][]byte{purposeKey: selfSignedCertDER(t, otherKey)},
	}
	service.kmsService = mockKMS

	// Prove the mismatch directly: the tenant signer's public key must not
	// match the issuer certificate KMS handed back for the same tenant/purpose.
	signingCAInfo := &entities.SigningCAInfo{Type: entities.SigningCATypeIntermediate, TenantID: "tenant-1"}
	signer, signerErr := service.getTenantCASigner(context.Background(), signingCAInfo)
	require.NoError(t, signerErr)
	issuerCert, issuerErr := service.tenantIssuerCertificate(context.Background(), signingCAInfo)
	require.NoError(t, issuerErr)
	assert.False(t, signerMatchesIssuer(signer, issuerCert))

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	account.TenantID = "tenant-1"
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	require.NoError(t, accountDAO.Save(context.Background(), account))

	resp, order := finalizeTenantOrder(t, service, key, account)

	require.Equal(t, http.StatusInternalServerError, resp.Code)
	assert.Equal(t, common.StatusInvalid, order.Status)
	require.NotNil(t, order.Error)
	assert.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeServerInternal, order.Error.Type)
}
