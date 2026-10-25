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
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	"github.com/jeremyhahn/go-xkms/pkg/acme/linter"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

const (
	svidTenant = "tenant-1"
	svidID     = "spiffe://tenant-1/svc/web"
)

// newSVIDRootCA returns a real, in-memory global CA.
func newSVIDRootCA(t *testing.T) *ca.CA {
	t.Helper()
	keyBackend, err := software.NewBackend(&software.Config{KeyStorage: xkmsstorage.NewMemory()})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{Backend: keyBackend, CertStorage: xkmsstorage.NewMemory()})
	require.NoError(t, err)
	certStore, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)

	config := ca.DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "SVID Test Root CA"
	config.Identity[0].Keys[0].KeyType = "CA"
	root, err := ca.NewFromMultiIdentityConfig(&ca.MultiIdentityParams{
		Config:   config,
		KeyStore: backend,
		BackendForStore: func(string, types.StoreType) (xkms.Backend, error) {
			return backend, nil
		},
		RevocationStore: xkmsstorage.NewMemory(),
		CertStore:       certStore,
	})
	require.NoError(t, err)
	require.NoError(t, root.Init(context.Background()))
	concrete, ok := root.(*ca.CA)
	require.True(t, ok)
	return concrete
}

// setupSVIDService returns a service backed by a real global CA, with
// tenant-1 holding its own intermediate CA, name-constrained to its trust
// domain, in KMS. The tenant record itself is the caller's.
func setupSVIDService(t *testing.T, tenantDAO *mockTenantDAOSimple) (*RestService, *x509.Certificate) {
	t.Helper()
	service, _, cleanup := setupTenantCAService(t, tenantDAO)
	t.Cleanup(cleanup)
	root := newSVIDRootCA(t)
	// The private-PKI lint set admits the tenant OU[0] every tenant
	// certificate carries; the SVID issuer adds the SPIFFE URI SAN.
	setCAWithLint(t, service, root, linter.PrivatePKIConfig())

	tenantKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tenantCA, err := root.IssueSubordinateCA(context.Background(), &ca.SubordinateCARequest{
		Subject:   pkix.Name{CommonName: svidTenant + " Tenant CA"},
		PublicKey: tenantKey.Public(),
		NameConstraints: &ca.NameConstraints{
			Critical:            true,
			PermittedURIDomains: []string{svidTenant},
		},
	})
	require.NoError(t, err)

	purposeKey := svidTenant + "-" + string(kms.KeyPurposeTenantIntermediateCA)
	service.kmsService = &mockKMSService90{
		signers:      map[string]crypto.Signer{purposeKey: tenantKey},
		certificates: map[string][]byte{purposeKey: tenantCA.Raw},
	}
	return service, tenantCA
}

// tenantWithCA is tenant-1 with its own active intermediate CA.
func tenantWithCA() *entities.Tenant {
	return &entities.Tenant{
		ID:              svidTenant,
		Status:          entities.TenantStatusActive,
		IntermediateCAs: []*entities.TenantIntermediateCA{{ID: "ca1", Status: entities.CAStatusActive}},
	}
}

// svidAccount creates an account bound to tenantID ("" for none).
func svidAccount(t *testing.T, service *RestService, tenantID string) (*TestKey, *entities.ACMEAccount) {
	t.Helper()
	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	account.TenantID = tenantID
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)
	require.NoError(t, accountDAO.Save(context.Background(), account))
	return key, account
}

func postNewOrder(t *testing.T, service *RestService, key *TestKey, account *entities.ACMEAccount, payload NewOrderRequest) *httptest.ResponseRecorder {
	t.Helper()
	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-order", payload, true, account.ID)
	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)
	return resp
}

func svidOrderRequest(id string) NewOrderRequest {
	return NewOrderRequest{
		Profile:     ca.ProfileNameX509SVID,
		Identifiers: []entities.ACMEIdentifier{{Type: common.AuthzTypeSPIFFE, Value: id}},
	}
}

// postFinalize finalizes order orderID with a CSR built from template.
func postFinalize(t *testing.T, service *RestService, key *TestKey, account *entities.ACMEAccount, orderID uint64, template *x509.CertificateRequest) *httptest.ResponseRecorder {
	t.Helper()
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}
	url := fmt.Sprintf("%s/acme/order/%d/finalize", service.baseRESTURI, orderID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", orderID)})
	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)
	return resp
}

// orderIDFromLocation reads the order ID from a newOrder Location header.
func orderIDFromLocation(t *testing.T, resp *httptest.ResponseRecorder) uint64 {
	t.Helper()
	location := resp.Header().Get("Location")
	var id uint64
	_, err := fmt.Sscanf(location[strings.LastIndex(location, "/")+1:], "%d", &id)
	require.NoError(t, err)
	return id
}

// issuedLeaf reads back the leaf certificate a valid order delivered.
func issuedLeaf(t *testing.T, service *RestService, order *entities.ACMEOrder) *x509.Certificate {
	t.Helper()
	serial := order.Certificate[strings.LastIndex(order.Certificate, "/")+1:]
	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	stored, err := certDAO.Get(context.Background(), (&entities.ACMECertificate{Serial: serial}).EntityID())
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(stored.PEM))
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return leaf
}

func TestDirectoryHandler_ListsX509SVIDProfile(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	resp := httptest.NewRecorder()
	service.DirectoryHandler(resp, httptest.NewRequest(http.MethodGet, "/acme/directory", nil))

	require.Equal(t, http.StatusOK, resp.Code)
	var directory common.Directory
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&directory))
	assert.Contains(t, directory.Meta.Profiles, ca.ProfileNameX509SVID)
}

func TestX509SVIDOrder_IssuesTenantSVID(t *testing.T) {
	tenantDAO := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{svidTenant: tenantWithCA()}}
	service, tenantCA := setupSVIDService(t, tenantDAO)
	key, account := svidAccount(t, service, svidTenant)

	resp := postNewOrder(t, service, key, account, svidOrderRequest(svidID))
	require.Equal(t, http.StatusCreated, resp.Code, resp.Body.String())
	var created struct {
		Status         string   `json:"status"`
		Profile        string   `json:"profile"`
		Authorizations []string `json:"authorizations"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	assert.Equal(t, common.StatusReady, created.Status, "a tenant-bound SVID order needs no challenge")
	assert.Equal(t, ca.ProfileNameX509SVID, created.Profile)
	require.Len(t, created.Authorizations, 1)

	orderID := orderIDFromLocation(t, resp)
	resp = postFinalize(t, service, key, account, orderID, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "web"},
	})
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	order, err := orderDAO.Get(context.Background(), orderID)
	require.NoError(t, err)
	require.Equal(t, common.StatusValid, order.Status)

	leaf := issuedLeaf(t, service, order)
	require.Len(t, leaf.URIs, 1)
	assert.Equal(t, svidID, leaf.URIs[0].String())
	require.NotEmpty(t, leaf.Subject.OrganizationalUnit)
	assert.Equal(t, svidTenant, leaf.Subject.OrganizationalUnit[0])
	assert.Empty(t, leaf.DNSNames)
	require.NoError(t, leaf.CheckSignatureFrom(tenantCA), "the SVID is signed by the tenant's own CA")
}

func TestX509SVIDOrder_Refusals(t *testing.T) {
	tests := []struct {
		name       string
		tenants    map[string]*entities.Tenant
		accountTID string
		request    NewOrderRequest
		errType    string
		status     int
	}{
		{
			name:       "identifier in another tenant",
			tenants:    map[string]*entities.Tenant{svidTenant: tenantWithCA()},
			accountTID: svidTenant,
			request:    svidOrderRequest("spiffe://tenant-2/svc/web"),
			errType:    common.ErrTypeUnauthorized,
			status:     http.StatusUnauthorized,
		},
		{
			name:       "account not bound to a tenant",
			tenants:    map[string]*entities.Tenant{svidTenant: tenantWithCA()},
			accountTID: "",
			request:    svidOrderRequest(svidID),
			errType:    common.ErrTypeUnauthorized,
			status:     http.StatusUnauthorized,
		},
		{
			name: "tenant without its own CA",
			tenants: map[string]*entities.Tenant{
				svidTenant: {ID: svidTenant, Status: entities.TenantStatusActive},
			},
			accountTID: svidTenant,
			request:    svidOrderRequest(svidID),
			errType:    common.ErrTypeUnauthorized,
			status:     http.StatusUnauthorized,
		},
		{
			name:       "unknown profile",
			tenants:    map[string]*entities.Tenant{svidTenant: tenantWithCA()},
			accountTID: svidTenant,
			request: NewOrderRequest{
				Profile:     "x509-unknown",
				Identifiers: []entities.ACMEIdentifier{{Type: common.AuthzTypeDNS, Value: "example.com"}},
			},
			errType: common.ErrTypeInvalidProfile,
			status:  http.StatusBadRequest,
		},
		{
			name:       "user kind",
			tenants:    map[string]*entities.Tenant{svidTenant: tenantWithCA()},
			accountTID: svidTenant,
			request:    svidOrderRequest("spiffe://tenant-1/user/alice"),
			errType:    common.ErrTypeRejectedIdentifier,
			status:     http.StatusForbidden,
		},
		{
			name:       "spiffe identifier without the profile",
			tenants:    map[string]*entities.Tenant{svidTenant: tenantWithCA()},
			accountTID: svidTenant,
			request: NewOrderRequest{
				Identifiers: []entities.ACMEIdentifier{{Type: common.AuthzTypeSPIFFE, Value: svidID}},
			},
			errType: common.ErrTypeUnsupportedIdentifier,
			status:  http.StatusBadRequest,
		},
		{
			name:       "dns identifier under the profile",
			tenants:    map[string]*entities.Tenant{svidTenant: tenantWithCA()},
			accountTID: svidTenant,
			request: NewOrderRequest{
				Profile:     ca.ProfileNameX509SVID,
				Identifiers: []entities.ACMEIdentifier{{Type: common.AuthzTypeDNS, Value: "example.com"}},
			},
			errType: common.ErrTypeMalformedError,
			status:  http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _ := setupSVIDService(t, &mockTenantDAOSimple{tenants: tt.tenants})
			key, account := svidAccount(t, service, tt.accountTID)

			resp := postNewOrder(t, service, key, account, tt.request)

			assertErrorType(t, resp, tt.errType, tt.status)
		})
	}
}

func TestX509SVIDOrder_FinalizeRefusesOtherNames(t *testing.T) {
	tenantDAO := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{svidTenant: tenantWithCA()}}
	service, _ := setupSVIDService(t, tenantDAO)
	key, account := svidAccount(t, service, svidTenant)

	resp := postNewOrder(t, service, key, account, svidOrderRequest(svidID))
	require.Equal(t, http.StatusCreated, resp.Code, resp.Body.String())
	orderID := orderIDFromLocation(t, resp)

	resp = postFinalize(t, service, key, account, orderID, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "web"},
		DNSNames: []string{"web.example.com"},
	})

	assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	order, err := orderDAO.Get(context.Background(), orderID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusReady, order.Status, "a refused CSR leaves the order ready")
}

func TestX509SVIDOrder_FinalizeRefusesTenantThatLostItsCA(t *testing.T) {
	tenant := tenantWithCA()
	tenantDAO := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{svidTenant: tenant}}
	service, _ := setupSVIDService(t, tenantDAO)
	key, account := svidAccount(t, service, svidTenant)

	resp := postNewOrder(t, service, key, account, svidOrderRequest(svidID))
	require.Equal(t, http.StatusCreated, resp.Code, resp.Body.String())
	orderID := orderIDFromLocation(t, resp)

	// The tenant falls back to the global CA between order and finalize.
	tenant.IntermediateCAs = nil

	resp = postFinalize(t, service, key, account, orderID, &x509.CertificateRequest{})

	assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	order, err := orderDAO.Get(context.Background(), orderID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusInvalid, order.Status)
	assert.Empty(t, order.Certificate)
}

func TestSVIDIdentity(t *testing.T) {
	bound := &entities.ACMEAccount{TenantID: svidTenant}
	spiffeID := func(value string) []entities.ACMEIdentifier {
		return []entities.ACMEIdentifier{{Type: common.AuthzTypeSPIFFE, Value: value}}
	}

	id, err := svidIdentity(bound, spiffeID(svidID))
	require.NoError(t, err)
	assert.Equal(t, svidTenant, id.TenantID)
	assert.Equal(t, "web", id.Name)

	tests := []struct {
		name        string
		account     *entities.ACMEAccount
		identifiers []entities.ACMEIdentifier
		want        error
	}{
		{"unbound account", &entities.ACMEAccount{}, spiffeID(svidID), ErrSVIDAccountNotTenantBound},
		{"no identifier", bound, nil, ErrSVIDIdentifierRequired},
		{"two identifiers", bound, append(spiffeID(svidID), spiffeID("spiffe://tenant-1/svc/api")...), ErrSVIDIdentifierRequired},
		{"not a tenant path", bound, spiffeID("spiffe://tenant-1/web"), ErrSVIDIdentifierInvalid},
		{"invalid tenant", bound, spiffeID("spiffe://Tenant-1/svc/web"), ErrSVIDIdentifierInvalid},
		{"not canonical", bound, spiffeID("spiffe://tenant-1/svc/web?x=1"), ErrSVIDIdentifierInvalid},
		{"user kind", bound, spiffeID("spiffe://tenant-1/user/web"), ErrSVIDKindNotService},
		{"other tenant", bound, spiffeID("spiffe://tenant-2/svc/web"), ErrSVIDOtherTenant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svidIdentity(tt.account, tt.identifiers)
			assert.True(t, errors.Is(err, tt.want), "got %v, want %v", err, tt.want)
		})
	}
}
