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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock implementations (Simple suffix to avoid conflicts)
// =============================================================================

type mockTenantAwareFactorySimple struct {
	storage.Factory
	tenantDAO    qrdbsdk.GenericDAO[*entities.Tenant]
	tenantDAOErr error
}

func (m *mockTenantAwareFactorySimple) TenantDAO() (qrdbsdk.GenericDAO[*entities.Tenant], error) {
	if m.tenantDAOErr != nil {
		return nil, m.tenantDAOErr
	}
	return m.tenantDAO, nil
}

func (m *mockTenantAwareFactorySimple) ForTenant(tenantID string) (storage.Factory, error) {
	return m, nil
}

func (m *mockTenantAwareFactorySimple) GetTenantID() string {
	return ""
}

func (m *mockTenantAwareFactorySimple) TenantAccountDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return m.Factory.AccountDAO()
}

func (m *mockTenantAwareFactorySimple) TenantOrderDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return m.Factory.OrderDAO(accountID)
}

func (m *mockTenantAwareFactorySimple) TenantAuthorizationDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.Factory.AuthorizationDAO(accountID)
}

func (m *mockTenantAwareFactorySimple) TenantChallengeDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.Factory.ChallengeDAO(accountID)
}

func (m *mockTenantAwareFactorySimple) TenantCertificateDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.Factory.CertificateDAO()
}

func (m *mockTenantAwareFactorySimple) TenantExternalAccountBindingDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.Factory.ExternalAccountBindingDAO()
}

type mockTenantDAOSimple struct {
	tenants map[string]*entities.Tenant
	getErr  error
}

func (m *mockTenantDAOSimple) Save(_ context.Context, tenant *entities.Tenant) error {
	if m.tenants == nil {
		m.tenants = make(map[string]*entities.Tenant)
	}
	m.tenants[tenant.ID] = tenant
	return nil
}

func (m *mockTenantDAOSimple) SaveWithCondition(_ context.Context, _ *entities.Tenant, _ qrdbsdk.Condition) error {
	panic("not implemented")
}

func (m *mockTenantDAOSimple) SaveIfAbsent(_ context.Context, _ *entities.Tenant) (bool, error) {
	panic("not implemented")
}

func (m *mockTenantDAOSimple) Get(_ context.Context, id uint64) (*entities.Tenant, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	for _, t := range m.tenants {
		if t.EntityID() == id {
			return t, nil
		}
	}
	return nil, ErrTenantNotFound
}

func (m *mockTenantDAOSimple) Delete(_ context.Context, tenant *entities.Tenant) error {
	delete(m.tenants, tenant.ID)
	return nil
}

func (m *mockTenantDAOSimple) Count(_ context.Context) (int, error) {
	return len(m.tenants), nil
}

func (m *mockTenantDAOSimple) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.Tenant], error) {
	panic("not implemented")
}

func (m *mockTenantDAOSimple) ForEachPage(_ context.Context, _ qrdbsdk.PageQuery, _ qrdbsdk.PagerFunc[*entities.Tenant]) error {
	panic("not implemented")
}

func (m *mockTenantDAOSimple) EntityType() string {
	return "tenants"
}

func (m *mockTenantDAOSimple) QueryByIndex(_ context.Context, fieldName string, value interface{}) ([]*entities.Tenant, error) {
	if fieldName == "ID" {
		id, ok := value.(string)
		if !ok {
			return nil, nil
		}
		if t, found := m.tenants[id]; found {
			return []*entities.Tenant{t}, nil
		}
	}
	return nil, nil
}

func (m *mockTenantDAOSimple) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.Tenant, error) {
	return nil, nil
}

func (m *mockTenantDAOSimple) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.Tenant, error) {
	return nil, nil
}

func (m *mockTenantDAOSimple) QueryOneByIndex(_ context.Context, fieldName string, value interface{}) (*entities.Tenant, error) {
	if fieldName == "ID" {
		id, ok := value.(string)
		if !ok {
			return nil, ErrTenantNotFound
		}
		if m.getErr != nil {
			return nil, m.getErr
		}
		if t, found := m.tenants[id]; found {
			return t, nil
		}
	}
	return nil, ErrTenantNotFound
}

func (m *mockTenantDAOSimple) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.Tenant, error) {
	panic("not implemented")
}

func (m *mockTenantDAOSimple) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.Tenant], error) {
	panic("not implemented")
}

func (m *mockTenantDAOSimple) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (m *mockTenantDAOSimple) Find(_ context.Context) *qrdbsdk.QueryBuilder[*entities.Tenant] {
	panic("not implemented")
}

type mockKMSServiceSimple struct {
	signers      map[string]crypto.Signer
	getSignerErr error
}

func (m *mockKMSServiceSimple) CreateSigningKey(ctx context.Context, tenantID string, purpose kms.KeyPurpose, algorithm string) (*kms.KeyMetadata, error) {
	return &kms.KeyMetadata{KeyID: tenantID + "-" + string(purpose)}, nil
}

func (m *mockKMSServiceSimple) GetSigningKey(ctx context.Context, tenantID string, purpose kms.KeyPurpose) (crypto.Signer, error) {
	if m.getSignerErr != nil {
		return nil, m.getSignerErr
	}
	key := tenantID + "-" + string(purpose)
	if signer, ok := m.signers[key]; ok {
		return signer, nil
	}
	return nil, errors.New("key not found")
}

func (m *mockKMSServiceSimple) ListSigningKeys(ctx context.Context, tenantID string) ([]*kms.KeyMetadata, error) {
	return nil, nil
}

func (m *mockKMSServiceSimple) DeleteSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return nil
}

func (m *mockKMSServiceSimple) EnableSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return nil
}

func (m *mockKMSServiceSimple) DisableSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return nil
}

func (m *mockKMSServiceSimple) StoreCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose, certDER []byte) error {
	return nil
}

func (m *mockKMSServiceSimple) GetCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose) ([]byte, error) {
	return nil, errors.New("not found")
}

func (m *mockKMSServiceSimple) DeleteCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose) error {
	return nil
}

// =============================================================================
// Setup helpers
// =============================================================================

func setupServiceWithTenantFactory(t *testing.T, tenantDAO *mockTenantDAOSimple) (*RestService, func()) {
	tmpDir, err := os.MkdirTemp("", "acme-simple-test-*")
	require.NoError(t, err)

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)

	factory, err := objstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	tenantAwareFactory := &mockTenantAwareFactorySimple{
		Factory:   factory,
		tenantDAO: tenantDAO,
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		CAAIdentities:  []string{"acme.test.example.com"},
		ChallengeMap:   make(map[string]common.ChallengeVerifierFunc),
		Logger:         logger,
		StorageFactory: tenantAwareFactory,
		TermsOfService: "https://acme.test.example.com/tos",
	}

	service, err := NewRestService(params)
	require.NoError(t, err)

	return service.(*RestService), func() { _ = os.RemoveAll(tmpDir) }
}

// =============================================================================
// findPCRValue Tests
// =============================================================================

func TestFindPCRValue_EmptyDataSimple(t *testing.T) {
	value, found := findPCRValue(nil, 0)
	assert.False(t, found)
	assert.Nil(t, value)
}

func TestFindPCRValue_InvalidGobSimple(t *testing.T) {
	value, found := findPCRValue([]byte("invalid"), 0)
	assert.False(t, found)
	assert.Nil(t, value)
}

func TestFindPCRValue_ValidBanksSimple(t *testing.T) {
	banks := []xkmssdk.PCRBank{
		{Algorithm: "sha256", PCRs: []xkmssdk.PCR{{ID: 0, Value: []byte("pcr0")}, {ID: 7, Value: []byte("pcr7")}}},
	}
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(banks)
	require.NoError(t, err)

	value, found := findPCRValue(buf.Bytes(), 0)
	assert.True(t, found)
	assert.Equal(t, []byte("pcr0"), value)

	value, found = findPCRValue(buf.Bytes(), 7)
	assert.True(t, found)
	assert.Equal(t, []byte("pcr7"), value)

	value, found = findPCRValue(buf.Bytes(), 23)
	assert.False(t, found)
	assert.Nil(t, value)
}

func TestFindPCRValue_SHA256PreferredSimple(t *testing.T) {
	banks := []xkmssdk.PCRBank{
		{Algorithm: "SHA256", PCRs: []xkmssdk.PCR{{ID: 0, Value: []byte("sha256")}}},
		{Algorithm: "sha1", PCRs: []xkmssdk.PCR{{ID: 0, Value: []byte("sha1")}}},
	}
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(banks)
	require.NoError(t, err)

	value, found := findPCRValue(buf.Bytes(), 0)
	assert.True(t, found)
	assert.Equal(t, []byte("sha256"), value)
}

// =============================================================================
// NewPCRValidationHook Tests
// =============================================================================

func TestNewPCRValidationHook_SkipsNonTCGSimple(t *testing.T) {
	hook := NewPCRValidationHook(&PCRPolicy{ExpectedPCRs: map[int][]byte{0: {0x01}}, StrictMode: true})

	err := hook(&PreIssuanceHookContext{IsTCGCSR: false})
	assert.NoError(t, err)

	err = hook(&PreIssuanceHookContext{IsTCGCSR: true, TCGData: nil})
	assert.NoError(t, err)
}

func TestNewPCRValidationHook_StrictMissingDataSimple(t *testing.T) {
	hook := NewPCRValidationHook(&PCRPolicy{ExpectedPCRs: map[int][]byte{0: {0x01}}, StrictMode: true})

	err := hook(&PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData:  &TCGEnrollmentData{ProdCaData: nil},
	})
	assert.ErrorIs(t, err, ErrAttestationDataMissing)
}

// =============================================================================
// validateDeviceAgainstProfile Tests
// =============================================================================

func TestValidateDeviceAgainstProfile_EmptyPCRsSimple(t *testing.T) {
	profile := &DeviceProfile{ExpectedPCRs: nil}
	tcgData := &TCGEnrollmentData{}
	err := validateDeviceAgainstProfile(tcgData, profile)
	assert.NoError(t, err)
}

func TestValidateDeviceAgainstProfile_InvalidDataSimple(t *testing.T) {
	profile := &DeviceProfile{ExpectedPCRs: map[int][]byte{0: {0x01}}}
	tcgData := &TCGEnrollmentData{ProdCaData: []byte("invalid")}
	err := validateDeviceAgainstProfile(tcgData, profile)
	assert.Error(t, err)
}

// =============================================================================
// resolveTenantSigningCA Tests
// =============================================================================

func TestResolveTenantSigningCA_DAOErrorSimple(t *testing.T) {
	dao := &mockTenantDAOSimple{tenants: make(map[string]*entities.Tenant), getErr: errors.New("db error")}
	service, cleanup := setupServiceWithTenantFactory(t, dao)
	defer cleanup()

	result, err := service.resolveTenantSigningCA(context.Background(), &entities.ACMEAccount{ID: 1, TenantID: "t1"}, "")
	assert.ErrorIs(t, err, ErrTenantNotFound)
	assert.Nil(t, result)
}

func TestResolveTenantSigningCA_TenantInactiveSimple(t *testing.T) {
	dao := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{"t1": {ID: "t1", Status: entities.TenantStatusSuspended}}}
	service, cleanup := setupServiceWithTenantFactory(t, dao)
	defer cleanup()

	result, err := service.resolveTenantSigningCA(context.Background(), &entities.ACMEAccount{ID: 1, TenantID: "t1"}, "")
	assert.ErrorIs(t, err, ErrTenantInactive)
	assert.Nil(t, result)
}

func TestResolveTenantSigningCA_WithIntermediateSimple(t *testing.T) {
	dao := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{
		"t1": {ID: "t1", Status: entities.TenantStatusActive, IntermediateCAs: []*entities.TenantIntermediateCA{{ID: "ca1", Status: entities.CAStatusActive}}},
	}}
	service, cleanup := setupServiceWithTenantFactory(t, dao)
	defer cleanup()

	result, err := service.resolveTenantSigningCA(context.Background(), &entities.ACMEAccount{ID: 1, TenantID: "t1"}, "")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, entities.SigningCATypeIntermediate, result.Type)
}

func TestResolveTenantSigningCA_FallbackGlobalSimple(t *testing.T) {
	dao := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{"t1": {ID: "t1", Status: entities.TenantStatusActive}}}
	service, cleanup := setupServiceWithTenantFactory(t, dao)
	defer cleanup()

	result, err := service.resolveTenantSigningCA(context.Background(), &entities.ACMEAccount{ID: 1, TenantID: "t1"}, "")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.UseGlobalDefault)
}

// =============================================================================
// getTenantCASigner Tests
// =============================================================================

func TestGetTenantCASigner_NilKMSSimple(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	result, err := service.getTenantCASigner(context.Background(), &entities.SigningCAInfo{Type: entities.SigningCATypeIntermediate, TenantID: "t1"})
	assert.ErrorIs(t, err, ErrTenantSignerUnavailable)
	assert.Nil(t, result)
}

func TestGetTenantCASigner_UnknownTypeSimple(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()
	service.kmsService = &mockKMSServiceSimple{signers: make(map[string]crypto.Signer)}

	result, err := service.getTenantCASigner(context.Background(), &entities.SigningCAInfo{Type: "unknown", TenantID: "t1"})
	assert.ErrorIs(t, err, ErrTenantCATypeUnsupported)
	assert.Nil(t, result)
}

func TestGetTenantCASigner_KMSErrorSimple(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()
	service.kmsService = &mockKMSServiceSimple{signers: make(map[string]crypto.Signer), getSignerErr: errors.New("kms fail")}

	result, err := service.getTenantCASigner(context.Background(), &entities.SigningCAInfo{Type: entities.SigningCATypeIntermediate, TenantID: "t1"})
	assert.ErrorIs(t, err, ErrTenantSignerUnavailable)
	assert.Nil(t, result)
}

func TestGetTenantCASigner_IntermediateSuccessSimple(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	service.kmsService = &mockKMSServiceSimple{signers: map[string]crypto.Signer{
		"t1-" + string(kms.KeyPurposeTenantIntermediateCA): key,
	}}

	result, err := service.getTenantCASigner(context.Background(), &entities.SigningCAInfo{Type: entities.SigningCATypeIntermediate, TenantID: "t1"})
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGetTenantCASigner_RootSuccessSimple(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	service.kmsService = &mockKMSServiceSimple{signers: map[string]crypto.Signer{
		"t1-" + string(kms.KeyPurposeTenantRootCA): key,
	}}

	result, err := service.getTenantCASigner(context.Background(), &entities.SigningCAInfo{Type: entities.SigningCATypeRoot, TenantID: "t1"})
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

// =============================================================================
// resolveTenantComplianceConfig Tests
// =============================================================================

func TestResolveTenantComplianceConfig_NotFoundSimple(t *testing.T) {
	dao := &mockTenantDAOSimple{tenants: make(map[string]*entities.Tenant)}
	service, cleanup := setupServiceWithTenantFactory(t, dao)
	defer cleanup()
	service.globalComplianceConfig = &GlobalComplianceConfig{ComplianceConfig: ComplianceConfig{Enabled: true}}

	result := service.resolveTenantComplianceConfig(context.Background(), &entities.ACMEAccount{ID: 1, TenantID: "t1"})
	assert.NotNil(t, result)
	assert.True(t, result.Enabled)
}

func TestResolveTenantComplianceConfig_TenantConfigSimple(t *testing.T) {
	dao := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{
		"t1": {ID: "t1", Status: entities.TenantStatusActive, Settings: &entities.TenantSettings{
			ComplianceConfig: &entities.ComplianceConfig{Enabled: true, RequireSignedReport: true},
		}},
	}}
	service, cleanup := setupServiceWithTenantFactory(t, dao)
	defer cleanup()
	service.globalComplianceConfig = &GlobalComplianceConfig{ComplianceConfig: ComplianceConfig{Enabled: false}}

	result := service.resolveTenantComplianceConfig(context.Background(), &entities.ACMEAccount{ID: 1, TenantID: "t1"})
	assert.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.True(t, result.RequireSignedReport)
}

func TestResolveTenantComplianceConfig_EnforcedGlobalSimple(t *testing.T) {
	dao := &mockTenantDAOSimple{tenants: map[string]*entities.Tenant{
		"t1": {ID: "t1", Status: entities.TenantStatusActive, Settings: &entities.TenantSettings{
			ComplianceConfig: &entities.ComplianceConfig{Enabled: false},
		}},
	}}
	service, cleanup := setupServiceWithTenantFactory(t, dao)
	defer cleanup()
	service.globalComplianceConfig = &GlobalComplianceConfig{ComplianceConfig: ComplianceConfig{Enabled: true}, Enforce: true}

	result := service.resolveTenantComplianceConfig(context.Background(), &entities.ACMEAccount{ID: 1, TenantID: "t1"})
	assert.NotNil(t, result)
	assert.True(t, result.Enabled)
}

// =============================================================================
// validateEventLogAgainstPCRs Tests
// =============================================================================

func TestValidateEventLogAgainstPCRs_EmptySimple(t *testing.T) {
	assert.NoError(t, validateEventLogAgainstPCRs(nil, []byte("data")))
	assert.NoError(t, validateEventLogAgainstPCRs([]byte("data"), nil))
	assert.NoError(t, validateEventLogAgainstPCRs(nil, nil))
}

// =============================================================================
// KeyChangeHandler Tests
// =============================================================================

func TestKeyChangeHandler_SameKeySimple(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	payload := createKeyChangePayloadSimple(t, service, account, key, key)

	url := service.baseRESTURI + "/acme/key-change"
	req := createJWSRequest(t, service, key, url, json.RawMessage(payload), true, account.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestKeyChangeHandler_ConflictSimple(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	_ = createTestAccount(t, service, key2)

	payload := createKeyChangePayloadSimple(t, service, account1, key1, key2)

	url := service.baseRESTURI + "/acme/key-change"
	req := createJWSRequest(t, service, key1, url, json.RawMessage(payload), true, account1.ID)

	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)
	assert.Equal(t, http.StatusConflict, resp.Code)
}

func createKeyChangePayloadSimple(t *testing.T, service *RestService, account *entities.ACMEAccount, oldKey, newKey *TestKey) []byte {
	oldKeyJWK := &jose.JSONWebKey{Key: oldKey.PublicKey}
	oldKeyJSON, _ := oldKeyJWK.MarshalJSON()
	var oldKeyMap map[string]interface{}
	json.Unmarshal(oldKeyJSON, &oldKeyMap)

	innerPayload := map[string]interface{}{"account": account.URL, "oldKey": oldKeyMap}
	innerPayloadBytes, _ := json.Marshal(innerPayload)

	innerSignerOpts := &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]interface{}{"url": service.baseRESTURI + "/acme/key-change"}}
	innerSignerOpts.EmbedJWK = true

	innerSigner, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: newKey.PrivateKey}, innerSignerOpts)
	innerJWS, _ := innerSigner.Sign(innerPayloadBytes)

	return []byte(innerJWS.FullSerialize())
}

// =============================================================================
// NewAccountHandler Tests
// =============================================================================

func TestNewAccountHandler_DAOErrorSimple(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "acme-dao-test-*")
	defer os.RemoveAll(tmpDir)

	kv, _ := kvadapter.New(xkmsstorage.NewMemory())

	factory, _ := objstore.NewFactoryFromKVStore(kv)
	failingFactory := &failingAccountDAOFactorySimple{Factory: factory}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		CAAIdentities:  []string{"acme.test.example.com"},
		ChallengeMap:   make(map[string]common.ChallengeVerifierFunc),
		Logger:         logger,
		StorageFactory: failingFactory,
		TermsOfService: "https://acme.test.example.com/tos",
	}

	service, _ := NewRestService(params)

	key := generateTestKey(t)
	payload := NewAccountRequest{Contact: []string{"mailto:test@example.com"}, TermsOfServiceAgreed: true}

	url := params.BaseRESTURI + "/acme/new-account"
	nonce, _ := common.GenerateNonce(nonceSize)
	service.(*RestService).nonceStore.Add(nonce)

	signerOpts := &jose.SignerOptions{NonceSource: &staticNonceSource{nonce: nonce}, ExtraHeaders: map[jose.HeaderKey]interface{}{"url": url}}
	signerOpts.EmbedJWK = true
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key.PrivateKey}, signerOpts)
	payloadBytes, _ := json.Marshal(payload)
	jws, _ := signer.Sign(payloadBytes)

	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(jws.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)
	assert.Equal(t, http.StatusInternalServerError, resp.Code)
}

type failingAccountDAOFactorySimple struct {
	storage.Factory
}

func (f *failingAccountDAOFactorySimple) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return nil, errors.New("forced DAO failure")
}

// =============================================================================
// OrderFinalizeHandler Tests
// =============================================================================

func TestOrderFinalizeHandler_UnauthorizedSimple(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	account2 := createTestAccount(t, service, key2)

	ctx := context.Background()
	orderDAO, _ := service.storageFactory.OrderDAO(account1.ID)
	order := &entities.ACMEOrder{ID: 99999, AccountID: account1.ID, Status: common.StatusReady, Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "example.com"}}}
	orderDAO.Save(ctx, order)

	payload := OrderFinalizeRequest{CSR: "test-csr"}
	url := service.baseRESTURI + "/acme/order/99999/finalize"
	req := createJWSRequest(t, service, key2, url, payload, true, account2.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "99999"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)
	// Order lookup uses the authenticated account's ID, so order won't be found (400)
	// rather than being found and access denied (401)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}
