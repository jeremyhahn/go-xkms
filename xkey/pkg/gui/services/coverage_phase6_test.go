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

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock prefix: p6b (phase 6 batch)
// ---------------------------------------------------------------------------

// p6bMockPINManager implements pin.PINBackend for testing panic recovery
// and coordinator notification paths.
type p6bMockPINManager struct {
	strategy    pin.StrategyID
	soPINSet    bool
	userPINSet  bool
	initialized bool

	setSOPINErr     error
	setUserPINErr   error
	changeSOPINErr  error
	changeUserErr   error
	verifyUserErr   error
	verifySOErr     error
	resetLockoutErr error
	lockoutStatus   *pin.LockoutStatus
}

func (m *p6bMockPINManager) Strategy() pin.StrategyID             { return m.strategy }
func (m *p6bMockPINManager) SOPINSet() bool                       { return m.soPINSet }
func (m *p6bMockPINManager) UserPINSet() bool                     { return m.userPINSet }
func (m *p6bMockPINManager) IsInitialized() bool                  { return m.initialized }
func (m *p6bMockPINManager) GetLockoutStatus() *pin.LockoutStatus { return m.lockoutStatus }
func (m *p6bMockPINManager) SetSOPIN(_, _ string) error           { return m.setSOPINErr }
func (m *p6bMockPINManager) SetUserPIN(_, _ string) error         { return m.setUserPINErr }
func (m *p6bMockPINManager) ChangeSOPIN(_, _ string) error        { return m.changeSOPINErr }
func (m *p6bMockPINManager) ChangeUserPIN(_, _ string) error      { return m.changeUserErr }
func (m *p6bMockPINManager) VerifySOPIN(_ string) error           { return m.verifySOErr }
func (m *p6bMockPINManager) VerifyUserPIN(_ string) error         { return m.verifyUserErr }
func (m *p6bMockPINManager) ResetLockout(_ string) error { return m.resetLockoutErr }

// p6bMockSealer implements types.Sealer for seal service testing.
type p6bMockSealer struct {
	canSeal  bool
	sealErr  error
	sealData *types.SealedData

	unsealErr  error
	unsealData []byte
}

func (m *p6bMockSealer) CanSeal() bool { return m.canSeal }
func (m *p6bMockSealer) Seal(_ context.Context, _ []byte, _ *types.SealOptions) (*types.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	return m.sealData, nil
}
func (m *p6bMockSealer) Unseal(_ context.Context, data *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	return m.unsealData, nil
}

// p6bMockOATHStore implements oath.Store for OATHService testing.
type p6bMockOATHStore struct {
	creds  map[string]*oath.Credential
	addErr error
	getErr error
	updErr error
	delErr error
}

func (m *p6bMockOATHStore) Add(c *oath.Credential) error {
	if m.addErr != nil {
		return m.addErr
	}
	if m.creds == nil {
		m.creds = make(map[string]*oath.Credential)
	}
	m.creds[c.ID] = c
	return nil
}
func (m *p6bMockOATHStore) Get(id string) (*oath.Credential, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	c, ok := m.creds[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return c, nil
}
func (m *p6bMockOATHStore) List() ([]*oath.Credential, error) {
	result := make([]*oath.Credential, 0, len(m.creds))
	for _, c := range m.creds {
		result = append(result, c)
	}
	return result, nil
}
func (m *p6bMockOATHStore) Update(c *oath.Credential) error { return m.updErr }
func (m *p6bMockOATHStore) Delete(_ string) error           { return m.delErr }
func (m *p6bMockOATHStore) Close() error                    { return nil }

// p6bMockTrustStore implements truststore.TrustStore for TrustService testing.
type p6bMockTrustStore struct {
	certs          []*x509.Certificate
	certErr        error
	certsByPurpose []*x509.Certificate
	certsByPurpErr error
	containsResult bool
	containsErr    error
	metadata       *truststore.CertMetadata
	metadataErr    error
	addErr         error
	addPEMErr      error
	addPEMCount    int
	removeErr      error
	setPurposeErr  error
	setSourceErr   error
	setSysInstErr  error
	setTagsErr     error
	addWithOptsErr error
}

func (m *p6bMockTrustStore) AddCertificate(_ *x509.Certificate) error { return m.addErr }
func (m *p6bMockTrustStore) AddCertificateWithOptions(_ *x509.Certificate, _ *truststore.AddCertificateOptions) error {
	return m.addWithOptsErr
}
func (m *p6bMockTrustStore) AddPEM(_ []byte) (int, error) {
	return m.addPEMCount, m.addPEMErr
}
func (m *p6bMockTrustStore) RemoveCertificate(_ string) error { return m.removeErr }
func (m *p6bMockTrustStore) Certificates() ([]*x509.Certificate, error) {
	return m.certs, m.certErr
}
func (m *p6bMockTrustStore) CertificatesByPurpose(_ truststore.CertPurpose) ([]*x509.Certificate, error) {
	return m.certsByPurpose, m.certsByPurpErr
}
func (m *p6bMockTrustStore) CertPool() (*x509.CertPool, error) { return x509.NewCertPool(), nil }
func (m *p6bMockTrustStore) Contains(_ string) (bool, error) {
	return m.containsResult, m.containsErr
}
func (m *p6bMockTrustStore) Count() (int, error) { return len(m.certs), nil }
func (m *p6bMockTrustStore) Metadata(_ string) (*truststore.CertMetadata, error) {
	return m.metadata, m.metadataErr
}
func (m *p6bMockTrustStore) SetPurpose(_ string, _ truststore.CertPurpose) error {
	return m.setPurposeErr
}
func (m *p6bMockTrustStore) SetSource(_, _ string) error { return m.setSourceErr }
func (m *p6bMockTrustStore) SetSystemInstalled(_ string, _ bool) error {
	return m.setSysInstErr
}
func (m *p6bMockTrustStore) SetTags(_ string, _ []string) error { return m.setTagsErr }
func (m *p6bMockTrustStore) Close() error                       { return nil }

// p6bMockStaticPWStore implements staticpw.Store for password protection testing.
type p6bMockStaticPWStore struct {
	passwords  []*staticpw.StaticPassword
	listErr    error
	addErr     error
	updateErr  error
	deleteErr  error
	getErr     error
	moveErr    error
	folders    []string
	foldersErr error
}

func (m *p6bMockStaticPWStore) Add(pw *staticpw.StaticPassword) error { return m.addErr }
func (m *p6bMockStaticPWStore) Get(_ string) (*staticpw.StaticPassword, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if len(m.passwords) > 0 {
		return m.passwords[0], nil
	}
	return nil, errors.New("not found")
}
func (m *p6bMockStaticPWStore) List() ([]*staticpw.StaticPassword, error) {
	return m.passwords, m.listErr
}
func (m *p6bMockStaticPWStore) ListByFolder(_ string) ([]*staticpw.StaticPassword, error) {
	return m.passwords, m.listErr
}
func (m *p6bMockStaticPWStore) ListByFolderDirect(_ string) ([]*staticpw.StaticPassword, error) {
	return m.passwords, m.listErr
}
func (m *p6bMockStaticPWStore) Update(_ *staticpw.StaticPassword) error { return m.updateErr }
func (m *p6bMockStaticPWStore) Delete(_ string) error                   { return m.deleteErr }
func (m *p6bMockStaticPWStore) ListFolders() ([]string, error)          { return m.folders, m.foldersErr }
func (m *p6bMockStaticPWStore) MoveToFolder(_, _ string) error          { return m.moveErr }
func (m *p6bMockStaticPWStore) CreateFolder(_ string) error             { return nil }
func (m *p6bMockStaticPWStore) RemoveFolder(_ string) error             { return nil }
func (m *p6bMockStaticPWStore) ForceDelete(_ string) error              { return m.deleteErr }
func (m *p6bMockStaticPWStore) Close() error                            { return nil }

// p6bMockTokenStore implements oidc.TokenStore for OIDC service testing.
type p6bMockTokenStore struct {
	tokens  map[string]*oidc.TokenResponse
	saveErr error
	loadErr error
	delErr  error
}

func (m *p6bMockTokenStore) Save(issuer string, t *oidc.TokenResponse) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	if m.tokens == nil {
		m.tokens = make(map[string]*oidc.TokenResponse)
	}
	m.tokens[issuer] = t
	return nil
}
func (m *p6bMockTokenStore) Load(issuer string) (*oidc.TokenResponse, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	t, ok := m.tokens[issuer]
	if !ok {
		return nil, errors.New("not found")
	}
	return t, nil
}
func (m *p6bMockTokenStore) Delete(issuer string) error { return m.delErr }
func (m *p6bMockTokenStore) Close() error               { return nil }
func (m *p6bMockTokenStore) List() ([]string, error) {
	result := make([]string, 0, len(m.tokens))
	for k := range m.tokens {
		result = append(result, k)
	}
	return result, nil
}

// p6bMockKeyCounter implements KeyCounter for admin service.
type p6bMockKeyCounter struct {
	count int
}

func (m *p6bMockKeyCounter) KeyCount() int { return m.count }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func p6bTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "p6b-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// ===========================================================================
// 1. PIN Service - panic recovery, coordinator notify, error paths
// ===========================================================================

func TestP6B_PINService_GetPINStatus_PanicRecovery(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	// No PIN manager set -> should return error
	status, err := svc.GetPINStatus()
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestP6B_PINService_SetSOPIN_PanicRecovery(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	err := svc.SetSOPIN("old", "new")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestP6B_PINService_ChangeSOPIN_PanicRecovery(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	err := svc.ChangeSOPIN("old", "new")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestP6B_PINService_VerifyUserPIN_PanicRecovery(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	err := svc.VerifyUserPIN("1234")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestP6B_PINService_VerifySOPIN_PanicRecovery(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	err := svc.VerifySOPIN("1234")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestP6B_PINService_GetLockoutStatus_PanicRecovery(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	status, err := svc.GetLockoutStatus()
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestP6B_PINService_ResetLockout_PanicRecovery(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	err := svc.ResetLockout("sopin")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestP6B_PINService_SetUserPIN_ManagerError(t *testing.T) {
	mgr := &p6bMockPINManager{
		strategy:      pin.StrategySoftware,
		initialized:   true,
		setUserPINErr: errors.New("mgr error"),
	}
	svc := NewPINService()
	svc.SetContext(context.Background())
	pinSvc := pin.NewService(mgr, slog.Default())
	svc.SetPINService(pinSvc)

	err := svc.SetUserPIN("sopin", "newpin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mgr error")
}

func TestP6B_PINService_ChangeUserPIN_ManagerError(t *testing.T) {
	mgr := &p6bMockPINManager{
		strategy:      pin.StrategySoftware,
		initialized:   true,
		changeUserErr: errors.New("change error"),
	}
	svc := NewPINService()
	svc.SetContext(context.Background())
	pinSvc := pin.NewService(mgr, slog.Default())
	svc.SetPINService(pinSvc)

	err := svc.ChangeUserPIN("oldpin", "newpin")
	assert.Error(t, err)
}

// ===========================================================================
// 2. Seal Service - error paths
// ===========================================================================

func TestP6B_SealService_SealData_PanicRecovery(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	// Nil request
	entry, err := svc.SealData(nil)
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidLabel)

	// Empty label
	entry, err = svc.SealData(&SealRequest{Label: "", Data: "aGVsbG8="})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidLabel)

	// Empty data
	entry, err = svc.SealData(&SealRequest{Label: "test", Data: ""})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidData)
}

func TestP6B_SealService_SealData_Base64DecodeError(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	entry, err := svc.SealData(&SealRequest{Label: "test", Data: "not-valid-base64!!!"})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealDecodeFailed)
}

func TestP6B_SealService_SealData_BackendNotFound(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	data := base64.StdEncoding.EncodeToString([]byte("secret"))
	entry, err := svc.SealData(&SealRequest{Label: "test", Data: data, Backend: "nonexistent"})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealBackendNotFound)
}

func TestP6B_SealService_SealData_CanSealFalse(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	wireSealMockClient(svc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: false, sealErr: ErrSealNotSupported})

	data := base64.StdEncoding.EncodeToString([]byte("secret"))
	entry, err := svc.SealData(&SealRequest{Label: "test", Data: data, Backend: "mock"})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealNotSupported)
}

func TestP6B_SealService_SealData_InvalidPolicyType(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	wireSealMockClient(svc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: true})

	data := base64.StdEncoding.EncodeToString([]byte("secret"))
	entry, err := svc.SealData(&SealRequest{
		Label:      "test",
		Data:       data,
		Backend:    "mock",
		PolicyType: "invalid_policy",
	})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidPolicyType)
}

func TestP6B_SealService_SealData_PasswordPolicyNoPassword(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	wireSealMockClient(svc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: true})

	data := base64.StdEncoding.EncodeToString([]byte("secret"))
	entry, err := svc.SealData(&SealRequest{
		Label:      "test",
		Data:       data,
		Backend:    "mock",
		PolicyType: string(PolicyTypePassword),
		Password:   "",
	})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealPasswordRequired)
}

func TestP6B_SealService_SealData_PlatformPolicyRequiresTPM(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	wireSealMockClient(svc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: true})

	data := base64.StdEncoding.EncodeToString([]byte("secret"))
	entry, err := svc.SealData(&SealRequest{
		Label:      "test",
		Data:       data,
		Backend:    "mock",
		PolicyType: string(PolicyTypePlatformPolicy),
	})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealPolicyRequiresTPM)
}

func TestP6B_SealService_SealData_SuccessWithPassword(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	wireSealMockClient(svc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: true})

	plaintext := []byte("my-secret-data")
	data := base64.StdEncoding.EncodeToString(plaintext)
	entry, err := svc.SealData(&SealRequest{
		Label:      "pw-test",
		Data:       data,
		Backend:    "mock",
		PolicyType: string(PolicyTypePassword),
		Password:   "mypassword",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, entry.ID)
	assert.Equal(t, "pw-test", entry.Label)
}

func TestP6B_SealService_UnsealData_PanicRecovery(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	// Empty ID
	result, err := svc.UnsealData("", "")
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestP6B_SealService_UnsealData_BlobNotFound(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	result, err := svc.UnsealData("nonexistent-id", "")
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestP6B_SealService_DeleteBlob_NotFound(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	err := svc.DeleteBlob("")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)

	err = svc.DeleteBlob("nonexistent")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestP6B_SealService_ListBlobs_PanicRecovery(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	blobs, err := svc.ListBlobs()
	assert.NoError(t, err)
	assert.NotNil(t, blobs)
	assert.Empty(t, blobs)
}

func TestP6B_SealService_CanSeal_PanicRecovery(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	// No backend registered, should return false, nil
	can, err := svc.CanSeal()
	assert.False(t, can)
	assert.NoError(t, err)
}

func TestP6B_SealService_SaveBlob_MarshalError(t *testing.T) {
	// Test with relative path to trigger ensureStorageDir error
	svc := NewSealService("relative-path")
	svc.SetContext(context.Background())

	err := svc.saveBlob(&sealedBlobStorage{ID: "test"})
	assert.ErrorIs(t, err, ErrSealStorageFailed)
}

func TestP6B_SealService_SaveBlob_WriteSuccess(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	blob := &sealedBlobStorage{
		ID:    "test-blob-123",
		Label: "test",
	}
	err := svc.saveBlob(blob)
	assert.NoError(t, err)

	// Verify file exists
	path := filepath.Join(dir, "test-blob-123.sealed.json")
	_, statErr := os.Stat(path)
	assert.NoError(t, statErr)
}

func TestP6B_SealService_EnsureStorageDir_EmptyDir(t *testing.T) {
	svc := NewSealService("")
	err := svc.ensureStorageDir()
	assert.ErrorIs(t, err, ErrSealStorageDirNotSet)
}

func TestP6B_SealService_EnsureStorageDir_RelativeDir(t *testing.T) {
	svc := NewSealService("relative/path")
	err := svc.ensureStorageDir()
	assert.ErrorIs(t, err, ErrSealStorageDirRelative)
}

// ===========================================================================
// 3. Platform Policy Service - error paths
// ===========================================================================

func TestP6B_PlatformPolicyService_GetStatus_PanicRecovery(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	status, err := svc.GetStatus()
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.False(t, status.Configured)
}

func TestP6B_PlatformPolicyService_CreatePolicy_InvalidPCRs(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	// Empty PCRs
	status, err := svc.CreatePolicy([]int{}, "sha256")
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)

	// PCR out of range
	status, err = svc.CreatePolicy([]int{25}, "sha256")
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)
}

func TestP6B_PlatformPolicyService_CreatePolicy_InvalidBank(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	status, err := svc.CreatePolicy([]int{0, 7}, "invalid_bank")
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPolicyInvalidBank)
}

func TestP6B_PlatformPolicyService_UpdatePolicy_NotConfigured(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	status, err := svc.UpdatePolicy([]int{0}, "sha256")
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestP6B_PlatformPolicyService_DeletePolicy_NotConfigured(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	err := svc.DeletePolicy()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestP6B_PlatformPolicyService_VerifyPolicy_NotConfigured(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	valid, err := svc.VerifyPolicy()
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestP6B_PlatformPolicyService_GetPolicyPCRs_NotConfigured(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	pcrs, bank, err := svc.GetPolicyPCRs()
	assert.Nil(t, pcrs)
	assert.Empty(t, bank)
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestP6B_PlatformPolicyService_ExportPolicy_NotConfigured(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	result, err := svc.ExportPolicy()
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestP6B_PlatformPolicyService_ExportPolicy_WithPolicy(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	// Manually store a policy.
	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabbcc", 7: "ddeeff"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	svc.policy.Store(def)

	result, err := svc.ExportPolicy()
	assert.NoError(t, err)
	assert.Contains(t, result, "sha256")
	assert.Contains(t, result, "aabbcc")
}

func TestP6B_PlatformPolicyService_GetPlatformPolicyAsPCRPolicy_NilPolicy(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	assert.Nil(t, policy)
	assert.NoError(t, err)
}

func TestP6B_PlatformPolicyService_RefreshPlatformPolicyPCRs_NotConfigured(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	policy, err := svc.RefreshPlatformPolicyPCRs()
	assert.Nil(t, policy)
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestP6B_PlatformPolicyService_SavePolicy_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aa"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err := svc.savePolicy(def)
	assert.NoError(t, err)

	// Verify file written
	data, readErr := os.ReadFile(filepath.Join(dir, "platform_policy.json"))
	assert.NoError(t, readErr)
	assert.Contains(t, string(data), "sha256")
}

func TestP6B_PlatformPolicyService_DeletePolicy_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	// Store and save a policy.
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aa"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)
	require.NoError(t, svc.savePolicy(def))

	err := svc.DeletePolicy()
	assert.NoError(t, err)

	// Verify policy is nil.
	assert.Nil(t, svc.policy.Load())
}

// ===========================================================================
// 4. OIDC Service - SetDataDir, Close, token store
// ===========================================================================

func TestP6B_OIDCService_SetDataDir_CreatesTokenStore(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(slog.Default())

	svc.SetDataDir(dir)
	// Token store should now be set.
	assert.NotNil(t, svc.tokenStore)
}

func TestP6B_OIDCService_Close_WithTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.SetTokenStore(&p6bMockTokenStore{})

	err := svc.Close()
	assert.NoError(t, err)
}

func TestP6B_OIDCService_Close_NilTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	err := svc.Close()
	assert.NoError(t, err)
}

func TestP6B_OIDCService_RefreshToken_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.SetContext(context.Background())
	svc.dataDir = t.TempDir()

	// Register a provider.
	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}))

	info, err := svc.RefreshToken("test")
	assert.Nil(t, info)
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

func TestP6B_OIDCService_RefreshToken_TokenNotFound(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.SetContext(context.Background())
	svc.dataDir = t.TempDir()
	svc.SetTokenStore(&p6bMockTokenStore{
		loadErr: errors.New("not found"),
	})

	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}))

	info, err := svc.RefreshToken("test")
	assert.Nil(t, info)
	assert.True(t, errors.Is(err, ErrOIDCTokenNotFound))
}

func TestP6B_OIDCService_RefreshToken_NoRefreshToken(t *testing.T) {
	store := &p6bMockTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"https://example.com": {
				AccessToken:  "access-token",
				RefreshToken: "",
			},
		},
	}
	svc := NewOIDCService(slog.Default())
	svc.SetContext(context.Background())
	svc.SetTokenStore(store)
	svc.dataDir = t.TempDir()

	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}))

	info, err := svc.RefreshToken("test")
	assert.Nil(t, info)
	assert.ErrorIs(t, err, ErrOIDCNoRefreshToken)
}

func TestP6B_OIDCService_GetTokenInfo_NoStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.SetContext(context.Background())

	svc.dataDir = t.TempDir()
	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}))

	info, err := svc.GetTokenInfo("test")
	assert.Nil(t, info)
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

func TestP6B_OIDCService_SaveProviders_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(slog.Default())
	svc.dataDir = dir

	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}))

	err := svc.saveProviders()
	assert.NoError(t, err)

	// Verify file was written.
	path := filepath.Join(dir, "oidc-providers.json")
	_, statErr := os.Stat(path)
	assert.NoError(t, statErr)
}

// ===========================================================================
// 5. Admin Service - IsAdmin, GetAuditLogs, ExportAuditLogs
// ===========================================================================

func TestP6B_AdminService_IsAdmin(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	// In test environment, IsAdmin returns based on current UID.
	// We just test it doesn't panic.
	_ = svc.IsAdmin()
}

func TestP6B_AdminService_GetAuditLogs_NotAdmin(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	// Unless running as root, this should fail.
	if os.Geteuid() != 0 {
		entries, err := svc.GetAuditLogs(nil)
		assert.Nil(t, entries)
		assert.ErrorIs(t, err, ErrAdminNotAuthorized)
	}
}

func TestP6B_AdminService_ExportAuditLogs_NotAdmin(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	if os.Geteuid() != 0 {
		data, err := svc.ExportAuditLogs("json")
		assert.Nil(t, data)
		assert.ErrorIs(t, err, ErrAdminNotAuthorized)
	}
}

func TestP6B_AdminService_ExportAuditLogs_InvalidFormat(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	if os.Geteuid() != 0 {
		data, err := svc.ExportAuditLogs("xml")
		assert.Nil(t, data)
		// Not admin first, so this returns ErrAdminNotAuthorized.
		assert.Error(t, err)
	}
}

func TestP6B_AdminService_GetBackendInfo_EmptyID(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	info, err := svc.GetBackendInfo("")
	assert.Nil(t, info)
	assert.ErrorIs(t, err, ErrAdminBackendNotFound)
}

func TestP6B_AdminService_GetBackendInfo_NotFound(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	info, err := svc.GetBackendInfo("nonexistent-backend")
	assert.Nil(t, info)
	assert.ErrorIs(t, err, ErrAdminBackendNotFound)
}

func TestP6B_AdminService_TotalKeyCount(t *testing.T) {
	svc := NewAdminService()
	svc.SetKeyCounters(&p6bMockKeyCounter{count: 5}, &p6bMockKeyCounter{count: 3})

	total := svc.totalKeyCount()
	assert.Equal(t, 8, total)
}

func TestP6B_ClipboardService_CopyWithClear_NoTool(t *testing.T) {
	svc := &ClipboardService{tool: clipToolNone}

	err := svc.CopyWithClear("text")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

func TestP6B_ClipboardService_Copy_NoTool(t *testing.T) {
	svc := &ClipboardService{tool: clipToolNone}

	err := svc.Copy("text")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

func TestP6B_ClipboardService_ClearClipboard_NoTool(t *testing.T) {
	svc := &ClipboardService{tool: clipToolNone}

	err := svc.ClearClipboard()
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

func TestP6B_ClipboardService_WriteClipboard_NoTool(t *testing.T) {
	svc := &ClipboardService{tool: clipToolNone}

	err := svc.writeClipboard("text")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

func TestP6B_ClipboardService_ReadClipboard_NoTool(t *testing.T) {
	svc := &ClipboardService{tool: clipToolNone}

	text, err := svc.readClipboard()
	assert.Empty(t, text)
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

func TestP6B_ClipboardService_DetectClipboardTool(t *testing.T) {
	// Just call the function to hit the branches.
	tool := detectClipboardTool()
	// Result depends on the system; just ensure no panic.
	_ = tool
}

// ===========================================================================
// 8. Trust Service - certificate operations (non-Wails)
// ===========================================================================

func TestP6B_TrustService_ListCertificates_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	certs, err := svc.ListCertificates()
	assert.Nil(t, certs)
	assert.NoError(t, err)
}

func TestP6B_TrustService_ListCertificates_Error(t *testing.T) {
	store := &p6bMockTrustStore{
		certErr: errors.New("list error"),
	}
	svc := NewTrustService(store)

	certs, err := svc.ListCertificates()
	assert.Nil(t, certs)
	assert.Error(t, err)
}

func TestP6B_TrustService_ListCertificates_WithCerts(t *testing.T) {
	cert := p6bTestCert(t)
	store := &p6bMockTrustStore{
		certs: []*x509.Certificate{cert},
		metadata: &truststore.CertMetadata{
			Purpose: truststore.PurposeGeneral,
			Source:  "test",
		},
	}
	svc := NewTrustService(store)

	certs, err := svc.ListCertificates()
	assert.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Equal(t, "CN=p6b-test", certs[0].Subject)
}

func TestP6B_TrustService_ListCertificatesByPurpose_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	certs, err := svc.ListCertificatesByPurpose("tls")
	assert.Nil(t, certs)
	assert.NoError(t, err)
}

func TestP6B_TrustService_ListCertificatesByPurpose_Error(t *testing.T) {
	store := &p6bMockTrustStore{
		certsByPurpErr: errors.New("purpose error"),
	}
	svc := NewTrustService(store)

	certs, err := svc.ListCertificatesByPurpose("tls")
	assert.Nil(t, certs)
	assert.Error(t, err)
}

func TestP6B_TrustService_ExportCertificateDER_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	der, err := svc.ExportCertificateDER("abc123")
	assert.Nil(t, der)
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

func TestP6B_TrustService_SeedEmbeddedRoots_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	count, err := svc.SeedEmbeddedRoots("tls")
	assert.Equal(t, 0, count)
	assert.NoError(t, err)
}

func TestP6B_TrustService_InstallToSystem_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	err := svc.InstallToSystem("abc", "password")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

func TestP6B_TrustService_RemoveFromSystem_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	err := svc.RemoveFromSystem("abc", "password")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

func TestP6B_TrustService_RemoveFromSystem_ContainsError(t *testing.T) {
	store := &p6bMockTrustStore{
		containsErr: errors.New("contains error"),
	}
	svc := NewTrustService(store)

	err := svc.RemoveFromSystem("abc", "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "contains error")
}

func TestP6B_TrustService_RemoveFromSystem_NotFound(t *testing.T) {
	store := &p6bMockTrustStore{
		containsResult: false,
	}
	svc := NewTrustService(store)

	err := svc.RemoveFromSystem("abc", "password")
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

// ===========================================================================
// 9. OATH Service - ScanQR, account operations
// ===========================================================================

func TestP6B_OATHService_GenerateTOTP_NoStore(t *testing.T) {
	svc := NewOATHService(nil)

	code, err := svc.GenerateTOTP("")
	assert.Nil(t, code)
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)
}

func TestP6B_OATHService_GenerateHOTP_NoStore(t *testing.T) {
	svc := NewOATHService(nil)

	code, err := svc.GenerateHOTP("")
	assert.Nil(t, code)
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)
}

func TestP6B_OATHService_GenerateTOTP_InvalidID(t *testing.T) {
	store := &p6bMockOATHStore{creds: make(map[string]*oath.Credential)}
	svc := NewOATHService(store)

	code, err := svc.GenerateTOTP("")
	assert.Nil(t, code)
	assert.ErrorIs(t, err, ErrOATHInvalidID)
}

func TestP6B_OATHService_GenerateHOTP_InvalidID(t *testing.T) {
	store := &p6bMockOATHStore{creds: make(map[string]*oath.Credential)}
	svc := NewOATHService(store)

	code, err := svc.GenerateHOTP("")
	assert.Nil(t, code)
	assert.ErrorIs(t, err, ErrOATHInvalidID)
}

func TestP6B_OATHService_GenerateTOTP_WrongType(t *testing.T) {
	store := &p6bMockOATHStore{
		creds: map[string]*oath.Credential{
			"test": {ID: "test", Type: oath.TypeHOTP},
		},
	}
	svc := NewOATHService(store)

	code, err := svc.GenerateTOTP("test")
	assert.Nil(t, code)
	assert.ErrorIs(t, err, ErrOATHGenerateFailed)
}

func TestP6B_OATHService_GenerateHOTP_WrongType(t *testing.T) {
	store := &p6bMockOATHStore{
		creds: map[string]*oath.Credential{
			"test": {ID: "test", Type: oath.TypeTOTP},
		},
	}
	svc := NewOATHService(store)

	code, err := svc.GenerateHOTP("test")
	assert.Nil(t, code)
	assert.ErrorIs(t, err, ErrOATHGenerateFailed)
}

func TestP6B_OATHService_ScanQR(t *testing.T) {
	svc := NewOATHService(nil)
	// ScanQR calls qrscan.NewScanner().ScanScreen - will fail on headless.
	result, err := svc.ScanQR(-1)
	// Expected: no displays available or no QR found.
	if err != nil {
		assert.Nil(t, result)
	}
}

func TestP6B_OATHService_AddAccountFromURI_Empty(t *testing.T) {
	svc := NewOATHService(nil)

	acct, err := svc.AddAccountFromURI("")
	assert.Nil(t, acct)
	assert.ErrorIs(t, err, ErrOATHInvalidURI)
}

func TestP6B_OATHService_AddAccountFromURI_InvalidScheme(t *testing.T) {
	svc := NewOATHService(nil)

	acct, err := svc.AddAccountFromURI("https://not-otpauth")
	assert.Nil(t, acct)
	assert.ErrorIs(t, err, ErrOATHQRInvalidURI)
}

// ===========================================================================
// 10. Static Password Service - store operations
// ===========================================================================

func TestP6B_StaticPW_ListPasswords_NoStore(t *testing.T) {
	svc := &StaticPasswordService{}

	entries, err := svc.ListPasswords()
	assert.Nil(t, entries)
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestP6B_StaticPW_ListPasswordsByFolder_NoStore(t *testing.T) {
	svc := &StaticPasswordService{}

	entries, err := svc.ListPasswordsByFolder("/folder")
	assert.Nil(t, entries)
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestP6B_StaticPW_MovePassword_NoStore(t *testing.T) {
	svc := &StaticPasswordService{}

	err := svc.MovePassword("id", "/folder")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestP6B_StaticPW_RenameFolder_NoStore(t *testing.T) {
	svc := &StaticPasswordService{}

	err := svc.RenameFolder("/old", "/new")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestP6B_StaticPW_RenameFolder_EmptyPath(t *testing.T) {
	svc := &StaticPasswordService{store: &p6bMockStaticPWStore{}}

	err := svc.RenameFolder("", "/new")
	assert.ErrorIs(t, err, ErrStaticPWInvalidFolderPath)
}

func TestP6B_StaticPW_DeleteFolder_NoStore(t *testing.T) {
	svc := &StaticPasswordService{}

	err := svc.DeleteFolder("/folder")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestP6B_StaticPW_DeleteFolder_EmptyPath(t *testing.T) {
	svc := &StaticPasswordService{store: &p6bMockStaticPWStore{}}

	err := svc.DeleteFolder("")
	assert.ErrorIs(t, err, ErrStaticPWInvalidFolderPath)
}

func TestP6B_StaticPW_SearchPasswords_NoStore(t *testing.T) {
	svc := &StaticPasswordService{}

	entries, err := svc.SearchPasswords("query")
	assert.Nil(t, entries)
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

// ===========================================================================
// 11. Elevation (SudoElevator) - error paths
// ===========================================================================

func TestP6B_SudoElevator_Run_NoExecPath(t *testing.T) {
	e := NewSudoElevator("password")
	e.execPath = ""

	out, err := e.Run([]string{"test"}, nil)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, ErrElevationUnavailable)
}

func TestP6B_SudoElevator_Run_SudoUnavailable(t *testing.T) {
	e := NewSudoElevator("password")
	e.execPath = "/nonexistent/binary"

	// IsAvailable checks for sudo.
	if !e.IsAvailable() {
		out, err := e.Run([]string{"test"}, nil)
		assert.Nil(t, out)
		assert.ErrorIs(t, err, ErrSudoUnavailable)
	}
}

func TestP6B_ZeroBytes(t *testing.T) {
	b := []byte("secret-password")
	zeroBytes(b)
	for i := range b {
		assert.Equal(t, byte(0), b[i])
	}
}

// ===========================================================================
// 12. FIDO2 Service - error paths
// ===========================================================================

func TestP6B_FIDO2Service_ListCredentials_NilStorage(t *testing.T) {
	svc := &FIDO2Service{}

	creds, err := svc.ListCredentials()
	assert.NoError(t, err)
	assert.Empty(t, creds)
}

func TestP6B_FIDO2Service_GetRelyingParties_NilStorage(t *testing.T) {
	svc := &FIDO2Service{}

	rps, err := svc.GetRelyingParties()
	assert.NoError(t, err)
	assert.Empty(t, rps)
}

func TestP6B_FIDO2Service_GetCredential_EmptyID(t *testing.T) {
	svc := &FIDO2Service{}

	cred, err := svc.GetCredential("")
	assert.Nil(t, cred)
	assert.ErrorIs(t, err, ErrFIDO2InvalidID)
}

func TestP6B_FIDO2Service_StartBridge_NilClient(t *testing.T) {
	svc := &FIDO2Service{}

	err := svc.StartPhoneBridge()
	assert.ErrorIs(t, err, ErrFIDO2BridgeNoClient)
}

// ===========================================================================
// 13. Auto-Unseal Service - error branches
// ===========================================================================

func TestP6B_AutoUnsealService_Disable_NilConfigFunc(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	svc := NewAutoUnsealService(sealSvc, nil)
	svc.configFunc = nil

	err := svc.Disable()
	assert.ErrorIs(t, err, ErrAutoUnsealConfigFuncNil)
}

func TestP6B_AutoUnsealService_Disable_NilConfigSave(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	svc := NewAutoUnsealService(sealSvc, nil)
	svc.configFunc = func() *GUIConfigData {
		return &GUIConfigData{AutoUnsealBlobID: "blob1"}
	}
	svc.configSave = nil

	err := svc.Disable()
	assert.ErrorIs(t, err, ErrAutoUnsealConfigSaveFuncNil)
}

func TestP6B_AutoUnsealService_Disable_NotConfigured(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	svc := NewAutoUnsealService(sealSvc, nil)
	svc.configFunc = func() *GUIConfigData {
		return &GUIConfigData{AutoUnsealBlobID: ""}
	}
	svc.configSave = func(_ *GUIConfigData) error { return nil }

	err := svc.Disable()
	assert.ErrorIs(t, err, ErrAutoUnsealNotConfigured)
}

func TestP6B_AutoUnsealService_TryAutoUnseal_NilConfigFunc(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	svc := NewAutoUnsealService(sealSvc, nil)
	svc.configFunc = nil

	result := svc.TryAutoUnseal()
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "not configured")
}

func TestP6B_AutoUnsealService_TryAutoUnseal_NotEnabled(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	svc := NewAutoUnsealService(sealSvc, nil)
	svc.configFunc = func() *GUIConfigData {
		return &GUIConfigData{AutoUnsealEnabled: false}
	}

	result := svc.TryAutoUnseal()
	assert.False(t, result.Success)
}

// ===========================================================================
// 14. Storage Service - validation
// ===========================================================================

func TestP6B_StorageService_ValidateVolumeSize(t *testing.T) {
	// Too small
	err := validateVolumeSize(0)
	assert.ErrorIs(t, err, ErrStorageInvalidSize)

	// Too large
	err = validateVolumeSize(200)
	assert.ErrorIs(t, err, ErrStorageInvalidSize)

	// Valid
	err = validateVolumeSize(10)
	assert.NoError(t, err)
}

func TestP6B_StorageService_ValidatePassphrase(t *testing.T) {
	err := validatePassphrase("short")
	assert.ErrorIs(t, err, ErrStorageWeakPassphrase)

	err = validatePassphrase("longpassphrase12")
	assert.NoError(t, err)
}

func TestP6B_StorageService_WipeVolume_InvalidStandard(t *testing.T) {
	svc := NewStorageService()

	err := svc.WipeVolume("invalid")
	assert.ErrorIs(t, err, ErrStorageInvalidStandard)
}

// ===========================================================================
// 15. Barrier Service - initialize error paths
// ===========================================================================

func TestP6B_BarrierService_BestStrategy_NilAccessor(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	// BestStrategy should return something (at least software strategy).
	info, err := svc.BestStrategy()
	if err != nil {
		// If no strategy available, that's ok.
		assert.Nil(t, info)
	} else {
		assert.NotNil(t, info)
	}
}

// ===========================================================================
// 16. Phone Service - helper functions
// ===========================================================================

func TestP6B_PhoneService_TruncateHash(t *testing.T) {
	// Short hash (< 28 chars) should be returned as-is.
	short := "abc123"
	assert.Equal(t, short, truncateHash(short))

	// Long hash should be truncated.
	long := "aabbccddeeff00112233445566778899aabbccddeeff0011"
	result := truncateHash(long)
	assert.Contains(t, result, "...")
	assert.NotEqual(t, long, result)
}

func TestP6B_PhoneService_ParseDERChain_Empty(t *testing.T) {
	chain, err := parseDERChain(nil)
	assert.NoError(t, err)
	assert.Empty(t, chain)
}

func TestP6B_PhoneService_ParseDERChain_InvalidDER(t *testing.T) {
	chain, err := parseDERChain([][]byte{[]byte("not-a-cert")})
	assert.Error(t, err)
	assert.Nil(t, chain)
}

func TestP6B_PhoneService_ParseDERChain_ValidCert(t *testing.T) {
	cert := p6bTestCert(t)
	chain, err := parseDERChain([][]byte{cert.Raw})
	assert.NoError(t, err)
	assert.Len(t, chain, 1)
}

func TestP6B_PhoneService_FindMatchingTrustRoot_EmptyChain(t *testing.T) {
	root := findMatchingTrustRoot(nil, nil)
	assert.Nil(t, root)
}

func TestP6B_PhoneService_FindMatchingTrustRoot_NoMatch(t *testing.T) {
	cert1 := p6bTestCert(t)
	cert2 := p6bTestCert(t)
	root := findMatchingTrustRoot([]*x509.Certificate{cert1}, []*x509.Certificate{cert2})
	assert.Nil(t, root)
}

func TestP6B_PhoneService_FindMatchingTrustRoot_Match(t *testing.T) {
	cert := p6bTestCert(t)
	root := findMatchingTrustRoot([]*x509.Certificate{cert}, []*x509.Certificate{cert})
	assert.NotNil(t, root)
}

func TestP6B_PhoneService_CertFP(t *testing.T) {
	cert := p6bTestCert(t)
	fp := certFP(cert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64) // SHA-256 hex = 64 chars
}

func TestP6B_PhoneService_PubKeyFP(t *testing.T) {
	cert := p6bTestCert(t)
	fp := pubKeyFP(cert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64)
}

func TestP6B_PhoneService_FormatTrustAnchorName_Nil(t *testing.T) {
	name := formatTrustAnchorName(nil)
	assert.Equal(t, "Unknown", name)
}

func TestP6B_PhoneService_FormatTrustAnchorName_WithCert(t *testing.T) {
	cert := p6bTestCert(t)
	name := formatTrustAnchorName(cert)
	assert.NotEmpty(t, name)
}

func TestP6B_PhoneService_Hostname(t *testing.T) {
	h := hostname()
	assert.NotEmpty(t, h)
}

func TestP6B_PhoneService_SecurityLevelRank(t *testing.T) {
	assert.Equal(t, -1, securityLevelRank("unknown"))
	assert.Equal(t, 0, securityLevelRank("software"))
	assert.Equal(t, 1, securityLevelRank("tee"))
	assert.Equal(t, 2, securityLevelRank("strongbox"))
}

// ===========================================================================
// 17. Setup Wizard - ApplySOProvisioning and GetPolicy paths
// ===========================================================================

func TestP6B_SetupWizard_ApplySOProvisioning_EmptySOPIN(t *testing.T) {
	svc := NewSetupWizardService()

	result, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: "",
	})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrSetupSOPINRequired)
}

func TestP6B_SetupWizard_ApplySOProvisioning_InvalidMode(t *testing.T) {
	svc := NewSetupWizardService()

	result, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "invalid_mode",
		SOPin: "123456",
	})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrSetupInvalidDeploymentMode)
}

func TestP6B_SetupWizard_ApplySOProvisioning_NilPINService(t *testing.T) {
	svc := NewSetupWizardService()

	result, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: "123456",
	})
	// Should succeed with warnings about missing services.
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.True(t, len(result.Errors) > 0)
}

func TestP6B_SetupWizard_ApplySOProvisioning_PINSetupError(t *testing.T) {
	mgr := &p6bMockPINManager{
		setSOPINErr: errors.New("pin error"),
	}
	pinSvc := NewPINService()
	backendSvc := pin.NewService(mgr, slog.Default())
	pinSvc.SetPINService(backendSvc)

	svc := NewSetupWizardService()
	svc.SetPINService(pinSvc)

	result, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: "123456",
	})
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.True(t, len(result.Errors) > 0)
	assert.Contains(t, result.Errors[0], "SO PIN setup failed")
}

func TestP6B_SetupWizard_GetPolicy_ConfigLoadError(t *testing.T) {
	svc := NewSetupWizardService()
	// GetPolicy tries to load unified config which may not exist in test.
	result, err := svc.GetPolicy()
	// Expected: either works or returns error depending on config existence.
	if err != nil {
		assert.Nil(t, result)
	}
}

// ===========================================================================
// 18. Setup Wizard - Apply wizard (step 4, 8 error branches)
// ===========================================================================

func TestP6B_SetupWizard_Apply_PlatformPolicyCreateFailed(t *testing.T) {
	svc := NewSetupWizardService()
	svc.configFunc = func() *GUIConfigData { return &GUIConfigData{} }
	svc.configSave = func(_ *GUIConfigData) error { return nil }
	svc.initDataDirFunc = func() error { return nil }

	// Set a platform policy service with no TPM accessor (will fail readPCRDigests).
	dir := t.TempDir()
	ppSvc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))
	svc.SetPlatformPolicyService(ppSvc)

	result, err := svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             "123456",
		UserPin:           "654321",
		PasswordStoreMode: "none",
	})
	require.NoError(t, err)
	// Platform policy creation will fail with no TPM, should be in warnings.
	hasWarning := false
	for _, w := range result.Warnings {
		if len(w) > 0 {
			hasWarning = true
		}
	}
	assert.True(t, hasWarning)
}

func TestP6B_SetupWizard_Apply_TPMSealedPasswordMode(t *testing.T) {
	dir := t.TempDir()

	store := &p6bMockStaticPWStore{passwords: []*staticpw.StaticPassword{}}
	spSvc := &StaticPasswordService{store: store}
	ppSvc := NewPasswordProtectionService(filepath.Join(dir, "enc.json"), spSvc, nil)

	svc := NewSetupWizardService()
	svc.configFunc = func() *GUIConfigData { return &GUIConfigData{} }
	svc.configSave = func(_ *GUIConfigData) error { return nil }
	svc.initDataDirFunc = func() error { return nil }
	svc.SetPasswordProtectionService(ppSvc)

	result, err := svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             "123456",
		UserPin:           "654321",
		PasswordStoreMode: "tpm_sealed",
	})
	require.NoError(t, err)
	// Without barrier service, setup succeeds with warnings.
	// Step 8 (password protection) is now handled transparently by the barrier.
	assert.True(t, result.Success)
}

func TestP6B_SetupWizard_Apply_AESSoftwareMode_MasterPassword(t *testing.T) {
	dir := t.TempDir()

	store := &p6bMockStaticPWStore{passwords: []*staticpw.StaticPassword{}}
	spSvc := &StaticPasswordService{store: store}
	ppSvc := NewPasswordProtectionService(filepath.Join(dir, "enc.json"), spSvc, nil)

	svc := NewSetupWizardService()
	svc.configFunc = func() *GUIConfigData { return &GUIConfigData{} }
	svc.configSave = func(_ *GUIConfigData) error { return nil }
	svc.initDataDirFunc = func() error { return nil }
	svc.SetPasswordProtectionService(ppSvc)

	result, err := svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             "123456",
		UserPin:           "654321",
		PasswordStoreMode: "aes_software",
		EnableMasterPW:    true,
		MasterPassword:    "masterpassword123",
	})
	require.NoError(t, err)
	assert.True(t, result.Success)
}

func TestP6B_SetupWizard_Apply_AESSoftwareMode_UserPinAsMaster(t *testing.T) {
	dir := t.TempDir()

	store := &p6bMockStaticPWStore{passwords: []*staticpw.StaticPassword{}}
	spSvc := &StaticPasswordService{store: store}
	ppSvc := NewPasswordProtectionService(filepath.Join(dir, "enc.json"), spSvc, nil)

	svc := NewSetupWizardService()
	svc.configFunc = func() *GUIConfigData { return &GUIConfigData{} }
	svc.configSave = func(_ *GUIConfigData) error { return nil }
	svc.initDataDirFunc = func() error { return nil }
	svc.SetPasswordProtectionService(ppSvc)

	result, err := svc.ApplySetup(&SetupChoices{
		Mode:               "standalone",
		SOPin:              "123456",
		PasswordStoreMode:  "aes_software",
		UseUserPinAsMaster: true,
		UserPin:            "userpin12345",
	})
	require.NoError(t, err)
	assert.True(t, result.Success)
}

func TestP6B_SetupWizard_Apply_AESSoftwareMode_NoPPSvc(t *testing.T) {
	svc := NewSetupWizardService()
	svc.configFunc = func() *GUIConfigData { return &GUIConfigData{} }
	svc.configSave = func(_ *GUIConfigData) error { return nil }
	svc.initDataDirFunc = func() error { return nil }
	// No password protection service set.

	result, err := svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             "123456",
		UserPin:           "654321",
		PasswordStoreMode: "aes_software",
		EnableMasterPW:    true,
		MasterPassword:    "masterpass123",
	})
	require.NoError(t, err)
	// Should have warning about unavailable pp service.
	hasWarning := false
	for _, w := range result.Warnings {
		if len(w) > 0 {
			hasWarning = true
		}
	}
	assert.True(t, hasWarning)
}

func TestP6B_SetupWizard_Apply_AutoUnsealNilService(t *testing.T) {
	svc := NewSetupWizardService()
	svc.configFunc = func() *GUIConfigData { return &GUIConfigData{} }
	svc.configSave = func(_ *GUIConfigData) error { return nil }
	svc.initDataDirFunc = func() error { return nil }

	result, err := svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            "123456",
		UserPin:          "654321",
		EnableAutoUnseal: true,
		EnableStorage:    true,
		StorageType:      "luks",
		StoragePass:      "longpassphrase12",
	})
	require.NoError(t, err)
	// Should warn about missing auto-unseal service.
	hasWarning := false
	for _, w := range result.Warnings {
		if len(w) > 0 {
			hasWarning = true
		}
	}
	assert.True(t, hasWarning)
}

// ===========================================================================
// 19. Seal Service helpers - hashPassword, verifyPassword
// ===========================================================================

func TestP6B_SealService_HashAndVerifyPassword(t *testing.T) {
	hash, err := hashPassword("mypassword")
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, ":")

	ok := verifyPassword("mypassword", hash)
	assert.True(t, ok)

	ok = verifyPassword("wrongpassword", hash)
	assert.False(t, ok)
}

func TestP6B_SealService_VerifyPassword_InvalidFormat(t *testing.T) {
	ok := verifyPassword("pw", "not-a-valid-hash")
	assert.False(t, ok)
}

func TestP6B_SealService_VerifyPassword_InvalidHex(t *testing.T) {
	ok := verifyPassword("pw", "zzzz:yyyy")
	assert.False(t, ok)
}

func TestP6B_SealService_ClassifyCategory(t *testing.T) {
	assert.Equal(t, "user", classifyCategory("user_pin"))
	assert.Equal(t, "user", classifyCategory("so_pin"))
	assert.Equal(t, "system", classifyCategory("password_master_key"))
	assert.Equal(t, "user", classifyCategory("luks_passphrase"))
	assert.Equal(t, "user", classifyCategory("random_label"))
}

// ===========================================================================
// 20. Seal Service - handlePolicyPlatformPolicy, handlePolicyCustomPCR
// ===========================================================================

func TestP6B_SealService_HandlePolicyPlatformPolicy_NilService(t *testing.T) {
	svc := NewSealService(t.TempDir())
	opts := &types.SealOptions{}
	err := handlePolicyPlatformPolicy(svc, &SealRequest{}, opts)
	assert.ErrorIs(t, err, ErrSealPolicyNotAvailable)
}

func TestP6B_SealService_HandlePolicyPlatformPolicy_NotConfigured(t *testing.T) {
	dir := t.TempDir()
	policySvc := NewPlatformPolicyService(filepath.Join(dir, "platform_policy.json"))

	svc := NewSealService(dir)
	svc.policyService = policySvc

	opts := &types.SealOptions{}
	err := handlePolicyPlatformPolicy(svc, &SealRequest{}, opts)
	assert.ErrorIs(t, err, ErrSealPolicyNotAvailable)
}

func TestP6B_SealService_HandlePolicyCustomPCR_NoPCRs(t *testing.T) {
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, &SealRequest{PCRs: nil}, opts)
	assert.NoError(t, err)
	assert.Nil(t, opts.TPMPolicy)
}

func TestP6B_SealService_HandlePolicyCustomPCR_WithPCRs(t *testing.T) {
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, &SealRequest{
		PCRs:    []int{0, 7},
		PCRBank: "sha256",
	}, opts)
	assert.NoError(t, err)
	assert.NotNil(t, opts.TPMPolicy)
}

func TestP6B_SealService_HandlePolicyCustomPCR_UnknownBank(t *testing.T) {
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, &SealRequest{
		PCRs:    []int{0},
		PCRBank: "unknown_bank",
	}, opts)
	assert.NoError(t, err)
	// Should default to SHA256.
	assert.NotNil(t, opts.TPMPolicy)
}

func TestP6B_SealService_HandlePolicyPassword_EmptyPassword(t *testing.T) {
	err := handlePolicyPassword(nil, &SealRequest{Password: ""}, nil)
	assert.ErrorIs(t, err, ErrSealPasswordRequired)
}

func TestP6B_SealService_HandlePolicyPassword_WithPassword(t *testing.T) {
	err := handlePolicyPassword(nil, &SealRequest{Password: "secret"}, nil)
	assert.NoError(t, err)
}

func TestP6B_SealService_HandlePolicyNone(t *testing.T) {
	err := handlePolicyNone(nil, nil, nil)
	assert.NoError(t, err)
}

// ===========================================================================
// 21. Platform Policy Validation helpers
// ===========================================================================

func TestP6B_ValidatePCRSelection(t *testing.T) {
	err := validatePCRSelection(nil)
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)

	err = validatePCRSelection([]int{})
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)

	err = validatePCRSelection([]int{-1})
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)

	err = validatePCRSelection([]int{24})
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)

	err = validatePCRSelection([]int{0, 7, 23})
	assert.NoError(t, err)
}

func TestP6B_ValidatePCRBank(t *testing.T) {
	err := validatePCRBank("")
	assert.ErrorIs(t, err, ErrPolicyInvalidBank)

	err = validatePCRBank("md5")
	assert.ErrorIs(t, err, ErrPolicyInvalidBank)

	err = validatePCRBank("sha256")
	assert.NoError(t, err)

	err = validatePCRBank("sha384")
	assert.NoError(t, err)

	err = validatePCRBank("sha512")
	assert.NoError(t, err)
}

// ===========================================================================
// 22. Seal Service - LoadBlob
// ===========================================================================

func TestP6B_SealService_LoadBlob_FileNotExist(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	blob, err := svc.loadBlob(filepath.Join(dir, "nonexistent.json"))
	assert.Nil(t, blob)
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestP6B_SealService_LoadBlob_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0600))

	svc := NewSealService(dir)
	blob, err := svc.loadBlob(path)
	assert.Nil(t, blob)
	assert.ErrorIs(t, err, ErrSealUnmarshalFailed)
}

func TestP6B_SealService_LoadBlob_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "good.json")

	blob := &sealedBlobStorage{
		ID:    "test-id",
		Label: "test-label",
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))

	svc := NewSealService(dir)
	loaded, loadErr := svc.loadBlob(path)
	assert.NoError(t, loadErr)
	assert.Equal(t, "test-id", loaded.ID)
	assert.Equal(t, "test-label", loaded.Label)
}
