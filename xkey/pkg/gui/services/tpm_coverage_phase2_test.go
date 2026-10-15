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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mockTPMWithCommands wraps mockTPM to provide configurable SupportedCommands
// and SupportedECCCurves responses.
// ---------------------------------------------------------------------------

type mockTPMWithCommands struct {
	*mockTPM
	commands    []string
	commandsErr error
	curves      []string
	curvesErr   error
}

func (m *mockTPMWithCommands) SupportedCommands() ([]string, error) {
	return m.commands, m.commandsErr
}

func (m *mockTPMWithCommands) SupportedECCCurves() ([]string, error) {
	return m.curves, m.curvesErr
}

// ---------------------------------------------------------------------------
// mockStaticPWStore implements staticpw.Store in-memory for testing policy
// password save/find/delete operations.
// ---------------------------------------------------------------------------

type mockStaticPWStore struct {
	mu      sync.RWMutex
	entries map[string]*staticpw.StaticPassword
}

func (m *mockStaticPWStore) Add(pw *staticpw.StaticPassword) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := staticpw.GenerateID(pw.Name, pw.FolderPath)
	if _, exists := m.entries[id]; exists {
		return staticpw.ErrPasswordExists
	}
	stored := *pw
	stored.ID = id
	now := time.Now()
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = now
	}
	stored.UpdatedAt = now
	m.entries[id] = &stored
	return nil
}

func (m *mockStaticPWStore) Get(idOrName string) (*staticpw.StaticPassword, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if pw, ok := m.entries[idOrName]; ok {
		cp := *pw
		return &cp, nil
	}
	lower := strings.ToLower(idOrName)
	for _, pw := range m.entries {
		if strings.ToLower(pw.Name) == lower {
			cp := *pw
			return &cp, nil
		}
	}
	return nil, staticpw.ErrPasswordNotFound
}

func (m *mockStaticPWStore) List() ([]*staticpw.StaticPassword, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*staticpw.StaticPassword, 0, len(m.entries))
	for _, pw := range m.entries {
		cp := *pw
		result = append(result, &cp)
	}
	return result, nil
}

func (m *mockStaticPWStore) Update(pw *staticpw.StaticPassword) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[pw.ID]; !exists {
		return staticpw.ErrPasswordNotFound
	}
	stored := *pw
	stored.UpdatedAt = time.Now()
	m.entries[pw.ID] = &stored
	return nil
}

func (m *mockStaticPWStore) Delete(idOrName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[idOrName]; exists {
		if m.entries[idOrName].ReadOnly {
			return staticpw.ErrPasswordReadOnly
		}
		delete(m.entries, idOrName)
		return nil
	}
	lower := strings.ToLower(idOrName)
	for id, pw := range m.entries {
		if strings.ToLower(pw.Name) == lower {
			if pw.ReadOnly {
				return staticpw.ErrPasswordReadOnly
			}
			delete(m.entries, id)
			return nil
		}
	}
	return staticpw.ErrPasswordNotFound
}

func (m *mockStaticPWStore) ForceDelete(idOrName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[idOrName]; exists {
		delete(m.entries, idOrName)
		return nil
	}
	lower := strings.ToLower(idOrName)
	for id, pw := range m.entries {
		if strings.ToLower(pw.Name) == lower {
			delete(m.entries, id)
			return nil
		}
	}
	return staticpw.ErrPasswordNotFound
}

func (m *mockStaticPWStore) ListByFolder(folderPath string) ([]*staticpw.StaticPassword, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*staticpw.StaticPassword, 0)
	for _, pw := range m.entries {
		if pw.FolderPath == folderPath {
			cp := *pw
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (m *mockStaticPWStore) ListFolders() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[string]struct{})
	for _, pw := range m.entries {
		if pw.FolderPath != "" {
			seen[pw.FolderPath] = struct{}{}
		}
	}
	folders := make([]string, 0, len(seen))
	for f := range seen {
		folders = append(folders, f)
	}
	return folders, nil
}

func (m *mockStaticPWStore) MoveToFolder(_, _ string) error { return nil }
func (m *mockStaticPWStore) CreateFolder(_ string) error    { return nil }
func (m *mockStaticPWStore) RemoveFolder(_ string) error    { return nil }
func (m *mockStaticPWStore) ListByFolderDirect(folderPath string) ([]*staticpw.StaticPassword, error) {
	return m.ListByFolder(folderPath)
}
func (m *mockStaticPWStore) Close() error { return nil }

// compile-time check
var _ staticpw.Store = (*mockStaticPWStore)(nil)

func TestTPMService_GetInfo_ECCCurves(t *testing.T) {
	inner := defaultMockTPM()
	mock := &mockTPMWithCommands{
		mockTPM: inner,
		curves:  []string{"P-256", "P-384", "P-521"},
	}
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return mock }))

	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.Equal(t, []string{"P-256", "P-384", "P-521"}, info.ECCCurves)
}

func TestTPMService_GetInfo_ECCCurvesError(t *testing.T) {
	inner := defaultMockTPM()
	mock := &mockTPMWithCommands{
		mockTPM:   inner,
		curvesErr: errors.New("no curves"),
	}
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return mock }))

	info, err := svc.GetInfo()
	require.NoError(t, err)
	// ECCCurves should be empty/nil when the TPM returns an error.
	assert.Empty(t, info.ECCCurves)
}

func TestTPMService_GetInfo_SupportedCommandsWithValues(t *testing.T) {
	inner := defaultMockTPM()
	mock := &mockTPMWithCommands{
		mockTPM:  inner,
		commands: []string{"TPM2_Sign", "TPM2_Create", "TPM2_Load"},
	}
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return mock }))

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.Len(t, info.Commands, 3)
	assert.Equal(t, "TPM2_Sign", info.Commands[0].Name)
	assert.Equal(t, "TPM 2.0 command", info.Commands[0].Description)
}

func TestTPMService_GetInfo_OverviewProperties(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedProps.InputBufferMax = 1024
	mock.fixedProps.MaxDigestSize = 64
	mock.fixedProps.MaxObjectContext = 2048
	mock.fixedProps.LockoutInterval = 300
	mock.fixedProps.LockoutRecovery = 600
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.Equal(t, 1024, info.InputBufferMax)
	assert.Equal(t, 64, info.MaxDigestSize)
	assert.Equal(t, 2048, info.MaxObjectContext)
	assert.Equal(t, 300, info.LockoutInterval)
	assert.Equal(t, 600, info.LockoutRecovery)
}

func TestTPMService_GetInfo_AlgorithmsEmptyConfigHash(t *testing.T) {
	mock := defaultMockTPM()
	mock.supportedAlgos = nil
	mock.supportedAlgosErr = errors.New("not supported")
	mock.config.Hash = ""
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	// No algorithms from TPM and no config hash, so Algorithms should be empty.
	assert.Empty(t, info.Algorithms)
}

func TestTPMService_GetInfo_PCRBanksFallbackDefault(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanksErr = errors.New("PCR read fail")
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	// detectPCRBanks returns nil on error, so falls back to ["sha256"].
	assert.Contains(t, info.PCRBanks, "sha256")
}

func TestTPMService_GetInfo_WithEKCertTCGOverrides(t *testing.T) {
	_, caCert, ekCert := testCASignedCert(t)
	_ = caCert
	mock := defaultMockTPM()
	mock.ekCert = ekCert
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	// The cert is a simple test cert without TCG OIDs, so the basic info
	// from FixedProperties should remain. Just verifying the code path runs.
	assert.NotEmpty(t, info.Manufacturer)
	assert.NotNil(t, info.Capabilities)
}

// ---------------------------------------------------------------------------
// GetEKInfo - coverage for cert + trust store verification path
// ---------------------------------------------------------------------------

func TestTPMService_GetEKInfo_WithCertAndTrustStore(t *testing.T) {
	_, caCert, ekCert := testCASignedCert(t)
	mock := defaultMockTPM()
	mock.ekCert = ekCert
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)

	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}
	svc.SetTrustStore(ts)

	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Contains(t, info.Certificate, "CERTIFICATE")
	assert.True(t, info.Verified)
}

func TestTPMService_GetEKInfo_CertNotVerifiedByTrustStore(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)

	// Trust store has no manufacturer certs -- verification should fail.
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{},
	}
	svc.SetTrustStore(ts)

	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.False(t, info.Verified)
}

// ---------------------------------------------------------------------------
// GetEKECCInfo - coverage for cert + trust store verification path
// ---------------------------------------------------------------------------

func TestTPMService_GetEKECCInfo_WithCertAndTrustStore(t *testing.T) {
	_, caCert, ekCert := testCASignedCert(t)
	mock := defaultMockTPM()
	mock.ekCertEC = ekCert
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)

	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}
	svc.SetTrustStore(ts)

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Contains(t, info.Certificate, "CERTIFICATE")
	assert.True(t, info.Verified)
}

func TestTPMService_GetEKECCInfo_CertNotVerified(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = testECCCert()
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)

	// Trust store returns error for purpose.
	ts := &mockTrustStore{
		purposeErr: errors.New("no certs"),
	}
	svc.SetTrustStore(ts)

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.False(t, info.Verified)
}

// ---------------------------------------------------------------------------
// verifyCertAgainstTrustStore - comprehensive coverage
// ---------------------------------------------------------------------------

func TestVerifyCertAgainstTrustStore_ValidCert(t *testing.T) {
	_, caCert, ekCert := testCASignedCert(t)
	svc := NewTPMService()
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}
	svc.SetTrustStore(ts)

	result := svc.verifyCertAgainstTrustStore(ekCert, truststore.PurposeTPMManufacturer)
	assert.True(t, result)
}

func TestVerifyCertAgainstTrustStore_InvalidCert(t *testing.T) {
	svc := NewTPMService()
	// Self-signed cert that is not a CA won't verify against a different CA.
	untrustedCert := testCert()
	caCert := testCert() // Different self-signed cert
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}
	svc.SetTrustStore(ts)

	result := svc.verifyCertAgainstTrustStore(untrustedCert, truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

func TestVerifyCertAgainstTrustStore_TrustStoreError(t *testing.T) {
	svc := NewTPMService()
	ts := &mockTrustStore{
		purposeErr: errors.New("store error"),
	}
	svc.SetTrustStore(ts)

	result := svc.verifyCertAgainstTrustStore(testCert(), truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

func TestTPMService_GetInfo_AlgorithmsFromTPM(t *testing.T) {
	mock := defaultMockTPM()
	// supportedAlgos already set in defaultMockTPM
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.Contains(t, info.Algorithms, "RSA")
	assert.Contains(t, info.Algorithms, "ECC")
	assert.Contains(t, info.Algorithms, "SHA-256")
}

func TestTPMService_GetInfo_NilConfig(t *testing.T) {
	mock := defaultMockTPM()
	mock.config = nil
	mock.supportedAlgos = nil
	mock.supportedAlgosErr = errors.New("unsupported")
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	// With nil config and no supported algos, algorithms should be empty.
	assert.Empty(t, info.Algorithms)
}

func TestVerifyCertAgainstTrustStore_EmptyPurposeCerts(t *testing.T) {
	svc := NewTPMService()
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {},
		},
	}
	svc.SetTrustStore(ts)

	result := svc.verifyCertAgainstTrustStore(testCert(), truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

func TestVerifyCertAgainstTrustStore_SelfSignedCA(t *testing.T) {
	// Create a self-signed CA and use it as both the cert and the trust store root.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Self-Signed CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	svc := NewTPMService()
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {cert},
		},
	}
	svc.SetTrustStore(ts)

	// A self-signed CA verifies against itself.
	result := svc.verifyCertAgainstTrustStore(cert, truststore.PurposeTPMManufacturer)
	assert.True(t, result)
}
