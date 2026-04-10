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

package sync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockTrustStoreAccessor struct {
	certs      []*x509.Certificate
	meta       map[string]*backup.CertMetadataInfo
	contains   map[string]bool
	addedPEM   [][]byte
	certsErr   error
	metaErr    error
	containErr error
	addPEMErr  error
}

func (m *mockTrustStoreAccessor) Certificates() ([]*x509.Certificate, error) {
	if m.certsErr != nil {
		return nil, m.certsErr
	}
	return m.certs, nil
}

func (m *mockTrustStoreAccessor) Metadata(fingerprint string) (*backup.CertMetadataInfo, error) {
	if m.metaErr != nil {
		return nil, m.metaErr
	}
	if m.meta == nil {
		return nil, errors.New("no metadata")
	}
	info, ok := m.meta[fingerprint]
	if !ok {
		return nil, errors.New("metadata not found")
	}
	return info, nil
}

func (m *mockTrustStoreAccessor) Contains(fingerprint string) (bool, error) {
	if m.containErr != nil {
		return false, m.containErr
	}
	if m.contains == nil {
		return false, nil
	}
	return m.contains[fingerprint], nil
}

func (m *mockTrustStoreAccessor) AddPEM(pemData []byte) (int, error) {
	if m.addPEMErr != nil {
		return 0, m.addPEMErr
	}
	m.addedPEM = append(m.addedPEM, pemData)
	return 1, nil
}

type mockOATHAccessor struct {
	creds     map[string]*backup.OATHCredentialInfo
	listErr   error
	getErr    error
	addErr    error
	updateErr error
	added     []*backup.OATHCredentialInfo
	updated   []*backup.OATHCredentialInfo
}

func newMockOATHAccessor() *mockOATHAccessor {
	return &mockOATHAccessor{
		creds: make(map[string]*backup.OATHCredentialInfo),
	}
}

func (m *mockOATHAccessor) List() ([]*backup.OATHCredentialInfo, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]*backup.OATHCredentialInfo, 0, len(m.creds))
	for _, c := range m.creds {
		result = append(result, c)
	}
	return result, nil
}

func (m *mockOATHAccessor) Get(id string) (*backup.OATHCredentialInfo, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	c, ok := m.creds[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return c, nil
}

func (m *mockOATHAccessor) Add(cred *backup.OATHCredentialInfo) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.creds[cred.ID] = cred
	m.added = append(m.added, cred)
	return nil
}

func (m *mockOATHAccessor) Update(cred *backup.OATHCredentialInfo) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.creds[cred.ID] = cred
	m.updated = append(m.updated, cred)
	return nil
}

type mockPasswordAccessor struct {
	passwords map[string]*backup.PasswordInfo
	listErr   error
	getErr    error
	addErr    error
	updateErr error
	added     []*backup.PasswordInfo
	updated   []*backup.PasswordInfo
}

func newMockPasswordAccessor() *mockPasswordAccessor {
	return &mockPasswordAccessor{
		passwords: make(map[string]*backup.PasswordInfo),
	}
}

func (m *mockPasswordAccessor) List() ([]*backup.PasswordInfo, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]*backup.PasswordInfo, 0, len(m.passwords))
	for _, p := range m.passwords {
		result = append(result, p)
	}
	return result, nil
}

func (m *mockPasswordAccessor) Get(id string) (*backup.PasswordInfo, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	p, ok := m.passwords[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return p, nil
}

func (m *mockPasswordAccessor) Add(pw *backup.PasswordInfo) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.passwords[pw.ID] = pw
	m.added = append(m.added, pw)
	return nil
}

func (m *mockPasswordAccessor) Update(pw *backup.PasswordInfo) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.passwords[pw.ID] = pw
	m.updated = append(m.updated, pw)
	return nil
}

type mockCAReader struct {
	certPEM  []byte
	chainPEM []byte
	certErr  error
	chainErr error
}

func (m *mockCAReader) GetCACertificatePEM() ([]byte, error) {
	if m.certErr != nil {
		return nil, m.certErr
	}
	return m.certPEM, nil
}

func (m *mockCAReader) GetCAChainPEM() ([]byte, error) {
	if m.chainErr != nil {
		return nil, m.chainErr
	}
	return m.chainPEM, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func testConfig() *Config {
	return &Config{DeviceName: "test-laptop"}
}

func testConfigWithState(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	return &Config{
		DeviceName:    "test-laptop",
		StateFilePath: filepath.Join(dir, "sync-state.json"),
	}
}

func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func testCertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

func testOATHCreds() []*backup.OATHCredentialInfo {
	return []*backup.OATHCredentialInfo{
		{
			ID: "oath-1", Name: "GitHub", Issuer: "GitHub",
			AccountName: "user@example.com", Secret: "JBSWY3DPEHPK3PXP",
			Type: "totp", Algorithm: "SHA1", Digits: 6, Period: 30,
		},
		{
			ID: "oath-2", Name: "AWS", Issuer: "Amazon",
			AccountName: "admin@corp.com", Secret: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			Type: "totp", Algorithm: "SHA256", Digits: 8, Period: 30,
		},
	}
}

func testPasswords() []*backup.PasswordInfo {
	return []*backup.PasswordInfo{
		{
			ID: "pw-1", Name: "Server SSH", Title: "Production Server",
			Username: "admin", Password: "s3cret!",
			URL: "ssh://prod.example.com", Notes: "Primary server",
			FolderPath: "/servers",
		},
		{
			ID: "pw-2", Name: "Database", Title: "Postgres Master",
			Username: "dbadmin", Password: "db-p@ss",
			URL:        "postgres://db.local:5432",
			FolderPath: "/databases",
		},
	}
}

// ---------------------------------------------------------------------------
// NewService tests
// ---------------------------------------------------------------------------

func TestNewService_NilConfig(t *testing.T) {
	svc, err := NewService(nil)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrNilConfig)
}

func TestNewService_ValidConfig(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "test-laptop", svc.config.DeviceName)
	assert.Nil(t, svc.trustStore)
	assert.Nil(t, svc.oath)
	assert.Nil(t, svc.passwords)
	assert.Nil(t, svc.caReader)
}

func TestNewService_WithOptions(t *testing.T) {
	ts := &mockTrustStoreAccessor{}
	oa := newMockOATHAccessor()
	pw := newMockPasswordAccessor()
	ca := &mockCAReader{}

	svc, err := NewService(testConfig(),
		WithTrustStore(ts),
		WithOATH(oa),
		WithPasswords(pw),
		WithCA(ca),
	)
	require.NoError(t, err)
	require.NotNil(t, svc)

	assert.Equal(t, ts, svc.trustStore)
	assert.Equal(t, oa, svc.oath)
	assert.Equal(t, pw, svc.passwords)
	assert.Equal(t, ca, svc.caReader)
}

// ---------------------------------------------------------------------------
// ComputeLocalTrustStoreDelta tests
// ---------------------------------------------------------------------------

func TestComputeLocalTrustStoreDelta_NilTrustStore(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	delta, err := svc.ComputeLocalTrustStoreDelta()
	assert.NoError(t, err)
	assert.Nil(t, delta)
}

func TestComputeLocalTrustStoreDelta_EmptyStore(t *testing.T) {
	ts := &mockTrustStoreAccessor{}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalTrustStoreDelta()
	require.NoError(t, err)
	require.NotNil(t, delta)
	assert.Empty(t, delta.Certificates)
}

func TestComputeLocalTrustStoreDelta_WithCerts(t *testing.T) {
	cert := testCert(t)
	fp := testCertFingerprint(cert)

	ts := &mockTrustStoreAccessor{
		certs: []*x509.Certificate{cert},
		meta: map[string]*backup.CertMetadataInfo{
			fp: {
				Fingerprint: fp,
				Purpose:     "tls-root",
				Source:      "manual",
				Tags:        []string{"production"},
			},
		},
	}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalTrustStoreDelta()
	require.NoError(t, err)
	require.NotNil(t, delta)
	require.Len(t, delta.Certificates, 1)

	assert.Equal(t, fp, delta.Certificates[0].Fingerprint)
	assert.Equal(t, "tls-root", delta.Certificates[0].Purpose)
	assert.Equal(t, "manual", delta.Certificates[0].Source)
	assert.Equal(t, []string{"production"}, delta.Certificates[0].Tags)
	assert.Contains(t, delta.Certificates[0].PEM, "BEGIN CERTIFICATE")
}

func TestComputeLocalTrustStoreDelta_CertificatesError(t *testing.T) {
	ts := &mockTrustStoreAccessor{
		certsErr: errors.New("storage offline"),
	}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalTrustStoreDelta()
	assert.Nil(t, delta)
	assert.ErrorIs(t, err, ErrTrustStoreSyncFailed)
}

func TestComputeLocalTrustStoreDelta_NoMetadata(t *testing.T) {
	cert := testCert(t)
	ts := &mockTrustStoreAccessor{
		certs: []*x509.Certificate{cert},
		meta:  nil,
	}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalTrustStoreDelta()
	require.NoError(t, err)
	require.Len(t, delta.Certificates, 1)
	assert.Empty(t, delta.Certificates[0].Purpose)
	assert.Empty(t, delta.Certificates[0].Source)
}

// ---------------------------------------------------------------------------
// ComputeLocalOATHDelta tests
// ---------------------------------------------------------------------------

func TestComputeLocalOATHDelta_NilAccessor(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	delta, err := svc.ComputeLocalOATHDelta()
	assert.NoError(t, err)
	assert.Nil(t, delta)
}

func TestComputeLocalOATHDelta_WithCreds(t *testing.T) {
	oa := newMockOATHAccessor()
	for _, c := range testOATHCreds() {
		oa.creds[c.ID] = c
	}

	svc, err := NewService(testConfig(), WithOATH(oa))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalOATHDelta()
	require.NoError(t, err)
	require.NotNil(t, delta)
	assert.Len(t, delta.Credentials, 2)

	ids := make(map[string]bool)
	for _, c := range delta.Credentials {
		ids[c.ID] = true
	}
	assert.True(t, ids["oath-1"])
	assert.True(t, ids["oath-2"])
}

func TestComputeLocalOATHDelta_ListError(t *testing.T) {
	oa := newMockOATHAccessor()
	oa.listErr = errors.New("db locked")

	svc, err := NewService(testConfig(), WithOATH(oa))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalOATHDelta()
	assert.Nil(t, delta)
	assert.ErrorIs(t, err, ErrOATHSyncFailed)
}

// ---------------------------------------------------------------------------
// ComputeLocalPasswordDelta tests
// ---------------------------------------------------------------------------

func TestComputeLocalPasswordDelta_NilAccessor(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	delta, err := svc.ComputeLocalPasswordDelta()
	assert.NoError(t, err)
	assert.Nil(t, delta)
}

func TestComputeLocalPasswordDelta_WithPasswords(t *testing.T) {
	pw := newMockPasswordAccessor()
	for _, p := range testPasswords() {
		pw.passwords[p.ID] = p
	}

	svc, err := NewService(testConfig(), WithPasswords(pw))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalPasswordDelta()
	require.NoError(t, err)
	require.NotNil(t, delta)
	assert.Len(t, delta.Passwords, 2)

	ids := make(map[string]bool)
	for _, p := range delta.Passwords {
		ids[p.ID] = true
	}
	assert.True(t, ids["pw-1"])
	assert.True(t, ids["pw-2"])
}

func TestComputeLocalPasswordDelta_ListError(t *testing.T) {
	pw := newMockPasswordAccessor()
	pw.listErr = errors.New("vault sealed")

	svc, err := NewService(testConfig(), WithPasswords(pw))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalPasswordDelta()
	assert.Nil(t, delta)
	assert.ErrorIs(t, err, ErrPasswordSyncFailed)
}

// ---------------------------------------------------------------------------
// ComputeLocalCADelta tests
// ---------------------------------------------------------------------------

func TestComputeLocalCADelta_NilCAReader(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	delta, err := svc.ComputeLocalCADelta()
	assert.NoError(t, err)
	assert.Nil(t, delta)
}

func TestComputeLocalCADelta_WithCert(t *testing.T) {
	ca := &mockCAReader{
		certPEM:  []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"),
		chainPEM: []byte("-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n"),
	}
	svc, err := NewService(testConfig(), WithCA(ca))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalCADelta()
	require.NoError(t, err)
	require.NotNil(t, delta)
	assert.Contains(t, delta.CACertPEM, "CA")
	assert.Contains(t, delta.CAChainPEM, "CHAIN")
}

func TestComputeLocalCADelta_EmptyCert(t *testing.T) {
	ca := &mockCAReader{certPEM: []byte{}}
	svc, err := NewService(testConfig(), WithCA(ca))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalCADelta()
	require.NoError(t, err)
	require.NotNil(t, delta)
	assert.Empty(t, delta.CACertPEM)
}

func TestComputeLocalCADelta_CertError(t *testing.T) {
	ca := &mockCAReader{certErr: errors.New("ca unavailable")}
	svc, err := NewService(testConfig(), WithCA(ca))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalCADelta()
	assert.Nil(t, delta)
	assert.ErrorIs(t, err, ErrCASyncFailed)
}

func TestComputeLocalCADelta_ChainError(t *testing.T) {
	ca := &mockCAReader{
		certPEM:  []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"),
		chainErr: errors.New("chain unavailable"),
	}
	svc, err := NewService(testConfig(), WithCA(ca))
	require.NoError(t, err)

	delta, err := svc.ComputeLocalCADelta()
	require.NoError(t, err)
	require.NotNil(t, delta)
	assert.Contains(t, delta.CACertPEM, "CA")
	assert.Empty(t, delta.CAChainPEM)
}

// ---------------------------------------------------------------------------
// ApplyTrustStoreDelta tests
// ---------------------------------------------------------------------------

func TestApplyTrustStoreDelta_NilDelta(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.ApplyTrustStoreDelta(nil)
	require.NoError(t, err)
	assert.Equal(t, DataTypeTrustStore, result.DataType)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 0, result.Skipped)
}

func TestApplyTrustStoreDelta_EmptyDelta(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.ApplyTrustStoreDelta(&TrustStoreDelta{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
}

func TestApplyTrustStoreDelta_NoAccessor(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	delta := &TrustStoreDelta{
		Certificates: []TrustStoreCertSync{
			{PEM: "cert", Fingerprint: "fp1"},
		},
	}
	result, err := svc.ApplyTrustStoreDelta(delta)
	assert.ErrorIs(t, err, ErrTrustStoreSyncFailed)
	assert.NotNil(t, result)
	assert.Len(t, result.Errors, 1)
}

func TestApplyTrustStoreDelta_NewCertsAdded(t *testing.T) {
	ts := &mockTrustStoreAccessor{
		contains: map[string]bool{},
	}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta := &TrustStoreDelta{
		Certificates: []TrustStoreCertSync{
			{PEM: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n", Fingerprint: "fp1"},
			{PEM: "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n", Fingerprint: "fp2"},
		},
	}

	result, err := svc.ApplyTrustStoreDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 2, result.Added)
	assert.Equal(t, 0, result.Skipped)
	assert.Empty(t, result.Errors)
	assert.Len(t, ts.addedPEM, 2)
}

func TestApplyTrustStoreDelta_DuplicatesSkipped(t *testing.T) {
	ts := &mockTrustStoreAccessor{
		contains: map[string]bool{"fp1": true, "fp2": true},
	}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta := &TrustStoreDelta{
		Certificates: []TrustStoreCertSync{
			{PEM: "cert1", Fingerprint: "fp1"},
			{PEM: "cert2", Fingerprint: "fp2"},
		},
	}

	result, err := svc.ApplyTrustStoreDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 2, result.Skipped)
	assert.Empty(t, ts.addedPEM)
}

func TestApplyTrustStoreDelta_EmptyPEMSkipped(t *testing.T) {
	ts := &mockTrustStoreAccessor{
		contains: map[string]bool{},
	}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta := &TrustStoreDelta{
		Certificates: []TrustStoreCertSync{
			{PEM: "", Fingerprint: "fp-empty"},
		},
	}

	result, err := svc.ApplyTrustStoreDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 1, result.Skipped)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "empty PEM data")
}

func TestApplyTrustStoreDelta_ContainsError(t *testing.T) {
	ts := &mockTrustStoreAccessor{
		containErr: errors.New("storage error"),
	}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta := &TrustStoreDelta{
		Certificates: []TrustStoreCertSync{
			{PEM: "cert1", Fingerprint: "fp1"},
		},
	}

	result, err := svc.ApplyTrustStoreDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 1, result.Skipped)
	assert.Len(t, result.Errors, 1)
}

func TestApplyTrustStoreDelta_AddPEMError(t *testing.T) {
	ts := &mockTrustStoreAccessor{
		contains:  map[string]bool{},
		addPEMErr: errors.New("write failed"),
	}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta := &TrustStoreDelta{
		Certificates: []TrustStoreCertSync{
			{PEM: "cert1", Fingerprint: "fp1"},
		},
	}

	result, err := svc.ApplyTrustStoreDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 1, result.Skipped)
	assert.Len(t, result.Errors, 1)
}

func TestApplyTrustStoreDelta_MixedNewAndDuplicate(t *testing.T) {
	ts := &mockTrustStoreAccessor{
		contains: map[string]bool{"fp-existing": true},
	}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta := &TrustStoreDelta{
		Certificates: []TrustStoreCertSync{
			{PEM: "cert-new", Fingerprint: "fp-new"},
			{PEM: "cert-existing", Fingerprint: "fp-existing"},
			{PEM: "cert-new2", Fingerprint: "fp-new2"},
		},
	}

	result, err := svc.ApplyTrustStoreDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 2, result.Added)
	assert.Equal(t, 1, result.Skipped)
}

// ---------------------------------------------------------------------------
// ApplyOATHDelta tests
// ---------------------------------------------------------------------------

func TestApplyOATHDelta_NilDelta(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.ApplyOATHDelta(nil)
	require.NoError(t, err)
	assert.Equal(t, DataTypeOATH, result.DataType)
	assert.Equal(t, 0, result.Added)
}

func TestApplyOATHDelta_EmptyDelta(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.ApplyOATHDelta(&OATHDelta{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
}

func TestApplyOATHDelta_NoAccessor(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	delta := &OATHDelta{
		Credentials: []OATHCredentialSync{
			{ID: "c1", Name: "Test"},
		},
	}
	result, err := svc.ApplyOATHDelta(delta)
	assert.ErrorIs(t, err, ErrOATHSyncFailed)
	assert.NotNil(t, result)
}

func TestApplyOATHDelta_NewCredsAdded(t *testing.T) {
	oa := newMockOATHAccessor()
	svc, err := NewService(testConfig(), WithOATH(oa))
	require.NoError(t, err)

	delta := &OATHDelta{
		Credentials: []OATHCredentialSync{
			{
				ID: "oath-1", Name: "GitHub", Issuer: "GitHub",
				AccountName: "user@example.com", Secret: "JBSWY3DPEHPK3PXP",
				Type: "totp", Algorithm: "SHA1", Digits: 6, Period: 30,
				UpdatedAt: time.Now(),
			},
		},
	}

	result, err := svc.ApplyOATHDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Added)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 0, result.Skipped)
	assert.Len(t, oa.added, 1)
	assert.Equal(t, "GitHub", oa.added[0].Name)
}

func TestApplyOATHDelta_ExistingUpdatedWhenRemoteNewer(t *testing.T) {
	oa := newMockOATHAccessor()
	oa.creds["oath-1"] = &backup.OATHCredentialInfo{
		ID: "oath-1", Name: "GitHub", Secret: "OLD_SECRET",
	}

	svc, err := NewService(testConfig(), WithOATH(oa))
	require.NoError(t, err)

	delta := &OATHDelta{
		Credentials: []OATHCredentialSync{
			{
				ID: "oath-1", Name: "GitHub Updated", Secret: "NEW_SECRET",
				Type: "totp", Algorithm: "SHA1", Digits: 6, Period: 30,
				UpdatedAt: time.Now(),
			},
		},
	}

	result, err := svc.ApplyOATHDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 1, result.Updated)
	assert.Equal(t, 0, result.Skipped)
	assert.Len(t, oa.updated, 1)
	assert.Equal(t, "GitHub Updated", oa.updated[0].Name)
}

func TestApplyOATHDelta_ExistingSkippedWhenZeroTimestamp(t *testing.T) {
	oa := newMockOATHAccessor()
	oa.creds["oath-1"] = &backup.OATHCredentialInfo{
		ID: "oath-1", Name: "GitHub", Secret: "LOCAL_SECRET",
	}

	svc, err := NewService(testConfig(), WithOATH(oa))
	require.NoError(t, err)

	delta := &OATHDelta{
		Credentials: []OATHCredentialSync{
			{
				ID: "oath-1", Name: "GitHub Remote", Secret: "REMOTE_SECRET",
				Type: "totp", Algorithm: "SHA1", Digits: 6, Period: 30,
				// UpdatedAt is zero
			},
		},
	}

	result, err := svc.ApplyOATHDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 1, result.Skipped)
}

func TestApplyOATHDelta_AddError(t *testing.T) {
	oa := newMockOATHAccessor()
	oa.addErr = errors.New("storage full")

	svc, err := NewService(testConfig(), WithOATH(oa))
	require.NoError(t, err)

	delta := &OATHDelta{
		Credentials: []OATHCredentialSync{
			{ID: "c1", Name: "Test", UpdatedAt: time.Now()},
		},
	}

	result, err := svc.ApplyOATHDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 1, result.Skipped)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "add")
}

func TestApplyOATHDelta_UpdateError(t *testing.T) {
	oa := newMockOATHAccessor()
	oa.creds["c1"] = &backup.OATHCredentialInfo{ID: "c1", Name: "Existing"}
	oa.updateErr = errors.New("update failed")

	svc, err := NewService(testConfig(), WithOATH(oa))
	require.NoError(t, err)

	delta := &OATHDelta{
		Credentials: []OATHCredentialSync{
			{ID: "c1", Name: "Updated", UpdatedAt: time.Now()},
		},
	}

	result, err := svc.ApplyOATHDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 1, result.Skipped)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "update")
}

// ---------------------------------------------------------------------------
// ApplyPasswordDelta tests
// ---------------------------------------------------------------------------

func TestApplyPasswordDelta_NilDelta(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.ApplyPasswordDelta(nil)
	require.NoError(t, err)
	assert.Equal(t, DataTypePasswords, result.DataType)
	assert.Equal(t, 0, result.Added)
}

func TestApplyPasswordDelta_EmptyDelta(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.ApplyPasswordDelta(&PasswordDelta{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
}

func TestApplyPasswordDelta_NoAccessor(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	delta := &PasswordDelta{
		Passwords: []PasswordSync{
			{ID: "p1", Name: "Test", Password: "secret"},
		},
	}
	result, err := svc.ApplyPasswordDelta(delta)
	assert.ErrorIs(t, err, ErrPasswordSyncFailed)
	assert.NotNil(t, result)
}

func TestApplyPasswordDelta_NewPasswordsAdded(t *testing.T) {
	pw := newMockPasswordAccessor()
	svc, err := NewService(testConfig(), WithPasswords(pw))
	require.NoError(t, err)

	delta := &PasswordDelta{
		Passwords: []PasswordSync{
			{
				ID: "pw-1", Name: "Server SSH", Password: "s3cret!",
				Username: "admin", UpdatedAt: time.Now(),
			},
		},
	}

	result, err := svc.ApplyPasswordDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Added)
	assert.Equal(t, 0, result.Updated)
	assert.Len(t, pw.added, 1)
	assert.Equal(t, "Server SSH", pw.added[0].Name)
}

func TestApplyPasswordDelta_ExistingUpdatedWhenRemoteNewer(t *testing.T) {
	pw := newMockPasswordAccessor()
	pw.passwords["pw-1"] = &backup.PasswordInfo{
		ID: "pw-1", Name: "Server SSH", Password: "old-pass",
	}

	svc, err := NewService(testConfig(), WithPasswords(pw))
	require.NoError(t, err)

	delta := &PasswordDelta{
		Passwords: []PasswordSync{
			{
				ID: "pw-1", Name: "Server SSH Updated", Password: "new-pass",
				UpdatedAt: time.Now(),
			},
		},
	}

	result, err := svc.ApplyPasswordDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 1, result.Updated)
	assert.Len(t, pw.updated, 1)
	assert.Equal(t, "Server SSH Updated", pw.updated[0].Name)
}

func TestApplyPasswordDelta_ExistingSkippedWhenZeroTimestamp(t *testing.T) {
	pw := newMockPasswordAccessor()
	pw.passwords["pw-1"] = &backup.PasswordInfo{
		ID: "pw-1", Name: "Server SSH", Password: "local-pass",
	}

	svc, err := NewService(testConfig(), WithPasswords(pw))
	require.NoError(t, err)

	delta := &PasswordDelta{
		Passwords: []PasswordSync{
			{
				ID: "pw-1", Name: "Remote SSH", Password: "remote-pass",
				// UpdatedAt is zero
			},
		},
	}

	result, err := svc.ApplyPasswordDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 1, result.Skipped)
}

func TestApplyPasswordDelta_AddError(t *testing.T) {
	pw := newMockPasswordAccessor()
	pw.addErr = errors.New("storage full")

	svc, err := NewService(testConfig(), WithPasswords(pw))
	require.NoError(t, err)

	delta := &PasswordDelta{
		Passwords: []PasswordSync{
			{ID: "p1", Name: "Test", Password: "pass", UpdatedAt: time.Now()},
		},
	}

	result, err := svc.ApplyPasswordDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 1, result.Skipped)
	assert.Len(t, result.Errors, 1)
}

func TestApplyPasswordDelta_UpdateError(t *testing.T) {
	pw := newMockPasswordAccessor()
	pw.passwords["p1"] = &backup.PasswordInfo{ID: "p1", Name: "Existing"}
	pw.updateErr = errors.New("update failed")

	svc, err := NewService(testConfig(), WithPasswords(pw))
	require.NoError(t, err)

	delta := &PasswordDelta{
		Passwords: []PasswordSync{
			{ID: "p1", Name: "Updated", Password: "pass", UpdatedAt: time.Now()},
		},
	}

	result, err := svc.ApplyPasswordDelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 1, result.Skipped)
	assert.Len(t, result.Errors, 1)
}

// ---------------------------------------------------------------------------
// ApplyCADelta tests
// ---------------------------------------------------------------------------

func TestApplyCADelta_NilDelta(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.ApplyCADelta(nil)
	require.NoError(t, err)
	assert.Equal(t, DataTypeCA, result.DataType)
	assert.Equal(t, 0, result.Added)
}

func TestApplyCADelta_EmptyCertPEM(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.ApplyCADelta(&CADelta{CACertPEM: ""})
	require.NoError(t, err)
	assert.Equal(t, 0, result.Added)
}

func TestApplyCADelta_NoAccessor(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	delta := &CADelta{CACertPEM: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"}
	result, err := svc.ApplyCADelta(delta)
	assert.ErrorIs(t, err, ErrCASyncFailed)
	assert.NotNil(t, result)
}

func TestApplyCADelta_CertAddedToTrustStore(t *testing.T) {
	ts := &mockTrustStoreAccessor{}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta := &CADelta{
		CACertPEM: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
	}

	result, err := svc.ApplyCADelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Added)
	assert.Len(t, ts.addedPEM, 1)
}

func TestApplyCADelta_CertAndChain(t *testing.T) {
	ts := &mockTrustStoreAccessor{}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta := &CADelta{
		CACertPEM:  "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
		CAChainPEM: "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n",
	}

	result, err := svc.ApplyCADelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 2, result.Added)
	assert.Len(t, ts.addedPEM, 2)
}

func TestApplyCADelta_CertAddError(t *testing.T) {
	ts := &mockTrustStoreAccessor{
		addPEMErr: errors.New("cert add failed"),
	}
	svc, err := NewService(testConfig(), WithTrustStore(ts))
	require.NoError(t, err)

	delta := &CADelta{
		CACertPEM: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
	}

	result, err := svc.ApplyCADelta(delta)
	require.NoError(t, err) // graceful error, not returned
	assert.Equal(t, 0, result.Added)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "ca cert")
}

func TestApplyCADelta_ChainAddError(t *testing.T) {
	callCount := 0
	ts := &mockTrustStoreAccessor{}
	// Override AddPEM to fail on second call (chain)
	origAddPEM := ts.AddPEM
	_ = origAddPEM // We need a different approach since mock fields are simple

	// Use a custom accessor that fails on the second AddPEM call.
	customTS := &countingTrustStoreAccessor{
		contains: map[string]bool{},
		addFunc: func(pemData []byte) (int, error) {
			callCount++
			if callCount == 2 {
				return 0, errors.New("chain add failed")
			}
			return 1, nil
		},
	}

	svc, err := NewService(testConfig(), WithTrustStore(customTS))
	require.NoError(t, err)

	delta := &CADelta{
		CACertPEM:  "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
		CAChainPEM: "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n",
	}

	result, err := svc.ApplyCADelta(delta)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Added) // cert succeeded, chain failed
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "ca chain")
}

// countingTrustStoreAccessor provides custom AddPEM behavior for testing.
type countingTrustStoreAccessor struct {
	contains map[string]bool
	addFunc  func(pemData []byte) (int, error)
}

func (c *countingTrustStoreAccessor) Certificates() ([]*x509.Certificate, error) {
	return nil, nil
}

func (c *countingTrustStoreAccessor) Metadata(_ string) (*backup.CertMetadataInfo, error) {
	return nil, errors.New("not implemented")
}

func (c *countingTrustStoreAccessor) Contains(fingerprint string) (bool, error) {
	return c.contains[fingerprint], nil
}

func (c *countingTrustStoreAccessor) AddPEM(pemData []byte) (int, error) {
	return c.addFunc(pemData)
}

// ---------------------------------------------------------------------------
// State management tests
// ---------------------------------------------------------------------------

func TestSaveState_LoadState_RoundTrip(t *testing.T) {
	cfg := testConfigWithState(t)
	svc, err := NewService(cfg)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	state := &SyncState{
		LastSync: now,
		DeviceID: "android-phone-1",
		StoreChecksums: map[string]string{
			DataTypeTrustStore: "abc123",
			DataTypeOATH:       "def456",
		},
	}

	err = svc.SaveState(state)
	require.NoError(t, err)

	loaded, err := svc.LoadState()
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, state.DeviceID, loaded.DeviceID)
	assert.WithinDuration(t, state.LastSync, loaded.LastSync, time.Second)
	assert.Equal(t, state.StoreChecksums[DataTypeTrustStore], loaded.StoreChecksums[DataTypeTrustStore])
	assert.Equal(t, state.StoreChecksums[DataTypeOATH], loaded.StoreChecksums[DataTypeOATH])
}

func TestLoadState_MissingFile(t *testing.T) {
	cfg := &Config{
		DeviceName:    "test",
		StateFilePath: filepath.Join(t.TempDir(), "nonexistent", "state.json"),
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)

	state, err := svc.LoadState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.LastSync.IsZero())
	assert.NotNil(t, state.StoreChecksums)
}

func TestLoadState_EmptyPath(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	state, err := svc.LoadState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.NotNil(t, state.StoreChecksums)
}

func TestSaveState_EmptyPath(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	err = svc.SaveState(&SyncState{})
	assert.NoError(t, err) // no-op for empty path
}

func TestLoadState_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	err := os.WriteFile(statePath, []byte("not-json{{{"), 0600)
	require.NoError(t, err)

	cfg := &Config{
		DeviceName:    "test",
		StateFilePath: statePath,
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)

	state, err := svc.LoadState()
	assert.Nil(t, state)
	assert.ErrorIs(t, err, ErrStateLoad)
}

func TestLoadState_NilChecksums(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	// Write valid JSON but with null checksums
	data := `{"last_sync":"2025-01-01T00:00:00Z","device_id":"test","store_checksums":null}`
	err := os.WriteFile(statePath, []byte(data), 0600)
	require.NoError(t, err)

	cfg := &Config{
		DeviceName:    "test",
		StateFilePath: statePath,
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)

	state, err := svc.LoadState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.NotNil(t, state.StoreChecksums) // should be initialized
}

func TestSaveState_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "nested", "deep", "state.json")

	cfg := &Config{
		DeviceName:    "test",
		StateFilePath: statePath,
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)

	state := &SyncState{
		LastSync:       time.Now().UTC(),
		DeviceID:       "phone",
		StoreChecksums: map[string]string{"x": "y"},
	}

	err = svc.SaveState(state)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(statePath)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Checksum helper tests
// ---------------------------------------------------------------------------

func TestComputeChecksum(t *testing.T) {
	data := []byte("hello world")
	checksum := computeChecksum(data)

	// SHA-256 of "hello world"
	expected := sha256.Sum256(data)
	assert.Equal(t, hex.EncodeToString(expected[:]), checksum)
	assert.Len(t, checksum, 64) // 256 bits = 64 hex chars
}

func TestComputeChecksum_DeterministicOutput(t *testing.T) {
	data := []byte("deterministic input")
	cs1 := computeChecksum(data)
	cs2 := computeChecksum(data)
	assert.Equal(t, cs1, cs2)
}

func TestComputeChecksum_DifferentInputsDifferentOutput(t *testing.T) {
	cs1 := computeChecksum([]byte("input1"))
	cs2 := computeChecksum([]byte("input2"))
	assert.NotEqual(t, cs1, cs2)
}

// ---------------------------------------------------------------------------
// SyncResult helper tests
// ---------------------------------------------------------------------------

func TestSyncResult_TotalAdded(t *testing.T) {
	r := &SyncResult{
		Items: []SyncItemResult{
			{DataType: DataTypeTrustStore, Added: 3},
			{DataType: DataTypeOATH, Added: 2},
			{DataType: DataTypePasswords, Added: 1},
		},
	}
	assert.Equal(t, 6, r.TotalAdded())
}

func TestSyncResult_TotalUpdated(t *testing.T) {
	r := &SyncResult{
		Items: []SyncItemResult{
			{DataType: DataTypeTrustStore, Updated: 0},
			{DataType: DataTypeOATH, Updated: 5},
			{DataType: DataTypePasswords, Updated: 3},
		},
	}
	assert.Equal(t, 8, r.TotalUpdated())
}

func TestSyncResult_TotalSkipped(t *testing.T) {
	r := &SyncResult{
		Items: []SyncItemResult{
			{DataType: DataTypeTrustStore, Skipped: 10},
			{DataType: DataTypeOATH, Skipped: 0},
		},
	}
	assert.Equal(t, 10, r.TotalSkipped())
}

func TestSyncResult_HasConflicts(t *testing.T) {
	r := &SyncResult{}
	assert.False(t, r.HasConflicts())

	r.Conflicts = []SyncConflict{
		{DataType: DataTypeOATH, ItemID: "c1", Resolution: "local-wins"},
	}
	assert.True(t, r.HasConflicts())
}

func TestSyncResult_EmptyItems(t *testing.T) {
	r := &SyncResult{}
	assert.Equal(t, 0, r.TotalAdded())
	assert.Equal(t, 0, r.TotalUpdated())
	assert.Equal(t, 0, r.TotalSkipped())
}

// ---------------------------------------------------------------------------
// Type tests
// ---------------------------------------------------------------------------

func TestSyncScopeAll(t *testing.T) {
	scope := SyncScopeAll()
	assert.True(t, scope.TrustStore)
	assert.True(t, scope.OATH)
	assert.True(t, scope.Passwords)
	assert.True(t, scope.CA)
}

func TestSyncScope_DefaultsToFalse(t *testing.T) {
	scope := SyncScope{}
	assert.False(t, scope.TrustStore)
	assert.False(t, scope.OATH)
	assert.False(t, scope.Passwords)
	assert.False(t, scope.CA)
}

// ---------------------------------------------------------------------------
// JSON serialization round-trip tests
// ---------------------------------------------------------------------------

func TestTrustStoreDelta_JSONRoundTrip(t *testing.T) {
	delta := &TrustStoreDelta{
		Certificates: []TrustStoreCertSync{
			{
				PEM:         "-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----\n",
				Fingerprint: "abc123",
				Purpose:     "tls-root",
				Source:      "manual",
				Tags:        []string{"production", "primary"},
			},
		},
	}

	data, err := json.Marshal(delta)
	require.NoError(t, err)

	var restored TrustStoreDelta
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	require.Len(t, restored.Certificates, 1)
	assert.Equal(t, delta.Certificates[0].Fingerprint, restored.Certificates[0].Fingerprint)
	assert.Equal(t, delta.Certificates[0].Purpose, restored.Certificates[0].Purpose)
	assert.Equal(t, delta.Certificates[0].Tags, restored.Certificates[0].Tags)
}

func TestOATHDelta_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	delta := &OATHDelta{
		Credentials: []OATHCredentialSync{
			{
				ID: "oath-1", Name: "GitHub", Issuer: "GitHub",
				AccountName: "user@example.com", Secret: "JBSWY3DPEHPK3PXP",
				Type: "totp", Algorithm: "SHA1", Digits: 6, Period: 30,
				Counter: 0, UpdatedAt: now,
			},
		},
	}

	data, err := json.Marshal(delta)
	require.NoError(t, err)

	var restored OATHDelta
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	require.Len(t, restored.Credentials, 1)
	assert.Equal(t, "oath-1", restored.Credentials[0].ID)
	assert.Equal(t, "GitHub", restored.Credentials[0].Name)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", restored.Credentials[0].Secret)
	assert.Equal(t, now, restored.Credentials[0].UpdatedAt)
}

func TestPasswordDelta_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	delta := &PasswordDelta{
		Passwords: []PasswordSync{
			{
				ID: "pw-1", Name: "Server SSH", Title: "Production",
				Username: "admin", Password: "s3cret!",
				URL: "ssh://prod.example.com", Notes: "Primary",
				FolderPath: "/servers", UpdatedAt: now,
			},
		},
	}

	data, err := json.Marshal(delta)
	require.NoError(t, err)

	var restored PasswordDelta
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	require.Len(t, restored.Passwords, 1)
	assert.Equal(t, "pw-1", restored.Passwords[0].ID)
	assert.Equal(t, "s3cret!", restored.Passwords[0].Password)
	assert.Equal(t, now, restored.Passwords[0].UpdatedAt)
}

func TestCADelta_JSONRoundTrip(t *testing.T) {
	delta := &CADelta{
		CACertPEM:  "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
		CAChainPEM: "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n",
	}

	data, err := json.Marshal(delta)
	require.NoError(t, err)

	var restored CADelta
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, delta.CACertPEM, restored.CACertPEM)
	assert.Equal(t, delta.CAChainPEM, restored.CAChainPEM)
}

func TestSyncState_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := &SyncState{
		LastSync: now,
		DeviceID: "android-phone-1",
		StoreChecksums: map[string]string{
			DataTypeTrustStore: "checksum1",
			DataTypeOATH:       "checksum2",
			DataTypePasswords:  "checksum3",
			DataTypeCA:         "checksum4",
		},
	}

	data, err := json.Marshal(state)
	require.NoError(t, err)

	var restored SyncState
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, state.DeviceID, restored.DeviceID)
	assert.Equal(t, state.LastSync, restored.LastSync)
	assert.Equal(t, len(state.StoreChecksums), len(restored.StoreChecksums))
	for k, v := range state.StoreChecksums {
		assert.Equal(t, v, restored.StoreChecksums[k])
	}
}

func TestSyncScope_JSONRoundTrip(t *testing.T) {
	scope := SyncScopeAll()
	data, err := json.Marshal(scope)
	require.NoError(t, err)

	var restored SyncScope
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, scope, restored)
}

func TestSyncConflict_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	conflict := SyncConflict{
		DataType:   DataTypeOATH,
		ItemID:     "oath-1",
		LocalTime:  now.Add(-time.Hour),
		RemoteTime: now,
		Resolution: "remote-wins",
	}

	data, err := json.Marshal(conflict)
	require.NoError(t, err)

	var restored SyncConflict
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, conflict.DataType, restored.DataType)
	assert.Equal(t, conflict.ItemID, restored.ItemID)
	assert.Equal(t, conflict.Resolution, restored.Resolution)
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestCertFingerprint(t *testing.T) {
	cert := testCert(t)
	fp := certFingerprint(cert)

	// SHA-256 fingerprint should be 64 hex chars.
	assert.Len(t, fp, 64)
	_, err := hex.DecodeString(fp)
	assert.NoError(t, err)

	// Same cert produces same fingerprint.
	assert.Equal(t, fp, certFingerprint(cert))
}

func TestCertFingerprint_DifferentCerts(t *testing.T) {
	cert1 := testCert(t)
	cert2 := testCert(t) // different key, different serial
	fp1 := certFingerprint(cert1)
	fp2 := certFingerprint(cert2)
	assert.NotEqual(t, fp1, fp2)
}

func TestEncodeCertPEM(t *testing.T) {
	cert := testCert(t)
	pemStr := encodeCertPEM(cert)
	assert.Contains(t, pemStr, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, pemStr, "-----END CERTIFICATE-----")
}

func TestOATHSyncToInfo(t *testing.T) {
	cs := &OATHCredentialSync{
		ID: "oath-1", Name: "GitHub", Issuer: "GitHub",
		AccountName: "user@example.com", Secret: "SECRET",
		Type: "totp", Algorithm: "SHA256", Digits: 8, Period: 60,
		Counter: 42,
	}

	info := oathSyncToInfo(cs)
	assert.Equal(t, cs.ID, info.ID)
	assert.Equal(t, cs.Name, info.Name)
	assert.Equal(t, cs.Issuer, info.Issuer)
	assert.Equal(t, cs.AccountName, info.AccountName)
	assert.Equal(t, cs.Secret, info.Secret)
	assert.Equal(t, cs.Type, info.Type)
	assert.Equal(t, cs.Algorithm, info.Algorithm)
	assert.Equal(t, cs.Digits, info.Digits)
	assert.Equal(t, cs.Period, info.Period)
	assert.Equal(t, cs.Counter, info.Counter)
}

func TestPasswordSyncToInfo(t *testing.T) {
	ps := &PasswordSync{
		ID: "pw-1", Name: "Server SSH", Title: "Production",
		Username: "admin", Password: "s3cret!",
		URL: "ssh://prod.example.com", Notes: "Primary",
		FolderPath: "/servers",
	}

	info := passwordSyncToInfo(ps)
	assert.Equal(t, ps.ID, info.ID)
	assert.Equal(t, ps.Name, info.Name)
	assert.Equal(t, ps.Title, info.Title)
	assert.Equal(t, ps.Username, info.Username)
	assert.Equal(t, ps.Password, info.Password)
	assert.Equal(t, ps.URL, info.URL)
	assert.Equal(t, ps.Notes, info.Notes)
	assert.Equal(t, ps.FolderPath, info.FolderPath)
}

// ---------------------------------------------------------------------------
// Direction constants test
// ---------------------------------------------------------------------------

func TestSyncDirectionConstants(t *testing.T) {
	assert.Equal(t, SyncDirection("bidirectional"), SyncBidirectional)
	assert.Equal(t, SyncDirection("push"), SyncPush)
	assert.Equal(t, SyncDirection("pull"), SyncPull)
}

// ---------------------------------------------------------------------------
// Data type constants test
// ---------------------------------------------------------------------------

func TestDataTypeConstants(t *testing.T) {
	assert.Equal(t, "trust-store", DataTypeTrustStore)
	assert.Equal(t, "oath-credentials", DataTypeOATH)
	assert.Equal(t, "static-passwords", DataTypePasswords)
	assert.Equal(t, "ca-data", DataTypeCA)
}

// ---------------------------------------------------------------------------
// Error sentinel tests
// ---------------------------------------------------------------------------

func TestErrorSentinels(t *testing.T) {
	sentinels := []error{
		ErrNilConfig,
		ErrNoDataSources,
		ErrSyncFailed,
		ErrTrustStoreSyncFailed,
		ErrOATHSyncFailed,
		ErrPasswordSyncFailed,
		ErrCASyncFailed,
		ErrConflictDetected,
		ErrMergeConflict,
		ErrRemoteUnavailable,
		ErrNilDelta,
		ErrStateSave,
		ErrStateLoad,
	}

	for _, sentinel := range sentinels {
		assert.NotNil(t, sentinel)
		assert.NotEmpty(t, sentinel.Error())
	}

	// Verify uniqueness.
	seen := make(map[string]bool, len(sentinels))
	for _, sentinel := range sentinels {
		msg := sentinel.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}
