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

package backup

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockTrustStore struct {
	certs []*x509.Certificate
	meta  map[string]*CertMetadataInfo
	err   error
}

func (m *mockTrustStore) Certificates() ([]*x509.Certificate, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.certs, nil
}

func (m *mockTrustStore) Metadata(fingerprint string) (*CertMetadataInfo, error) {
	if m.meta == nil {
		return nil, errors.New("no metadata")
	}
	info, ok := m.meta[fingerprint]
	if !ok {
		return nil, errors.New("metadata not found")
	}
	return info, nil
}

type mockOATHReader struct {
	creds []*OATHCredentialInfo
	err   error
}

func (m *mockOATHReader) List() ([]*OATHCredentialInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.creds, nil
}

type mockPasswordReader struct {
	passwords []*PasswordInfo
	err       error
}

func (m *mockPasswordReader) List() ([]*PasswordInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.passwords, nil
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

type mockTrustStoreWriter struct {
	added [][]byte
	err   error
}

func (m *mockTrustStoreWriter) AddPEM(pemData []byte) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	m.added = append(m.added, pemData)
	return 1, nil
}

type mockOATHWriter struct {
	creds []*OATHCredentialInfo
	err   error
}

func (m *mockOATHWriter) Add(cred *OATHCredentialInfo) error {
	if m.err != nil {
		return m.err
	}
	m.creds = append(m.creds, cred)
	return nil
}

type mockPasswordWriter struct {
	passwords []*PasswordInfo
	err       error
}

func (m *mockPasswordWriter) Add(pw *PasswordInfo) error {
	if m.err != nil {
		return m.err
	}
	m.passwords = append(m.passwords, pw)
	return nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func testKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
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

func testConfig() *Config {
	return &Config{DeviceName: "test-device"}
}

func testOATHCreds() []*OATHCredentialInfo {
	return []*OATHCredentialInfo{
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

func testPasswords() []*PasswordInfo {
	return []*PasswordInfo{
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
// Tests
// ---------------------------------------------------------------------------

func TestNewService_NilConfig(t *testing.T) {
	svc, err := NewService(nil)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrNilConfig)
}

func TestNewService_WithOptions(t *testing.T) {
	ts := &mockTrustStore{}
	oa := &mockOATHReader{}
	pw := &mockPasswordReader{}
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
	assert.Equal(t, oa, svc.oathReader)
	assert.Equal(t, pw, svc.passwordReader)
	assert.Equal(t, ca, svc.caReader)
}

func TestNewService_NoOptions(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Nil(t, svc.trustStore)
	assert.Nil(t, svc.oathReader)
	assert.Nil(t, svc.passwordReader)
	assert.Nil(t, svc.caReader)
}

func TestCreateBackup_EmptyBackup(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	eb, err := svc.CreateBackup(testKey())
	assert.Nil(t, eb)
	assert.ErrorIs(t, err, ErrEmptyBackup)
}

func TestCreateBackup_EmptyBackup_NilSources(t *testing.T) {
	// All sources set but return empty data.
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{}),
		WithOATH(&mockOATHReader{}),
		WithPasswords(&mockPasswordReader{}),
		WithCA(&mockCAReader{}),
	)
	require.NoError(t, err)

	eb, err := svc.CreateBackup(testKey())
	assert.Nil(t, eb)
	assert.ErrorIs(t, err, ErrEmptyBackup)
}

func TestCreateBackup_TrustStoreOnly(t *testing.T) {
	cert := testCert(t)
	fp := testCertFingerprint(cert)

	ts := &mockTrustStore{
		certs: []*x509.Certificate{cert},
		meta: map[string]*CertMetadataInfo{
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

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)
	require.NotNil(t, eb)

	assert.Equal(t, BackupMagic, eb.Magic)
	assert.Equal(t, BackupVersion, eb.Version)
	assert.Len(t, eb.Nonce, 24)
	assert.NotEmpty(t, eb.Ciphertext)

	// Decrypt and verify.
	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err)
	require.NotNil(t, archive.TrustStore)
	assert.Len(t, archive.TrustStore.Certificates, 1)
	assert.Equal(t, fp, archive.TrustStore.Certificates[0].Fingerprint)
	assert.Equal(t, "tls-root", archive.TrustStore.Certificates[0].Purpose)
	assert.Equal(t, "manual", archive.TrustStore.Certificates[0].Source)
	assert.Equal(t, []string{"production"}, archive.TrustStore.Certificates[0].Tags)
}

func TestCreateBackup_AllSources(t *testing.T) {
	cert := testCert(t)
	fp := testCertFingerprint(cert)

	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
			meta: map[string]*CertMetadataInfo{
				fp: {Fingerprint: fp, Purpose: "ca-root", Source: "system"},
			},
		}),
		WithOATH(&mockOATHReader{creds: testOATHCreds()}),
		WithPasswords(&mockPasswordReader{passwords: testPasswords()}),
		WithCA(&mockCAReader{
			certPEM:  []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"),
			chainPEM: []byte("-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n"),
		}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err)

	assert.NotNil(t, archive.TrustStore)
	assert.Len(t, archive.TrustStore.Certificates, 1)

	assert.NotNil(t, archive.CAData)
	assert.Contains(t, archive.CAData.CACertPEM, "CA")
	assert.Contains(t, archive.CAData.CAChainPEM, "CHAIN")

	assert.Len(t, archive.OATHCreds, 2)
	assert.Equal(t, "GitHub", archive.OATHCreds[0].Name)
	assert.Equal(t, "AWS", archive.OATHCreds[1].Name)

	assert.Len(t, archive.Passwords, 2)
	assert.Equal(t, "Server SSH", archive.Passwords[0].Name)
	assert.Equal(t, "Database", archive.Passwords[1].Name)
}

func TestDecryptBackup_InvalidMagic(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	eb := &EncryptedBackup{
		Magic:   "BAAD",
		Version: BackupVersion,
	}
	archive, err := svc.DecryptBackup(eb, testKey())
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrInvalidBackup)
}

func TestDecryptBackup_NilBackup(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(nil, testKey())
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrInvalidBackup)
}

func TestDecryptBackup_VersionMismatch(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	eb := &EncryptedBackup{
		Magic:   BackupMagic,
		Version: 999,
	}
	archive, err := svc.DecryptBackup(eb, testKey())
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrVersionMismatch)
}

func TestDecryptBackup_WrongKey(t *testing.T) {
	cert := testCert(t)
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
		}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	wrongKey := testKey()
	archive, err := svc.DecryptBackup(eb, wrongKey)
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecryptBackup_CorruptedCiphertext(t *testing.T) {
	cert := testCert(t)
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
		}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	// Corrupt the ciphertext.
	eb.Ciphertext[0] ^= 0xFF
	eb.Ciphertext[len(eb.Ciphertext)-1] ^= 0xFF

	archive, err := svc.DecryptBackup(eb, key)
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestCreateDecryptRoundTrip(t *testing.T) {
	cert := testCert(t)
	fp := testCertFingerprint(cert)
	oathCreds := testOATHCreds()
	passwords := testPasswords()

	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
			meta: map[string]*CertMetadataInfo{
				fp: {Fingerprint: fp, Purpose: "tls-root", Source: "test"},
			},
		}),
		WithOATH(&mockOATHReader{creds: oathCreds}),
		WithPasswords(&mockPasswordReader{passwords: passwords}),
		WithCA(&mockCAReader{
			certPEM: []byte("-----BEGIN CERTIFICATE-----\nTESTCA\n-----END CERTIFICATE-----\n"),
		}),
	)
	require.NoError(t, err)

	key := testKey()

	// Create backup.
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)
	require.NotNil(t, eb)

	// Decrypt backup.
	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err)

	// Verify manifest.
	assert.Equal(t, BackupVersion, archive.Manifest.Version)
	assert.Equal(t, "test-device", archive.Manifest.DeviceName)
	assert.NotEmpty(t, archive.Manifest.Checksum)
	assert.WithinDuration(t, time.Now(), archive.Manifest.Created, 5*time.Second)

	// Verify trust store round-trip.
	require.NotNil(t, archive.TrustStore)
	require.Len(t, archive.TrustStore.Certificates, 1)
	assert.Equal(t, fp, archive.TrustStore.Certificates[0].Fingerprint)
	assert.Contains(t, archive.TrustStore.Certificates[0].PEM, "BEGIN CERTIFICATE")

	// Verify OATH round-trip.
	require.Len(t, archive.OATHCreds, 2)
	assert.Equal(t, oathCreds[0].ID, archive.OATHCreds[0].ID)
	assert.Equal(t, oathCreds[0].Secret, archive.OATHCreds[0].Secret)
	assert.Equal(t, oathCreds[1].AccountName, archive.OATHCreds[1].AccountName)

	// Verify password round-trip.
	require.Len(t, archive.Passwords, 2)
	assert.Equal(t, passwords[0].Password, archive.Passwords[0].Password)
	assert.Equal(t, passwords[1].FolderPath, archive.Passwords[1].FolderPath)

	// Verify CA round-trip.
	require.NotNil(t, archive.CAData)
	assert.Contains(t, archive.CAData.CACertPEM, "TESTCA")
}

func TestGetManifest(t *testing.T) {
	cert := testCert(t)

	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
		}),
		WithOATH(&mockOATHReader{creds: testOATHCreds()}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	manifest, err := svc.GetManifest(eb, key)
	require.NoError(t, err)
	require.NotNil(t, manifest)

	assert.Equal(t, BackupVersion, manifest.Version)
	assert.Equal(t, "test-device", manifest.DeviceName)
	assert.NotEmpty(t, manifest.Checksum)
	assert.Len(t, manifest.Contents, 2)
}

func TestGetManifest_InvalidBackup(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	manifest, err := svc.GetManifest(nil, testKey())
	assert.Nil(t, manifest)
	assert.ErrorIs(t, err, ErrInvalidBackup)
}

func TestRestoreTrustStore(t *testing.T) {
	cert := testCert(t)
	fp := testCertFingerprint(cert)

	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
			meta: map[string]*CertMetadataInfo{
				fp: {Fingerprint: fp, Purpose: "tls", Source: "test"},
			},
		}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err)

	writer := &mockTrustStoreWriter{}
	result, err := svc.RestoreTrustStore(archive, writer)
	require.NoError(t, err)
	assert.Equal(t, ItemTrustStore, result.ItemType)
	assert.Equal(t, 1, result.Restored)
	assert.Equal(t, 0, result.Skipped)
	assert.Empty(t, result.Errors)
	assert.Len(t, writer.added, 1)
}

func TestRestoreTrustStore_NilArchive(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.RestoreTrustStore(nil, &mockTrustStoreWriter{})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrRestoreFailed)
}

func TestRestoreTrustStore_Empty(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	archive := &Archive{}
	writer := &mockTrustStoreWriter{}
	result, err := svc.RestoreTrustStore(archive, writer)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Restored)
	assert.Empty(t, writer.added)
}

func TestRestoreTrustStore_WriterError(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	archive := &Archive{
		TrustStore: &TrustStoreData{
			Certificates: []TrustStoreCert{
				{PEM: "cert1", Fingerprint: "fp1"},
				{PEM: "cert2", Fingerprint: "fp2"},
			},
		},
	}

	writer := &mockTrustStoreWriter{err: errors.New("write failed")}
	result, err := svc.RestoreTrustStore(archive, writer)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Restored)
	assert.Equal(t, 2, result.Skipped)
	assert.Len(t, result.Errors, 2)
}

func TestRestoreOATH(t *testing.T) {
	creds := testOATHCreds()
	svc, err := NewService(testConfig(),
		WithOATH(&mockOATHReader{creds: creds}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err)

	writer := &mockOATHWriter{}
	result, err := svc.RestoreOATH(archive, writer)
	require.NoError(t, err)
	assert.Equal(t, ItemOATH, result.ItemType)
	assert.Equal(t, 2, result.Restored)
	assert.Equal(t, 0, result.Skipped)
	assert.Empty(t, result.Errors)
	assert.Len(t, writer.creds, 2)
	assert.Equal(t, "GitHub", writer.creds[0].Name)
	assert.Equal(t, "AWS", writer.creds[1].Name)
}

func TestRestoreOATH_NilArchive(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.RestoreOATH(nil, &mockOATHWriter{})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrRestoreFailed)
}

func TestRestoreOATH_WriterError(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	archive := &Archive{
		OATHCreds: []OATHCredential{
			{ID: "c1", Name: "Test"},
		},
	}

	writer := &mockOATHWriter{err: errors.New("add failed")}
	result, err := svc.RestoreOATH(archive, writer)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Restored)
	assert.Equal(t, 1, result.Skipped)
	assert.Len(t, result.Errors, 1)
}

func TestRestorePasswords(t *testing.T) {
	passwords := testPasswords()
	svc, err := NewService(testConfig(),
		WithPasswords(&mockPasswordReader{passwords: passwords}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err)

	writer := &mockPasswordWriter{}
	result, err := svc.RestorePasswords(archive, writer)
	require.NoError(t, err)
	assert.Equal(t, ItemPasswords, result.ItemType)
	assert.Equal(t, 2, result.Restored)
	assert.Equal(t, 0, result.Skipped)
	assert.Empty(t, result.Errors)
	assert.Len(t, writer.passwords, 2)
	assert.Equal(t, "s3cret!", writer.passwords[0].Password)
}

func TestRestorePasswords_NilArchive(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	result, err := svc.RestorePasswords(nil, &mockPasswordWriter{})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrRestoreFailed)
}

func TestRestorePasswords_WriterError(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	archive := &Archive{
		Passwords: []PasswordEntry{
			{ID: "p1", Name: "pw1", Password: "secret"},
		},
	}

	writer := &mockPasswordWriter{err: errors.New("add failed")}
	result, err := svc.RestorePasswords(archive, writer)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Restored)
	assert.Equal(t, 1, result.Skipped)
	assert.Len(t, result.Errors, 1)
}

func TestManifest_ItemCounts(t *testing.T) {
	cert1 := testCert(t)
	cert2 := testCert(t)

	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert1, cert2},
		}),
		WithOATH(&mockOATHReader{creds: testOATHCreds()}),
		WithPasswords(&mockPasswordReader{passwords: testPasswords()}),
		WithCA(&mockCAReader{
			certPEM: []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"),
		}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err)

	// Build a lookup for easy assertion.
	itemCounts := make(map[string]int, len(archive.Manifest.Contents))
	for _, item := range archive.Manifest.Contents {
		itemCounts[item.Type] = item.Count
	}

	assert.Equal(t, 2, itemCounts[ItemTrustStore])
	assert.Equal(t, 1, itemCounts[ItemCAData])
	assert.Equal(t, 2, itemCounts[ItemOATH])
	assert.Equal(t, 2, itemCounts[ItemPasswords])
}

func TestEncryptedBackup_JSONRoundTrip(t *testing.T) {
	cert := testCert(t)
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
		}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	// Serialize to JSON.
	data, err := json.Marshal(eb)
	require.NoError(t, err)

	// Deserialize.
	var restored EncryptedBackup
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, eb.Magic, restored.Magic)
	assert.Equal(t, eb.Version, restored.Version)
	assert.Equal(t, eb.Nonce, restored.Nonce)
	assert.Equal(t, eb.Ciphertext, restored.Ciphertext)

	// The restored EncryptedBackup must decrypt correctly.
	archive, err := svc.DecryptBackup(&restored, key)
	require.NoError(t, err)
	require.NotNil(t, archive.TrustStore)
	assert.Len(t, archive.TrustStore.Certificates, 1)
}

func TestCollect_TrustStoreError(t *testing.T) {
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			err: errors.New("cert store offline"),
		}),
	)
	require.NoError(t, err)

	eb, err := svc.CreateBackup(testKey())
	assert.Nil(t, eb)
	assert.ErrorIs(t, err, ErrCollectFailed)
}

func TestCollect_OATHError(t *testing.T) {
	svc, err := NewService(testConfig(),
		WithOATH(&mockOATHReader{err: errors.New("oath db locked")}),
	)
	require.NoError(t, err)

	eb, err := svc.CreateBackup(testKey())
	assert.Nil(t, eb)
	assert.ErrorIs(t, err, ErrCollectFailed)
}

func TestCollect_PasswordError(t *testing.T) {
	svc, err := NewService(testConfig(),
		WithPasswords(&mockPasswordReader{err: errors.New("vault sealed")}),
	)
	require.NoError(t, err)

	eb, err := svc.CreateBackup(testKey())
	assert.Nil(t, eb)
	assert.ErrorIs(t, err, ErrCollectFailed)
}

func TestCollect_CAError(t *testing.T) {
	svc, err := NewService(testConfig(),
		WithCA(&mockCAReader{certErr: errors.New("ca unavailable")}),
	)
	require.NoError(t, err)

	eb, err := svc.CreateBackup(testKey())
	assert.Nil(t, eb)
	assert.ErrorIs(t, err, ErrCollectFailed)
}

func TestCollect_TrustStoreNoMetadata(t *testing.T) {
	cert := testCert(t)

	// Trust store returns certs but no metadata (nil map).
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
			meta:  nil,
		}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err)
	require.Len(t, archive.TrustStore.Certificates, 1)

	// Metadata fields should be empty strings since lookup failed.
	assert.Empty(t, archive.TrustStore.Certificates[0].Purpose)
	assert.Empty(t, archive.TrustStore.Certificates[0].Source)
}

func TestCollect_CAChainError(t *testing.T) {
	// CA cert available but chain fetch errors -- should still succeed
	// with just the cert.
	svc, err := NewService(testConfig(),
		WithCA(&mockCAReader{
			certPEM:  []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"),
			chainErr: errors.New("chain unavailable"),
		}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err)
	require.NotNil(t, archive.CAData)
	assert.Contains(t, archive.CAData.CACertPEM, "CA")
	assert.Empty(t, archive.CAData.CAChainPEM)
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	cert := testCert(t)
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
		}),
	)
	require.NoError(t, err)

	// Key too short.
	shortKey := make([]byte, 16)
	eb, err := svc.CreateBackup(shortKey)
	assert.Nil(t, eb)
	assert.ErrorIs(t, err, ErrEncryptionFailed)
}

func TestDecrypt_InvalidKeySize(t *testing.T) {
	cert := testCert(t)
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
		}),
	)
	require.NoError(t, err)

	key := testKey()
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	shortKey := make([]byte, 16)
	archive, err := svc.DecryptBackup(eb, shortKey)
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestRestoreTrustStore_PartialFailure(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	callCount := 0
	writer := &countingTrustStoreWriter{
		addFunc: func(pemData []byte) (int, error) {
			callCount++
			if callCount == 2 {
				return 0, errors.New("second cert failed")
			}
			return 1, nil
		},
	}

	archive := &Archive{
		TrustStore: &TrustStoreData{
			Certificates: []TrustStoreCert{
				{PEM: "cert1", Fingerprint: "fp1"},
				{PEM: "cert2", Fingerprint: "fp2"},
				{PEM: "cert3", Fingerprint: "fp3"},
			},
		},
	}

	result, err := svc.RestoreTrustStore(archive, writer)
	require.NoError(t, err)
	assert.Equal(t, 2, result.Restored)
	assert.Equal(t, 1, result.Skipped)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "fp2")
}

// countingTrustStoreWriter is a mock that uses a callback for AddPEM.
type countingTrustStoreWriter struct {
	addFunc func(pemData []byte) (int, error)
}

func (w *countingTrustStoreWriter) AddPEM(pemData []byte) (int, error) {
	return w.addFunc(pemData)
}

func TestRestoreOATH_EmptyCreds(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	archive := &Archive{}
	writer := &mockOATHWriter{}
	result, err := svc.RestoreOATH(archive, writer)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Restored)
	assert.Empty(t, writer.creds)
}

func TestRestorePasswords_EmptyPasswords(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	archive := &Archive{}
	writer := &mockPasswordWriter{}
	result, err := svc.RestorePasswords(archive, writer)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Restored)
	assert.Empty(t, writer.passwords)
}

func TestCertFingerprint(t *testing.T) {
	cert := testCert(t)
	fp := certFingerprint(cert)

	// Fingerprint must be a valid 64-char hex string (SHA-256).
	assert.Len(t, fp, 64)
	_, err := hex.DecodeString(fp)
	assert.NoError(t, err)

	// Same cert must produce same fingerprint.
	assert.Equal(t, fp, certFingerprint(cert))
}

func TestEncodeCertPEM(t *testing.T) {
	cert := testCert(t)
	pemStr := encodeCertPEM(cert)
	assert.Contains(t, pemStr, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, pemStr, "-----END CERTIFICATE-----")
}
