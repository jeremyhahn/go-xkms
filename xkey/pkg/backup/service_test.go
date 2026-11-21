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
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

// mockTrustStore serves certs with the metadata in meta. A nil meta files
// every certificate as general; metaErr fails every metadata lookup.
type mockTrustStore struct {
	certs   []*x509.Certificate
	meta    map[string]*CertMetadataInfo
	metaErr error
	err     error
}

func (m *mockTrustStore) Certificates() ([]*x509.Certificate, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.certs, nil
}

func (m *mockTrustStore) Metadata(fingerprint string) (*CertMetadataInfo, error) {
	if m.metaErr != nil {
		return nil, m.metaErr
	}
	if m.meta == nil {
		return &CertMetadataInfo{Fingerprint: fingerprint, Purpose: "general"}, nil
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

// List returns records of its own on every call, as the OATHReader contract
// requires: the service destroys what it is handed.
func (m *mockOATHReader) List() ([]*OATHCredentialInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := make([]*OATHCredentialInfo, 0, len(m.creds))
	for _, c := range m.creds {
		clone, err := c.Clone()
		if err != nil {
			return nil, err
		}
		out = append(out, clone)
	}
	return out, nil
}

type mockPasswordReader struct {
	passwords []*PasswordInfo
	err       error
}

// List returns records of its own on every call, as the PasswordReader
// contract requires: the service destroys what it is handed.
func (m *mockPasswordReader) List() ([]*PasswordInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := make([]*PasswordInfo, 0, len(m.passwords))
	for _, p := range m.passwords {
		clone, err := p.Clone()
		if err != nil {
			return nil, err
		}
		out = append(out, clone)
	}
	return out, nil
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
	opts  []*truststore.AddCertificateOptions
	err   error
}

func (m *mockTrustStoreWriter) ImportPEM(pemData []byte, opts *truststore.AddCertificateOptions) (truststore.ImportResult, error) {
	if m.err != nil {
		return truststore.ImportResult{}, m.err
	}
	m.added = append(m.added, pemData)
	m.opts = append(m.opts, opts)
	return truststore.ImportResult{Added: 1}, nil
}

type mockOATHWriter struct {
	creds []*OATHCredentialInfo
	err   error
}

// Add keeps a copy, as the OATHWriter contract requires: the service destroys
// cred as soon as Add returns.
func (m *mockOATHWriter) Add(cred *OATHCredentialInfo) error {
	if m.err != nil {
		return m.err
	}
	clone, err := cred.Clone()
	if err != nil {
		return err
	}
	m.creds = append(m.creds, clone)
	return nil
}

type mockPasswordWriter struct {
	passwords []*PasswordInfo
	err       error
}

// Add keeps a copy, as the PasswordWriter contract requires: the service
// destroys pw as soon as Add returns.
func (m *mockPasswordWriter) Add(pw *PasswordInfo) error {
	if m.err != nil {
		return m.err
	}
	clone, err := pw.Clone()
	if err != nil {
		return err
	}
	m.passwords = append(m.passwords, clone)
	return nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func testKey() *Key {
	key, err := GenerateKey()
	if err != nil {
		panic(err)
	}
	return key
}

// sealTestPayload seals plaintext under key the way CreateBackup does, so a
// test can build an envelope around an arbitrary (malformed) payload.
func sealTestPayload(t *testing.T, plaintext []byte, key *Key) *EncryptedBackup {
	t.Helper()
	eb := &EncryptedBackup{Magic: BackupMagic, Version: BackupVersion, KDF: key.KDF()}
	aad, err := eb.headerAAD()
	require.NoError(t, err)
	eb.Ciphertext, eb.Nonce, err = encrypt(plaintext, key.Bytes(), aad)
	require.NoError(t, err)
	return eb
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
		withSecret(&OATHCredentialInfo{
			ID: "oath-1", Name: "GitHub", Issuer: "GitHub",
			AccountName: "user@example.com",
			Type:        "totp", Algorithm: "SHA1", Digits: 6, Period: 30,
		}, "JBSWY3DPEHPK3PXP"),
		withSecret(&OATHCredentialInfo{
			ID: "oath-2", Name: "AWS", Issuer: "Amazon",
			AccountName: "admin@corp.com",
			Type:        "totp", Algorithm: "SHA256", Digits: 8, Period: 30,
		}, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"),
	}
}

func testPasswords() []*PasswordInfo {
	return []*PasswordInfo{
		withPassword(&PasswordInfo{
			ID: "pw-1", Name: "Server SSH", Title: "Production Server",
			Username: "admin",
			URL:      "ssh://prod.example.com", Notes: "Primary server",
			FolderPath: "/servers",
		}, "s3cret!"),
		withPassword(&PasswordInfo{
			ID: "pw-2", Name: "Database", Title: "Postgres Master",
			Username:   "dbadmin",
			URL:        "postgres://db.local:5432",
			FolderPath: "/databases",
		}, "db-p@ss"),
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
				Purpose:     "user-ca",
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
	assert.Len(t, eb.Nonce, gcmNonceSize)
	assert.NotEmpty(t, eb.Ciphertext)

	// Decrypt and verify.
	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err)
	require.NotNil(t, archive.TrustStore)
	assert.Len(t, archive.TrustStore.Certificates, 1)
	assert.Equal(t, fp, archive.TrustStore.Certificates[0].Fingerprint)
	assert.Equal(t, "user-ca", archive.TrustStore.Certificates[0].Purpose)
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
				fp: {Fingerprint: fp, Purpose: "general", Source: "system"},
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

// TestDecryptBackup_XChaChaVersion2Refused checks that a version 2 file, the
// retired XChaCha20-Poly1305 format, is refused by version with no attempt
// to read it.
func TestDecryptBackup_XChaChaVersion2Refused(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	eb := &EncryptedBackup{
		Magic:      BackupMagic,
		Version:    2,
		Nonce:      make([]byte, 24),
		Ciphertext: []byte("opaque version 2 ciphertext"),
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

// TestDecryptBackup_WrongNonceLength verifies that DecryptBackup returns an
// error instead of panicking when the backup file carries a nonce that is
// not exactly the AES-GCM nonce size (12 bytes). A corrupted or maliciously
// crafted import file must not be able to crash the process or shift nonce
// bytes into the ciphertext.
func TestDecryptBackup_WrongNonceLength(t *testing.T) {
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

	tests := []struct {
		name      string
		nonceSize int
	}{
		{name: "24-byte XChaCha20-Poly1305 nonce", nonceSize: 24},
		{name: "empty nonce", nonceSize: 0},
		{name: "single byte nonce", nonceSize: 1},
		{name: "oversized nonce", nonceSize: 48},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := *eb
			tampered.Nonce = make([]byte, tt.nonceSize)

			archive, err := svc.DecryptBackup(&tampered, key)
			assert.Nil(t, archive)
			assert.ErrorIs(t, err, ErrDecryptionFailed)
		})
	}
}

// TestDecryptBackup_InvalidJSONPayload verifies that a payload which
// decrypts successfully (correct key and an authentic AEAD tag) but is not
// valid JSON is reported as an invalid backup rather than panicking on the
// Unmarshal.
func TestDecryptBackup_InvalidJSONPayload(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	key := testKey()
	eb := sealTestPayload(t, []byte("not valid json"), key)

	archive, err := svc.DecryptBackup(eb, key)
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrInvalidBackup)
}

// TestDecryptBackup_ChecksumMismatch verifies that a payload which decrypts
// and parses successfully but carries a checksum that does not match its own
// content is reported as corrupted rather than accepted.
func TestDecryptBackup_ChecksumMismatch(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	key := testKey()
	archive := &Archive{
		Manifest: Manifest{
			Version:    BackupVersion,
			Created:    time.Now().UTC(),
			DeviceName: "tampered",
			Checksum:   "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	plaintext, err := json.Marshal(archive)
	require.NoError(t, err)

	eb := sealTestPayload(t, plaintext, key)

	got, err := svc.DecryptBackup(eb, key)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrCorruptedBackup)
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
				fp: {Fingerprint: fp, Purpose: "user-ca", Source: "test"},
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
	assert.Equal(t, secretText(oathCreds[0]), textOf(archive.OATHCreds[0].Secret))
	assert.Equal(t, oathCreds[1].AccountName, archive.OATHCreds[1].AccountName)

	// Verify password round-trip.
	require.Len(t, archive.Passwords, 2)
	assert.Equal(t, passwordText(passwords[0]), textOf(archive.Passwords[0].Password))
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
				fp: {Fingerprint: fp, Purpose: "tpm-manufacturer", Source: "test", Tags: []string{"lab"}},
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

	// The certificate is filed under exactly the metadata it was backed up
	// with, never auto-classified (#1312).
	require.Len(t, writer.opts, 1)
	require.NotNil(t, writer.opts[0])
	assert.Equal(t, truststore.PurposeTPMManufacturer, writer.opts[0].Purpose)
	assert.Equal(t, "test", writer.opts[0].Source)
	assert.Equal(t, []string{"lab"}, writer.opts[0].Tags)
}

// TestRestoreTrustStore_PreservesEveryRecordedPurpose restores one
// certificate per trust-store purpose and checks each lands under the purpose
// the archive recorded -- including synced, which auto-classification would
// promote out of quarantine.
func TestRestoreTrustStore_PreservesEveryRecordedPurpose(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	purposes := []truststore.CertPurpose{
		truststore.PurposeGeneral,
		truststore.PurposeTPMManufacturer,
		truststore.PurposeAndroidHardware,
		truststore.PurposeUserCA,
		truststore.PurposeBootstrapCA,
		truststore.PurposeIDevIDIssuer,
		truststore.PurposeSynced,
	}
	certs := make([]TrustStoreCert, 0, len(purposes))
	for i, purpose := range purposes {
		certs = append(certs, TrustStoreCert{
			PEM:         fmt.Sprintf("cert%d", i),
			Fingerprint: fmt.Sprintf("fp%d", i),
			Purpose:     string(purpose),
		})
	}

	writer := &mockTrustStoreWriter{}
	result, err := svc.RestoreTrustStore(&Archive{TrustStore: &TrustStoreData{Certificates: certs}}, writer)
	require.NoError(t, err)
	assert.Equal(t, len(purposes), result.Restored)
	require.Len(t, writer.opts, len(purposes))
	for i, purpose := range purposes {
		assert.Equal(t, purpose, writer.opts[i].Purpose)
	}
}

// TestRestoreTrustStore_RefusesUnrecordedOrInvalidPurpose checks that an
// archive whose certificate has no recorded purpose, or one that is not a
// trust-store purpose, is refused with a typed error and writes nothing --
// not even the valid certificates before it.
func TestRestoreTrustStore_RefusesUnrecordedOrInvalidPurpose(t *testing.T) {
	tests := []struct {
		name    string
		purpose string
		wantErr error
	}{
		{"missing", "", ErrMissingRecordedPurpose},
		{"unknown", "tls-root", ErrInvalidRecordedPurpose},
		{"wrong case", "USER-CA", ErrInvalidRecordedPurpose},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewService(testConfig())
			require.NoError(t, err)

			archive := &Archive{
				TrustStore: &TrustStoreData{
					Certificates: []TrustStoreCert{
						{PEM: "cert1", Fingerprint: "fp1", Purpose: string(truststore.PurposeUserCA)},
						{PEM: "cert2", Fingerprint: "fp2", Purpose: tt.purpose},
					},
				},
			}

			writer := &mockTrustStoreWriter{}
			result, err := svc.RestoreTrustStore(archive, writer)
			assert.Nil(t, result)
			require.ErrorIs(t, err, tt.wantErr)
			assert.ErrorIs(t, err, ErrRestoreFailed)

			var purposeErr *RecordedPurposeError
			require.ErrorAs(t, err, &purposeErr)
			assert.Equal(t, "fp2", purposeErr.Fingerprint)
			assert.Equal(t, tt.purpose, purposeErr.Purpose)
			assert.Contains(t, err.Error(), "fp2", "the refusal must name the certificate")
			assert.Empty(t, writer.added, "a refused archive must write no certificate")
		})
	}
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
				{PEM: "cert1", Fingerprint: "fp1", Purpose: "general"},
				{PEM: "cert2", Fingerprint: "fp2", Purpose: "general"},
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
	assert.Equal(t, "s3cret!", passwordText(writer.passwords[0]))
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
			{ID: "p1", Name: "pw1", Password: mustSecretText("secret")},
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

// TestCollect_TrustStoreNoMetadata checks that a certificate whose metadata
// cannot be read fails the backup: restore refuses a certificate with no
// recorded purpose (#1312), so an archive without one would be unrestorable.
func TestCollect_TrustStoreNoMetadata(t *testing.T) {
	cert := testCert(t)

	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs:   []*x509.Certificate{cert},
			metaErr: errors.New("no metadata"),
		}),
	)
	require.NoError(t, err)

	eb, err := svc.CreateBackup(testKey())
	assert.Nil(t, eb)
	assert.ErrorIs(t, err, ErrCollectFailed)
}

// TestCollect_TrustStoreNilMetadata checks that a store reporting no error
// but nil metadata also fails the backup rather than recording no purpose.
func TestCollect_TrustStoreNilMetadata(t *testing.T) {
	cert := testCert(t)
	fp := testCertFingerprint(cert)

	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
			meta:  map[string]*CertMetadataInfo{fp: nil},
		}),
	)
	require.NoError(t, err)

	eb, err := svc.CreateBackup(testKey())
	assert.Nil(t, eb)
	assert.ErrorIs(t, err, ErrCollectFailed)
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

func TestCreateBackup_NilKey(t *testing.T) {
	cert := testCert(t)
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
		}),
	)
	require.NoError(t, err)

	eb, err := svc.CreateBackup(nil)
	assert.Nil(t, eb)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestDecryptBackup_NilKey(t *testing.T) {
	cert := testCert(t)
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{
			certs: []*x509.Certificate{cert},
		}),
	)
	require.NoError(t, err)

	eb, err := svc.CreateBackup(testKey())
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(eb, nil)
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestRestoreTrustStore_PartialFailure(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	callCount := 0
	writer := &countingTrustStoreWriter{
		addFunc: func(pemData []byte) (truststore.ImportResult, error) {
			callCount++
			if callCount == 2 {
				return truststore.ImportResult{}, errors.New("second cert failed")
			}
			return truststore.ImportResult{Added: 1}, nil
		},
	}

	archive := &Archive{
		TrustStore: &TrustStoreData{
			Certificates: []TrustStoreCert{
				{PEM: "cert1", Fingerprint: "fp1", Purpose: "general"},
				{PEM: "cert2", Fingerprint: "fp2", Purpose: "general"},
				{PEM: "cert3", Fingerprint: "fp3", Purpose: "general"},
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

// countingTrustStoreWriter is a mock that uses a callback for ImportPEM.
type countingTrustStoreWriter struct {
	addFunc func(pemData []byte) (truststore.ImportResult, error)
}

func (w *countingTrustStoreWriter) ImportPEM(pemData []byte, _ *truststore.AddCertificateOptions) (truststore.ImportResult, error) {
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
