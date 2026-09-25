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

package cmd

// Tests for the data-source wiring that connects the backup commands to the
// xkey backup service: store resolution, the store adapters, the on-disk
// envelope, and the create/contents/restore round trip.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolatedBackupHome points HOME at a fresh temporary directory and clears
// the home resolved by the root command, so store resolution is hermetic.
func isolatedBackupHome(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("HOME", dir)

	previous := resolvedHome
	resolvedHome = nil
	t.Cleanup(func() { resolvedHome = previous })

	return dir
}

// backupTestDataDir returns the data directory beneath an isolated home.
func backupTestDataDir(home string) string {
	return filepath.Join(home, ".xkey", "data")
}

// newTestCertificatePEM returns a self-signed certificate in PEM form.
func newTestCertificatePEM(t *testing.T, commonName string) []byte {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// seedBackupStores writes one certificate, one OATH credential, and one
// static password into the default stores beneath the isolated home.
func seedBackupStores(t *testing.T, home string) {
	t.Helper()

	dataDir := backupTestDataDir(home)

	trustStore, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(dataDir, backupTrustStoreDir),
	})
	require.NoError(t, err)
	added, err := trustStore.AddPEM(newTestCertificatePEM(t, "backup-unit-test-ca"))
	require.NoError(t, err)
	require.Equal(t, 1, added)
	require.NoError(t, trustStore.Close())

	oathStore, err := oath.NewFileStore(filepath.Join(dataDir, backupOATHStoreFile))
	require.NoError(t, err)
	require.NoError(t, oathStore.Add(withOATHSecret(&oath.Credential{
		ID:          "oath-unit-test",
		Name:        "UnitTestOATH",
		Issuer:      "Example",
		AccountName: "user@example.com",
		Type:        oath.TypeTOTP,
		Algorithm:   oath.AlgorithmSHA1,
		Digits:      6,
		Period:      30,
		CreatedAt:   time.Now().UTC(),
	}, "JBSWY3DPEHPK3PXP")))
	require.NoError(t, oathStore.Close())

	passwordStore, err := openPasswordStore(filepath.Join(dataDir, backupPasswordStoreDir))
	require.NoError(t, err)
	require.NoError(t, passwordStore.Add(&xkms.StaticPassword{
		Name:     "UnitTestEntry",
		Username: "operator",
		Password: "s3cret-value",
	}))
	require.NoError(t, passwordStore.Close())
}

// setBackupFlags applies flag values to a command and restores the previous
// values when the test ends, so the shared cobra command objects do not leak
// state between tests.
func setBackupFlags(t *testing.T, cmd *cobra.Command, values map[string]string) {
	t.Helper()

	previous := make(map[string]string, len(values))
	for name, value := range values {
		flag := cmd.Flags().Lookup(name)
		require.NotNil(t, flag, "flag %q must exist", name)
		previous[name] = flag.Value.String()
		require.NoError(t, cmd.Flags().Set(name, value))
	}

	t.Cleanup(func() {
		for name, value := range previous {
			_ = cmd.Flags().Set(name, value)
		}
	})
}

// certFingerprintHex returns the hex-encoded SHA-256 fingerprint of raw DER
// certificate bytes, matching the trust store's metadata key.
func certFingerprintHex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// parseGeneratedBackupKey extracts the hex key printed by "backup create"
// when no password was supplied.
func parseGeneratedBackupKey(t *testing.T, output string) string {
	t.Helper()

	const marker = "Generated encryption key (save this):"
	index := strings.Index(output, marker)
	require.GreaterOrEqual(t, index, 0, "create must print the generated key: %s", output)

	remainder := strings.TrimSpace(output[index+len(marker):])
	key := strings.TrimSpace(strings.SplitN(remainder, "\n", 2)[0])
	require.Len(t, key, 64, "the generated key must be 32 hex-encoded bytes")

	return key
}

// --- OATH counter conversion ---

func TestOATHCounterConversion_RoundTrip(t *testing.T) {
	for _, counter := range []uint64{0, 1, 42, math.MaxInt64} {
		signed := oathCounterToInt64(counter)
		assert.Equal(t, counter, oathCounterFromInt64(signed))
	}
}

func TestOATHCounterConversion_ClampsOutOfRange(t *testing.T) {
	assert.Equal(t, int64(math.MaxInt64), oathCounterToInt64(math.MaxUint64),
		"counters above MaxInt64 must clamp instead of wrapping negative")
	assert.Equal(t, uint64(0), oathCounterFromInt64(-1),
		"negative counters must clamp to zero")
}

// --- Decrypt error classification ---

func TestClassifyBackupDecryptError_KnownReasons(t *testing.T) {
	tests := []struct {
		name     string
		cause    error
		contains string
	}{
		{"wrong_key", backup.ErrDecryptionFailed, "incorrect password or key"},
		{"corrupt", backup.ErrCorruptedBackup, "checksum mismatch"},
		{"version", backup.ErrVersionMismatch, "unsupported backup format version"},
		{"not_a_backup", backup.ErrInvalidBackup, "not an xkey backup envelope"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyBackupDecryptError(tc.cause)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrBackupDecryptFailed)
			assert.Contains(t, err.Error(), tc.contains)
		})
	}
}

func TestClassifyBackupDecryptError_UnknownCausePreserved(t *testing.T) {
	cause := errors.New("some transport failure")

	err := classifyBackupDecryptError(cause)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
	assert.ErrorIs(t, err, cause, "an unrecognized cause must stay in the chain")
}

// --- Manifest projection ---

func TestNewBackupManifest_ProjectsCounts(t *testing.T) {
	created := time.Now().UTC().Truncate(time.Second)

	view := newBackupManifest(&backup.Manifest{
		Version:    backup.BackupVersion,
		Created:    created,
		DeviceName: "test-host",
		Contents: []backup.ManifestItem{
			{Type: backup.ItemTrustStore, Count: 3},
			{Type: backup.ItemOATH, Count: 2},
			{Type: backup.ItemPasswords, Count: 1},
			{Type: backup.ItemCAData, Count: 1},
		},
	})

	assert.Equal(t, backup.BackupVersion, view.Version)
	assert.Equal(t, "test-host", view.DeviceName)
	assert.Equal(t, created, view.CreatedAt)
	assert.Equal(t, 3, view.TrustCerts)
	assert.Equal(t, 2, view.OATHAccounts)
	assert.Equal(t, 1, view.Passwords)
	assert.Equal(t, 1, view.CACerts)
}

func TestNewBackupManifest_IgnoresUnknownItems(t *testing.T) {
	view := newBackupManifest(&backup.Manifest{
		Version: backup.BackupVersion,
		Contents: []backup.ManifestItem{
			{Type: "future-category", Count: 99},
		},
	})

	assert.Equal(t, 0, view.TrustCerts)
	assert.Equal(t, 0, view.OATHAccounts)
	assert.Equal(t, 0, view.Passwords)
	assert.Equal(t, 0, view.CACerts)
}

// --- On-disk envelope ---

func TestEncryptedBackupFile_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "envelope.xkb")
	original := &backup.EncryptedBackup{
		Magic:      backup.BackupMagic,
		Version:    backup.BackupVersion,
		Nonce:      []byte("0123456789abcdefghijklmn"),
		Ciphertext: []byte("sealed-bytes"),
	}

	require.NoError(t, writeEncryptedBackup(path, original))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "backups must not be world readable")

	loaded, err := readEncryptedBackup(path)
	require.NoError(t, err)
	assert.Equal(t, original, loaded)

	// The plaintext envelope must not leak the sealed payload in the clear.
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(raw, &envelope))
	assert.Equal(t, backup.BackupMagic, envelope["magic"])
	assert.NotContains(t, envelope, "manifest")
}

func TestReadEncryptedBackup_NotJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.xkb")
	require.NoError(t, os.WriteFile(path, []byte("definitely { not json"), 0600))

	_, err := readEncryptedBackup(path)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
}

func TestReadEncryptedBackup_Missing(t *testing.T) {
	_, err := readEncryptedBackup(filepath.Join(t.TempDir(), "absent.xkb"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupRestoreFailed)
}

func TestRequireBackupFile(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.xkb")
	require.NoError(t, os.WriteFile(present, []byte("{}"), 0600))

	assert.NoError(t, requireBackupFile(present))

	err := requireBackupFile(filepath.Join(dir, "absent.xkb"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupFileNotFound)
}

// --- Store resolution ---

func TestBackupStorePathsFromFlags(t *testing.T) {
	setBackupFlags(t, backupCreateCmd, map[string]string{
		"trust-store":    "/tmp/t",
		"oath-store":     "/tmp/o.json",
		"password-store": "/tmp/p",
	})

	paths := backupStorePathsFromFlags(backupCreateCmd)
	assert.Equal(t, "/tmp/t", paths.trust)
	assert.Equal(t, "/tmp/o.json", paths.oath)
	assert.Equal(t, "/tmp/p", paths.passwords)
}

func TestResolveBackupSources_Defaults(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	sources, err := resolveBackupSources(backupCreateCmd, backupStorePaths{})
	require.NoError(t, err)
	defer sources.Close()

	assert.Equal(t, filepath.Join(dataDir, backupTrustStoreDir), sources.trust.path)
	assert.Equal(t, filepath.Join(dataDir, backupOATHStoreFile), sources.oath.path)
	assert.Equal(t, filepath.Join(dataDir, backupPasswordStoreDir), sources.passwords.path)
	assert.Len(t, sources.readerOptions(), 3)

	require.Len(t, sources.skipped, 1)
	assert.Equal(t, backup.ItemCAData, sources.skipped[0].Item)
	assert.Contains(t, sources.summary(), backup.ItemCAData)
}

func TestResolveBackupSources_ExplicitPaths(t *testing.T) {
	isolatedBackupHome(t)
	dir := t.TempDir()

	paths := backupStorePaths{
		trust:     filepath.Join(dir, "custom-trust"),
		oath:      filepath.Join(dir, "custom-oath.json"),
		passwords: filepath.Join(dir, "custom-passwords"),
	}

	sources, err := resolveBackupSources(backupCreateCmd, paths)
	require.NoError(t, err)
	defer sources.Close()

	assert.Equal(t, paths.trust, sources.trust.path)
	assert.Equal(t, paths.oath, sources.oath.path)
	assert.Equal(t, paths.passwords, sources.passwords.path)
}

func TestResolveBackupSources_BarrierEncryptedRefused(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	rootKey := filepath.Join(dataDir, defaultBarrierRootKeyPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(rootKey), 0700))
	require.NoError(t, os.WriteFile(rootKey, []byte("sealed"), 0600))

	_, err := resolveBackupSources(backupCreateCmd, backupStorePaths{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupBarrierEncrypted)
}

func TestResolveBackupSources_ExplicitPathsBypassBarrierCheck(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	rootKey := filepath.Join(dataDir, defaultBarrierRootKeyPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(rootKey), 0700))
	require.NoError(t, os.WriteFile(rootKey, []byte("sealed"), 0600))

	dir := t.TempDir()
	sources, err := resolveBackupSources(backupCreateCmd, backupStorePaths{
		trust:     filepath.Join(dir, "trust"),
		oath:      filepath.Join(dir, "oath.json"),
		passwords: filepath.Join(dir, "passwords"),
	})
	require.NoError(t, err)
	sources.Close()
}

func TestResolveBackupSources_UnopenableStore(t *testing.T) {
	isolatedBackupHome(t)
	dir := t.TempDir()

	// A regular file where the trust store directory belongs makes the
	// store impossible to open.
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	_, err := resolveBackupSources(backupCreateCmd, backupStorePaths{
		trust:     filepath.Join(blocker, "trust"),
		oath:      filepath.Join(dir, "oath.json"),
		passwords: filepath.Join(dir, "passwords"),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupStoreUnavailable)
	assert.Contains(t, err.Error(), backup.ItemTrustStore)
}

func TestBackupSources_CloseIsNilSafe(t *testing.T) {
	var sources *backupSources
	assert.NotPanics(t, func() { sources.Close() })
}

// --- Store adapters ---

func TestTrustStoreAdapter_ReadsMetadata(t *testing.T) {
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &trustStoreAdapter{store: store, path: dir}

	added, err := adapter.AddPEM(newTestCertificatePEM(t, "adapter-ca"))
	require.NoError(t, err)
	require.Equal(t, 1, added)

	certs, err := adapter.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)

	meta, err := adapter.Metadata(certFingerprintHex(certs[0].Raw))
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, certFingerprintHex(certs[0].Raw), meta.Fingerprint)
	assert.NotEmpty(t, meta.Purpose)
}

func TestTrustStoreAdapter_MetadataUnknownFingerprint(t *testing.T) {
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &trustStoreAdapter{store: store, path: dir}

	_, err = adapter.Metadata(strings.Repeat("ab", 32))
	assert.Error(t, err, "an unknown fingerprint must not resolve to metadata")
}

func TestOATHStoreAdapter_ListAndAdd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oath.json")
	store, err := oath.NewFileStore(path)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &oathStoreAdapter{store: store, path: path}

	restoredCred := &backup.OATHCredentialInfo{
		ID:          "restored-id",
		Name:        "Restored",
		Issuer:      "Example",
		AccountName: "user@example.com",
		Type:        oath.TypeTOTP,
		Algorithm:   oath.AlgorithmSHA1,
		Digits:      6,
		Period:      30,
		Counter:     7,
	}
	require.NoError(t, restoredCred.SetSecret("JBSWY3DPEHPK3PXP"))
	require.NoError(t, adapter.Add(restoredCred))

	creds, err := adapter.List()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "restored-id", creds[0].ID)
	assert.Equal(t, "Restored", creds[0].Name)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", creds[0].SecretString())
	assert.Equal(t, int64(7), creds[0].Counter)
}

func TestOATHStoreAdapter_AddInvalidCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oath.json")
	store, err := oath.NewFileStore(path)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &oathStoreAdapter{store: store, path: path}

	// No secret and no algorithm: the store must reject the credential
	// rather than persist an unusable entry.
	err = adapter.Add(&backup.OATHCredentialInfo{ID: "bad", Name: "Bad"})
	assert.Error(t, err)
}

func TestPasswordStoreAdapter_ListAndAdd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwords")
	store, err := openPasswordStore(path)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &passwordStoreAdapter{store: store, path: path}

	restoredPW := &backup.PasswordInfo{
		Name:     "Restored",
		Title:    "Restored Entry",
		Username: "operator",
		URL:      "https://example.com",
		Notes:    "note",
	}
	require.NoError(t, restoredPW.SetPassword("s3cret"))
	require.NoError(t, adapter.Add(restoredPW))

	entries, err := adapter.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "Restored", entries[0].Name)
	assert.Equal(t, "s3cret", entries[0].PasswordString())
	assert.NotEmpty(t, entries[0].ID, "the store must derive an entry ID")
}

func TestPasswordStoreAdapter_AddInvalidEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwords")
	store, err := openPasswordStore(path)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &passwordStoreAdapter{store: store, path: path}

	err = adapter.Add(&backup.PasswordInfo{Name: ""})
	assert.Error(t, err, "an entry with no name and no password must be rejected")
}

func TestTrustStoreAdapter_Contains(t *testing.T) {
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &trustStoreAdapter{store: store, path: dir}

	added, err := adapter.AddPEM(newTestCertificatePEM(t, "contains-ca"))
	require.NoError(t, err)
	require.Equal(t, 1, added)

	certs, err := adapter.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
	fp := certFingerprintHex(certs[0].Raw)

	present, err := adapter.Contains(fp)
	require.NoError(t, err)
	assert.True(t, present)

	absent, err := adapter.Contains(strings.Repeat("ab", 32))
	require.NoError(t, err)
	assert.False(t, absent, "an unknown fingerprint must not be reported as contained")
}

func TestOATHStoreAdapter_GetAndUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oath.json")
	store, err := oath.NewFileStore(path)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &oathStoreAdapter{store: store, path: path}

	seed := &backup.OATHCredentialInfo{
		ID:        "get-and-update",
		Name:      "Original",
		Type:      oath.TypeTOTP,
		Algorithm: oath.AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}
	require.NoError(t, seed.SetSecret("JBSWY3DPEHPK3PXP"))
	require.NoError(t, adapter.Add(seed))

	got, err := adapter.Get("get-and-update")
	require.NoError(t, err)
	assert.Equal(t, "Original", got.Name)

	got.Name = "Renamed"
	require.NoError(t, adapter.Update(got))

	updated, err := adapter.Get("get-and-update")
	require.NoError(t, err)
	assert.Equal(t, "Renamed", updated.Name)
}

func TestOATHStoreAdapter_GetMissingReturnsStoreError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oath.json")
	store, err := oath.NewFileStore(path)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &oathStoreAdapter{store: store, path: path}

	_, err = adapter.Get("ghost")
	assert.Error(t, err)
}

func TestOATHStoreAdapter_UpdateMissingReturnsStoreError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oath.json")
	store, err := oath.NewFileStore(path)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &oathStoreAdapter{store: store, path: path}

	err = adapter.Update(&backup.OATHCredentialInfo{ID: "ghost", Name: "Ghost"})
	assert.Error(t, err, "updating a credential that was never added must fail")
}

func TestPasswordStoreAdapter_GetAndUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwords")
	store, err := openPasswordStore(path)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &passwordStoreAdapter{store: store, path: path}

	seed := &backup.PasswordInfo{Name: "Original", Title: "Entry"}
	require.NoError(t, seed.SetPassword("s3cret"))
	require.NoError(t, adapter.Add(seed))

	entries, err := adapter.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	got, err := adapter.Get(entries[0].ID)
	require.NoError(t, err)
	assert.Equal(t, "Original", got.Name)

	got.Title = "Renamed Entry"
	require.NoError(t, got.SetPassword("s3cret"))
	require.NoError(t, adapter.Update(got))

	updated, err := adapter.Get(entries[0].ID)
	require.NoError(t, err)
	assert.Equal(t, "Renamed Entry", updated.Title)
}

func TestPasswordStoreAdapter_GetMissingReturnsStoreError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwords")
	store, err := openPasswordStore(path)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := &passwordStoreAdapter{store: store, path: path}

	_, err = adapter.Get("ghost")
	assert.Error(t, err)
}

func TestBackupSources_SyncOptionsMatchesOpenedStores(t *testing.T) {
	home := isolatedBackupHome(t)
	_ = home

	sources, err := resolveBackupSources(backupCreateCmd, backupStorePaths{})
	require.NoError(t, err)
	defer sources.Close()

	assert.Len(t, sources.syncOptions(), 3,
		"one sync option must be returned per opened store")
}

// --- Command round trip ---

func TestBackupLifecycle_CreateContentsRestore(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)

	output := filepath.Join(home, "lifecycle.xkb")
	const passphrase = "correct-horse-battery-staple"

	setBackupFlags(t, backupCreateCmd, map[string]string{"output": output, "password": passphrase})

	var createOut bytes.Buffer
	backupCreateCmd.SetOut(&createOut)
	require.NoError(t, runBackupCreate(backupCreateCmd, nil))

	assert.Contains(t, createOut.String(), "Backup created: "+output)
	assert.Contains(t, createOut.String(), "Trust certs:  1")
	assert.Contains(t, createOut.String(), "OATH:         1")
	assert.Contains(t, createOut.String(), "Passwords:    1")

	// The file on disk must be sealed, not a plaintext manifest.
	raw, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "UnitTestEntry")
	assert.NotContains(t, string(raw), "s3cret-value")

	setBackupFlags(t, backupContentsCmd, map[string]string{"password": passphrase, "key": ""})
	var contentsOut bytes.Buffer
	backupContentsCmd.SetOut(&contentsOut)
	require.NoError(t, runBackupContents(backupContentsCmd, []string{output}))
	assert.Contains(t, contentsOut.String(), "Trust certs:  1")
	assert.Contains(t, contentsOut.String(), "Passwords:    1")

	// Restore into a second, empty home.
	restoreHome := isolatedBackupHome(t)
	setBackupFlags(t, backupRestoreCmd, map[string]string{"password": passphrase, "key": ""})
	var restoreOut bytes.Buffer
	backupRestoreCmd.SetOut(&restoreOut)
	require.NoError(t, runBackupRestore(backupRestoreCmd, []string{output}))
	assert.Contains(t, restoreOut.String(), "Restore completed successfully.")

	// The seeded data must now exist in the second home.
	restoredPasswords, err := openPasswordStore(filepath.Join(backupTestDataDir(restoreHome), backupPasswordStoreDir))
	require.NoError(t, err)
	defer func() { _ = restoredPasswords.Close() }()
	entries, err := restoredPasswords.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "UnitTestEntry", entries[0].Name)
	assert.Equal(t, "s3cret-value", entries[0].Password)

	restoredOATH, err := oath.NewFileStore(filepath.Join(backupTestDataDir(restoreHome), backupOATHStoreFile))
	require.NoError(t, err)
	defer func() { _ = restoredOATH.Close() }()
	creds, err := restoredOATH.List()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "UnitTestOATH", creds[0].Name)

	restoredTrust, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(backupTestDataDir(restoreHome), backupTrustStoreDir),
	})
	require.NoError(t, err)
	defer func() { _ = restoredTrust.Close() }()
	certs, err := restoredTrust.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "backup-unit-test-ca", certs[0].Subject.CommonName)
}

func TestBackupRestore_WrongPasswordFails(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)

	output := filepath.Join(home, "wrong-password.xkb")
	setBackupFlags(t, backupCreateCmd, map[string]string{"output": output, "password": "the-real-password"})
	var createOut bytes.Buffer
	backupCreateCmd.SetOut(&createOut)
	require.NoError(t, runBackupCreate(backupCreateCmd, nil))

	setBackupFlags(t, backupRestoreCmd, map[string]string{"password": "not-the-real-password", "key": ""})
	var restoreOut bytes.Buffer
	backupRestoreCmd.SetOut(&restoreOut)

	err := runBackupRestore(backupRestoreCmd, []string{output})
	require.Error(t, err, "a mismatched password must never restore")
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
	assert.Contains(t, err.Error(), "incorrect password or key")
	assert.NotContains(t, restoreOut.String(), "Restore completed")
}

func TestBackupContents_WrongPasswordFails(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)

	output := filepath.Join(home, "contents-wrong-password.xkb")
	setBackupFlags(t, backupCreateCmd, map[string]string{"output": output, "password": "the-real-password"})
	var createOut bytes.Buffer
	backupCreateCmd.SetOut(&createOut)
	require.NoError(t, runBackupCreate(backupCreateCmd, nil))

	setBackupFlags(t, backupContentsCmd, map[string]string{"password": "guessing", "key": ""})
	var contentsOut bytes.Buffer
	backupContentsCmd.SetOut(&contentsOut)

	err := runBackupContents(backupContentsCmd, []string{output})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
	assert.Empty(t, contentsOut.String())
}

func TestBackupCreate_GeneratedKeyRoundTrip(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)

	output := filepath.Join(home, "generated-key.xkb")
	setBackupFlags(t, backupCreateCmd, map[string]string{"output": output, "password": ""})
	var createOut bytes.Buffer
	backupCreateCmd.SetOut(&createOut)
	require.NoError(t, runBackupCreate(backupCreateCmd, nil))

	key := parseGeneratedBackupKey(t, createOut.String())

	setBackupFlags(t, backupContentsCmd, map[string]string{"password": "", "key": key})
	var contentsOut bytes.Buffer
	backupContentsCmd.SetOut(&contentsOut)
	require.NoError(t, runBackupContents(backupContentsCmd, []string{output}))
	assert.Contains(t, contentsOut.String(), "Trust certs:  1")
}

func TestBackupCreate_NoDataRefused(t *testing.T) {
	home := isolatedBackupHome(t)

	output := filepath.Join(home, "empty.xkb")
	setBackupFlags(t, backupCreateCmd, map[string]string{"output": output, "password": "pw"})
	var createOut bytes.Buffer
	backupCreateCmd.SetOut(&createOut)

	err := runBackupCreate(backupCreateCmd, nil)
	require.Error(t, err, "an empty backup must never be written")
	assert.ErrorIs(t, err, ErrBackupNoData)
	assert.Contains(t, err.Error(), backup.ItemCAData)

	_, statErr := os.Stat(output)
	assert.True(t, os.IsNotExist(statErr), "no file may be left behind")
}

func TestBackupList_ReportsListFailure(t *testing.T) {
	home := isolatedBackupHome(t)

	// A regular file where the backups directory belongs makes the listing
	// fail with the list sentinel, not the creation sentinel.
	blocked := filepath.Join(home, ".xkey", "backups")
	require.NoError(t, os.MkdirAll(filepath.Dir(blocked), 0700))
	require.NoError(t, os.WriteFile(blocked, []byte("not a directory"), 0600))

	var listOut bytes.Buffer
	backupListCmd.SetOut(&listOut)

	err := runBackupList(backupListCmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupListFailed)
	assert.NotErrorIs(t, err, ErrBackupCreateFailed)
}
