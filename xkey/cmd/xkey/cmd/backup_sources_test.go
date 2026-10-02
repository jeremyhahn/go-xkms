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

// seededTrustOptions is the metadata seedBackupStores files its certificate
// under.
func seededTrustOptions() *truststore.AddCertificateOptions {
	return &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeSynced,
		Source:  "backup-seed",
		Tags:    []string{"seed"},
	}
}

// seedBackupStores writes one certificate, one OATH credential, and one
// static password into the default stores beneath the isolated home.
func seedBackupStores(t *testing.T, home string) {
	t.Helper()

	dataDir := backupTestDataDir(home)

	trustStore, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(dataDir, trustDataSubdir),
	})
	require.NoError(t, err)
	// Filed under a purpose auto-classification would never choose for a
	// self-signed CA (it would pick user-ca), so a restore that re-classified
	// instead of honouring the recorded purpose is caught (#1312).
	imported, err := trustStore.ImportPEM(newTestCertificatePEM(t, "backup-unit-test-ca"), seededTrustOptions())
	require.NoError(t, err)
	require.Equal(t, 1, imported.Added)
	require.NoError(t, trustStore.Close())

	oathStore, err := oath.NewFileStore(filepath.Join(dataDir, oathStoreFilename))
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

	// The static password store lives at passwordStoreFeature ("staticpw"),
	// not a private "passwords" copy of the name (go-xkms#936): seeding
	// anywhere else would let a wrong default silently pass this fixture.
	passwordStore, err := openPasswordStore(filepath.Join(dataDir, passwordStoreFeature))
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
// backupPasswordTestKey is the setBackupFlags key that supplies the backup
// password. There is no --password value flag (go-xkms#1202): the value is
// routed through XKEY_BACKUP_PASSWORD, one of the two sources the backup
// commands read. An empty value supplies no password.
const backupPasswordTestKey = "password"

// backupKeyTestKey is the setBackupFlags key that supplies the backup's raw
// hex key. There is no --key value flag (go-xkms#1209): the value is routed
// through XKEY_BACKUP_KEY, one of the two sources "backup restore",
// "backup contents" and "backup from-device" read. An empty value supplies
// no key.
const backupKeyTestKey = "key"

// backupBarrierPasswordTestKey is the setBackupFlags key that supplies the
// barrier password. There is no --barrier-password value flag
// (go-xkms#1209): the value is routed through XKEY_BARRIER_PASSWORD, one of
// the sources resolveBarrierPassword reads.
const backupBarrierPasswordTestKey = "barrier-password"

// setBackupPassword supplies password to the backup commands through the
// XKEY_BACKUP_PASSWORD environment source for the rest of the test.
func setBackupPassword(t *testing.T, password string) {
	t.Helper()
	t.Setenv(backupPasswordSource.envVar, password)
}

// setBackupKey supplies the raw hex key to the backup commands through the
// XKEY_BACKUP_KEY environment source for the rest of the test.
func setBackupKey(t *testing.T, keyHex string) {
	t.Helper()
	t.Setenv(backupKeySource.envVar, keyHex)
}

func setBackupFlags(t *testing.T, cmd *cobra.Command, values map[string]string) {
	t.Helper()

	previous := make(map[string]string, len(values))
	for name, value := range values {
		switch name {
		case backupPasswordTestKey:
			setBackupPassword(t, value)
			continue
		case backupKeyTestKey:
			setBackupKey(t, value)
			continue
		case backupBarrierPasswordTestKey:
			t.Setenv(barrierPasswordSource.envVar, value)
			continue
		}
		flag := cmd.Flags().Lookup(name)
		require.NotNil(t, flag, "flag %q must exist", name)
		previous[name] = flag.Value.String()
		require.NoError(t, setFlagForTest(t, cmd.Flags(), name, value))
	}

	t.Cleanup(func() {
		for name, value := range previous {
			_ = setFlagForTest(t, cmd.Flags(), name, value)
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
		{"legacy_unsalted", backup.ErrLegacyBackupFormat, "re-create the backup"},
		{"raw_key_envelope", backup.ErrNotPasswordSealed, "--key"},
		{"kdf_record", backup.ErrKeyDerivationFailed, "key-derivation record"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyBackupDecryptError(tc.cause)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrBackupDecryptFailed)
			assert.ErrorIs(t, err, tc.cause, "the classified cause must stay in the chain")
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

// --- Missing-source helpers (go-xkms#936) ---

func TestPathExists_PresentAndAbsent(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	require.NoError(t, os.Mkdir(present, 0700))

	exists, err := pathExists(present)
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = pathExists(filepath.Join(dir, "absent"))
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestPathExists_RealStatFailure(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	// A path beneath a regular file can never be stat'd as a directory: this
	// is a genuine I/O error, not "does not exist".
	_, err := pathExists(filepath.Join(blocker, "child"))
	require.Error(t, err)
	assert.False(t, os.IsNotExist(err))
}

func TestRequireExplicitSource_NonStrictAlwaysPasses(t *testing.T) {
	err := requireExplicitSource(false, backup.ItemTrustStore, filepath.Join(t.TempDir(), "absent"))
	assert.NoError(t, err, "a write run never demands the destination already exist")
}

func TestRequireExplicitSource_StrictMissingErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	err := requireExplicitSource(true, backup.ItemTrustStore, path)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupSourceMissing)
	assert.Contains(t, err.Error(), backup.ItemTrustStore)
	assert.Contains(t, err.Error(), path)
}

func TestRequireExplicitSource_StrictPresentPasses(t *testing.T) {
	dir := t.TempDir()
	assert.NoError(t, requireExplicitSource(true, backup.ItemTrustStore, dir))
}

func TestDefaultSourceMissing_NonStrictAlwaysFalse(t *testing.T) {
	missing, err := defaultSourceMissing(false, backup.ItemPasswords, filepath.Join(t.TempDir(), "absent"))
	require.NoError(t, err)
	assert.False(t, missing)
}

func TestDefaultSourceMissing_StrictReportsAbsent(t *testing.T) {
	missing, err := defaultSourceMissing(true, backup.ItemPasswords, filepath.Join(t.TempDir(), "absent"))
	require.NoError(t, err)
	assert.True(t, missing)
}

func TestDefaultSourceMissing_StrictPresentReportsFalse(t *testing.T) {
	dir := t.TempDir()
	missing, err := defaultSourceMissing(true, backup.ItemPasswords, dir)
	require.NoError(t, err)
	assert.False(t, missing)
}

func TestDefaultSourceMissing_StrictStatFailurePropagates(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	_, err := defaultSourceMissing(true, backup.ItemPasswords, filepath.Join(blocker, "child"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupStoreUnavailable)
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

// TestResolveBackupSources_Defaults_NothingWrittenYet is the go-xkms#936
// regression guard for a fresh xkey home: in strict (read) mode, a default
// store location that has never been written to must be reported as a
// missing source and left unopened, not auto-created and silently backed up
// as empty.
func TestResolveBackupSources_Defaults_NothingWrittenYet(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	sources, err := resolveBackupSources(backupCreateCmd, backupStorePaths{}, true)
	require.NoError(t, err)
	defer sources.Close()

	assert.Nil(t, sources.trust)
	assert.Nil(t, sources.oath)
	assert.Nil(t, sources.passwords)
	assert.Empty(t, sources.readerOptions())

	require.Len(t, sources.skipped, 4)
	items := make([]string, len(sources.skipped))
	for i, skip := range sources.skipped {
		items[i] = skip.Item
	}
	assert.Contains(t, items, backup.ItemCAData)
	assert.Contains(t, items, backup.ItemTrustStore)
	assert.Contains(t, items, backup.ItemOATH)
	assert.Contains(t, items, backup.ItemPasswords)

	summary := sources.summary()
	assert.Contains(t, summary, filepath.Join(dataDir, trustDataSubdir))
	assert.Contains(t, summary, filepath.Join(dataDir, oathStoreFilename))
	assert.Contains(t, summary, filepath.Join(dataDir, passwordStoreFeature))
}

// TestResolveBackupSources_Defaults_PopulatedStores is the counterpart to
// the regression guard above: once the default stores actually hold data
// (seedBackupStores writes to the real defaults, including passwordStoreFeature
// "staticpw"), strict mode opens all three and reports nothing missing.
func TestResolveBackupSources_Defaults_PopulatedStores(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)
	seedBackupStores(t, home)

	sources, err := resolveBackupSources(backupCreateCmd, backupStorePaths{}, true)
	require.NoError(t, err)
	defer sources.Close()

	require.NotNil(t, sources.trust)
	require.NotNil(t, sources.oath)
	require.NotNil(t, sources.passwords)
	assert.Equal(t, filepath.Join(dataDir, trustDataSubdir), sources.trust.path)
	assert.Equal(t, filepath.Join(dataDir, oathStoreFilename), sources.oath.path)
	assert.Equal(t, filepath.Join(dataDir, passwordStoreFeature), sources.passwords.path)
	assert.Len(t, sources.readerOptions(), 3)

	require.Len(t, sources.skipped, 1)
	assert.Equal(t, backup.ItemCAData, sources.skipped[0].Item)
	assert.Contains(t, sources.summary(), backup.ItemCAData)

	passwords, err := sources.passwords.List()
	require.NoError(t, err)
	require.Len(t, passwords, 1)
	assert.Equal(t, "UnitTestEntry", passwords[0].Name)
}

// TestResolveBackupSources_Defaults_NonStrictAutoCreates covers the write
// (restore) side: a default location that has never been written to must
// still be opened -- and thereby created -- so restored data has somewhere
// to land, exactly like before go-xkms#936.
func TestResolveBackupSources_Defaults_NonStrictAutoCreates(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	sources, err := resolveBackupSources(backupCreateCmd, backupStorePaths{}, false)
	require.NoError(t, err)
	defer sources.Close()

	require.NotNil(t, sources.trust)
	require.NotNil(t, sources.oath)
	require.NotNil(t, sources.passwords)
	assert.Equal(t, filepath.Join(dataDir, trustDataSubdir), sources.trust.path)
	assert.Equal(t, filepath.Join(dataDir, oathStoreFilename), sources.oath.path)
	assert.Equal(t, filepath.Join(dataDir, passwordStoreFeature), sources.passwords.path)

	require.Len(t, sources.skipped, 1, "non-strict mode never reports a default as missing")
	assert.Equal(t, backup.ItemCAData, sources.skipped[0].Item)
}

func TestResolveBackupSources_ExplicitPaths(t *testing.T) {
	isolatedBackupHome(t)
	dir := t.TempDir()

	paths := backupStorePaths{
		trust:     filepath.Join(dir, "custom-trust"),
		oath:      filepath.Join(dir, "custom-oath.json"),
		passwords: filepath.Join(dir, "custom-passwords"),
	}

	// strict=false: this exercises path-override wiring, not the missing-
	// source behavior covered by the explicit-path tests below, so the
	// stores are created on first open exactly as a restore would.
	sources, err := resolveBackupSources(backupCreateCmd, paths, false)
	require.NoError(t, err)
	defer sources.Close()

	assert.Equal(t, paths.trust, sources.trust.path)
	assert.Equal(t, paths.oath, sources.oath.path)
	assert.Equal(t, paths.passwords, sources.passwords.path)
}

// TestResolveBackupSources_ExplicitPathMissing_StrictErrors is the
// go-xkms#936 explicit-path counterpart to the default-source regression
// guard: an operator-named source that does not exist must fail loudly in
// strict (read) mode, never silently auto-create an empty store.
func TestResolveBackupSources_ExplicitPathMissing_StrictErrors(t *testing.T) {
	isolatedBackupHome(t)
	dir := t.TempDir()

	_, err := resolveBackupSources(backupCreateCmd, backupStorePaths{
		trust: filepath.Join(dir, "never-created"),
	}, true)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupSourceMissing)
	assert.Contains(t, err.Error(), backup.ItemTrustStore)

	_, statErr := os.Stat(filepath.Join(dir, "never-created"))
	assert.True(t, os.IsNotExist(statErr), "a strict read must never create the path it could not find")
}

func TestResolveBackupSources_BarrierEncryptedRefused(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	rootKey := filepath.Join(dataDir, defaultBarrierRootKeyPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(rootKey), 0700))
	require.NoError(t, os.WriteFile(rootKey, []byte("sealed"), 0600))

	_, err := resolveBackupSources(backupCreateCmd, backupStorePaths{}, true)
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
	}, false)
	require.NoError(t, err)
	sources.Close()
}

func TestResolveBackupSources_UnopenableStore(t *testing.T) {
	isolatedBackupHome(t)
	dir := t.TempDir()

	// A regular file where the trust store directory belongs makes the
	// store impossible to open (and impossible to stat as a directory), so
	// this is a real I/O failure rather than a missing source.
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	_, err := resolveBackupSources(backupCreateCmd, backupStorePaths{
		trust:     filepath.Join(blocker, "trust"),
		oath:      filepath.Join(dir, "oath.json"),
		passwords: filepath.Join(dir, "passwords"),
	}, true)
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

	imported, err := adapter.ImportPEM(newTestCertificatePEM(t, "adapter-ca"),
		&truststore.AddCertificateOptions{Purpose: truststore.PurposeBootstrapCA, Source: "adapter-test"})
	require.NoError(t, err)
	require.Equal(t, 1, imported.Added)

	certs, err := adapter.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)

	meta, err := adapter.Metadata(certFingerprintHex(certs[0].Raw))
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, certFingerprintHex(certs[0].Raw), meta.Fingerprint)
	assert.Equal(t, string(truststore.PurposeBootstrapCA), meta.Purpose)
	assert.Equal(t, "adapter-test", meta.Source)
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
	require.NoError(t, restoredCred.SetSecret([]byte("JBSWY3DPEHPK3PXP")))
	require.NoError(t, adapter.Add(restoredCred))

	creds, err := adapter.List()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "restored-id", creds[0].ID)
	assert.Equal(t, "Restored", creds[0].Name)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", secretText(creds[0]))
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
	require.NoError(t, restoredPW.SetPassword([]byte("s3cret")))
	require.NoError(t, adapter.Add(restoredPW))

	entries, err := adapter.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "Restored", entries[0].Name)
	assert.Equal(t, "s3cret", passwordText(entries[0]))
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

	imported, err := adapter.ImportPEM(newTestCertificatePEM(t, "contains-ca"), seededTrustOptions())
	require.NoError(t, err)
	require.Equal(t, 1, imported.Added)

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
	require.NoError(t, seed.SetSecret([]byte("JBSWY3DPEHPK3PXP")))
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
	require.NoError(t, seed.SetPassword([]byte("s3cret")))
	require.NoError(t, adapter.Add(seed))

	entries, err := adapter.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	got, err := adapter.Get(entries[0].ID)
	require.NoError(t, err)
	assert.Equal(t, "Original", got.Name)

	got.Title = "Renamed Entry"
	require.NoError(t, got.SetPassword([]byte("s3cret")))
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

	sources, err := resolveBackupSources(backupCreateCmd, backupStorePaths{}, false)
	require.NoError(t, err)
	defer sources.Close()

	assert.Len(t, sources.syncOptions(), 3,
		"one sync option must be returned per opened store")
}

// --- Command round trip ---

// TestBackupCreate_DefaultCapturesStaticPasswords is the go-xkms#936
// end-to-end regression guard: "xkey backup create" with no --password-store
// override must read the real static password store location
// (passwordStoreFeature, "staticpw") and carry its entries, not the
// previously hard-coded "passwords" directory that nothing ever wrote to.
func TestBackupCreate_DefaultCapturesStaticPasswords(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	passwordStore, err := openPasswordStore(filepath.Join(dataDir, passwordStoreFeature))
	require.NoError(t, err)
	require.NoError(t, passwordStore.Add(&xkms.StaticPassword{
		Name:     "DefaultCaptureEntry",
		Username: "operator",
		Password: "captured-by-default",
	}))
	require.NoError(t, passwordStore.Close())

	output := filepath.Join(home, "default-capture.xkb")
	setBackupFlags(t, backupCreateCmd, map[string]string{"output": output, "password": "pw"})
	var createOut bytes.Buffer
	backupCreateCmd.SetOut(&createOut)
	require.NoError(t, runBackupCreate(backupCreateCmd, nil))
	assert.Contains(t, createOut.String(), "Passwords:    1")

	setBackupFlags(t, backupContentsCmd, map[string]string{"password": "pw", "key": ""})
	var contentsOut bytes.Buffer
	backupContentsCmd.SetOut(&contentsOut)
	require.NoError(t, runBackupContents(backupContentsCmd, []string{output}))
	assert.Contains(t, contentsOut.String(), "Passwords:    1")
}

// TestBackupCreate_MissingDefaultSourceReported is the go-xkms#936 guard for
// the other half of the fix: a default source that has never been written to
// must be named in the "Not included:" report, not silently absorbed into a
// "Passwords: 0" line with no explanation.
func TestBackupCreate_MissingDefaultSourceReported(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	// Seed only the trust store, so create has data to work with but the
	// static password store's default location is never touched.
	trustStore, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(dataDir, trustDataSubdir),
	})
	require.NoError(t, err)
	_, err = trustStore.AddPEM(newTestCertificatePEM(t, "missing-source-ca"))
	require.NoError(t, err)
	require.NoError(t, trustStore.Close())

	output := filepath.Join(home, "missing-source.xkb")
	setBackupFlags(t, backupCreateCmd, map[string]string{"output": output, "password": "pw"})
	var createOut bytes.Buffer
	backupCreateCmd.SetOut(&createOut)
	require.NoError(t, runBackupCreate(backupCreateCmd, nil))

	out := createOut.String()
	assert.Contains(t, out, "Not included:")
	assert.Contains(t, out, backup.ItemPasswords)
	assert.Contains(t, out, backup.ItemOATH)
}

// TestBackupCreate_ExplicitPasswordStoreWins is the go-xkms#936 guard for
// --password-store: an explicit override must be read from instead of the
// resolved default, even when the default location holds different data.
func TestBackupCreate_ExplicitPasswordStoreWins(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	defaultStore, err := openPasswordStore(filepath.Join(dataDir, passwordStoreFeature))
	require.NoError(t, err)
	require.NoError(t, defaultStore.Add(&xkms.StaticPassword{Name: "DefaultEntry", Password: "default-value"}))
	require.NoError(t, defaultStore.Close())

	explicitDir := filepath.Join(t.TempDir(), "explicit-passwords")
	explicitStore, err := openPasswordStore(explicitDir)
	require.NoError(t, err)
	require.NoError(t, explicitStore.Add(&xkms.StaticPassword{Name: "ExplicitEntry", Password: "explicit-value"}))
	require.NoError(t, explicitStore.Close())

	output := filepath.Join(home, "explicit-wins.xkb")
	setBackupFlags(t, backupCreateCmd, map[string]string{
		"output":         output,
		"password":       "pw",
		"password-store": explicitDir,
	})
	var createOut bytes.Buffer
	backupCreateCmd.SetOut(&createOut)
	require.NoError(t, runBackupCreate(backupCreateCmd, nil))

	setBackupFlags(t, backupContentsCmd, map[string]string{"password": "pw", "key": ""})
	var contentsOut bytes.Buffer
	backupContentsCmd.SetOut(&contentsOut)
	require.NoError(t, runBackupContents(backupContentsCmd, []string{output}))
	assert.Contains(t, contentsOut.String(), "Passwords:    1")

	svc, err := backup.NewService(&backup.Config{DeviceName: "test"})
	require.NoError(t, err)
	encrypted, err := readEncryptedBackup(output)
	require.NoError(t, err)
	key, err := encrypted.PasswordKey([]byte("pw"))
	require.NoError(t, err)
	archive, err := svc.DecryptBackup(encrypted, key)
	require.NoError(t, err)
	require.Len(t, archive.Passwords, 1)
	assert.Equal(t, "ExplicitEntry", archive.Passwords[0].Name,
		"the explicit --password-store entry must be backed up, not the default store's")
}

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
	restoredPasswords, err := openPasswordStore(filepath.Join(backupTestDataDir(restoreHome), passwordStoreFeature))
	require.NoError(t, err)
	defer func() { _ = restoredPasswords.Close() }()
	entries, err := restoredPasswords.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "UnitTestEntry", entries[0].Name)
	assert.Equal(t, "s3cret-value", entries[0].Password)

	restoredOATH, err := oath.NewFileStore(filepath.Join(backupTestDataDir(restoreHome), oathStoreFilename))
	require.NoError(t, err)
	defer func() { _ = restoredOATH.Close() }()
	creds, err := restoredOATH.List()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "UnitTestOATH", creds[0].Name)

	restoredTrust, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(backupTestDataDir(restoreHome), trustDataSubdir),
	})
	require.NoError(t, err)
	defer func() { _ = restoredTrust.Close() }()
	certs, err := restoredTrust.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "backup-unit-test-ca", certs[0].Subject.CommonName)

	// The certificate is restored under the metadata it was backed up with,
	// not re-classified (#1312).
	meta, err := restoredTrust.Metadata(truststore.Fingerprint(certs[0]))
	require.NoError(t, err)
	want := seededTrustOptions()
	assert.Equal(t, want.Purpose, meta.Purpose)
	assert.Equal(t, want.Source, meta.Source)
	assert.Equal(t, want.Tags, meta.Tags)
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
