// Copyright (c) 2025-2026 Jeremy Hahn
// Copyright (c) 2025-2026 Automate The Things, LLC
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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSecureBrowserCA generates a self-signed CA certificate for testing.
func testSecureBrowserCA(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// testSecureBrowserCA2 generates a second CA with a different serial.
func testSecureBrowserCA2(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test CA 2",
			Organization: []string{"Test Org 2"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0xCA, 0xFE, 0xBA, 0xBE},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// mockSecureBrowserTrustStore implements truststore.TrustStore for testing.
// Only methods used by SecureBrowserService (via TrustService.AllCertificates)
// have meaningful implementations.
type mockSecureBrowserTrustStore struct {
	certs []*x509.Certificate
}

var _ truststore.TrustStore = (*mockSecureBrowserTrustStore)(nil)

func (m *mockSecureBrowserTrustStore) AddCertificate(_ *x509.Certificate) error { return nil }
func (m *mockSecureBrowserTrustStore) AddCertificateWithOptions(_ *x509.Certificate, _ *truststore.AddCertificateOptions) error {
	return nil
}
func (m *mockSecureBrowserTrustStore) AddPEM(_ []byte) (int, error) { return 0, nil }
func (m *mockSecureBrowserTrustStore) RemoveCertificate(_ string) error {
	return nil
}
func (m *mockSecureBrowserTrustStore) Certificates() ([]*x509.Certificate, error) {
	return m.certs, nil
}
func (m *mockSecureBrowserTrustStore) CertificatesByPurpose(_ truststore.CertPurpose) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockSecureBrowserTrustStore) CertPool() (*x509.CertPool, error) { return nil, nil }
func (m *mockSecureBrowserTrustStore) Contains(_ string) (bool, error)   { return false, nil }
func (m *mockSecureBrowserTrustStore) Count() (int, error)               { return len(m.certs), nil }
func (m *mockSecureBrowserTrustStore) Metadata(_ string) (*truststore.CertMetadata, error) {
	return &truststore.CertMetadata{}, nil
}
func (m *mockSecureBrowserTrustStore) SetPurpose(_ string, _ truststore.CertPurpose) error {
	return nil
}
func (m *mockSecureBrowserTrustStore) SetSource(_ string, _ string) error       { return nil }
func (m *mockSecureBrowserTrustStore) SetSystemInstalled(_ string, _ bool) error { return nil }
func (m *mockSecureBrowserTrustStore) SetTags(_ string, _ []string) error       { return nil }
func (m *mockSecureBrowserTrustStore) Close() error                             { return nil }

// newTestSecureBrowserService creates a SecureBrowserService with a mock
// exec command for testing.
func newTestSecureBrowserService(t *testing.T, certs []*x509.Certificate) (*SecureBrowserService, string) {
	t.Helper()
	baseDir := filepath.Join(t.TempDir(), "browsers")
	require.NoError(t, os.MkdirAll(baseDir, 0o700))

	configPath := filepath.Join(t.TempDir(), "browser.json")
	logger := slog.Default()

	browserSvc, err := NewBrowserService(configPath, logger)
	require.NoError(t, err)

	trustSvc := NewTrustService(&mockSecureBrowserTrustStore{certs: certs})

	svc := NewSecureBrowserService(baseDir, browserSvc, trustSvc, logger)
	svc.execCommand = mockSecureBrowserExecCommand

	return svc, baseDir
}

// mockSecureBrowserExecCommand creates a command that immediately succeeds.
func mockSecureBrowserExecCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}

// TestComputeTrustHash verifies deterministic hash computation.
func TestComputeTrustHash(t *testing.T) {
	cert1 := testSecureBrowserCA(t, "CA 1")
	cert2 := testSecureBrowserCA2(t)

	// Same certs in same order should produce same hash.
	hash1 := computeTrustHash([]*x509.Certificate{cert1, cert2})
	hash2 := computeTrustHash([]*x509.Certificate{cert1, cert2})
	assert.Equal(t, hash1, hash2)

	// Order should not matter (sorted internally).
	hash3 := computeTrustHash([]*x509.Certificate{cert2, cert1})
	assert.Equal(t, hash1, hash3)

	// Different cert set should produce different hash.
	hash4 := computeTrustHash([]*x509.Certificate{cert1})
	assert.NotEqual(t, hash1, hash4)
}

// TestComputeTrustHashEmpty verifies hash of empty cert list.
func TestComputeTrustHashEmpty(t *testing.T) {
	hash := computeTrustHash(nil)
	// SHA-256 of empty string.
	expected := sha256.Sum256([]byte(""))
	assert.Equal(t, hex.EncodeToString(expected[:]), hash)
}

// TestComputeTrustHashDeterministic verifies the exact hash value.
func TestComputeTrustHashDeterministic(t *testing.T) {
	cert := testSecureBrowserCA(t, "Deterministic CA")
	fp := certFingerprint(cert)

	// Manual computation.
	sorted := []string{fp}
	sort.Strings(sorted)
	expected := sha256.Sum256([]byte(strings.Join(sorted, "")))

	hash := computeTrustHash([]*x509.Certificate{cert})
	assert.Equal(t, hex.EncodeToString(expected[:]), hash)
}

// TestClassifyBrowser verifies browser family detection from binary paths.
func TestClassifyBrowser(t *testing.T) {
	tests := []struct {
		path   string
		family string
	}{
		{"/usr/bin/google-chrome", "chrome"},
		{"/usr/bin/chromium", "chrome"},
		{"/usr/bin/chromium-browser", "chrome"},
		{"/usr/bin/brave-browser", "chrome"},
		{"/usr/bin/microsoft-edge", "chrome"},
		{"/usr/bin/vivaldi", "chrome"},
		{"/usr/bin/opera", "chrome"},
		{"/usr/bin/firefox", "firefox"},
		{"/usr/bin/librewolf", "firefox"},
		{"/usr/bin/waterfox", "firefox"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			family := classifyBrowser(tt.path)
			assert.Equal(t, tt.family, string(family))
		})
	}
}

// TestClassifyBrowserUnknown verifies empty return for unrecognized browsers.
func TestClassifyBrowserUnknown(t *testing.T) {
	family := classifyBrowser("/usr/bin/safari")
	assert.Empty(t, string(family))

	family = classifyBrowser("/usr/bin/lynx")
	assert.Empty(t, string(family))
}

// TestFirefoxPoliciesGeneration verifies correct policies.json structure.
func TestFirefoxPoliciesGeneration(t *testing.T) {
	cert := testSecureBrowserCA(t, "Firefox Test CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	err := svc.syncFirefox([]*x509.Certificate{cert})
	require.NoError(t, err)

	// Verify policies.json exists and is valid.
	policiesPath := filepath.Join(baseDir, "firefox", firefoxPoliciesFile)
	data, err := os.ReadFile(policiesPath)
	require.NoError(t, err)

	var policies firefoxPolicies
	err = json.Unmarshal(data, &policies)
	require.NoError(t, err)

	assert.True(t, policies.Policies.Certificates.ImportEnterpriseRoots)
	assert.Len(t, policies.Policies.Certificates.Install, 1)
	assert.Contains(t, policies.Policies.Certificates.Install[0], ".pem")
}

// TestFirefoxPoliciesMultipleCerts verifies policies with multiple certs.
func TestFirefoxPoliciesMultipleCerts(t *testing.T) {
	cert1 := testSecureBrowserCA(t, "FF CA 1")
	cert2 := testSecureBrowserCA2(t)
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert1, cert2})

	err := svc.syncFirefox([]*x509.Certificate{cert1, cert2})
	require.NoError(t, err)

	policiesPath := filepath.Join(baseDir, "firefox", firefoxPoliciesFile)
	data, err := os.ReadFile(policiesPath)
	require.NoError(t, err)

	var policies firefoxPolicies
	require.NoError(t, json.Unmarshal(data, &policies))
	assert.Len(t, policies.Policies.Certificates.Install, 2)
}

// TestFirefoxPEMExport verifies individual PEM files are created.
func TestFirefoxPEMExport(t *testing.T) {
	cert := testSecureBrowserCA(t, "PEM Export CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	err := svc.syncFirefox([]*x509.Certificate{cert})
	require.NoError(t, err)

	certsDir := filepath.Join(baseDir, "firefox", "certs")
	entries, err := os.ReadDir(certsDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	// Verify the PEM file contains a valid certificate.
	pemPath := filepath.Join(certsDir, entries[0].Name())
	pemData, err := os.ReadFile(pemPath)
	require.NoError(t, err)
	assert.Contains(t, string(pemData), "BEGIN CERTIFICATE")
}

// TestFirefoxPEMExportCleansOldFiles verifies stale PEM files are removed.
func TestFirefoxPEMExportCleansOldFiles(t *testing.T) {
	cert1 := testSecureBrowserCA(t, "PEM Clean CA 1")
	cert2 := testSecureBrowserCA2(t)
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert1, cert2})

	// First sync with two certs.
	err := svc.syncFirefox([]*x509.Certificate{cert1, cert2})
	require.NoError(t, err)

	certsDir := filepath.Join(baseDir, "firefox", "certs")
	entries, err := os.ReadDir(certsDir)
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	// Second sync with one cert should remove the other.
	err = svc.syncFirefox([]*x509.Certificate{cert1})
	require.NoError(t, err)

	entries, err = os.ReadDir(certsDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

// TestChromeNSSDB verifies NSS database creation for Chrome.
func TestChromeNSSDB(t *testing.T) {
	cert := testSecureBrowserCA(t, "Chrome NSS CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	err := svc.syncChrome([]*x509.Certificate{cert})
	require.NoError(t, err)

	// Verify NSS database files exist.
	nssdbDir := filepath.Join(baseDir, "chrome", "profile", "pki", "nssdb")
	_, err = os.Stat(filepath.Join(nssdbDir, "cert9.db"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(nssdbDir, "key4.db"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(nssdbDir, "pkcs11.txt"))
	require.NoError(t, err)
}

// TestChromeNSSDBMultipleCerts verifies adding multiple certs to NSS DB.
func TestChromeNSSDBMultipleCerts(t *testing.T) {
	cert1 := testSecureBrowserCA(t, "Chrome CA 1")
	cert2 := testSecureBrowserCA2(t)
	svc, _ := newTestSecureBrowserService(t, []*x509.Certificate{cert1, cert2})

	err := svc.syncChrome([]*x509.Certificate{cert1, cert2})
	require.NoError(t, err)

	// Re-sync should succeed (idempotent via RemoveByPrefix + re-add).
	err = svc.syncChrome([]*x509.Certificate{cert1})
	require.NoError(t, err)
}

// TestLaunchBrowserChrome verifies Chrome launch with correct arguments.
func TestLaunchBrowserChrome(t *testing.T) {
	cert := testSecureBrowserCA(t, "Launch Chrome CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	svc.SetContext(context.Background())

	var capturedArgs []string
	svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = append([]string{name}, args...)
		return exec.CommandContext(ctx, "true")
	}

	result, err := svc.LaunchBrowser("/usr/bin/google-chrome", "https://example.com")
	require.NoError(t, err)
	assert.Equal(t, "chrome", result.Family)
	assert.Equal(t, ProfileModeIsolated, result.Mode)
	assert.Equal(t, 1, result.CertCount)

	// Verify --user-data-dir is set for isolated mode.
	assert.Contains(t, capturedArgs[1], "--user-data-dir="+filepath.Join(baseDir, "chrome", "profile"))
	assert.Equal(t, "https://example.com", capturedArgs[len(capturedArgs)-1])
}

// TestLaunchBrowserFirefox verifies Firefox launch with correct arguments.
func TestLaunchBrowserFirefox(t *testing.T) {
	cert := testSecureBrowserCA(t, "Launch Firefox CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	svc.SetContext(context.Background())

	var capturedArgs []string
	svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = append([]string{name}, args...)
		return exec.CommandContext(ctx, "true")
	}

	result, err := svc.LaunchBrowser("/usr/bin/firefox", "https://example.com")
	require.NoError(t, err)
	assert.Equal(t, "firefox", result.Family)
	assert.Equal(t, ProfileModeIsolated, result.Mode)
	assert.Equal(t, 1, result.CertCount)

	// Verify --profile is set for isolated mode.
	assert.Contains(t, capturedArgs, "--profile")
	profileDir := filepath.Join(baseDir, "firefox", "profile")
	assert.Contains(t, capturedArgs, profileDir)
	assert.Equal(t, "https://example.com", capturedArgs[len(capturedArgs)-1])
}

// TestLaunchBrowserSharedMode verifies shared profile mode omits profile flags.
func TestLaunchBrowserSharedMode(t *testing.T) {
	cert := testSecureBrowserCA(t, "Shared Mode CA")
	svc, _ := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	svc.SetContext(context.Background())

	// Configure shared mode for Chrome.
	config := svc.browserService.GetConfig()
	config.ChromeProfileMode = ProfileModeShared
	require.NoError(t, svc.browserService.SetConfig(config))

	var capturedArgs []string
	svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = append([]string{name}, args...)
		return exec.CommandContext(ctx, "true")
	}

	result, err := svc.LaunchBrowser("/usr/bin/google-chrome", "https://example.com")
	require.NoError(t, err)
	assert.Equal(t, ProfileModeShared, result.Mode)

	// --user-data-dir should NOT be present in shared mode.
	for _, arg := range capturedArgs {
		assert.False(t, strings.HasPrefix(arg, "--user-data-dir="),
			"shared mode should not set --user-data-dir")
	}
}

// TestLaunchBrowserEmptyPath verifies error on empty browser path.
func TestLaunchBrowserEmptyPath(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)
	_, err := svc.LaunchBrowser("", "https://example.com")
	assert.ErrorIs(t, err, ErrSecureBrowserEmptyPath)
}

// TestLaunchBrowserEmptyURL verifies error on empty URL.
func TestLaunchBrowserEmptyURL(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)
	_, err := svc.LaunchBrowser("/usr/bin/firefox", "")
	assert.ErrorIs(t, err, ErrSecureBrowserEmptyURL)
}

// TestLaunchBrowserUnknownFamily verifies error for unrecognized browser.
func TestLaunchBrowserUnknownFamily(t *testing.T) {
	cert := testSecureBrowserCA(t, "Unknown CA")
	svc, _ := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	_, err := svc.LaunchBrowser("/usr/bin/lynx", "https://example.com")
	assert.ErrorIs(t, err, ErrSecureBrowserUnknownFamily)
}

// TestLaunchBrowserNoCerts verifies error when trust store is empty.
func TestLaunchBrowserNoCerts(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, []*x509.Certificate{})
	_, err := svc.LaunchBrowser("/usr/bin/firefox", "https://example.com")
	assert.ErrorIs(t, err, ErrSecureBrowserNoCerts)
}

// TestLaunchBrowserNilTrustStore verifies error when trust store is nil.
func TestLaunchBrowserNilTrustStore(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "browsers")
	require.NoError(t, os.MkdirAll(baseDir, 0o700))

	configPath := filepath.Join(t.TempDir(), "browser.json")
	browserSvc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	// TrustService with nil store.
	trustSvc := NewTrustService(nil)
	svc := NewSecureBrowserService(baseDir, browserSvc, trustSvc, slog.Default())

	_, launchErr := svc.LaunchBrowser("/usr/bin/firefox", "https://example.com")
	assert.ErrorIs(t, launchErr, ErrSecureBrowserCertSync)
}

// TestDetectBrowsersFiltering verifies that only Chrome/Firefox family
// browsers are returned and system default is excluded.
func TestDetectBrowsersFiltering(t *testing.T) {
	cert := testSecureBrowserCA(t, "Detect CA")
	svc, _ := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	browsers := svc.DetectBrowsers()
	for _, b := range browsers {
		assert.NotEqual(t, BrowserSystem, b.Path, "system default should be filtered out")
		family := classifyBrowser(b.Path)
		assert.NotEmpty(t, string(family), "all returned browsers should have a known family")
	}
}

// TestRebuild verifies forced rebuild updates the trust hash.
func TestRebuild(t *testing.T) {
	cert := testSecureBrowserCA(t, "Rebuild CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	err := svc.Rebuild()
	require.NoError(t, err)

	// Verify trust hash was written.
	hashPath := filepath.Join(baseDir, trustHashFile)
	data, err := os.ReadFile(hashPath)
	require.NoError(t, err)
	assert.NotEmpty(t, string(data))

	// Verify the hash matches the expected value.
	expectedHash := computeTrustHash([]*x509.Certificate{cert})
	assert.Equal(t, expectedHash, strings.TrimSpace(string(data)))
}

// TestRebuildUpdatesHash verifies that rebuild writes a new hash when
// certs change.
func TestRebuildUpdatesHash(t *testing.T) {
	cert1 := testSecureBrowserCA(t, "Rebuild CA 1")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert1})

	require.NoError(t, svc.Rebuild())

	hashPath := filepath.Join(baseDir, trustHashFile)
	data1, err := os.ReadFile(hashPath)
	require.NoError(t, err)

	// Change the certs in the mock trust store.
	cert2 := testSecureBrowserCA2(t)
	svc.trustService.SetStore(&mockSecureBrowserTrustStore{
		certs: []*x509.Certificate{cert1, cert2},
	})

	require.NoError(t, svc.Rebuild())

	data2, err := os.ReadFile(hashPath)
	require.NoError(t, err)
	assert.NotEqual(t, string(data1), string(data2))
}

// TestSyncIfChangedSkipsWhenUnchanged verifies no-op when hash matches.
func TestSyncIfChangedSkipsWhenUnchanged(t *testing.T) {
	cert := testSecureBrowserCA(t, "Skip CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	// Write the expected hash.
	expectedHash := computeTrustHash([]*x509.Certificate{cert})
	require.NoError(t, os.WriteFile(
		filepath.Join(baseDir, trustHashFile),
		[]byte(expectedHash),
		0o600,
	))

	nssdbDir := filepath.Join(baseDir, "chrome", "profile", "pki", "nssdb")
	_, statErr := os.Stat(nssdbDir)
	assert.True(t, os.IsNotExist(statErr), "nssdb should not exist before sync")

	// syncIfChanged should be a no-op since hash matches.
	err := svc.syncIfChanged("chrome", []*x509.Certificate{cert})
	require.NoError(t, err)

	// nssdb should still not exist (sync was skipped).
	_, statErr = os.Stat(nssdbDir)
	assert.True(t, os.IsNotExist(statErr), "nssdb should not exist after skipped sync")
}

// TestSyncIfChangedTriggersOnNewHash verifies rebuild when hash differs.
func TestSyncIfChangedTriggersOnNewHash(t *testing.T) {
	cert := testSecureBrowserCA(t, "New Hash CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	// Write a stale hash.
	require.NoError(t, os.WriteFile(
		filepath.Join(baseDir, trustHashFile),
		[]byte("stale-hash-value"),
		0o600,
	))

	err := svc.syncIfChanged("chrome", []*x509.Certificate{cert})
	require.NoError(t, err)

	// nssdb should now exist (sync was triggered).
	nssdbDir := filepath.Join(baseDir, "chrome", "profile", "pki", "nssdb")
	_, statErr := os.Stat(nssdbDir)
	assert.NoError(t, statErr, "nssdb should exist after triggered sync")
}

// TestTrustHashReadWrite verifies trust hash persistence.
func TestTrustHashReadWrite(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)

	hash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	err := svc.writeTrustHash(hash)
	require.NoError(t, err)

	read, err := svc.readTrustHash()
	require.NoError(t, err)
	assert.Equal(t, hash, read)
}

// TestTrustHashReadMissing verifies error on missing hash file.
func TestTrustHashReadMissing(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)
	svc.baseDir = filepath.Join(t.TempDir(), "nonexistent")

	_, err := svc.readTrustHash()
	assert.ErrorIs(t, err, ErrSecureBrowserHashRead)
}

// TestProfileModeDefaults verifies isolated mode is the default.
func TestProfileModeDefaults(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)

	assert.Equal(t, ProfileModeIsolated, svc.profileMode("chrome"))
	assert.Equal(t, ProfileModeIsolated, svc.profileMode("firefox"))
}

// TestProfileModeShared verifies shared mode when configured.
func TestProfileModeShared(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)

	config := svc.browserService.GetConfig()
	config.ChromeProfileMode = ProfileModeShared
	config.FirefoxProfileMode = ProfileModeShared
	require.NoError(t, svc.browserService.SetConfig(config))

	assert.Equal(t, ProfileModeShared, svc.profileMode("chrome"))
	assert.Equal(t, ProfileModeShared, svc.profileMode("firefox"))
}

// TestCertFingerprint verifies deterministic fingerprint computation.
func TestCertFingerprintSecureBrowser(t *testing.T) {
	cert := testSecureBrowserCA(t, "Fingerprint CA")

	fp1 := certFingerprint(cert)
	fp2 := certFingerprint(cert)
	assert.Equal(t, fp1, fp2)

	// Manually verify.
	hash := sha256.Sum256(cert.Raw)
	expected := hex.EncodeToString(hash[:])
	assert.Equal(t, expected, fp1)
}

// TestCertFingerprintDifferent verifies different certs have different fingerprints.
func TestCertFingerprintDifferent(t *testing.T) {
	cert1 := testSecureBrowserCA(t, "FP CA 1")
	cert2 := testSecureBrowserCA2(t)

	fp1 := certFingerprint(cert1)
	fp2 := certFingerprint(cert2)
	assert.NotEqual(t, fp1, fp2)
}

// TestBuildLaunchArgsChromeIsolated verifies Chrome isolated launch args.
func TestBuildLaunchArgsChromeIsolated(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, nil)

	args, env, err := svc.buildLaunchArgs("chrome", ProfileModeIsolated, "/usr/bin/google-chrome", "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, env)
	assert.Equal(t, "/usr/bin/google-chrome", args[0])
	assert.Contains(t, args[1], "--user-data-dir="+filepath.Join(baseDir, "chrome", "profile"))
	assert.Equal(t, "https://example.com", args[2])
}

// TestBuildLaunchArgsChromeShared verifies Chrome shared launch args.
func TestBuildLaunchArgsChromeShared(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)

	args, env, err := svc.buildLaunchArgs("chrome", ProfileModeShared, "/usr/bin/google-chrome", "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, env)
	assert.Equal(t, "/usr/bin/google-chrome", args[0])
	assert.Equal(t, "https://example.com", args[1])
	assert.Len(t, args, 2)
}

// TestBuildLaunchArgsFirefoxIsolated verifies Firefox isolated launch args.
func TestBuildLaunchArgsFirefoxIsolated(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, nil)

	args, env, err := svc.buildLaunchArgs("firefox", ProfileModeIsolated, "/usr/bin/firefox", "https://example.com")
	require.NoError(t, err)
	require.Len(t, env, 1)
	assert.Contains(t, env[0], "MOZ_POLICIES_FILE=")
	assert.Equal(t, "/usr/bin/firefox", args[0])
	assert.Equal(t, "--profile", args[1])
	assert.Equal(t, filepath.Join(baseDir, "firefox", "profile"), args[2])
	assert.Equal(t, "https://example.com", args[3])
}

// TestBuildLaunchArgsFirefoxShared verifies Firefox shared launch args.
func TestBuildLaunchArgsFirefoxShared(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)

	args, env, err := svc.buildLaunchArgs("firefox", ProfileModeShared, "/usr/bin/firefox", "https://example.com")
	require.NoError(t, err)
	require.Len(t, env, 1)
	assert.Contains(t, env[0], "MOZ_POLICIES_FILE=")
	assert.Equal(t, "/usr/bin/firefox", args[0])
	assert.Equal(t, "https://example.com", args[1])
	assert.Len(t, args, 2)
}

// TestBuildLaunchArgsUnknownFamily verifies error for unknown browser family.
func TestBuildLaunchArgsUnknownFamily(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)
	_, _, err := svc.buildLaunchArgs("safari", ProfileModeIsolated, "/usr/bin/safari", "https://example.com")
	assert.ErrorIs(t, err, ErrSecureBrowserUnknownFamily)
}

// TestNewSecureBrowserServiceNilLogger verifies default logger is used.
func TestNewSecureBrowserServiceNilLogger(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "browser.json")
	browserSvc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	trustSvc := NewTrustService(nil)
	svc := NewSecureBrowserService(t.TempDir(), browserSvc, trustSvc, nil)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

// TestSetContextSecureBrowser verifies context is stored.
func TestSetContextSecureBrowser(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)
	ctx := context.WithValue(context.Background(), struct{}{}, "test")
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

// TestRebuildWithEmptyStore verifies rebuild with no certs is a no-op.
func TestRebuildWithEmptyStore(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{})

	err := svc.Rebuild()
	require.NoError(t, err)

	// Hash should still be written (hash of empty list).
	hashPath := filepath.Join(baseDir, trustHashFile)
	data, err := os.ReadFile(hashPath)
	require.NoError(t, err)

	expected := computeTrustHash(nil)
	assert.Equal(t, expected, strings.TrimSpace(string(data)))
}

// TestFirefoxProfileDirCreated verifies isolated Firefox profile dir is created.
func TestFirefoxProfileDirCreated(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, nil)

	_, _, err := svc.buildLaunchArgs("firefox", ProfileModeIsolated, "/usr/bin/firefox", "https://example.com")
	require.NoError(t, err)

	profileDir := filepath.Join(baseDir, "firefox", "profile")
	info, statErr := os.Stat(profileDir)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
}
