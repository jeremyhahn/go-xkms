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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
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

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // pure-Go SQLite driver for inspecting NSS cert9.db
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
func (m *mockSecureBrowserTrustStore) ImportPEM(_ []byte, _ *truststore.AddCertificateOptions) (truststore.ImportResult, error) {
	return truststore.ImportResult{}, nil
}
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
func (m *mockSecureBrowserTrustStore) SetSource(_ string, _ string) error        { return nil }
func (m *mockSecureBrowserTrustStore) SetSystemInstalled(_ string, _ bool) error { return nil }
func (m *mockSecureBrowserTrustStore) SetTags(_ string, _ []string) error        { return nil }
func (m *mockSecureBrowserTrustStore) Close() error                              { return nil }
func (m *mockSecureBrowserTrustStore) Reload() error                             { return nil }

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

// TestComputeTrustHashEmpty verifies hash of empty cert list. The hash
// is salted with trustHashImplVersion (followed by '|') so an empty
// cert list still hashes the version-only payload.
func TestComputeTrustHashEmpty(t *testing.T) {
	hash := computeTrustHash(nil)
	expected := sha256.Sum256([]byte(trustHashImplVersion + "|"))
	assert.Equal(t, hex.EncodeToString(expected[:]), hash)
}

// TestComputeTrustHashDeterministic verifies the exact hash value.
// The hash is salted with trustHashImplVersion so that on-disk hashes
// from older xkey builds are invalidated when the sync logic changes.
func TestComputeTrustHashDeterministic(t *testing.T) {
	cert := testSecureBrowserCA(t, "Deterministic CA")
	fp := certFingerprint(cert)

	// Manual computation: version || sorted-fingerprints.
	sorted := []string{fp}
	sort.Strings(sorted)
	expected := sha256.Sum256([]byte(trustHashImplVersion + "|" + strings.Join(sorted, "")))

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
	nssdbDir := filepath.Join(baseDir, "chrome", "profile", ".pki", "nssdb")
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
	// Shared profile mode writes the NSS database at $HOME/.pki/nssdb. The
	// helper below isolates baseDir and the browser config, not HOME, so
	// without this the test populated the developer's real NSS store.
	//
	// Claimed here rather than inside newTestSecureBrowserService: the
	// mode-flip tests set HOME themselves before calling the helper and assert
	// against that path, so isolating in the helper silently moved the
	// directory out from under them (measured: two failures).
	isolateHome(t)

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

// TestLaunchBrowserInvalidURL_DoesNotExec verifies that a URL failing
// launch validation is rejected before any subprocess is created -- the
// dangerous case being a scheme like javascript:/file: or a leading '-'
// reaching the browser binary's argv (go-xkms#1275).
func TestLaunchBrowserInvalidURL_DoesNotExec(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "javascript scheme", url: "javascript:alert(1)"},
		{name: "file scheme", url: "file:///etc/passwd"},
		{name: "leading dash", url: "-x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := testSecureBrowserCA(t, "Invalid URL CA")
			svc, _ := newTestSecureBrowserService(t, []*x509.Certificate{cert})
			svc.SetContext(context.Background())

			execCalled := false
			svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				execCalled = true
				return exec.CommandContext(ctx, "true")
			}

			_, err := svc.LaunchBrowser("/usr/bin/google-chrome", tt.url)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrSecureBrowserInvalidURL)
			assert.False(t, execCalled, "no subprocess should be created for a rejected URL")
		})
	}
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

	// Verify the per-target trust hash was written for each family's
	// currently configured (default isolated) mode.
	expectedHash := computeTrustHash([]*x509.Certificate{cert})
	for _, name := range []string{
		trustHashFilePrefix + ".chrome.isolated",
		trustHashFilePrefix + ".firefox.isolated",
	} {
		data, readErr := os.ReadFile(filepath.Join(baseDir, name))
		require.NoError(t, readErr, "missing per-target hash file %s", name)
		assert.Equal(t, expectedHash, strings.TrimSpace(string(data)))
	}
}

// TestRebuildUpdatesHash verifies that rebuild writes a new hash when
// certs change.
func TestRebuildUpdatesHash(t *testing.T) {
	cert1 := testSecureBrowserCA(t, "Rebuild CA 1")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert1})

	require.NoError(t, svc.Rebuild())

	hashPath := filepath.Join(baseDir, trustHashFilePrefix+".chrome.isolated")
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

	// The first sync establishes the trust hash AND the browser stores. (A skip
	// requires BOTH: the hash matches and the stores are present — a matching
	// hash with missing stores must still rebuild, which is why merely writing
	// the hash is not enough to trigger a skip.)
	require.NoError(t, svc.syncIfChanged("chrome", []*x509.Certificate{cert}))
	certDB := filepath.Join(baseDir, "chrome", "profile", ".pki", "nssdb", "cert9.db")
	require.FileExists(t, certDB, "nssdb cert DB should exist after first sync")

	// Mark the cert DB with a sentinel; a genuine skip leaves it untouched.
	require.NoError(t, os.WriteFile(certDB, []byte("SENTINEL"), 0o600))

	// A second sync with the same certs is a no-op (hash matches + stores
	// present), so the cert DB is not rebuilt and the sentinel survives.
	require.NoError(t, svc.syncIfChanged("chrome", []*x509.Certificate{cert}))
	data, err := os.ReadFile(certDB)
	require.NoError(t, err)
	assert.Equal(t, []byte("SENTINEL"), data, "cert DB must not be rebuilt on an unchanged sync")
}

// TestSyncIfChangedTriggersOnNewHash verifies rebuild when hash differs.
func TestSyncIfChangedTriggersOnNewHash(t *testing.T) {
	cert := testSecureBrowserCA(t, "New Hash CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	// Write a stale hash for the chrome isolated target store.
	require.NoError(t, os.WriteFile(
		filepath.Join(baseDir, trustHashFilePrefix+".chrome.isolated"),
		[]byte("stale-hash-value"),
		0o600,
	))

	err := svc.syncIfChanged("chrome", []*x509.Certificate{cert})
	require.NoError(t, err)

	// nssdb should now exist (sync was triggered).
	nssdbDir := filepath.Join(baseDir, "chrome", "profile", ".pki", "nssdb")
	_, statErr := os.Stat(nssdbDir)
	assert.NoError(t, statErr, "nssdb should exist after triggered sync")
}

// TestSyncIfChanged_TrustHashReadFailureLogsAndForcesResync is the
// failure-injection test for issue #687: `storedHash, _ :=
// s.readTrustHash(family)` used to discard a genuine read failure (as
// opposed to the file simply not existing yet) with no signal at all. It
// proves a non-ErrNotExist failure is now logged, while syncIfChanged still
// treats it as "changed" and proceeds to sync — the pre-existing, safe
// fallback behavior this fix must not disturb.
func TestSyncIfChanged_TrustHashReadFailureLogsAndForcesResync(t *testing.T) {
	cert := testSecureBrowserCA(t, "Read Failure CA")
	baseDir := filepath.Join(t.TempDir(), "browsers")
	require.NoError(t, os.MkdirAll(baseDir, 0o700))
	configPath := filepath.Join(t.TempDir(), "browser.json")

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	browserSvc, err := NewBrowserService(configPath, logger)
	require.NoError(t, err)
	trustSvc := NewTrustService(&mockSecureBrowserTrustStore{certs: []*x509.Certificate{cert}})
	svc := NewSecureBrowserService(baseDir, browserSvc, trustSvc, logger)
	svc.execCommand = mockSecureBrowserExecCommand

	// Pre-create the trust-hash path as a directory so os.ReadFile fails
	// with something other than ErrNotExist (EISDIR). This also makes the
	// later writeTrustHash fail (same clobbered path), which is how the
	// test observes that syncIfChanged took the real sync branch rather
	// than the fast-path skip: a skip would return nil without ever
	// reaching writeTrustHash.
	hashPath := filepath.Join(baseDir, trustHashFilePrefix+".chrome.isolated")
	require.NoError(t, os.MkdirAll(hashPath, 0o700))

	err = svc.syncIfChanged("chrome", []*x509.Certificate{cert})
	require.Error(t, err, "writeTrustHash fails against the clobbered path, proving the sync branch (not the fast-path skip) ran")
	assert.Contains(t, err.Error(), "failed to write trust hash")
	assert.Contains(t, logBuf.String(), "failed to read stored trust hash",
		"the discarded read failure must be logged, not silently dropped")

	// The sync itself ran (before the final write step) despite the
	// unreadable hash file.
	nssdbDir := filepath.Join(baseDir, "chrome", "profile", ".pki", "nssdb")
	_, statErr := os.Stat(nssdbDir)
	assert.NoError(t, statErr, "nssdb should exist: the sync ran before the write step failed")
}

// TestSyncIfChanged_MissingTrustHashDoesNotLog proves the common first-sync
// case (no hash file yet) is not logged as a failure: it is the expected,
// benign condition that already forces a resync via an empty stored hash.
func TestSyncIfChanged_MissingTrustHashDoesNotLog(t *testing.T) {
	cert := testSecureBrowserCA(t, "Missing Hash CA")
	baseDir := filepath.Join(t.TempDir(), "browsers")
	require.NoError(t, os.MkdirAll(baseDir, 0o700))
	configPath := filepath.Join(t.TempDir(), "browser.json")

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	browserSvc, err := NewBrowserService(configPath, logger)
	require.NoError(t, err)
	trustSvc := NewTrustService(&mockSecureBrowserTrustStore{certs: []*x509.Certificate{cert}})
	svc := NewSecureBrowserService(baseDir, browserSvc, trustSvc, logger)
	svc.execCommand = mockSecureBrowserExecCommand

	// No hash file exists yet (first sync ever) — this must not be logged.
	err = svc.syncIfChanged("chrome", []*x509.Certificate{cert})
	require.NoError(t, err)
	assert.NotContains(t, logBuf.String(), "failed to read stored trust hash",
		"a first-run missing hash file is expected and must not be logged as a failure")
}

// TestTrustHashReadWrite verifies trust hash persistence.
func TestTrustHashReadWrite(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)

	hash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	err := svc.writeTrustHash("chrome", hash)
	require.NoError(t, err)

	read, err := svc.readTrustHash("chrome")
	require.NoError(t, err)
	assert.Equal(t, hash, read)
}

// TestTrustHashReadMissing verifies error on missing hash file.
func TestTrustHashReadMissing(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)
	svc.baseDir = filepath.Join(t.TempDir(), "nonexistent")

	_, err := svc.readTrustHash("chrome")
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
	// Isolated mode redirects HOME to the profile dir (so Chrome reads the
	// in-profile NSS trust DB) and appends first-run-suppression flags; the URL
	// is therefore the final argument, not a fixed index.
	profileDir := filepath.Join(baseDir, "chrome", "profile")
	assert.Contains(t, env, "HOME="+profileDir)
	assert.Equal(t, "/usr/bin/google-chrome", args[0])
	assert.Contains(t, args[1], "--user-data-dir="+profileDir)
	assert.Equal(t, "https://example.com", args[len(args)-1])
}

// TestBuildLaunchArgsChromeShared verifies Chrome shared launch args.
func TestBuildLaunchArgsChromeShared(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)

	args, env, err := svc.buildLaunchArgs("chrome", ProfileModeShared, "/usr/bin/google-chrome", "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, env)
	assert.Equal(t, "/usr/bin/google-chrome", args[0])
	// "--" marks the end of Chromium's own switches, guaranteeing url is
	// never parsed as one even if it somehow began with '-'.
	assert.Equal(t, "--", args[1])
	assert.Equal(t, "https://example.com", args[2])
	assert.Len(t, args, 3)
}

// TestBuildLaunchArgsFirefoxIsolated verifies Firefox isolated launch args.
// Firefox loads CAs from the profile's cert9.db (seeded by syncFirefox), so
// no environment variables are passed at launch.
func TestBuildLaunchArgsFirefoxIsolated(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, nil)

	args, env, err := svc.buildLaunchArgs("firefox", ProfileModeIsolated, "/usr/bin/firefox", "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, env, "firefox launch must not set any env vars (policies.json is per-profile NSS DB)")
	assert.Equal(t, "/usr/bin/firefox", args[0])
	assert.Equal(t, "--profile", args[1])
	assert.Equal(t, filepath.Join(baseDir, "firefox", "profile"), args[2])
	// "--" marks the end of Firefox's own switches, guaranteeing url is
	// never parsed as one even if it somehow began with '-'.
	assert.Equal(t, "--", args[3])
	assert.Equal(t, "https://example.com", args[4])
}

// TestBuildLaunchArgsFirefoxShared verifies Firefox shared launch args.
// In shared mode the launcher does not touch the user's profile NSS DB
// and does not pass any env vars; system administrators must deploy the
// policies.json into a Firefox-supported path.
func TestBuildLaunchArgsFirefoxShared(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)

	args, env, err := svc.buildLaunchArgs("firefox", ProfileModeShared, "/usr/bin/firefox", "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, env, "firefox shared launch must not set any env vars")
	assert.Equal(t, "/usr/bin/firefox", args[0])
	// "--" marks the end of Firefox's own switches, guaranteeing url is
	// never parsed as one even if it somehow began with '-'.
	assert.Equal(t, "--", args[1])
	assert.Equal(t, "https://example.com", args[2])
	assert.Len(t, args, 3)
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
	ctx := context.WithValue(context.Background(), testCtxKey("sb"), "test")
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

// TestRebuildWithEmptyStore verifies rebuild with no certs is a no-op.
func TestRebuildWithEmptyStore(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{})

	err := svc.Rebuild()
	require.NoError(t, err)

	// Per-target hashes should still be written (hash of empty list).
	expected := computeTrustHash(nil)
	for _, name := range []string{
		trustHashFilePrefix + ".chrome.isolated",
		trustHashFilePrefix + ".firefox.isolated",
	} {
		data, readErr := os.ReadFile(filepath.Join(baseDir, name))
		require.NoError(t, readErr, "missing per-target hash file %s", name)
		assert.Equal(t, expected, strings.TrimSpace(string(data)))
	}
}

// setChromeMode sets the Chrome profile mode on the service's browser config.
func setChromeMode(t *testing.T, svc *SecureBrowserService, mode string) {
	t.Helper()
	config := svc.browserService.GetConfig()
	config.ChromeProfileMode = mode
	require.NoError(t, svc.browserService.SetConfig(config))
}

// nssdbCertLabels opens an NSS cert9.db and returns the set of xkey-managed
// certificate labels (column a3) it contains. It is used to assert which
// certificates landed in a given target store.
func nssdbCertLabels(t *testing.T, nssdbDir string) map[string]struct{} {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(nssdbDir, "cert9.db"))
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	rows, err := db.Query(
		"SELECT CAST(a3 AS TEXT) FROM nssPublic WHERE typeof(a3) = 'blob' AND CAST(a3 AS TEXT) LIKE ?",
		nssdbCertLabelPrefix+"%",
	)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	labels := make(map[string]struct{})
	for rows.Next() {
		var label string
		require.NoError(t, rows.Scan(&label))
		labels[label] = struct{}{}
	}
	require.NoError(t, rows.Err())
	return labels
}

// expectedCertLabel returns the xkey- NSS label syncChrome/syncFirefox assign
// to the given certificate.
func expectedCertLabel(cert *x509.Certificate) string {
	return nssdbCertLabelPrefix + certFingerprint(cert)[:16]
}

// TestSyncIfChangedReSyncsOnModeFlipSharedToIsolated reproduces the confirmed
// bug: a shared-mode sync records its hash, then the mode is flipped to
// isolated. With a single global hash the launch short-circuited (hash matched
// and a stale isolated cert9.db happened to exist), leaving the isolated NSS DB
// without the current CAs. Change detection is now per resolved target store,
// so the isolated store MUST be re-synced.
func TestSyncIfChangedReSyncsOnModeFlipSharedToIsolated(t *testing.T) {
	// Redirect HOME so shared-mode chrome targets a hermetic ~/.pki/nssdb and
	// never the real user store.
	home := t.TempDir()
	t.Setenv("HOME", home)

	// oldCA is the stale CA that a prior launch left in the isolated store
	// (e.g. from May). newCA is the current trust-store CA.
	oldCA := testSecureBrowserCA(t, "Stale May CA")
	newCA := testSecureBrowserCA2(t)
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{newCA})
	isolatedNSSDB := filepath.Join(baseDir, "chrome", "profile", ".pki", "nssdb")

	// Seed a stale-but-valid isolated NSS DB containing only the OLD CA, as
	// if a previous isolated launch weeks ago populated it. Done directly so
	// no hash is recorded for the isolated target.
	require.NoError(t, svc.syncChrome([]*x509.Certificate{oldCA}))
	require.FileExists(t, filepath.Join(isolatedNSSDB, "cert9.db"))

	// 1. Shared mode: sync the NEW CA. This records the shared-store hash and
	//    populates ~/.pki/nssdb — but must NOT touch the isolated store.
	setChromeMode(t, svc, ProfileModeShared)
	require.NoError(t, svc.syncIfChanged("chrome", []*x509.Certificate{newCA}))
	require.FileExists(t, filepath.Join(baseDir, trustHashFilePrefix+".chrome.shared"),
		"shared-mode hash must be recorded")
	require.FileExists(t, filepath.Join(home, ".pki", "nssdb", "cert9.db"),
		"shared store must be populated")

	// Precondition for the bug: the isolated store still holds the OLD CA and
	// NOT the new one.
	staleLabels := nssdbCertLabels(t, isolatedNSSDB)
	require.Contains(t, staleLabels, expectedCertLabel(oldCA))
	require.NotContains(t, staleLabels, expectedCertLabel(newCA))

	// 2. Flip to isolated mode and launch. With a global hash this skipped
	//    (hash matched + isolated cert9.db existed). It must now re-sync the
	//    isolated store so it holds the NEW CA and no longer the OLD one.
	setChromeMode(t, svc, ProfileModeIsolated)
	require.NoError(t, svc.syncIfChanged("chrome", []*x509.Certificate{newCA}))

	labels := nssdbCertLabels(t, isolatedNSSDB)
	assert.Contains(t, labels, expectedCertLabel(newCA),
		"isolated store must receive the current CA after mode flip")
	assert.NotContains(t, labels, expectedCertLabel(oldCA),
		"isolated store must drop the stale CA after re-sync")
	assert.FileExists(t, filepath.Join(baseDir, trustHashFilePrefix+".chrome.isolated"),
		"isolated-mode hash must be recorded after re-sync")
}

// TestSyncIfChangedReSyncsOnModeFlipIsolatedToShared verifies the reverse
// direction: an isolated-mode sync records its hash, then the mode is flipped
// to shared; the shared store (~/.pki/nssdb) must be synced even though the
// trust contents are unchanged.
func TestSyncIfChangedReSyncsOnModeFlipIsolatedToShared(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cert := testSecureBrowserCA(t, "Reverse Flip CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	// 1. Isolated mode sync.
	setChromeMode(t, svc, ProfileModeIsolated)
	require.NoError(t, svc.syncIfChanged("chrome", []*x509.Certificate{cert}))
	require.FileExists(t, filepath.Join(baseDir, trustHashFilePrefix+".chrome.isolated"))
	sharedDB := filepath.Join(home, ".pki", "nssdb", "cert9.db")
	require.NoFileExists(t, sharedDB, "shared store must not exist after isolated sync")

	// 2. Flip to shared mode and launch. The shared store has no recorded
	//    hash, so the sync MUST run and populate ~/.pki/nssdb.
	setChromeMode(t, svc, ProfileModeShared)
	require.NoError(t, svc.syncIfChanged("chrome", []*x509.Certificate{cert}))

	assert.FileExists(t, sharedDB, "shared store must be synced after mode flip")
	sharedLabels := nssdbCertLabels(t, filepath.Join(home, ".pki", "nssdb"))
	assert.Contains(t, sharedLabels, expectedCertLabel(cert),
		"shared store must receive the current CA after mode flip")
	assert.FileExists(t, filepath.Join(baseDir, trustHashFilePrefix+".chrome.shared"),
		"shared-mode hash must be recorded")

	// Bookkeeping must never be written into the real ~/.pki/nssdb.
	assert.NoFileExists(t, filepath.Join(home, ".pki", "nssdb", trustHashFilePrefix+".chrome.shared"),
		"trust hash must not be written into the user's ~/.pki/nssdb")
}

// TestSyncIfChangedReSyncsWhenStoreWiped verifies the preserved wiped-store
// behavior: the per-target hash matches the current trust contents, but the
// target store's cert9.db was deleted externally — the sync must still run.
func TestSyncIfChangedReSyncsWhenStoreWiped(t *testing.T) {
	cert := testSecureBrowserCA(t, "Wiped Store CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	// First sync establishes the isolated hash and the NSS DB.
	require.NoError(t, svc.syncIfChanged("chrome", []*x509.Certificate{cert}))
	certDB := filepath.Join(baseDir, "chrome", "profile", ".pki", "nssdb", "cert9.db")
	require.FileExists(t, certDB)

	// Externally wipe the store while leaving the hash file intact.
	require.NoError(t, os.Remove(certDB))

	// Same certs => hash matches, but the store is gone, so the existence
	// guard must force a re-sync that recreates cert9.db.
	require.NoError(t, svc.syncIfChanged("chrome", []*x509.Certificate{cert}))
	assert.FileExists(t, certDB, "wiped store must be re-synced even when hash matches")
}

// TestSyncIfChangedFastPathSkipsRedundantWrite verifies the no-change fast
// path: same mode, same trust contents, store present => the sync is skipped
// and no redundant write touches the target store.
func TestSyncIfChangedFastPathSkipsRedundantWrite(t *testing.T) {
	cert := testSecureBrowserCA(t, "Fast Path CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	require.NoError(t, svc.syncIfChanged("chrome", []*x509.Certificate{cert}))
	certDB := filepath.Join(baseDir, "chrome", "profile", ".pki", "nssdb", "cert9.db")
	require.FileExists(t, certDB)

	// Sentinel: a genuine skip leaves the cert DB untouched.
	require.NoError(t, os.WriteFile(certDB, []byte("SENTINEL"), 0o600))

	require.NoError(t, svc.syncIfChanged("chrome", []*x509.Certificate{cert}))
	data, err := os.ReadFile(certDB)
	require.NoError(t, err)
	assert.Equal(t, []byte("SENTINEL"), data,
		"unchanged sync must skip and not rebuild the target store")
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
