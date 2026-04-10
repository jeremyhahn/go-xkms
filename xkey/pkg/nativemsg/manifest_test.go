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

package nativemsg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// overrideHomeDir sets homeDirFunc to return the given directory and
// registers a cleanup to restore the original function.
func overrideHomeDir(t *testing.T, dir string) {
	t.Helper()
	old := homeDirFunc
	homeDirFunc = func() (string, error) { return dir, nil }
	t.Cleanup(func() { homeDirFunc = old })
}

// overrideHomeDirError sets homeDirFunc to return an error and registers
// a cleanup to restore the original function.
func overrideHomeDirError(t *testing.T) {
	t.Helper()
	old := homeDirFunc
	homeDirFunc = func() (string, error) {
		return "", errors.New("no home directory")
	}
	t.Cleanup(func() { homeDirFunc = old })
}

// simulateBrowserInstalled creates the parent directory of the browser's
// NativeMessagingHosts dir under tmpDir so that isBrowserInstalled returns true.
func simulateBrowserInstalled(t *testing.T, kb knownBrowser, tmpDir string) {
	t.Helper()
	nmhDir := browserDir(kb, tmpDir)
	parentDir := filepath.Dir(nmhDir)
	require.NoError(t, os.MkdirAll(parentDir, 0755))
}

// findBrowser returns the first knownBrowser with the given name.
func findBrowser(name string) knownBrowser {
	for _, kb := range knownBrowsers {
		if kb.Name == name {
			return kb
		}
	}
	panic("browser not found: " + name)
}

// --- GenerateManifest tests ---

func TestGenerateManifest_Chrome(t *testing.T) {
	m, err := GenerateManifest(BrowserChrome, "/usr/bin/xkey")
	require.NoError(t, err)

	assert.Equal(t, NativeHostName, m.Name)
	assert.Equal(t, "stdio", m.Type)
	assert.Equal(t, "/usr/bin/xkey", m.Path)
	assert.Equal(t, manifestDescription, m.Description)
	require.Len(t, m.AllowedOrigins, 1)
	assert.Equal(t, ChromeExtensionID, m.AllowedOrigins[0])
	assert.Nil(t, m.AllowedExtensions)
}

func TestGenerateManifest_Firefox(t *testing.T) {
	m, err := GenerateManifest(BrowserFirefox, "/usr/bin/xkey")
	require.NoError(t, err)

	assert.Equal(t, NativeHostName, m.Name)
	assert.Equal(t, "stdio", m.Type)
	assert.Equal(t, "/usr/bin/xkey", m.Path)
	assert.Equal(t, manifestDescription, m.Description)
	require.Len(t, m.AllowedExtensions, 1)
	assert.Equal(t, FirefoxExtensionID, m.AllowedExtensions[0])
	assert.Nil(t, m.AllowedOrigins)
}

func TestGenerateManifest_InvalidBrowser(t *testing.T) {
	_, err := GenerateManifest(Browser("safari"), "/usr/bin/xkey")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidManifest))
}

func TestGenerateManifest_RelativePath(t *testing.T) {
	// A relative path should be resolved to absolute.
	m, err := GenerateManifest(BrowserChrome, "xkey")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(m.Path))
}

func TestGenerateManifest_JSONRoundtrip(t *testing.T) {
	m, err := GenerateManifest(BrowserChrome, "/opt/xkey/bin/xkey")
	require.NoError(t, err)

	data, err := json.Marshal(m)
	require.NoError(t, err)

	var parsed Manifest
	require.NoError(t, json.Unmarshal(data, &parsed))
	assert.Equal(t, m.Name, parsed.Name)
	assert.Equal(t, m.Path, parsed.Path)
	assert.Equal(t, m.AllowedOrigins, parsed.AllowedOrigins)
}

func TestGenerateManifest_ChromeAllowedOriginOverride(t *testing.T) {
	original := ChromeAllowedOriginOverride
	t.Cleanup(func() { ChromeAllowedOriginOverride = original })

	customOrigin := "chrome-extension://custom_test_extension_id/"
	ChromeAllowedOriginOverride = customOrigin

	m, err := GenerateManifest(BrowserChrome, "/usr/bin/xkey")
	require.NoError(t, err)

	require.Len(t, m.AllowedOrigins, 1)
	assert.Equal(t, customOrigin, m.AllowedOrigins[0])
}

func TestGenerateManifest_ChromeAllowedOriginOverrideEmpty(t *testing.T) {
	// Ensure empty override falls back to the default.
	original := ChromeAllowedOriginOverride
	t.Cleanup(func() { ChromeAllowedOriginOverride = original })

	ChromeAllowedOriginOverride = ""

	m, err := GenerateManifest(BrowserChrome, "/usr/bin/xkey")
	require.NoError(t, err)

	require.Len(t, m.AllowedOrigins, 1)
	assert.Equal(t, ChromeExtensionID, m.AllowedOrigins[0])
}

func TestGenerateManifest_FirefoxIgnoresOverride(t *testing.T) {
	// Firefox should not be affected by the Chrome override.
	original := ChromeAllowedOriginOverride
	t.Cleanup(func() { ChromeAllowedOriginOverride = original })

	ChromeAllowedOriginOverride = "chrome-extension://custom_test_extension_id/"

	m, err := GenerateManifest(BrowserFirefox, "/usr/bin/xkey")
	require.NoError(t, err)

	require.Len(t, m.AllowedExtensions, 1)
	assert.Equal(t, FirefoxExtensionID, m.AllowedExtensions[0])
	assert.Nil(t, m.AllowedOrigins)
}

// --- ManifestPath tests ---

func TestManifestPath_CurrentPlatform(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("unsupported platform %s", runtime.GOOS)
	}

	for _, browser := range []Browser{BrowserChrome, BrowserFirefox} {
		path, err := ManifestPath(browser)
		require.NoError(t, err)
		assert.True(t, filepath.IsAbs(path), "manifest path must be absolute")
		assert.Contains(t, path, NativeHostName)
		assert.Contains(t, path, ".json")
	}
}

func TestManifestPath_LinuxChrome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}

	path, err := ManifestPath(BrowserChrome)
	require.NoError(t, err)
	assert.Contains(t, path, ".config/google-chrome/NativeMessagingHosts")
}

func TestManifestPath_LinuxFirefox(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}

	path, err := ManifestPath(BrowserFirefox)
	require.NoError(t, err)
	assert.Contains(t, path, ".mozilla/native-messaging-hosts")
}

func TestManifestPath_InvalidBrowser(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("unsupported platform %s", runtime.GOOS)
	}

	_, err := ManifestPath(Browser("safari"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidManifest))
}

func TestManifestPath_HomeDirError(t *testing.T) {
	overrideHomeDirError(t)

	_, err := ManifestPath(BrowserChrome)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrManifestInstall))
}

// --- ManifestPaths tests ---

func TestManifestPaths_Chrome(t *testing.T) {
	overrideHomeDir(t, "/home/testuser")

	chromiumCount := len(chromiumBrowsers)
	require.Equal(t, 6, chromiumCount, "expected 6 Chromium-family browsers")

	paths, err := ManifestPaths(BrowserChrome)
	require.NoError(t, err)
	require.Len(t, paths, chromiumCount)

	for _, p := range paths {
		assert.True(t, filepath.IsAbs(p))
		assert.Contains(t, p, manifestFileName)
	}
}

func TestManifestPaths_Firefox(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("unsupported platform %s", runtime.GOOS)
	}

	overrideHomeDir(t, "/home/testuser")

	ffCount := len(firefoxBrowsers)
	require.Equal(t, 3, ffCount, "expected 3 Firefox-family browsers")

	paths, err := ManifestPaths(BrowserFirefox)
	require.NoError(t, err)
	require.Len(t, paths, ffCount)

	for _, p := range paths {
		assert.True(t, filepath.IsAbs(p))
		assert.Contains(t, p, manifestFileName)
	}
}

func TestManifestPaths_InvalidBrowser(t *testing.T) {
	_, err := ManifestPaths(Browser("safari"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidManifest))
}

func TestManifestPaths_HomeDirError(t *testing.T) {
	overrideHomeDirError(t)

	_, err := ManifestPaths(BrowserChrome)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrManifestInstall))
}

// --- Install / Uninstall roundtrip tests ---

func TestInstallManifest_UninstallManifest_Roundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	// Install Chrome manifest (will fall back to Chrome default since no
	// browser config dirs exist).
	err := InstallManifest(BrowserChrome, "/usr/bin/xkey")
	require.NoError(t, err)

	// Verify the file exists at the primary Chrome path and contains valid JSON.
	path, err := ManifestPath(BrowserChrome)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var m Manifest
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, NativeHostName, m.Name)
	assert.Equal(t, "stdio", m.Type)
	assert.Equal(t, "/usr/bin/xkey", m.Path)
	require.Len(t, m.AllowedOrigins, 1)
	assert.Equal(t, ChromeExtensionID, m.AllowedOrigins[0])

	// Uninstall.
	err = UninstallManifest(BrowserChrome)
	require.NoError(t, err)

	// Verify the file is gone.
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestInstallManifest_Firefox(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	err := InstallManifest(BrowserFirefox, "/opt/xkey")
	require.NoError(t, err)

	path, err := ManifestPath(BrowserFirefox)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var m Manifest
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, NativeHostName, m.Name)
	require.Len(t, m.AllowedExtensions, 1)
	assert.Equal(t, FirefoxExtensionID, m.AllowedExtensions[0])
}

func TestInstallManifest_InvalidBrowser(t *testing.T) {
	err := InstallManifest(Browser("edge"), "/usr/bin/xkey")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidManifest))
}

func TestInstallManifest_WithOverride(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	originalOverride := ChromeAllowedOriginOverride
	ChromeAllowedOriginOverride = "chrome-extension://overridden_id/"
	t.Cleanup(func() { ChromeAllowedOriginOverride = originalOverride })

	err := InstallManifest(BrowserChrome, "/usr/bin/xkey")
	require.NoError(t, err)

	path, err := ManifestPath(BrowserChrome)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var m Manifest
	require.NoError(t, json.Unmarshal(data, &m))
	require.Len(t, m.AllowedOrigins, 1)
	assert.Equal(t, "chrome-extension://overridden_id/", m.AllowedOrigins[0])
}

func TestInstallManifest_Overwrite(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	// Install with one path.
	require.NoError(t, InstallManifest(BrowserChrome, "/usr/bin/xkey-old"))

	// Overwrite with another path.
	require.NoError(t, InstallManifest(BrowserChrome, "/usr/bin/xkey-new"))

	path, err := ManifestPath(BrowserChrome)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var m Manifest
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, "/usr/bin/xkey-new", m.Path)
}

// --- Chromium auto-detection tests ---

func TestInstallChromiumManifests_DetectsInstalledBrowsers(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	chrome := findBrowser("Chrome")
	brave := findBrowser("Brave")

	// Create parent directories for Chrome and Brave to simulate them being installed.
	simulateBrowserInstalled(t, chrome, tmpDir)
	simulateBrowserInstalled(t, brave, tmpDir)

	err := InstallManifest(BrowserChrome, "/usr/bin/xkey")
	require.NoError(t, err)

	// Chrome and Brave should have manifests.
	chromeManifest := filepath.Join(browserDir(chrome, tmpDir), manifestFileName)
	_, err = os.Stat(chromeManifest)
	assert.NoError(t, err, "Chrome manifest should exist")

	braveManifest := filepath.Join(browserDir(brave, tmpDir), manifestFileName)
	_, err = os.Stat(braveManifest)
	assert.NoError(t, err, "Brave manifest should exist")

	// Chromium and Edge should NOT have manifests (no parent dir).
	chromiumKB := findBrowser("Chromium")
	chromiumManifest := filepath.Join(browserDir(chromiumKB, tmpDir), manifestFileName)
	_, err = os.Stat(chromiumManifest)
	assert.True(t, os.IsNotExist(err), "Chromium manifest should not exist")

	edge := findBrowser("Edge")
	edgeManifest := filepath.Join(browserDir(edge, tmpDir), manifestFileName)
	_, err = os.Stat(edgeManifest)
	assert.True(t, os.IsNotExist(err), "Edge manifest should not exist")
}

func TestInstallChromiumManifests_FallbackToChrome(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	// No browser config dirs exist. Should fall back to Chrome's default.
	err := InstallManifest(BrowserChrome, "/usr/bin/xkey")
	require.NoError(t, err)

	chrome := findBrowser("Chrome")
	chromeManifest := filepath.Join(browserDir(chrome, tmpDir), manifestFileName)
	data, err := os.ReadFile(chromeManifest)
	require.NoError(t, err)

	var m Manifest
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, NativeHostName, m.Name)
	assert.Equal(t, "/usr/bin/xkey", m.Path)
}

func TestInstallChromiumManifests_AllBrowsersDetected(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	// Create parent directories for ALL Chromium browsers.
	for _, kb := range chromiumBrowsers {
		simulateBrowserInstalled(t, kb, tmpDir)
	}

	err := InstallManifest(BrowserChrome, "/usr/bin/xkey")
	require.NoError(t, err)

	// All should have manifests.
	for _, kb := range chromiumBrowsers {
		manifestPath := filepath.Join(browserDir(kb, tmpDir), manifestFileName)
		_, statErr := os.Stat(manifestPath)
		assert.NoError(t, statErr, "%s manifest should exist", kb.Name)
	}
}

func TestInstallChromiumManifests_HomeDirError(t *testing.T) {
	overrideHomeDirError(t)

	err := InstallManifest(BrowserChrome, "/usr/bin/xkey")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrManifestInstall))
}

// --- Firefox family auto-detection tests ---

func TestInstallFirefoxFamilyManifests_DetectsInstalledBrowsers(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	firefox := findBrowser("Firefox")
	librewolf := findBrowser("LibreWolf")

	// Simulate Firefox and LibreWolf being installed.
	simulateBrowserInstalled(t, firefox, tmpDir)
	simulateBrowserInstalled(t, librewolf, tmpDir)

	err := InstallManifest(BrowserFirefox, "/usr/bin/xkey")
	require.NoError(t, err)

	// Firefox and LibreWolf should have manifests.
	firefoxManifest := filepath.Join(browserDir(firefox, tmpDir), manifestFileName)
	_, err = os.Stat(firefoxManifest)
	assert.NoError(t, err, "Firefox manifest should exist")

	librewolfManifest := filepath.Join(browserDir(librewolf, tmpDir), manifestFileName)
	_, err = os.Stat(librewolfManifest)
	assert.NoError(t, err, "LibreWolf manifest should exist")

	// Waterfox should NOT have a manifest (no parent dir).
	waterfox := findBrowser("Waterfox")
	waterfoxManifest := filepath.Join(browserDir(waterfox, tmpDir), manifestFileName)
	_, err = os.Stat(waterfoxManifest)
	assert.True(t, os.IsNotExist(err), "Waterfox manifest should not exist")
}

func TestInstallFirefoxFamilyManifests_FallbackToFirefox(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	// No browser config dirs exist. Should fall back to Firefox's default.
	err := InstallManifest(BrowserFirefox, "/usr/bin/xkey")
	require.NoError(t, err)

	firefox := findBrowser("Firefox")
	firefoxManifest := filepath.Join(browserDir(firefox, tmpDir), manifestFileName)
	data, err := os.ReadFile(firefoxManifest)
	require.NoError(t, err)

	var m Manifest
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, NativeHostName, m.Name)
	assert.Equal(t, "/usr/bin/xkey", m.Path)
	require.Len(t, m.AllowedExtensions, 1)
	assert.Equal(t, FirefoxExtensionID, m.AllowedExtensions[0])
}

// --- Uninstall tests ---

func TestUninstallManifest_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	err := UninstallManifest(BrowserChrome)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrManifestNotFound))
}

func TestUninstallManifest_FirefoxNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	err := UninstallManifest(BrowserFirefox)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrManifestNotFound))
}

func TestUninstallChromiumManifests_RemovesAll(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	// Create parent dirs for all Chromium browsers and install.
	for _, kb := range chromiumBrowsers {
		simulateBrowserInstalled(t, kb, tmpDir)
	}
	require.NoError(t, InstallManifest(BrowserChrome, "/usr/bin/xkey"))

	// Verify all exist.
	for _, kb := range chromiumBrowsers {
		manifestPath := filepath.Join(browserDir(kb, tmpDir), manifestFileName)
		_, err := os.Stat(manifestPath)
		require.NoError(t, err, "%s manifest should exist before uninstall", kb.Name)
	}

	// Uninstall.
	err := UninstallManifest(BrowserChrome)
	require.NoError(t, err)

	// Verify all removed.
	for _, kb := range chromiumBrowsers {
		manifestPath := filepath.Join(browserDir(kb, tmpDir), manifestFileName)
		_, err := os.Stat(manifestPath)
		assert.True(t, os.IsNotExist(err), "%s manifest should be removed", kb.Name)
	}
}

func TestUninstallFirefoxFamilyManifests_RemovesAll(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	// Create parent dirs for all Firefox browsers and install.
	for _, kb := range firefoxBrowsers {
		simulateBrowserInstalled(t, kb, tmpDir)
	}
	require.NoError(t, InstallManifest(BrowserFirefox, "/usr/bin/xkey"))

	// Verify all exist.
	for _, kb := range firefoxBrowsers {
		manifestPath := filepath.Join(browserDir(kb, tmpDir), manifestFileName)
		_, err := os.Stat(manifestPath)
		require.NoError(t, err, "%s manifest should exist before uninstall", kb.Name)
	}

	// Uninstall.
	err := UninstallManifest(BrowserFirefox)
	require.NoError(t, err)

	// Verify all removed.
	for _, kb := range firefoxBrowsers {
		manifestPath := filepath.Join(browserDir(kb, tmpDir), manifestFileName)
		_, err := os.Stat(manifestPath)
		assert.True(t, os.IsNotExist(err), "%s manifest should be removed", kb.Name)
	}
}

// --- GetManifestStatus tests ---

func TestGetManifestStatus_OnlyDetectedBrowsers(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	chrome := findBrowser("Chrome")
	firefox := findBrowser("Firefox")

	// Only Chrome and Firefox parent dirs exist.
	simulateBrowserInstalled(t, chrome, tmpDir)
	simulateBrowserInstalled(t, firefox, tmpDir)

	statuses := GetManifestStatus()

	// Only detected browsers should appear: Chrome and Firefox.
	require.Len(t, statuses, 2)

	names := make(map[string]bool, len(statuses))
	for _, s := range statuses {
		names[s.Name] = true
		assert.NotEmpty(t, s.Path)
	}

	assert.True(t, names["Chrome"], "status should include Chrome")
	assert.True(t, names["Firefox"], "status should include Firefox")
	assert.False(t, names["Brave"], "status should not include Brave")
	assert.False(t, names["Edge"], "status should not include Edge")
}

func TestGetManifestStatus_ChromeAndLibreWolf(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	chrome := findBrowser("Chrome")
	librewolf := findBrowser("LibreWolf")

	simulateBrowserInstalled(t, chrome, tmpDir)
	simulateBrowserInstalled(t, librewolf, tmpDir)

	statuses := GetManifestStatus()
	require.Len(t, statuses, 2)

	names := make(map[string]bool, len(statuses))
	for _, s := range statuses {
		names[s.Name] = true
	}

	assert.True(t, names["Chrome"], "status should include Chrome")
	assert.True(t, names["LibreWolf"], "status should include LibreWolf")
}

func TestGetManifestStatus_NoBrowsersDetected(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	statuses := GetManifestStatus()
	assert.Empty(t, statuses, "no browsers detected should produce empty/nil slice")
}

func TestGetManifestStatus_ChromeInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	chrome := findBrowser("Chrome")
	simulateBrowserInstalled(t, chrome, tmpDir)

	// Install Chrome manifest.
	err := InstallManifest(BrowserChrome, "/usr/bin/xkey")
	require.NoError(t, err)

	statuses := GetManifestStatus()
	require.Len(t, statuses, 1)

	assert.Equal(t, "Chrome", statuses[0].Name)
	assert.True(t, statuses[0].Installed, "Chrome manifest should be marked as installed")
}

func TestGetManifestStatus_ChromeDetectedNotInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	chrome := findBrowser("Chrome")
	simulateBrowserInstalled(t, chrome, tmpDir)

	// Chrome parent dir exists but no manifest installed.
	statuses := GetManifestStatus()
	require.Len(t, statuses, 1)

	assert.Equal(t, "Chrome", statuses[0].Name)
	assert.False(t, statuses[0].Installed, "Chrome manifest should not be installed")
	assert.NotEmpty(t, statuses[0].Path)
}

func TestGetManifestStatus_AllBrowsersDetectedAndInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	// Simulate all browsers installed.
	for _, kb := range knownBrowsers {
		simulateBrowserInstalled(t, kb, tmpDir)
	}

	// Install manifests for both families.
	require.NoError(t, InstallManifest(BrowserChrome, "/usr/bin/xkey"))
	require.NoError(t, InstallManifest(BrowserFirefox, "/usr/bin/xkey"))

	statuses := GetManifestStatus()
	require.Len(t, statuses, len(knownBrowsers))

	for _, s := range statuses {
		assert.True(t, s.Installed, "expected %s manifest to be installed", s.Name)
	}
}

func TestGetManifestStatus_HomeDirError(t *testing.T) {
	overrideHomeDirError(t)

	statuses := GetManifestStatus()
	assert.Nil(t, statuses)
}

func TestGetManifestStatus_BrowserFamilyField(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	chrome := findBrowser("Chrome")
	firefox := findBrowser("Firefox")
	simulateBrowserInstalled(t, chrome, tmpDir)
	simulateBrowserInstalled(t, firefox, tmpDir)

	statuses := GetManifestStatus()
	require.Len(t, statuses, 2)

	for _, s := range statuses {
		switch s.Name {
		case "Chrome":
			assert.Equal(t, BrowserChrome, s.Browser, "Chrome should have BrowserChrome family")
		case "Firefox":
			assert.Equal(t, BrowserFirefox, s.Browser, "Firefox should have BrowserFirefox family")
		}
	}
}

// --- knownBrowsers table tests ---

func TestKnownBrowsersTable_HasExpectedEntries(t *testing.T) {
	require.Equal(t, 9, len(knownBrowsers), "expected 9 total known browsers (6 Chromium + 3 Firefox)")

	require.Equal(t, 6, len(chromiumBrowsers), "expected 6 Chromium-family browsers")
	require.Equal(t, 3, len(firefoxBrowsers), "expected 3 Firefox-family browsers")

	names := make(map[string]bool, len(knownBrowsers))
	for _, kb := range knownBrowsers {
		assert.NotEmpty(t, kb.Name)
		assert.NotEmpty(t, kb.LinuxDir)
		assert.NotEmpty(t, kb.DarwinDir)
		names[kb.Name] = true
	}

	// Chromium family.
	assert.True(t, names["Chrome"])
	assert.True(t, names["Brave"])
	assert.True(t, names["Chromium"])
	assert.True(t, names["Edge"])
	assert.True(t, names["Opera"])
	assert.True(t, names["Vivaldi"])

	// Firefox family.
	assert.True(t, names["Firefox"])
	assert.True(t, names["LibreWolf"])
	assert.True(t, names["Waterfox"])
}

func TestKnownBrowsersTable_LinuxPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}

	expectedLinuxDirs := map[string]string{
		"Chrome":    ".config/google-chrome/NativeMessagingHosts",
		"Brave":     ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
		"Chromium":  ".config/chromium/NativeMessagingHosts",
		"Edge":      ".config/microsoft-edge/NativeMessagingHosts",
		"Opera":     ".config/opera/NativeMessagingHosts",
		"Vivaldi":   ".config/vivaldi/NativeMessagingHosts",
		"Firefox":   ".mozilla/native-messaging-hosts",
		"LibreWolf": ".librewolf/native-messaging-hosts",
		"Waterfox":  ".waterfox/native-messaging-hosts",
	}

	for _, kb := range knownBrowsers {
		expected, ok := expectedLinuxDirs[kb.Name]
		require.True(t, ok, "unexpected browser: %s", kb.Name)
		assert.Equal(t, expected, kb.LinuxDir, "LinuxDir mismatch for %s", kb.Name)
	}
}

func TestBrowserDir_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}

	for _, kb := range knownBrowsers {
		dir := browserDir(kb, "/home/testuser")
		assert.True(t, filepath.IsAbs(dir))
		assert.Contains(t, dir, "/home/testuser")
	}
}

func TestBrowserDir_ContainsNativeMessaging(t *testing.T) {
	for _, kb := range knownBrowsers {
		dir := browserDir(kb, "/home/testuser")
		// All dirs should end with either NativeMessagingHosts or native-messaging-hosts.
		base := filepath.Base(dir)
		hasNativeMessaging := base == "NativeMessagingHosts" || base == "native-messaging-hosts"
		assert.True(t, hasNativeMessaging,
			"%s dir %q should end with NativeMessagingHosts or native-messaging-hosts", kb.Name, dir)
	}
}

// --- isBrowserInstalled tests ---

func TestIsBrowserInstalled_ParentDirExists(t *testing.T) {
	tmpDir := t.TempDir()

	chrome := findBrowser("Chrome")
	simulateBrowserInstalled(t, chrome, tmpDir)

	assert.True(t, isBrowserInstalled(chrome, tmpDir), "Chrome should be detected as installed")
}

func TestIsBrowserInstalled_ParentDirMissing(t *testing.T) {
	tmpDir := t.TempDir()

	chrome := findBrowser("Chrome")
	assert.False(t, isBrowserInstalled(chrome, tmpDir), "Chrome should not be detected without parent dir")
}

func TestIsBrowserInstalled_AllBrowsers(t *testing.T) {
	tmpDir := t.TempDir()

	// No browsers installed initially.
	for _, kb := range knownBrowsers {
		assert.False(t, isBrowserInstalled(kb, tmpDir),
			"%s should not be detected without parent dir", kb.Name)
	}

	// Install all browsers.
	for _, kb := range knownBrowsers {
		simulateBrowserInstalled(t, kb, tmpDir)
	}

	// All should be detected.
	for _, kb := range knownBrowsers {
		assert.True(t, isBrowserInstalled(kb, tmpDir),
			"%s should be detected after creating parent dir", kb.Name)
	}
}

func TestIsBrowserInstalled_SelectiveBrowsers(t *testing.T) {
	tmpDir := t.TempDir()

	brave := findBrowser("Brave")
	librewolf := findBrowser("LibreWolf")

	// Only simulate Brave and LibreWolf.
	simulateBrowserInstalled(t, brave, tmpDir)
	simulateBrowserInstalled(t, librewolf, tmpDir)

	for _, kb := range knownBrowsers {
		if kb.Name == "Brave" || kb.Name == "LibreWolf" {
			assert.True(t, isBrowserInstalled(kb, tmpDir),
				"%s should be detected", kb.Name)
		} else {
			assert.False(t, isBrowserInstalled(kb, tmpDir),
				"%s should not be detected", kb.Name)
		}
	}
}

// --- browsersForFamily tests ---

func TestBrowsersForFamily_Chrome(t *testing.T) {
	browsers, err := browsersForFamily(BrowserChrome)
	require.NoError(t, err)
	require.Len(t, browsers, 6)

	for _, kb := range browsers {
		assert.Equal(t, familyChromium, kb.Family)
	}
}

func TestBrowsersForFamily_Firefox(t *testing.T) {
	browsers, err := browsersForFamily(BrowserFirefox)
	require.NoError(t, err)
	require.Len(t, browsers, 3)

	for _, kb := range browsers {
		assert.Equal(t, familyFirefox, kb.Family)
	}
}

func TestBrowsersForFamily_InvalidBrowser(t *testing.T) {
	_, err := browsersForFamily(Browser("safari"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidManifest))
}

// --- familyForBrowser tests ---

func TestFamilyForBrowser_ValidBrowsers(t *testing.T) {
	family, err := familyForBrowser(BrowserChrome)
	require.NoError(t, err)
	assert.Equal(t, familyChromium, family)

	family, err = familyForBrowser(BrowserFirefox)
	require.NoError(t, err)
	assert.Equal(t, familyFirefox, family)
}

func TestFamilyForBrowser_InvalidBrowser(t *testing.T) {
	_, err := familyForBrowser(Browser("safari"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidManifest))
}

// --- filterByFamily tests ---

func TestFilterByFamily_Counts(t *testing.T) {
	chromium := filterByFamily(familyChromium)
	assert.Len(t, chromium, 6, "expected 6 Chromium browsers")

	ff := filterByFamily(familyFirefox)
	assert.Len(t, ff, 3, "expected 3 Firefox browsers")
}

// --- Miscellaneous tests ---

func TestChromeExtensionIDFormat(t *testing.T) {
	// Verify the constant has the expected chrome-extension:// prefix and trailing slash.
	assert.Contains(t, ChromeExtensionID, "chrome-extension://")
	assert.True(t, ChromeExtensionID[len(ChromeExtensionID)-1] == '/',
		"ChromeExtensionID should end with a trailing slash")
}

func TestBrowserFamilyConstants(t *testing.T) {
	// Verify the family constants are distinct.
	assert.NotEqual(t, familyChromium, familyFirefox,
		"Chromium and Firefox family constants must be distinct")
}

func TestUninstallManifest_InvalidBrowser(t *testing.T) {
	err := UninstallManifest(Browser("safari"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidManifest))
}

func TestInstallManifest_HomeDirError_Firefox(t *testing.T) {
	overrideHomeDirError(t)

	err := InstallManifest(BrowserFirefox, "/usr/bin/xkey")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrManifestInstall))
}

func TestUninstallManifest_HomeDirError(t *testing.T) {
	overrideHomeDirError(t)

	err := UninstallManifest(BrowserChrome)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrManifestInstall))
}

func TestInstallFirefoxFamily_AllBrowsersDetected(t *testing.T) {
	tmpDir := t.TempDir()
	overrideHomeDir(t, tmpDir)

	// Create parent directories for ALL Firefox browsers.
	for _, kb := range firefoxBrowsers {
		simulateBrowserInstalled(t, kb, tmpDir)
	}

	err := InstallManifest(BrowserFirefox, "/usr/bin/xkey")
	require.NoError(t, err)

	// All should have manifests.
	for _, kb := range firefoxBrowsers {
		manifestPath := filepath.Join(browserDir(kb, tmpDir), manifestFileName)
		_, statErr := os.Stat(manifestPath)
		assert.NoError(t, statErr, "%s manifest should exist", kb.Name)
	}
}
