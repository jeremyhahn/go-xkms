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
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeChromeSource builds a hermetic fake source Chrome profile under a temp
// HOME and returns (home, sourceProfileDir). The HOME env var is set for the
// duration of the test so resolveSourceProfile and mirrorNativeMessagingHosts
// resolve into the fake tree, never the real user's profile.
//
// The fake profile contains:
//   - two extensions (extAlpha, extBeta) with a version dir + manifest each
//   - a Secure Preferences file registering extAlpha in extensions.settings
//     plus an unrelated pre-existing key that must survive any merge into a
//     different (target) file
//   - a Preferences file registering extBeta
//   - Local Extension Settings for extAlpha only (extBeta has none)
//   - an IndexedDB store for extAlpha
//   - a NativeMessagingHosts manifest
//   - privacy-sensitive files (Cookies, Login Data, History) that must NOT
//     be copied
func fakeChromeSource(t *testing.T) (home, source string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)

	source = filepath.Join(home, ".config", "google-chrome", "Default")
	require.NoError(t, os.MkdirAll(source, 0o700))

	// Extension version directories + manifests.
	for id, ver := range map[string]string{extAlpha: "1.2.3_0", extBeta: "4.5.6_0"} {
		verDir := filepath.Join(source, "Extensions", id, ver)
		require.NoError(t, os.MkdirAll(verDir, 0o700))
		require.NoError(t, os.WriteFile(
			filepath.Join(verDir, "manifest.json"),
			[]byte(`{"name":"`+id+`","version":"x"}`), 0o600))
	}

	// Secure Preferences: registers extAlpha and carries an unrelated key.
	securePrefs := map[string]any{
		"some_unrelated_top_level": "keep-me",
		"extensions": map[string]any{
			"settings": map[string]any{
				extAlpha: map[string]any{"state": 1, "location": 1},
			},
		},
	}
	writeJSON(t, filepath.Join(source, "Secure Preferences"), securePrefs)

	// Preferences: registers extBeta.
	plainPrefs := map[string]any{
		"extensions": map[string]any{
			"settings": map[string]any{
				extBeta: map[string]any{"state": 1, "location": 1},
			},
		},
	}
	writeJSON(t, filepath.Join(source, "Preferences"), plainPrefs)

	// Local Extension Settings for extAlpha only.
	localDir := filepath.Join(source, "Local Extension Settings", extAlpha)
	require.NoError(t, os.MkdirAll(localDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(localDir, "000003.log"),
		[]byte("leveldb-state"), 0o600))

	// IndexedDB for extAlpha.
	idbDir := filepath.Join(source, "IndexedDB", "chrome-extension_"+extAlpha+"_0.indexeddb.leveldb")
	require.NoError(t, os.MkdirAll(idbDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(idbDir, "CURRENT"),
		[]byte("MANIFEST-000001\n"), 0o600))

	// Native messaging host manifest. The source manifest lives under the real
	// user HOME (~/.config/google-chrome/NativeMessagingHosts), which is where
	// Chrome's installer writes user-level host manifests for default installs.
	nmhDir := filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts")
	require.NoError(t, os.MkdirAll(nmhDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(nmhDir, "com.anthropic.claude.json"),
		[]byte(`{"name":"com.anthropic.claude","description":"Claude native host","type":"stdio","path":"/opt/claude/host","allowed_origins":["chrome-extension://`+extAlpha+`/"]}`),
		0o600))

	// Privacy-sensitive artifacts that must never be copied.
	require.NoError(t, os.WriteFile(filepath.Join(source, "Cookies"), []byte("SECRET-COOKIES"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(source, "Login Data"), []byte("SECRET-LOGINS"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(source, "History"), []byte("SECRET-HISTORY"), 0o600))

	return home, source
}

const (
	extAlpha    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	extBeta     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	extExisting = "cccccccccccccccccccccccccccccccc"
)

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

// readExtensionSettings reads extensions.settings.<id> presence from a
// Chrome preferences file, returning the parsed settings map.
func readExtensionSettings(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	return loadExtensionSettings(path)
}

// TestImportCopiesVersionDirAndMergesExistingPreferences verifies that
// importing into a profile whose target Secure Preferences ALREADY contains
// unrelated keys merges the registration without clobbering pre-existing
// data, and copies the extension version directory.
func TestImportCopiesVersionDirAndMergesExistingPreferences(t *testing.T) {
	cert := testSecureBrowserCA(t, "Ext Import CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	_, source := fakeChromeSource(t)

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	targetDefault := filepath.Join(profileDir, "Default")
	require.NoError(t, os.MkdirAll(targetDefault, 0o700))

	// Pre-existing Secure Preferences in the isolated profile with a user
	// setting and a different extension already registered. None of this
	// may be lost by the merge.
	pre := map[string]any{
		"user_set_key": "do-not-clobber",
		"extensions": map[string]any{
			"settings": map[string]any{
				extExisting: map[string]any{"state": 1},
			},
		},
	}
	targetSecure := filepath.Join(targetDefault, "Secure Preferences")
	writeJSON(t, targetSecure, pre)

	n, err := svc.importChromeExtensions(profileDir, source, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "both extensions imported")

	// Version dir copied for extAlpha.
	assert.DirExists(t, filepath.Join(targetDefault, "Extensions", extAlpha, "1.2.3_0"))
	assert.FileExists(t, filepath.Join(targetDefault, "Extensions", extAlpha, "1.2.3_0", "manifest.json"))

	// Pre-existing top-level key and pre-existing extension survive.
	merged := map[string]json.RawMessage{}
	data, err := os.ReadFile(targetSecure)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &merged))
	assert.Contains(t, string(merged["user_set_key"]), "do-not-clobber")

	settings := readExtensionSettings(t, targetSecure)
	assert.Contains(t, settings, extExisting, "pre-existing extension registration kept")
	assert.Contains(t, settings, extAlpha, "imported extension registered")
}

// TestImportExtensionIDFilter verifies that only requested IDs are imported.
func TestImportExtensionIDFilter(t *testing.T) {
	cert := testSecureBrowserCA(t, "Filter CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	_, source := fakeChromeSource(t)

	profileDir := filepath.Join(baseDir, "chrome", "profile")

	n, err := svc.importChromeExtensions(profileDir, source, []string{extAlpha})
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	targetDefault := filepath.Join(profileDir, "Default")
	assert.DirExists(t, filepath.Join(targetDefault, "Extensions", extAlpha))
	assert.NoDirExists(t, filepath.Join(targetDefault, "Extensions", extBeta))

	// extAlpha lives in Secure Preferences; only it should be registered.
	settings := readExtensionSettings(t, filepath.Join(targetDefault, "Secure Preferences"))
	assert.Contains(t, settings, extAlpha)
	assert.NotContains(t, settings, extBeta)
}

// TestImportMirrorsNativeMessagingHostsLocation verifies NMH manifests land in
// <profileDir>/NativeMessagingHosts/ (chrome::DIR_USER_NATIVE_MESSAGING with
// --user-data-dir set) and NOT under the old .config/google-chrome path.
// Regression for Defect 1.
func TestImportMirrorsNativeMessagingHostsLocation(t *testing.T) {
	cert := testSecureBrowserCA(t, "NMH CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	_, source := fakeChromeSource(t)

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	_, err := svc.importChromeExtensions(profileDir, source, nil)
	require.NoError(t, err)

	// Correct location: <user-data-dir>/NativeMessagingHosts/<name>.json.
	manifest := filepath.Join(profileDir, "NativeMessagingHosts", "com.anthropic.claude.json")
	assert.FileExists(t, manifest)

	// The old .config/google-chrome location must NOT be used.
	assert.NoDirExists(t, filepath.Join(profileDir, ".config", "google-chrome", "NativeMessagingHosts"))
}

// TestImportRewritesNativeMessagingHostManifest verifies the generated manifest
// points "path" at the wrapper while preserving every other source field
// verbatim. Regression for Defect 2.
func TestImportRewritesNativeMessagingHostManifest(t *testing.T) {
	cert := testSecureBrowserCA(t, "NMH Rewrite CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	_, source := fakeChromeSource(t)

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	_, err := svc.importChromeExtensions(profileDir, source, nil)
	require.NoError(t, err)

	manifestPath := filepath.Join(profileDir, "NativeMessagingHosts", "com.anthropic.claude.json")
	data, err := os.ReadFile(manifestPath)
	require.NoError(t, err)

	var manifest map[string]any
	require.NoError(t, json.Unmarshal(data, &manifest))

	wrapperPath := filepath.Join(profileDir, "nmh-wrappers", "com.anthropic.claude.sh")
	assert.Equal(t, wrapperPath, manifest["path"], "manifest path must point at the wrapper")

	// All non-path fields preserved verbatim from the source manifest.
	assert.Equal(t, "com.anthropic.claude", manifest["name"])
	assert.Equal(t, "Claude native host", manifest["description"])
	assert.Equal(t, "stdio", manifest["type"])
	require.Contains(t, manifest, "allowed_origins")
	origins, ok := manifest["allowed_origins"].([]any)
	require.True(t, ok)
	require.Len(t, origins, 1)
	assert.Equal(t, "chrome-extension://"+extAlpha+"/", origins[0])
}

// TestImportGeneratesNativeMessagingHostWrapper verifies the wrapper script
// restores the real user HOME, execs the original host binary, and is
// executable. Regression for Defect 2.
func TestImportGeneratesNativeMessagingHostWrapper(t *testing.T) {
	cert := testSecureBrowserCA(t, "NMH Wrapper CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	home, source := fakeChromeSource(t)

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	_, err := svc.importChromeExtensions(profileDir, source, nil)
	require.NoError(t, err)

	wrapperPath := filepath.Join(profileDir, "nmh-wrappers", "com.anthropic.claude.sh")
	data, err := os.ReadFile(wrapperPath)
	require.NoError(t, err)
	script := string(data)

	assert.Contains(t, script, "#!/bin/sh")
	assert.Contains(t, script, "export HOME='"+home+"'", "wrapper must restore the real user HOME")
	assert.Contains(t, script, "exec '/opt/claude/host' \"$@\"", "wrapper must exec the original host binary")

	info, err := os.Stat(wrapperPath)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&0o100, "wrapper script must be executable")
}

// TestImportRegeneratesNativeMessagingHostOnReimport verifies a changed source
// manifest (different "path") regenerates the wrapper and rewritten manifest on
// a subsequent import. Regression for Defect 2 idempotency.
func TestImportRegeneratesNativeMessagingHostOnReimport(t *testing.T) {
	cert := testSecureBrowserCA(t, "NMH Reimport CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	home, source := fakeChromeSource(t)

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	_, err := svc.importChromeExtensions(profileDir, source, nil)
	require.NoError(t, err)

	wrapperPath := filepath.Join(profileDir, "nmh-wrappers", "com.anthropic.claude.sh")
	first, err := os.ReadFile(wrapperPath)
	require.NoError(t, err)
	assert.Contains(t, string(first), "exec '/opt/claude/host' \"$@\"")

	// The host was upgraded: source manifest now points at a new binary path.
	nmhSrc := filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts", "com.anthropic.claude.json")
	require.NoError(t, os.WriteFile(nmhSrc,
		[]byte(`{"name":"com.anthropic.claude","description":"Claude native host","type":"stdio","path":"/opt/claude/host-v2","allowed_origins":["chrome-extension://`+extAlpha+`/"]}`),
		0o600))

	_, err = svc.importChromeExtensions(profileDir, source, nil)
	require.NoError(t, err)

	// Wrapper now execs the upgraded binary.
	second, err := os.ReadFile(wrapperPath)
	require.NoError(t, err)
	assert.Contains(t, string(second), "exec '/opt/claude/host-v2' \"$@\"")

	// Manifest still points at the (stable) wrapper path.
	manifestPath := filepath.Join(profileDir, "NativeMessagingHosts", "com.anthropic.claude.json")
	mData, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(mData, &manifest))
	assert.Equal(t, wrapperPath, manifest["path"])
}

// TestImportCopiesLocalExtensionSettings verifies LevelDB state is copied
// when present (extAlpha) and silently skipped when absent (extBeta).
func TestImportCopiesLocalExtensionSettings(t *testing.T) {
	cert := testSecureBrowserCA(t, "State CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	_, source := fakeChromeSource(t)

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	_, err := svc.importChromeExtensions(profileDir, source, nil)
	require.NoError(t, err)

	targetDefault := filepath.Join(profileDir, "Default")

	// extAlpha had Local Extension Settings + IndexedDB -> copied.
	assert.FileExists(t, filepath.Join(targetDefault, "Local Extension Settings", extAlpha, "000003.log"))
	assert.FileExists(t, filepath.Join(targetDefault, "IndexedDB",
		"chrome-extension_"+extAlpha+"_0.indexeddb.leveldb", "CURRENT"))

	// extBeta had no state -> skipped cleanly, no directory created.
	assert.NoDirExists(t, filepath.Join(targetDefault, "Local Extension Settings", extBeta))
}

// TestImportPrivacyAllowlist verifies privacy-sensitive source files are
// never copied into the isolated profile.
func TestImportPrivacyAllowlist(t *testing.T) {
	cert := testSecureBrowserCA(t, "Privacy CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	_, source := fakeChromeSource(t)

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	_, err := svc.importChromeExtensions(profileDir, source, nil)
	require.NoError(t, err)

	targetDefault := filepath.Join(profileDir, "Default")
	for _, name := range []string{"Cookies", "Login Data", "History"} {
		assert.NoFileExists(t, filepath.Join(targetDefault, name),
			"%s must not be copied from the source profile", name)
		assert.NoFileExists(t, filepath.Join(profileDir, name))
	}
}

// TestImportMissingSourceProfile verifies a typed sentinel error is returned
// when the source profile directory does not exist.
func TestImportMissingSourceProfile(t *testing.T) {
	cert := testSecureBrowserCA(t, "Missing Source CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	t.Setenv("HOME", t.TempDir())

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := svc.importChromeExtensions(profileDir, missing, nil)
	assert.ErrorIs(t, err, ErrSecureBrowserSourceProfile)
}

// TestLaunchIncludeExtensionsSharedModeRejected verifies that requesting
// extension import in shared mode returns the unsupported sentinel error.
func TestLaunchIncludeExtensionsSharedModeRejected(t *testing.T) {
	cert := testSecureBrowserCA(t, "Shared Ext CA")
	svc, _ := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	svc.SetContext(context.Background())
	fakeChromeSource(t)

	config := svc.browserService.GetConfig()
	config.ChromeProfileMode = ProfileModeShared
	require.NoError(t, svc.browserService.SetConfig(config))

	svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	_, err := svc.LaunchBrowserWithOptions("/usr/bin/google-chrome", "https://example.com",
		LaunchOptions{IncludeExtensions: true})
	assert.ErrorIs(t, err, ErrSecureBrowserExtImportUnsupported)
}

// TestLaunchIncludeExtensionsFirefoxRejected verifies that requesting
// extension import for Firefox returns the unsupported sentinel error.
func TestLaunchIncludeExtensionsFirefoxRejected(t *testing.T) {
	cert := testSecureBrowserCA(t, "Firefox Ext CA")
	svc, _ := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	svc.SetContext(context.Background())
	fakeChromeSource(t)

	svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	_, err := svc.LaunchBrowserWithOptions("/usr/bin/firefox", "https://example.com",
		LaunchOptions{IncludeExtensions: true})
	assert.ErrorIs(t, err, ErrSecureBrowserExtImportUnsupported)
}

// TestLaunchWithExtensionsEndToEnd verifies the full Chrome isolated launch
// path imports extensions and reports the count on the result.
func TestLaunchWithExtensionsEndToEnd(t *testing.T) {
	cert := testSecureBrowserCA(t, "E2E Ext CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	svc.SetContext(context.Background())
	_, source := fakeChromeSource(t)

	svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	result, err := svc.LaunchBrowserWithOptions("/usr/bin/google-chrome", "https://example.com",
		LaunchOptions{IncludeExtensions: true, SourceProfile: source})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExtensionsImported)

	assert.DirExists(t, filepath.Join(baseDir, "chrome", "profile", "Default", "Extensions", extAlpha))
}

// TestImportPlainPreferencesMergePath verifies an extension registered only
// in the source Preferences (not Secure Preferences) is merged into the
// target Preferences file, exercising the plain-file branch.
func TestImportPlainPreferencesMergePath(t *testing.T) {
	cert := testSecureBrowserCA(t, "Plain Prefs CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	_, source := fakeChromeSource(t)

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	n, err := svc.importChromeExtensions(profileDir, source, []string{extBeta})
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	targetPlain := filepath.Join(profileDir, "Default", "Preferences")
	settings := readExtensionSettings(t, targetPlain)
	assert.Contains(t, settings, extBeta)
}

// TestImportSkipsUnregisteredExtension verifies that an extension present on
// disk but with no registration entry in either preferences file is skipped
// and not counted.
func TestImportSkipsUnregisteredExtension(t *testing.T) {
	cert := testSecureBrowserCA(t, "Unregistered CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	_, source := fakeChromeSource(t)

	// Add a version dir for an id with no registration entry.
	orphan := "dddddddddddddddddddddddddddddddd"
	require.NoError(t, os.MkdirAll(filepath.Join(source, "Extensions", orphan, "9.9.9_0"), 0o700))

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	n, err := svc.importChromeExtensions(profileDir, source, []string{orphan})
	require.NoError(t, err)
	assert.Equal(t, 0, n, "unregistered extension must be skipped")
	assert.NoDirExists(t, filepath.Join(profileDir, "Default", "Extensions", orphan))
}

// TestImportEmptySourceNoExtensions verifies a source profile with no
// Extensions directory imports nothing without error.
func TestImportEmptySourceNoExtensions(t *testing.T) {
	cert := testSecureBrowserCA(t, "Empty Source CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	home := t.TempDir()
	t.Setenv("HOME", home)
	source := filepath.Join(home, ".config", "google-chrome", "Default")
	require.NoError(t, os.MkdirAll(source, 0o700))

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	n, err := svc.importChromeExtensions(profileDir, source, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// TestImportFilterUnknownID verifies a requested id that is absent on disk is
// dropped without error.
func TestImportFilterUnknownID(t *testing.T) {
	cert := testSecureBrowserCA(t, "Unknown ID CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	_, source := fakeChromeSource(t)

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	n, err := svc.importChromeExtensions(profileDir, source, []string{"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"})
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// TestMergeExtensionSettingsCorruptTarget verifies a corrupt target
// preferences file is refused rather than clobbered.
func TestMergeExtensionSettingsCorruptTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Secure Preferences")
	require.NoError(t, os.WriteFile(path, []byte("{not valid json"), 0o600))

	err := mergeExtensionSettings(path, map[string]json.RawMessage{
		extAlpha: json.RawMessage(`{"state":1}`),
	})
	assert.ErrorIs(t, err, ErrSecureBrowserExtImport)

	// The corrupt file must be left untouched.
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "{not valid json", string(data))
}

// TestMergeExtensionSettingsNewFile verifies a fresh target file is created
// with the registration when none existed.
func TestMergeExtensionSettingsNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Default", "Secure Preferences")

	err := mergeExtensionSettings(path, map[string]json.RawMessage{
		extAlpha: json.RawMessage(`{"state":1}`),
	})
	require.NoError(t, err)

	settings := loadExtensionSettings(path)
	assert.Contains(t, settings, extAlpha)
}

// TestImportNoNativeMessagingHosts verifies a missing NMH directory is a
// no-op, not an error.
func TestImportNoNativeMessagingHosts(t *testing.T) {
	cert := testSecureBrowserCA(t, "No NMH CA")
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{cert})

	home := t.TempDir()
	t.Setenv("HOME", home)
	source := filepath.Join(home, ".config", "google-chrome", "Default")
	require.NoError(t, os.MkdirAll(filepath.Join(source, "Extensions", extAlpha, "1.0_0"), 0o700))
	writeJSON(t, filepath.Join(source, "Secure Preferences"), map[string]any{
		"extensions": map[string]any{"settings": map[string]any{
			extAlpha: map[string]any{"state": 1},
		}},
	})

	profileDir := filepath.Join(baseDir, "chrome", "profile")
	n, err := svc.importChromeExtensions(profileDir, source, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.NoDirExists(t, filepath.Join(profileDir, "NativeMessagingHosts"))
	assert.NoDirExists(t, filepath.Join(profileDir, "nmh-wrappers"))
}

// TestLaunchExtensionsViaConfigField verifies the persisted config field
// enables import even without the per-launch option override.
func TestLaunchExtensionsViaConfigField(t *testing.T) {
	cert := testSecureBrowserCA(t, "Config Ext CA")
	svc, _ := newTestSecureBrowserService(t, []*x509.Certificate{cert})
	svc.SetContext(context.Background())
	_, source := fakeChromeSource(t)

	config := svc.browserService.GetConfig()
	config.IncludeExtensions = true
	require.NoError(t, svc.browserService.SetConfig(config))

	svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	result, err := svc.LaunchBrowserWithOptions("/usr/bin/google-chrome", "https://example.com",
		LaunchOptions{SourceProfile: source})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExtensionsImported)
}
