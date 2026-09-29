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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/shellquote"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// Manifest represents a native messaging host manifest for Chrome (and all
// Chromium-based browsers) or Firefox.
type Manifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedOrigins    []string `json:"allowed_origins,omitempty"`    // Chromium-based browsers
	AllowedExtensions []string `json:"allowed_extensions,omitempty"` // Firefox
}

// Browser identifies a supported browser family.
type Browser string

const (
	// BrowserChrome identifies all Chromium-based browsers (Chrome, Brave,
	// Chromium, Edge, Opera, Vivaldi). Install/uninstall/status operations
	// automatically handle all known Chromium derivatives.
	BrowserChrome Browser = "chrome"

	// BrowserFirefox identifies all Firefox-based browsers (Firefox,
	// LibreWolf, Waterfox). Install/uninstall/status operations automatically
	// handle all known Firefox derivatives.
	BrowserFirefox Browser = "firefox"

	// manifestDescription is the human-readable description used in manifests.
	manifestDescription = "xkey native messaging host for browser extension integration"

	// manifestType is the communication type used in native messaging manifests.
	manifestType = "stdio"

	// manifestFileName is the manifest filename derived from the host name.
	manifestFileName = NativeHostName + ".json"

	// manifestDirMode is the permission mode for the manifest directory.
	manifestDirMode = 0755

	// manifestFileMode is the permission mode for the manifest file.
	manifestFileMode = 0644

	// nativeMessagingHostsDirName is the manifest directory name Chrome
	// resolves relative to a profile's user-data directory. It is the same
	// name every knownBrowsers Chromium entry uses relative to $HOME; a
	// --profile-dir install uses it directly against a profile's own
	// user-data directory instead.
	nativeMessagingHostsDirName = "NativeMessagingHosts"

	// launcherDirName is the instance-home subdirectory generated launcher
	// scripts live in, alongside the IPC socket's own "run" directory
	// (pkg/ipc.DefaultSocketPath).
	launcherDirName = "run"

	// launcherFileName is the generated launcher script's file name.
	launcherFileName = "extension-host-launcher.sh"

	// launcherFileMode is the permission mode for the generated launcher
	// script: owner-only, executable, matching the 0700 mode every other
	// xKey home subdirectory uses.
	launcherFileMode = 0700
)

// ChromeExtensionID is the expected Chrome extension ID. This corresponds to
// the RSA public key embedded in the extension manifest.json via the "key"
// field, which produces a deterministic extension ID for unpacked installs.
const ChromeExtensionID = "chrome-extension://ogbhdplieldlomhnokdapcopejmkelkl/"

// FirefoxExtensionID is the expected Firefox extension ID.
const FirefoxExtensionID = "xkey@automatethethings.com"

// ChromeAllowedOriginOverride, when non-empty, replaces ChromeExtensionID in
// the generated manifest. This allows operators to specify a custom extension
// origin via the CLI (e.g., xkey extension install --allowed-origin).
var ChromeAllowedOriginOverride string

// homeDirFunc returns the home directory for use in manifest paths.
// Overridable in tests.
var homeDirFunc = os.UserHomeDir

// browserFamily distinguishes Chromium-based and Firefox-based browsers
// for manifest format selection.
type browserFamily int

const (
	familyChromium browserFamily = iota
	familyFirefox
)

// knownBrowser describes a browser and its platform-specific NativeMessagingHosts
// directory relative to the home directory.
type knownBrowser struct {
	Name      string        // Display name shown in GUI/CLI
	Family    browserFamily // Determines manifest format
	LinuxDir  string        // NativeMessagingHosts path relative to $HOME (Linux)
	DarwinDir string        // NativeMessagingHosts path relative to $HOME (macOS)
}

// knownBrowsers lists all supported browsers and their manifest directories.
// Order matters: Chrome is first as the Chromium fallback, Firefox is first
// as the Firefox-family fallback.
var knownBrowsers = []knownBrowser{
	// Chromium-based
	{Name: "Chrome", Family: familyChromium, LinuxDir: ".config/google-chrome/NativeMessagingHosts", DarwinDir: "Library/Application Support/Google/Chrome/NativeMessagingHosts"},
	{Name: "Brave", Family: familyChromium, LinuxDir: ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts", DarwinDir: "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"},
	{Name: "Chromium", Family: familyChromium, LinuxDir: ".config/chromium/NativeMessagingHosts", DarwinDir: "Library/Application Support/Chromium/NativeMessagingHosts"},
	{Name: "Edge", Family: familyChromium, LinuxDir: ".config/microsoft-edge/NativeMessagingHosts", DarwinDir: "Library/Application Support/Microsoft Edge/NativeMessagingHosts"},
	{Name: "Opera", Family: familyChromium, LinuxDir: ".config/opera/NativeMessagingHosts", DarwinDir: "Library/Application Support/com.operasoftware.Opera/NativeMessagingHosts"},
	{Name: "Vivaldi", Family: familyChromium, LinuxDir: ".config/vivaldi/NativeMessagingHosts", DarwinDir: "Library/Application Support/Vivaldi/NativeMessagingHosts"},
	// Firefox-based
	{Name: "Firefox", Family: familyFirefox, LinuxDir: ".mozilla/native-messaging-hosts", DarwinDir: "Library/Application Support/Mozilla/NativeMessagingHosts"},
	{Name: "LibreWolf", Family: familyFirefox, LinuxDir: ".librewolf/native-messaging-hosts", DarwinDir: "Library/Application Support/LibreWolf/NativeMessagingHosts"},
	{Name: "Waterfox", Family: familyFirefox, LinuxDir: ".waterfox/native-messaging-hosts", DarwinDir: "Library/Application Support/Waterfox/NativeMessagingHosts"},
}

// chromiumBrowsers is a filtered view of knownBrowsers containing only
// Chromium-family entries.
var chromiumBrowsers = filterByFamily(familyChromium)

// firefoxBrowsers is a filtered view of knownBrowsers containing only
// Firefox-family entries.
var firefoxBrowsers = filterByFamily(familyFirefox)

// filterByFamily returns all knownBrowsers matching the given family.
func filterByFamily(family browserFamily) []knownBrowser {
	var result []knownBrowser
	for _, kb := range knownBrowsers {
		if kb.Family == family {
			result = append(result, kb)
		}
	}
	return result
}

// BrowserFamily returns the browser family for a display name.
// Returns BrowserChrome for Chromium-based browsers, BrowserFirefox for Firefox-based.
// Returns empty string if the name is not recognized.
func BrowserFamily(name string) Browser {
	for _, kb := range knownBrowsers {
		if strings.EqualFold(kb.Name, name) {
			switch kb.Family {
			case familyChromium:
				return BrowserChrome
			case familyFirefox:
				return BrowserFirefox
			}
		}
	}
	return ""
}

// familyForBrowser maps a Browser constant to its browserFamily.
func familyForBrowser(browser Browser) (browserFamily, error) {
	switch browser {
	case BrowserChrome:
		return familyChromium, nil
	case BrowserFirefox:
		return familyFirefox, nil
	default:
		return 0, &DetailError{Err: ErrInvalidManifest, Detail: fmt.Sprintf(": unsupported browser %q", browser)}
	}
}

// browsersForFamily returns the knownBrowser slice for the given Browser constant.
func browsersForFamily(browser Browser) ([]knownBrowser, error) {
	family, err := familyForBrowser(browser)
	if err != nil {
		return nil, err
	}
	switch family {
	case familyChromium:
		return chromiumBrowsers, nil
	case familyFirefox:
		return firefoxBrowsers, nil
	default:
		return nil, &DetailError{Err: ErrInvalidManifest, Detail: fmt.Sprintf(": unsupported browser %q", browser)}
	}
}

// browserDir returns the absolute NativeMessagingHosts directory for a browser
// given the user's home directory.
func browserDir(kb knownBrowser, home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, kb.DarwinDir)
	default: // linux
		return filepath.Join(home, kb.LinuxDir)
	}
}

// isBrowserInstalled checks if the parent directory of the NativeMessagingHosts
// directory exists, indicating the browser is installed. For example, for
// Chrome on Linux it checks if ~/.config/google-chrome exists.
func isBrowserInstalled(kb knownBrowser, home string) bool {
	dir := browserDir(kb, home)
	parentDir := filepath.Dir(dir)
	_, err := os.Stat(parentDir)
	return err == nil
}

// GenerateManifest creates a native messaging host manifest for the given
// browser family. BrowserChrome produces a manifest suitable for all
// Chromium-based browsers.
func GenerateManifest(browser Browser, xkeyBinaryPath string) (*Manifest, error) {
	absPath, err := filepath.Abs(xkeyBinaryPath)
	if err != nil {
		return nil, &DetailError{Err: ErrInvalidManifest, Detail: fmt.Sprintf(": invalid binary path: %v", err)}
	}

	m := &Manifest{
		Name:        NativeHostName,
		Description: manifestDescription,
		Path:        absPath,
		Type:        manifestType,
	}

	switch browser {
	case BrowserChrome:
		origin := ChromeExtensionID
		if ChromeAllowedOriginOverride != "" {
			origin = ChromeAllowedOriginOverride
		}
		m.AllowedOrigins = []string{origin}
	case BrowserFirefox:
		m.AllowedExtensions = []string{FirefoxExtensionID}
	default:
		return nil, &DetailError{Err: ErrInvalidManifest, Detail: fmt.Sprintf(": unsupported browser %q", browser)}
	}

	return m, nil
}

// ManifestPath returns the primary platform-appropriate manifest path for the
// given browser. For BrowserChrome this returns the Google Chrome path (the
// first Chromium entry). For BrowserFirefox this returns the Firefox path
// (the first Firefox entry). Use ManifestPaths to get all paths for a family.
func ManifestPath(browser Browser) (string, error) {
	home, err := homeDirFunc()
	if err != nil {
		return "", &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot determine home directory: %v", err)}
	}

	browsers, lookupErr := browsersForFamily(browser)
	if lookupErr != nil {
		return "", lookupErr
	}

	dir := browserDir(browsers[0], home)
	return filepath.Join(dir, manifestFileName), nil
}

// ManifestPaths returns all platform-appropriate manifest paths for the given
// browser family. For BrowserChrome, this returns paths for all known
// Chromium-based browsers. For BrowserFirefox, this returns paths for all
// known Firefox-based browsers.
func ManifestPaths(browser Browser) ([]string, error) {
	home, err := homeDirFunc()
	if err != nil {
		return nil, &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot determine home directory: %v", err)}
	}

	browsers, lookupErr := browsersForFamily(browser)
	if lookupErr != nil {
		return nil, lookupErr
	}

	paths := make([]string, len(browsers))
	for i, kb := range browsers {
		paths[i] = filepath.Join(browserDir(kb, home), manifestFileName)
	}
	return paths, nil
}

// InstallManifest generates and writes the manifest to the correct path(s).
// For each browser family, the manifest is installed for every detected browser
// in that family. If no browser in the family is detected, the manifest is
// installed to the default directory (Chrome for Chromium-family, Firefox for
// Firefox-family) so it is ready when the browser is installed later.
func InstallManifest(browser Browser, xkeyBinaryPath string) error {
	return installFamilyManifests(browser, xkeyBinaryPath)
}

// installFamilyManifests installs the native messaging manifest for every
// detected browser in the given family. If no browser in the family is
// detected, the first entry (the default) is used as a fallback.
func installFamilyManifests(browser Browser, xkeyBinaryPath string) error {
	home, err := homeDirFunc()
	if err != nil {
		return &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot determine home directory: %v", err)}
	}

	m, err := GenerateManifest(browser, xkeyBinaryPath)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot marshal manifest: %v", err)}
	}

	browsers, lookupErr := browsersForFamily(browser)
	if lookupErr != nil {
		return lookupErr
	}

	installed := 0
	for _, kb := range browsers {
		dir := browserDir(kb, home)
		parentDir := filepath.Dir(dir)
		if _, statErr := os.Stat(parentDir); os.IsNotExist(statErr) {
			continue // browser not installed, skip
		}
		if mkdirErr := os.MkdirAll(dir, manifestDirMode); mkdirErr != nil {
			return &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot create directory %q: %v", dir, mkdirErr)}
		}
		manifestPath := filepath.Join(dir, manifestFileName)
		if writeErr := os.WriteFile(manifestPath, data, manifestFileMode); writeErr != nil {
			return &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot write manifest to %q: %v", manifestPath, writeErr)}
		}
		installed++
	}

	if installed == 0 {
		// No browser in this family detected; force-install to the default
		// path so the manifest is ready when the browser is installed later.
		dir := browserDir(browsers[0], home)
		if mkdirErr := os.MkdirAll(dir, manifestDirMode); mkdirErr != nil {
			return &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot create directory %q: %v", dir, mkdirErr)}
		}
		manifestPath := filepath.Join(dir, manifestFileName)
		if writeErr := os.WriteFile(manifestPath, data, manifestFileMode); writeErr != nil {
			return &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot write manifest to %q: %v", manifestPath, writeErr)}
		}
	}

	return nil
}

// GenerateLauncherScript writes a small shell script under home's run/
// directory that pins the native messaging host it launches to one xkey
// instance: it exports XKEY_HOME before exec'ing xkeyBinaryPath, so the host
// process resolves this instance's IPC socket (pkg/ipc.DefaultSocketPath),
// data directory and config regardless of which user or environment invoked
// it — which for a browser-launched process is Chrome's own environment, not
// the agent's.
//
// Chrome native messaging manifests can only name a "path" to execute; they
// cannot carry extra arguments or environment variables. So a manifest that
// must pin a shared xkey binary to one instance cannot point at the binary
// directly — it points at this generated launcher instead. The script is
// regenerated (overwritten) on every call, so re-running `extension install
// --profile-dir` after the binary moves, or the instance home changes, keeps
// the launcher accurate rather than silently pointing at a stale path.
func GenerateLauncherScript(home *xhome.Home, xkeyBinaryPath string) (string, error) {
	if home == nil {
		return "", ErrLauncherNilHome
	}

	absBinary, err := filepath.Abs(xkeyBinaryPath)
	if err != nil {
		return "", &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": invalid binary path: %v", err)}
	}

	dir := filepath.Join(home.Root, launcherDirName)
	if mkdirErr := os.MkdirAll(dir, launcherFileMode); mkdirErr != nil {
		return "", &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot create launcher directory %q: %v", dir, mkdirErr)}
	}

	launcherPath := filepath.Join(dir, launcherFileName)
	script := fmt.Sprintf(
		"#!/bin/sh\n"+
			"# Generated by `xkey extension install --profile-dir`. Do not edit:\n"+
			"# it is overwritten on every install and pins the native messaging\n"+
			"# host it launches to this xkey instance.\n"+
			"export %s=%s\n"+
			"exec %s extension host \"$@\"\n",
		xhome.EnvHome, shellquote.SingleQuote(home.Root), shellquote.SingleQuote(absBinary),
	)

	if writeErr := os.WriteFile(launcherPath, []byte(script), launcherFileMode); writeErr != nil {
		return "", &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot write launcher script %q: %v", launcherPath, writeErr)}
	}

	return launcherPath, nil
}

// InstallProfileManifest installs a Chrome native messaging manifest scoped
// to one browser profile (a --user-data-dir) instead of the OS-wide default
// location every Chromium profile on the host shares. This is how two xkey
// instances running as the same OS user each pair with their own Chrome
// profile: Chrome resolves native messaging manifests from
// <user-data-dir>/NativeMessagingHosts (the default profile's
// NativeMessagingHosts directory IS relative to the default user-data-dir),
// so pointing --profile-dir at a distinct user-data-dir gives that profile a
// manifest the other profile never sees.
//
// The manifest's path points at a launcher script (GenerateLauncherScript)
// pinned to home, not at xkeyBinaryPath directly, for the reason documented
// there. It returns the path the manifest was written to.
func InstallProfileManifest(home *xhome.Home, xkeyBinaryPath, profileDir string) (string, error) {
	launcherPath, err := GenerateLauncherScript(home, xkeyBinaryPath)
	if err != nil {
		return "", err
	}

	m, err := GenerateManifest(BrowserChrome, launcherPath)
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot marshal manifest: %v", err)}
	}

	absProfileDir, err := filepath.Abs(profileDir)
	if err != nil {
		return "", &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": invalid profile directory: %v", err)}
	}

	dir := filepath.Join(absProfileDir, nativeMessagingHostsDirName)
	if mkdirErr := os.MkdirAll(dir, manifestDirMode); mkdirErr != nil {
		return "", &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot create directory %q: %v", dir, mkdirErr)}
	}

	manifestPath := filepath.Join(dir, manifestFileName)
	if writeErr := os.WriteFile(manifestPath, data, manifestFileMode); writeErr != nil {
		return "", &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot write manifest to %q: %v", manifestPath, writeErr)}
	}

	return manifestPath, nil
}

// UninstallProfileManifest removes the Chrome native messaging manifest
// previously written by InstallProfileManifest for profileDir. It does not
// remove the generated launcher script under the instance home: other
// profiles installed against the same instance may still reference it.
func UninstallProfileManifest(profileDir string) error {
	absProfileDir, err := filepath.Abs(profileDir)
	if err != nil {
		return &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": invalid profile directory: %v", err)}
	}

	manifestPath := filepath.Join(absProfileDir, nativeMessagingHostsDirName, manifestFileName)
	if removeErr := os.Remove(manifestPath); removeErr != nil {
		if os.IsNotExist(removeErr) {
			return &DetailError{Err: ErrManifestNotFound, Detail: fmt.Sprintf(": no manifest found at %q", manifestPath)}
		}
		return &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot remove manifest at %q: %v", manifestPath, removeErr)}
	}

	return nil
}

// UninstallManifest removes the manifest file(s) for the given browser family.
// For BrowserChrome, manifests are removed from all Chromium browser directories.
// For BrowserFirefox, manifests are removed from all Firefox browser directories.
func UninstallManifest(browser Browser) error {
	return uninstallFamilyManifests(browser)
}

// uninstallFamilyManifests removes manifests from all browser directories in
// the given family. Returns ErrManifestNotFound only if no manifests were
// found in any directory.
func uninstallFamilyManifests(browser Browser) error {
	home, err := homeDirFunc()
	if err != nil {
		return &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot determine home directory: %v", err)}
	}

	browsers, lookupErr := browsersForFamily(browser)
	if lookupErr != nil {
		return lookupErr
	}

	familyName := "chromium"
	if browser == BrowserFirefox {
		familyName = "firefox"
	}

	removed := 0
	for _, kb := range browsers {
		manifestPath := filepath.Join(browserDir(kb, home), manifestFileName)
		if removeErr := os.Remove(manifestPath); removeErr != nil {
			if os.IsNotExist(removeErr) {
				continue
			}
			return &DetailError{Err: ErrManifestInstall, Detail: fmt.Sprintf(": cannot remove manifest at %q: %v", manifestPath, removeErr)}
		}
		removed++
	}

	if removed == 0 {
		return &DetailError{Err: ErrManifestNotFound, Detail: fmt.Sprintf(": no %s manifests found", familyName)}
	}

	return nil
}

// ManifestStatusInfo describes the installation status of a manifest for a
// single browser or browser derivative.
type ManifestStatusInfo struct {
	Browser   Browser `json:"browser"`
	Name      string  `json:"name"` // Display name (e.g., "Chrome", "Brave", "Firefox")
	Installed bool    `json:"installed"`
	Path      string  `json:"path"`
}

// GetManifestStatus returns whether manifests are installed for each browser
// that is detected on the system. Only browsers whose parent configuration
// directory exists are included. For Chromium-based browsers, a separate entry
// is returned for each detected derivative. For Firefox-based browsers, a
// separate entry is returned for each detected derivative.
func GetManifestStatus() []ManifestStatusInfo {
	home, err := homeDirFunc()
	if err != nil {
		return nil
	}

	var statuses []ManifestStatusInfo

	for _, kb := range knownBrowsers {
		if !isBrowserInstalled(kb, home) {
			continue
		}

		manifestPath := filepath.Join(browserDir(kb, home), manifestFileName)
		info := ManifestStatusInfo{
			Name: kb.Name,
			Path: manifestPath,
		}

		switch kb.Family {
		case familyChromium:
			info.Browser = BrowserChrome
		case familyFirefox:
			info.Browser = BrowserFirefox
		}

		if _, statErr := os.Stat(manifestPath); statErr == nil {
			info.Installed = true
		}

		statuses = append(statuses, info)
	}

	return statuses
}
