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
// Chromium-family entries. Retained for backward compatibility with existing
// tests and callers.
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
		return 0, fmt.Errorf("%w: unsupported browser %q", ErrInvalidManifest, browser)
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
		return nil, fmt.Errorf("%w: unsupported browser %q", ErrInvalidManifest, browser)
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

// chromiumDir returns the absolute NativeMessagingHosts directory for a
// Chromium-based browser given the user's home directory. Retained for
// backward compatibility with existing tests.
func chromiumDir(kb knownBrowser, home string) string {
	return browserDir(kb, home)
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
		return nil, fmt.Errorf("%w: invalid binary path: %v", ErrInvalidManifest, err)
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
		return nil, fmt.Errorf("%w: unsupported browser %q", ErrInvalidManifest, browser)
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
		return "", fmt.Errorf("%w: cannot determine home directory: %v", ErrManifestInstall, err)
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
		return nil, fmt.Errorf("%w: cannot determine home directory: %v", ErrManifestInstall, err)
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
		return fmt.Errorf("%w: cannot determine home directory: %v", ErrManifestInstall, err)
	}

	m, err := GenerateManifest(browser, xkeyBinaryPath)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: cannot marshal manifest: %v", ErrManifestInstall, err)
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
			return fmt.Errorf("%w: cannot create directory %q: %v", ErrManifestInstall, dir, mkdirErr)
		}
		manifestPath := filepath.Join(dir, manifestFileName)
		if writeErr := os.WriteFile(manifestPath, data, manifestFileMode); writeErr != nil {
			return fmt.Errorf("%w: cannot write manifest to %q: %v", ErrManifestInstall, manifestPath, writeErr)
		}
		installed++
	}

	if installed == 0 {
		// No browser in this family detected; force-install to the default
		// path so the manifest is ready when the browser is installed later.
		dir := browserDir(browsers[0], home)
		if mkdirErr := os.MkdirAll(dir, manifestDirMode); mkdirErr != nil {
			return fmt.Errorf("%w: cannot create directory %q: %v", ErrManifestInstall, dir, mkdirErr)
		}
		manifestPath := filepath.Join(dir, manifestFileName)
		if writeErr := os.WriteFile(manifestPath, data, manifestFileMode); writeErr != nil {
			return fmt.Errorf("%w: cannot write manifest to %q: %v", ErrManifestInstall, manifestPath, writeErr)
		}
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
		return fmt.Errorf("%w: cannot determine home directory: %v", ErrManifestInstall, err)
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
			return fmt.Errorf("%w: cannot remove manifest at %q: %v", ErrManifestInstall, manifestPath, removeErr)
		}
		removed++
	}

	if removed == 0 {
		return fmt.Errorf("%w: no %s manifests found", ErrManifestNotFound, familyName)
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
