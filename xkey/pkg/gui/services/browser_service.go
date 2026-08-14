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

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// BrowserSystem is the default browser selection that delegates to the
// platform's default URL handler (xdg-open, open, rundll32).
const BrowserSystem = "system"

// TrustSyncer injects the trust store's certificates into the browsers' own
// certificate databases. *SecureBrowserService satisfies it.
//
// This exists because SSL_CERT_FILE does NOT make a browser trust anything:
// Chrome reads NSS (~/.pki/nssdb) and Firefox reads its profile's cert9.db,
// and both ignore the OpenSSL environment entirely. Setting the variable and
// calling it done produced exactly the failure it was meant to prevent — a
// TLS interstitial in a browser the user was told was trusted.
type TrustSyncer interface {
	// Rebuild writes the current trust-store contents into every browser
	// certificate database it manages.
	Rebuild() error
}

// Profile mode constants for browser cert injection.
const (
	// ProfileModeIsolated launches the browser with a separate, clean profile.
	ProfileModeIsolated = "isolated"

	// ProfileModeShared overlays certificates on the user's default profile.
	ProfileModeShared = "shared"
)

// BrowserConfig holds browser launcher configuration.
type BrowserConfig struct {
	// DefaultBrowser is "system" or an absolute path to a browser binary
	// such as "/usr/bin/firefox".
	DefaultBrowser string `json:"default_browser"`

	// CustomCommand is a custom launch command with a {url} placeholder.
	// Example: "/usr/bin/chromium --new-window {url}"
	CustomCommand string `json:"custom_command,omitempty"`

	// IncludeTrustBundle controls whether the CA trust bundle is applied
	// to browser processes when launching.
	IncludeTrustBundle bool `json:"include_trust_bundle"`

	// ChromeProfileMode controls whether Chrome launches with an isolated
	// profile or shares the user's default profile. Valid values are
	// "isolated" and "shared". Defaults to "isolated".
	ChromeProfileMode string `json:"chrome_profile_mode"`

	// FirefoxProfileMode controls whether Firefox launches with an isolated
	// profile or shares the user's default profile. Valid values are
	// "isolated" and "shared". Defaults to "isolated".
	FirefoxProfileMode string `json:"firefox_profile_mode"`

	// IncludeExtensions controls whether the user-installed extensions from
	// the system default Chrome profile are imported into the isolated
	// profile on launch. It applies only to Chrome-family browsers in
	// isolated mode. Defaults to false. A CLI flag overrides this value
	// per-launch. The GUI may surface this as a toggle.
	IncludeExtensions bool `json:"include_extensions"`
}

// BrowserInfo describes an available browser detected on the system.
type BrowserInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// BrowserService manages browser launching for xkey. It persists
// configuration as JSON and provides platform-aware URL opening. The
// service is bound to the Wails runtime so every exported method is
// callable from the frontend.
type BrowserService struct {
	ctx             context.Context
	mu              sync.RWMutex
	config          BrowserConfig
	configPath      string
	trustBundlePath string

	// trustSyncer injects certificates into the browsers' own stores. Set
	// after construction (SecureBrowserService depends on this service, so
	// the wiring cannot be a constructor argument in both directions).
	trustSyncer TrustSyncer
	logger      *slog.Logger

	// execCommand is the function used to create exec.Cmd instances.
	// It defaults to exec.CommandContext and can be overridden in tests.
	execCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

// NewBrowserService creates a new BrowserService. The configPath is the
// path to browser.json (e.g., ~/.xkey/config/browser.json). If the
// config file exists it is loaded; otherwise defaults are used.
func NewBrowserService(configPath string, logger *slog.Logger) (*BrowserService, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrBrowserConfigLoad, Cause: err}
		}
		configPath = filepath.Join(home, ".xkey", "config", "browser.json")
	}

	svc := &BrowserService{
		configPath:  configPath,
		logger:      logger.With("service", "browser"),
		execCommand: exec.CommandContext,
		config: BrowserConfig{
			DefaultBrowser:     BrowserSystem,
			ChromeProfileMode:  ProfileModeIsolated,
			FirefoxProfileMode: ProfileModeIsolated,
		},
	}

	// Attempt to load existing configuration.
	if err := svc.loadConfig(); err != nil {
		// If the file does not exist, use defaults silently.
		if !os.IsNotExist(err) {
			return nil, &SentinelCauseError{Sentinel: ErrBrowserConfigLoad, Cause: err}
		}
		svc.logger.Debug("no browser config found, using defaults", "path", configPath)
	}

	return svc, nil
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *BrowserService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetTrustSyncer wires the browser certificate-database injector. Without it,
// IncludeTrustBundle only reaches OpenSSL-based child processes — no browser.
func (s *BrowserService) SetTrustSyncer(syncer TrustSyncer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trustSyncer = syncer
}

// SetTrustBundlePath configures the path to the PEM trust bundle that
// will be applied to browser processes via the SSL_CERT_FILE environment
// variable.
func (s *BrowserService) SetTrustBundlePath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trustBundlePath = path
}

// GetTrustBundlePath returns the currently configured trust bundle path.
func (s *BrowserService) GetTrustBundlePath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.trustBundlePath
}

// OpenURL launches the configured browser with the given URL. The
// context used for subprocess creation comes from SetContext.
func (s *BrowserService) OpenURL(url string) error {
	if url == "" {
		return ErrBrowserEmptyURL
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.RLock()
	config := s.config
	s.mu.RUnlock()

	s.logger.Info("opening URL",
		"url", url,
		"default_browser", config.DefaultBrowser,
		"custom_command", config.CustomCommand,
	)

	// Make the browser actually trust the platform CAs before it starts.
	// A sync failure is logged, not fatal: the user asked to open a URL, and
	// refusing to launch would be a worse outcome than launching into a
	// certificate warning they can still read.
	s.syncBrowserTrust()

	// Custom command takes precedence.
	if config.CustomCommand != "" {
		return s.openCustomCommand(ctx, config.CustomCommand, url)
	}

	// System default browser.
	if config.DefaultBrowser == BrowserSystem {
		return s.openSystemBrowser(ctx, url)
	}

	// Specific browser binary.
	return s.openBrowserBinary(ctx, config.DefaultBrowser, url)
}

// GetConfig returns the current browser configuration.
func (s *BrowserService) GetConfig() BrowserConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// SetConfig updates the browser configuration and persists it.
func (s *BrowserService) SetConfig(config BrowserConfig) error {
	if err := validateConfig(config); err != nil {
		return err
	}

	s.mu.Lock()
	s.config = config
	s.mu.Unlock()

	if err := s.saveConfig(config); err != nil {
		return err
	}

	s.logger.Info("browser configuration updated",
		"default_browser", config.DefaultBrowser,
		"custom_command", config.CustomCommand,
	)

	return nil
}

// DetectBrowsers returns a list of available browsers on the system.
// The "system" option is always included.
func (s *BrowserService) DetectBrowsers() []BrowserInfo {
	browsers := []BrowserInfo{
		{Name: "System Default", Path: BrowserSystem},
	}

	candidates := knownBrowsers()
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate.Path); err == nil {
			browsers = append(browsers, candidate)
		}
	}

	return browsers
}

// openCustomCommand replaces the {url} placeholder and executes the
// custom command string. If no {url} placeholder is present, the URL
// is appended as the last argument.
func (s *BrowserService) openCustomCommand(ctx context.Context, command, url string) error {
	var expanded string
	if strings.Contains(command, "{url}") {
		expanded = strings.ReplaceAll(command, "{url}", url)
	} else {
		expanded = command + " " + url
	}

	parts := strings.Fields(expanded)
	if len(parts) == 0 {
		return ErrBrowserLaunchFailed
	}

	cmd := s.execCommand(ctx, parts[0], parts[1:]...)
	s.applyTrustBundle(cmd)
	if err := cmd.Start(); err != nil {
		s.logger.Error("custom browser command failed",
			"command", command,
			"url", url,
			"error", err,
		)
		return &SentinelCauseError{Sentinel: ErrBrowserLaunchFailed, Cause: err}
	}

	return nil
}

// openSystemBrowser uses the platform-specific default URL handler.
func (s *BrowserService) openSystemBrowser(ctx context.Context, url string) error {
	var name string
	var args []string

	switch runtime.GOOS {
	case "linux":
		name = "xdg-open"
		args = []string{url}
	case "darwin":
		name = "open"
		args = []string{url}
	case "windows":
		name = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	default:
		return &DetailError{Err: ErrBrowserLaunchFailed, Detail: fmt.Sprintf(": unsupported platform %s", runtime.GOOS)}
	}

	cmd := s.execCommand(ctx, name, args...)
	s.applyTrustBundle(cmd)
	if err := cmd.Start(); err != nil {
		s.logger.Error("system browser launch failed",
			"command", name,
			"url", url,
			"error", err,
		)
		return &SentinelCauseError{Sentinel: ErrBrowserLaunchFailed, Cause: err}
	}

	return nil
}

// openBrowserBinary launches a specific browser binary with the URL.
func (s *BrowserService) openBrowserBinary(ctx context.Context, binary, url string) error {
	cmd := s.execCommand(ctx, binary, url)
	s.applyTrustBundle(cmd)
	if err := cmd.Start(); err != nil {
		s.logger.Error("browser binary launch failed",
			"binary", binary,
			"url", url,
			"error", err,
		)
		return &SentinelCauseError{Sentinel: ErrBrowserLaunchFailed, Cause: err}
	}

	return nil
}

// syncBrowserTrust injects the trust store into the browsers' certificate
// databases when IncludeTrustBundle is configured.
func (s *BrowserService) syncBrowserTrust() {
	s.mu.RLock()
	syncer := s.trustSyncer
	include := s.config.IncludeTrustBundle
	s.mu.RUnlock()

	if !include || syncer == nil {
		return
	}
	if err := syncer.Rebuild(); err != nil {
		s.logger.Warn("browser trust sync failed; the browser may not trust platform certificates",
			"error", err)
	}
}

// applyTrustBundle sets environment variables on the command to load the
// custom CA trust bundle. This works for browsers that use the system's
// SSL/TLS library (OpenSSL, NSS, GnuTLS). The SSL_CERT_FILE environment
// variable is set to point at the PEM bundle file.
func (s *BrowserService) applyTrustBundle(cmd *exec.Cmd) {
	s.mu.RLock()
	bundlePath := s.trustBundlePath
	includeTrustBundle := s.config.IncludeTrustBundle
	s.mu.RUnlock()

	if !includeTrustBundle {
		return
	}

	if bundlePath == "" {
		return
	}
	if _, err := os.Stat(bundlePath); err != nil {
		return
	}

	// SSL_CERT_FILE reaches OpenSSL-based children (curl, native-messaging
	// helpers, anything linking OpenSSL) — NOT the browser itself. Browser
	// trust comes from syncBrowserTrust writing into NSS / cert9.db.
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+bundlePath)
	s.logger.Debug("applied trust bundle to child environment (OpenSSL consumers only)",
		"bundle", bundlePath)
}

// loadConfig reads the JSON configuration file from disk.
func (s *BrowserService) loadConfig() error {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return err
	}

	var config BrowserConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	// Backfill profile mode defaults for legacy configs persisted before
	// these fields existed.
	if config.ChromeProfileMode == "" {
		config.ChromeProfileMode = ProfileModeIsolated
	}
	if config.FirefoxProfileMode == "" {
		config.FirefoxProfileMode = ProfileModeIsolated
	}

	s.mu.Lock()
	s.config = config
	s.mu.Unlock()

	s.logger.Debug("browser config loaded", "path", s.configPath)
	return nil
}

// saveConfig marshals the configuration to JSON and writes it to disk.
func (s *BrowserService) saveConfig(config BrowserConfig) error {
	dir := filepath.Dir(s.configPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrBrowserConfigSave, Cause: err}
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBrowserConfigSave, Cause: err}
	}

	if err := os.WriteFile(s.configPath, data, 0o600); err != nil {
		return &SentinelCauseError{Sentinel: ErrBrowserConfigSave, Cause: err}
	}

	return nil
}

// validateConfig checks that the browser configuration is valid. At
// least one of DefaultBrowser or CustomCommand must be non-empty.
func validateConfig(config BrowserConfig) error {
	if config.DefaultBrowser == "" && config.CustomCommand == "" {
		return ErrBrowserInvalidConfig
	}
	return nil
}

// knownBrowsers returns browser candidates for the current platform.
func knownBrowsers() []BrowserInfo {
	switch runtime.GOOS {
	case "linux":
		return []BrowserInfo{
			{Name: "Firefox", Path: "/usr/bin/firefox"},
			{Name: "Chromium", Path: "/usr/bin/chromium"},
			{Name: "Chromium", Path: "/usr/bin/chromium-browser"},
			{Name: "Google Chrome", Path: "/usr/bin/google-chrome"},
			{Name: "Brave", Path: "/usr/bin/brave-browser"},
		}
	case "darwin":
		return []BrowserInfo{
			{Name: "Safari", Path: "/Applications/Safari.app/Contents/MacOS/Safari"},
			{Name: "Firefox", Path: "/Applications/Firefox.app/Contents/MacOS/firefox"},
			{Name: "Google Chrome", Path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
			{Name: "Brave", Path: "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"},
		}
	default:
		return nil
	}
}
