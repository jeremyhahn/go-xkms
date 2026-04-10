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
	logger          *slog.Logger

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
			return nil, fmt.Errorf("%w: %w", ErrBrowserConfigLoad, err)
		}
		configPath = filepath.Join(home, ".xkey", "config", "browser.json")
	}

	svc := &BrowserService{
		configPath:  configPath,
		logger:      logger.With("service", "browser"),
		execCommand: exec.CommandContext,
		config: BrowserConfig{
			DefaultBrowser: BrowserSystem,
		},
	}

	// Attempt to load existing configuration.
	if err := svc.loadConfig(); err != nil {
		// If the file does not exist, use defaults silently.
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %w", ErrBrowserConfigLoad, err)
		}
		svc.logger.Debug("no browser config found, using defaults", "path", configPath)
	}

	return svc, nil
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *BrowserService) SetContext(ctx context.Context) {
	s.ctx = ctx
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
		return fmt.Errorf("%w: %w", ErrBrowserLaunchFailed, err)
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
		return fmt.Errorf("%w: unsupported platform %s", ErrBrowserLaunchFailed, runtime.GOOS)
	}

	cmd := s.execCommand(ctx, name, args...)
	s.applyTrustBundle(cmd)
	if err := cmd.Start(); err != nil {
		s.logger.Error("system browser launch failed",
			"command", name,
			"url", url,
			"error", err,
		)
		return fmt.Errorf("%w: %w", ErrBrowserLaunchFailed, err)
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
		return fmt.Errorf("%w: %w", ErrBrowserLaunchFailed, err)
	}

	return nil
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

	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+bundlePath)
	s.logger.Debug("applied trust bundle to browser command",
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
		return fmt.Errorf("%w: %w", ErrBrowserConfigSave, err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBrowserConfigSave, err)
	}

	if err := os.WriteFile(s.configPath, data, 0o600); err != nil {
		return fmt.Errorf("%w: %w", ErrBrowserConfigSave, err)
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
