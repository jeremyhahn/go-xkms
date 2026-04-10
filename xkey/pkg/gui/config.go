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

package gui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/autofill"
	"github.com/spf13/viper"
)

// Theme constants.
const (
	ThemeLight  = "light"
	ThemeDark   = "dark"
	ThemeSystem = "system"
)

// Default window dimensions.
const (
	DefaultWindowWidth  = 1024
	DefaultWindowHeight = 768
)

// DefaultClipboardTimeout is the default number of seconds before the
// clipboard is cleared after a sensitive copy. 0 = disabled.
const DefaultClipboardTimeout = 30

// Valid server protocols.
var validProtocols = map[string]struct{}{
	"unix": {},
	"rest": {},
	"grpc": {},
	"quic": {},
	"mcp":  {},
}

// GUIConfig holds all configuration for the xKey desktop GUI.
type GUIConfig struct {
	// AutoTray enables automatic system tray minimization on window close.
	AutoTray bool `mapstructure:"auto_tray" json:"auto_tray"`

	// Theme controls the UI color scheme: light, dark, or system.
	Theme string `mapstructure:"theme" json:"theme"`

	// StartMinimized starts the application minimized to the system tray.
	StartMinimized bool `mapstructure:"start_minimized" json:"start_minimized"`

	// Notifications enables desktop notifications for security events.
	Notifications bool `mapstructure:"notifications" json:"notifications"`

	// WindowWidth is the initial window width in pixels.
	WindowWidth int `mapstructure:"window_width" json:"window_width"`

	// WindowHeight is the initial window height in pixels.
	WindowHeight int `mapstructure:"window_height" json:"window_height"`

	// RememberPosition restores the window to its last known position on startup.
	RememberPosition bool `mapstructure:"remember_position" json:"remember_position"`

	// WindowX is the last known horizontal window position.
	WindowX int `mapstructure:"window_x" json:"window_x"`

	// WindowY is the last known vertical window position.
	WindowY int `mapstructure:"window_y" json:"window_y"`

	// ServerAddress is the xkmsd server address (e.g., "localhost:9443").
	ServerAddress string `mapstructure:"server_address" json:"server_address"`

	// ServerProtocol is the transport protocol: unix, rest, grpc, quic, mcp.
	ServerProtocol string `mapstructure:"server_protocol" json:"server_protocol"`

	// ServerTLSEnabled enables TLS for the server connection.
	ServerTLSEnabled bool `mapstructure:"server_tls_enabled" json:"server_tls_enabled"`

	// ServerTLSSkipVerify skips TLS certificate verification (insecure).
	ServerTLSSkipVerify bool `mapstructure:"server_tls_skip_verify" json:"server_tls_skip_verify"`

	// ServerTLSCAFile is the path to a custom CA certificate file.
	ServerTLSCAFile string `mapstructure:"server_tls_ca_file" json:"server_tls_ca_file"`

	// ServerSPKIPin is the hex-encoded SHA-256 SPKI pin for certificate pinning.
	// When set, TLS is enabled automatically and the server certificate is verified
	// against this pin, enabling trust without a CA certificate.
	ServerSPKIPin string `mapstructure:"server_spki_pin" json:"server_spki_pin"`

	// ServerAutoConnect automatically connects to the server on startup.
	ServerAutoConnect bool `mapstructure:"server_auto_connect" json:"server_auto_connect"`

	// AutoUnsealEnabled enables automatic LUKS volume unlock on startup via sealed passphrase.
	AutoUnsealEnabled bool `mapstructure:"auto_unseal_enabled" json:"auto_unseal_enabled"`

	// AutoUnsealBlobID is the sealed blob ID containing the encrypted passphrase.
	AutoUnsealBlobID string `mapstructure:"auto_unseal_blob_id" json:"auto_unseal_blob_id"`

	// AutoUnsealPCRs is the list of TPM PCR indices the sealed blob is bound to.
	AutoUnsealPCRs []int `mapstructure:"auto_unseal_pcrs" json:"auto_unseal_pcrs"`

	// AutoUnsealPCRBank is the PCR hash algorithm bank (e.g., "sha256").
	AutoUnsealPCRBank string `mapstructure:"auto_unseal_pcr_bank" json:"auto_unseal_pcr_bank"`

	// AutoUnsealPolicyType is the policy type used when sealing the auto-unseal passphrase.
	AutoUnsealPolicyType string `mapstructure:"auto_unseal_policy_type" json:"auto_unseal_policy_type"`

	// AutoUnsealPolicyName is the human-readable name of the policy used for auto-unseal.
	AutoUnsealPolicyName string `mapstructure:"auto_unseal_policy_name" json:"auto_unseal_policy_name"`

	// AutoUnsealBackend is the seal backend used for auto-unseal (e.g., "tpm2", "software").
	AutoUnsealBackend string `mapstructure:"auto_unseal_backend" json:"auto_unseal_backend"`

	// FIDO2AuthenticatorEnabled enables the virtual FIDO2 HID authenticator on startup.
	FIDO2AuthenticatorEnabled bool `mapstructure:"fido2_authenticator_enabled" json:"fido2_authenticator_enabled"`

	// ClipboardTimeout is the number of seconds before clipboard is cleared after copy. 0 = disabled.
	ClipboardTimeout int `mapstructure:"clipboard_timeout" json:"clipboard_timeout"`

	// RequireAuth requires PIN authentication for sensitive operations like
	// disabling security toggles or changing critical settings.
	RequireAuth bool `mapstructure:"require_auth" json:"require_auth"`

	// AppAutoLockMinutes auto-locks the entire app after this many minutes of inactivity. 0 = disabled.
	AppAutoLockMinutes int `mapstructure:"app_auto_lock_minutes" json:"app_auto_lock_minutes"`

	// AppLockOnScreenLock locks the app when the OS screen lock activates.
	AppLockOnScreenLock bool `mapstructure:"app_lock_on_screen_lock" json:"app_lock_on_screen_lock"`

	// SetupComplete indicates the first-run setup wizard has been completed.
	SetupComplete bool `mapstructure:"setup_complete" json:"setup_complete"`

	// StorageType is the encrypted storage type: "luks" or "barrier".
	StorageType string `mapstructure:"storage_type" json:"storage_type"`

	// BarrierInitialized indicates whether the barrier has been initialized.
	BarrierInitialized bool `mapstructure:"barrier_initialized" json:"barrier_initialized"`

	// BarrierStrategy is the active barrier strategy ID (e.g., "software", "tpm2").
	BarrierStrategy string `mapstructure:"barrier_strategy" json:"barrier_strategy"`

	// BarrierAutoUnsealBlobID is the sealed blob ID containing the barrier password for auto-unseal.
	BarrierAutoUnsealBlobID string `mapstructure:"barrier_auto_unseal_blob_id" json:"barrier_auto_unseal_blob_id,omitempty"`

	// BarrierAutoUnsealEnabled controls whether the barrier is automatically unsealed
	// on startup (e.g., via TPM PCR policy or sealed password). When false, the user
	// must enter their PIN to unseal the barrier.
	BarrierAutoUnsealEnabled bool `mapstructure:"barrier_auto_unseal_enabled" json:"barrier_auto_unseal_enabled"`

	// SealerBackend is the user-selected default sealing backend (e.g., "tpm2", "software").
	// Empty means auto-select the best available.
	SealerBackend string `mapstructure:"sealer_backend" json:"sealer_backend,omitempty"`

	// PINStrategy records which PIN backend was successfully configured
	// ("tpm2" or "software"). On restart, initPINService uses this to
	// restore the correct backend without re-probing auth.
	PINStrategy string `mapstructure:"pin_strategy" json:"pin_strategy,omitempty"`

	// APIExplorerSandboxPolicy is the iframe sandbox directives for the API Explorer preview.
	// Default: "allow-same-origin allow-scripts allow-forms allow-popups"
	APIExplorerSandboxPolicy string `mapstructure:"api_explorer_sandbox_policy" json:"api_explorer_sandbox_policy"`

	// BrowserExtensionEnabled enables browser extension autofill integration.
	BrowserExtensionEnabled bool `mapstructure:"browser_extension_enabled" json:"browser_extension_enabled"`

	// FIDO2RequireUserPresence controls whether the FIDO2 authenticator requires
	// physical touch (user presence) for operations. When false, the authenticator
	// auto-approves presence checks. Mirrors YubiKey behavior where the RP
	// controls UV requirements and touch is always required.
	// Default: true
	FIDO2RequireUserPresence bool `mapstructure:"fido2_require_user_presence" json:"fido2_require_user_presence"`

	// FIDO2UserIntentCheck shows a confirmation dialog before entering PIN flow
	// during GetAssertion. This allows users with multiple security keys to
	// decline and let the browser fall through to a different device.
	// Default: true
	FIDO2UserIntentCheck bool `mapstructure:"fido2_user_intent_check" json:"fido2_user_intent_check"`

	// FIDO2FirmwareVersion is the firmware version reported in CTAP2 GetInfo
	// (key 0x0E). Encoded as major*10000 + minor*100 + patch.
	// Set at startup from the build-time version string.
	// Default: 0 (not reported)
	FIDO2FirmwareVersion uint32 `mapstructure:"fido2_firmware_version" json:"fido2_firmware_version"`

	// DeveloperTools enables the Developer Tools section in the sidebar
	// (API Explorer, OIDC). Users can toggle this from Settings when allowed.
	DeveloperTools bool `mapstructure:"developer_tools" json:"developer_tools"`

	// AutoFillPolicy configures autofill behavior for the browser extension.
	AutoFillPolicy *autofill.AutoFillPolicy `mapstructure:"autofill_policy" json:"autofill_policy,omitempty"`
}

// DefaultGUIConfig returns a GUIConfig populated with sensible defaults.
func DefaultGUIConfig() *GUIConfig {
	return &GUIConfig{
		AutoTray:                  true,
		Theme:                     ThemeSystem,
		StartMinimized:            false,
		Notifications:             true,
		WindowWidth:               DefaultWindowWidth,
		WindowHeight:              DefaultWindowHeight,
		RememberPosition:          true,
		WindowX:                   0,
		WindowY:                   0,
		ServerProtocol:            "grpc",
		ServerAutoConnect:         false,
		FIDO2AuthenticatorEnabled: true,
		ClipboardTimeout:          DefaultClipboardTimeout,
		RequireAuth:               true,
		AppAutoLockMinutes:        15,
		AppLockOnScreenLock:       true,
		SetupComplete:             false,
		APIExplorerSandboxPolicy:  "allow-same-origin allow-scripts allow-forms allow-popups",
		BrowserExtensionEnabled:   true,
		DeveloperTools:            true,
		FIDO2RequireUserPresence:  true,
		FIDO2UserIntentCheck:      true,
	}
}

// Validate checks whether the configuration values are acceptable.
func (c *GUIConfig) Validate() error {
	if err := ValidateTheme(c.Theme); err != nil {
		return err
	}
	if c.WindowWidth <= 0 {
		c.WindowWidth = DefaultWindowWidth
	}
	if c.WindowHeight <= 0 {
		c.WindowHeight = DefaultWindowHeight
	}
	if c.ServerProtocol != "" {
		if _, ok := validProtocols[c.ServerProtocol]; !ok {
			return ErrInvalidProtocol
		}
	}
	if c.ClipboardTimeout < 0 {
		c.ClipboardTimeout = 0
	}
	if c.AppAutoLockMinutes < 0 {
		c.AppAutoLockMinutes = 0
	}
	return nil
}

// configDir returns the path to the xKey configuration directory.
// This directory is always accessible (outside any LUKS mount point) and
// stores bootstrap config needed before LUKS mount (gui.json, sealed blobs,
// platform policy).
func configDir() (string, error) {
	cfgBase, err := os.UserConfigDir()
	if err != nil {
		// Fallback to ~/.config on Linux.
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return "", fmt.Errorf("%w: %v", ErrConfigLoad, homeErr)
		}
		cfgBase = filepath.Join(home, ".config")
	}
	dir := filepath.Join(cfgBase, "xkey")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("%w: %v", ErrConfigLoad, err)
	}
	return dir, nil
}

// guiConfigPath returns the file path for GUI-specific configuration.
// The config file lives in the OS config directory (~/.config/xkey/ on Linux)
// so it is accessible before any LUKS volume is mounted.
func guiConfigPath() (string, error) {
	cfgDir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfgDir, "gui.json"), nil
}

// legacyGUIConfigPath returns the old config file location (~/.xkey/gui.json)
// used before the config/data directory separation.
func legacyGUIConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrConfigLoad, err)
	}
	return filepath.Join(homeDir, ".xkey", "gui.json"), nil
}

// LoadGUIConfig loads the GUI configuration from viper settings and the
// GUI-specific JSON file. Viper values take precedence, then the JSON file,
// then defaults.
func LoadGUIConfig() (*GUIConfig, error) {
	cfg := DefaultGUIConfig()

	// Attempt to load from the GUI-specific JSON file.
	cfgPath, err := guiConfigPath()
	if err != nil {
		return cfg, nil // Return defaults on path error.
	}

	// Migrate from legacy path (~/.xkey/gui.json) if the new config
	// does not exist yet. This is a non-destructive copy so existing
	// LUKS setups that already have gui.json inside the mount point
	// keep their original file intact.
	if _, statErr := os.Stat(cfgPath); os.IsNotExist(statErr) {
		if legacyPath, legErr := legacyGUIConfigPath(); legErr == nil {
			if legacyData, readErr := os.ReadFile(legacyPath); readErr == nil {
				dir := filepath.Dir(cfgPath)
				if mkErr := os.MkdirAll(dir, 0700); mkErr == nil {
					_ = os.WriteFile(cfgPath, legacyData, 0600)
				}
			}
		}
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No file yet; fall through to viper overlay.
		} else {
			return nil, fmt.Errorf("%w: %v", ErrConfigLoad, err)
		}
	} else {
		if jsonErr := json.Unmarshal(data, cfg); jsonErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrConfigLoad, jsonErr)
		}
	}

	// Overlay viper keys when explicitly set (flags / env override file).
	if viper.IsSet("gui.auto_tray") {
		cfg.AutoTray = viper.GetBool("gui.auto_tray")
	}
	if viper.IsSet("gui.theme") {
		cfg.Theme = viper.GetString("gui.theme")
	}
	if viper.IsSet("gui.start_minimized") {
		cfg.StartMinimized = viper.GetBool("gui.start_minimized")
	}
	if viper.IsSet("gui.notifications") {
		cfg.Notifications = viper.GetBool("gui.notifications")
	}
	if viper.IsSet("gui.window_width") {
		cfg.WindowWidth = viper.GetInt("gui.window_width")
	}
	if viper.IsSet("gui.window_height") {
		cfg.WindowHeight = viper.GetInt("gui.window_height")
	}
	if viper.IsSet("gui.remember_position") {
		cfg.RememberPosition = viper.GetBool("gui.remember_position")
	}
	if viper.IsSet("gui.window_x") {
		cfg.WindowX = viper.GetInt("gui.window_x")
	}
	if viper.IsSet("gui.window_y") {
		cfg.WindowY = viper.GetInt("gui.window_y")
	}
	if viper.IsSet("gui.server_address") {
		cfg.ServerAddress = viper.GetString("gui.server_address")
	}
	if viper.IsSet("gui.server_protocol") {
		cfg.ServerProtocol = viper.GetString("gui.server_protocol")
	}
	if viper.IsSet("gui.server_tls_enabled") {
		cfg.ServerTLSEnabled = viper.GetBool("gui.server_tls_enabled")
	}
	if viper.IsSet("gui.server_tls_skip_verify") {
		cfg.ServerTLSSkipVerify = viper.GetBool("gui.server_tls_skip_verify")
	}
	if viper.IsSet("gui.server_tls_ca_file") {
		cfg.ServerTLSCAFile = viper.GetString("gui.server_tls_ca_file")
	}
	if viper.IsSet("gui.server_spki_pin") {
		cfg.ServerSPKIPin = viper.GetString("gui.server_spki_pin")
	}
	if viper.IsSet("gui.server_auto_connect") {
		cfg.ServerAutoConnect = viper.GetBool("gui.server_auto_connect")
	}
	if viper.IsSet("gui.auto_unseal_enabled") {
		cfg.AutoUnsealEnabled = viper.GetBool("gui.auto_unseal_enabled")
	}
	if viper.IsSet("gui.auto_unseal_blob_id") {
		cfg.AutoUnsealBlobID = viper.GetString("gui.auto_unseal_blob_id")
	}
	if viper.IsSet("gui.auto_unseal_pcr_bank") {
		cfg.AutoUnsealPCRBank = viper.GetString("gui.auto_unseal_pcr_bank")
	}
	if viper.IsSet("gui.auto_unseal_policy_type") {
		cfg.AutoUnsealPolicyType = viper.GetString("gui.auto_unseal_policy_type")
	}
	if viper.IsSet("gui.auto_unseal_policy_name") {
		cfg.AutoUnsealPolicyName = viper.GetString("gui.auto_unseal_policy_name")
	}
	if viper.IsSet("gui.auto_unseal_backend") {
		cfg.AutoUnsealBackend = viper.GetString("gui.auto_unseal_backend")
	}
	if viper.IsSet("gui.fido2_authenticator_enabled") {
		cfg.FIDO2AuthenticatorEnabled = viper.GetBool("gui.fido2_authenticator_enabled")
	}
	if viper.IsSet("gui.clipboard_timeout") {
		cfg.ClipboardTimeout = viper.GetInt("gui.clipboard_timeout")
	}
	if viper.IsSet("gui.require_auth") {
		cfg.RequireAuth = viper.GetBool("gui.require_auth")
	}
	if viper.IsSet("gui.app_auto_lock_minutes") {
		cfg.AppAutoLockMinutes = viper.GetInt("gui.app_auto_lock_minutes")
	}
	if viper.IsSet("gui.app_lock_on_screen_lock") {
		cfg.AppLockOnScreenLock = viper.GetBool("gui.app_lock_on_screen_lock")
	}
	if viper.IsSet("gui.setup_complete") {
		cfg.SetupComplete = viper.GetBool("gui.setup_complete")
	}
	if viper.IsSet("gui.barrier_auto_unseal_blob_id") {
		cfg.BarrierAutoUnsealBlobID = viper.GetString("gui.barrier_auto_unseal_blob_id")
	}
	if viper.IsSet("gui.barrier_auto_unseal_enabled") {
		cfg.BarrierAutoUnsealEnabled = viper.GetBool("gui.barrier_auto_unseal_enabled")
	}
	if viper.IsSet("gui.sealer_backend") {
		cfg.SealerBackend = viper.GetString("gui.sealer_backend")
	}
	if viper.IsSet("gui.pin_strategy") {
		cfg.PINStrategy = viper.GetString("gui.pin_strategy")
	}
	if viper.IsSet("gui.api_explorer_sandbox_policy") {
		cfg.APIExplorerSandboxPolicy = viper.GetString("gui.api_explorer_sandbox_policy")
	}
	if viper.IsSet("gui.developer_tools") {
		cfg.DeveloperTools = viper.GetBool("gui.developer_tools")
	}
	if viper.IsSet("gui.fido2_require_user_presence") {
		cfg.FIDO2RequireUserPresence = viper.GetBool("gui.fido2_require_user_presence")
	}
	if viper.IsSet("gui.fido2_user_intent_check") {
		cfg.FIDO2UserIntentCheck = viper.GetBool("gui.fido2_user_intent_check")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// SaveGUIConfig persists the GUI configuration to the JSON file.
func SaveGUIConfig(cfg *GUIConfig) error {
	if cfg == nil {
		return fmt.Errorf("%w: nil config", ErrConfigSave)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	cfgPath, err := guiConfigPath()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfigSave, err)
	}

	dir := filepath.Dir(cfgPath)
	if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
		return fmt.Errorf("%w: %v", ErrConfigSave, mkErr)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfigSave, err)
	}

	tmpPath := cfgPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrConfigSave, err)
	}

	if err := os.Rename(tmpPath, cfgPath); err != nil {
		return fmt.Errorf("%w: %v", ErrConfigSave, err)
	}

	return nil
}
