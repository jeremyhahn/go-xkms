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

// Package services provides Wails-bound service objects that expose
// xKey functionality to the Svelte frontend.
package services

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// Version is the xKey application version. It is set at build time.
var Version = "0.1.0-dev"

// AppStatus describes the current application state.
type AppStatus struct {
	Version          string `json:"version"`
	Uptime           string `json:"uptime"`
	PhoneConnected   bool   `json:"phone_connected"`
	PhoneDeviceName  string `json:"phone_device_name,omitempty"`
	KeyCount         int    `json:"key_count"`
	BridgeRunning    bool   `json:"bridge_running"`
	Platform         string `json:"platform"`
	GoVersion        string `json:"go_version"`
	ServerConnected  bool   `json:"server_connected"`
	ServerAddress    string `json:"server_address,omitempty"`
	RemoteKeyCount   int    `json:"remote_key_count"`
	OATHAccountCount int    `json:"oath_account_count"`
	FIDO2CredCount   int    `json:"fido2_cred_count"`
	PIVCertCount     int    `json:"piv_cert_count"`
	TPMAvailable     bool   `json:"tpm_available"`
	TPMDeviceExists  bool   `json:"tpm_device_exists"`
	TPMProvisioned   bool   `json:"tpm_provisioned"`
	StorageEncrypted bool   `json:"storage_encrypted"`
	StorageMounted   bool   `json:"storage_mounted"`
	Mode             string `json:"mode"`
	Sealed           bool   `json:"sealed"`
	PINConfigured    bool   `json:"pin_configured"`
	PINLocked        bool   `json:"pin_locked"`
	PINStrategy      string `json:"pin_strategy"`
	SealStrategy     string `json:"seal_strategy"`
	HardwareBacked   bool   `json:"hardware_backed"`
}

// IdentityConfig stores default X.509 subject fields used as defaults
// when generating certificates, CSRs, and PIV credentials. Configured
// once in Settings → Identity and reused across all cert operations.
type IdentityConfig struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Country            string `json:"country"`
	Province           string `json:"province"`
	Locality           string `json:"locality"`
}

// GUIConfigData mirrors the GUI-editable subset of gui.GUIConfig so the
// services package does not import the gui package (avoiding import
// cycles). The gui.App is responsible for creating this from gui.GUIConfig
// (see configToData) and for merging it back (see applyDataToConfig).
//
// Deliberately excluded fields -- gui.GUIConfig fields with no mapping here
// because they are not editable from the GUI. applyDataToConfig merges a
// GUIConfigData onto a copy of the existing gui.GUIConfig, so any field
// missing from this struct is always preserved unchanged rather than
// wiped by an unrelated settings save (go-xkms#1122):
//
//   - ServerSPKIPin: the hex SHA-256 SPKI pin for certificate pinning. Set
//     only via CLI flag/env (gui.server_spki_pin) or by editing gui.json
//     directly; there is no Settings UI control for it.
//   - FIDO2FirmwareVersion: the CTAP2 firmware version reported in
//     GetInfo. Set once at startup from the build-time version string
//     (gui.FirmwareVersion / ParseFirmwareVersion); not user-configurable.
type GUIConfigData struct {
	AutoTray                  bool                 `json:"auto_tray"`
	Theme                     string               `json:"theme"`
	StartMinimized            bool                 `json:"start_minimized"`
	Notifications             bool                 `json:"notifications"`
	WindowWidth               int                  `json:"window_width"`
	WindowHeight              int                  `json:"window_height"`
	RememberPosition          bool                 `json:"remember_position"`
	WindowX                   int                  `json:"window_x"`
	WindowY                   int                  `json:"window_y"`
	ServerAddress             string               `json:"server_address"`
	ServerProtocol            string               `json:"server_protocol"`
	ServerTLSEnabled          bool                 `json:"server_tls_enabled"`
	ServerTLSSkipVerify       bool                 `json:"server_tls_skip_verify"`
	ServerTLSCAFile           string               `json:"server_tls_ca_file"`
	ServerAutoConnect         bool                 `json:"server_auto_connect"`
	AutoUnsealEnabled         bool                 `json:"auto_unseal_enabled"`
	AutoUnsealBlobID          string               `json:"auto_unseal_blob_id"`
	AutoUnsealTPMPolicy       string               `json:"auto_unseal_tpm_policy"`
	AutoUnsealBackend         string               `json:"auto_unseal_backend"`
	FIDO2AuthenticatorEnabled bool                 `json:"fido2_authenticator_enabled"`
	ClipboardTimeout          int                  `json:"clipboard_timeout"`
	RequireAuth               bool                 `json:"require_auth"`
	SetupComplete             bool                 `json:"setup_complete"`
	StorageType               string               `json:"storage_type"`
	BarrierInitialized        bool                 `json:"barrier_initialized"`
	BarrierStrategy           string               `json:"barrier_strategy"`
	BarrierAutoUnsealEnabled  bool                 `json:"barrier_auto_unseal_enabled"`
	AppAutoLockMinutes        int                  `json:"app_auto_lock_minutes"`
	AppLockOnScreenLock       bool                 `json:"app_lock_on_screen_lock"`
	SealerBackend             string               `json:"sealer_backend,omitempty"`
	APIExplorerSandboxPolicy  string               `json:"api_explorer_sandbox_policy"`
	BrowserExtensionEnabled   bool                 `json:"browser_extension_enabled"`
	DeveloperTools            bool                 `json:"developer_tools"`
	FIDO2RequireUserPresence  bool                 `json:"fido2_require_user_presence"`
	FIDO2UserIntentCheck      bool                 `json:"fido2_user_intent_check"`
	AutoFillPolicy            *xkms.AutoFillPolicy `json:"autofill_policy,omitempty"`
	Identity                  IdentityConfig       `json:"identity"`
}

// ConfigUpdater is called by AppService.UpdateConfig to persist changes.
// It is set by the gui.App layer to break the import cycle.
type ConfigUpdater func(cfg *GUIConfigData) error

// ThemeValidator is called to validate a theme string.
type ThemeValidator func(theme string) error

// KeyCountFunc returns the total number of managed keys.
type KeyCountFunc func() int

// BridgeStatusFunc returns whether the FIDO2 bridge is running.
type BridgeStatusFunc func() bool

// ServerConnectedFunc returns whether the server is connected.
type ServerConnectedFunc func() bool

// ServerAddressFunc returns the current server address.
type ServerAddressFunc func() string

// RemoteKeyCountFunc returns the total number of remote keys.
type RemoteKeyCountFunc func() int

// OATHCountFunc returns the number of OATH accounts.
type OATHCountFunc func() int

// FIDO2CountFunc returns the number of FIDO2 credentials.
type FIDO2CountFunc func() int

// PIVCertCountFunc returns the number of loaded PIV certificates.
type PIVCertCountFunc func() int

// TPMStatusFunc returns TPM device existence, availability, and provisioned state.
type TPMStatusFunc func() (deviceExists bool, available bool, provisioned bool)

// StorageStatusFunc returns encrypted and mounted state.
type StorageStatusFunc func() (encrypted bool, mounted bool)

// WindowHideFunc hides the main application window.
type WindowHideFunc func()

// FIDO2ToggleFunc is called to toggle the FIDO2 authenticator on/off.
type FIDO2ToggleFunc func(enabled bool) error

// SealStatusFunc returns the current seal status.
// sealed indicates whether sealed data exists, strategy is the seal
// strategy name (e.g. "tpm2", "passphrase"), and hardwareBacked indicates
// whether the seal strategy uses hardware-backed keys.
type SealStatusFunc func() (sealed bool, strategy string, hardwareBacked bool)

// PINStatusFunc returns the current PIN configuration status.
// configured indicates whether a PIN has been set, locked indicates
// whether the PIN is currently locked out, and strategy is the PIN
// strategy name (e.g. "passphrase", "tpm2", "pkcs11").
type PINStatusFunc func() (configured bool, locked bool, strategy string)

// PhoneStatusFunc returns the current phone connection status.
// connected indicates whether a phone is currently connected, and
// deviceName is the name of the connected device (empty when disconnected).
type PhoneStatusFunc func() (connected bool, deviceName string)

// AppService manages application-level state and configuration.
// It is bound to the Wails runtime so every exported method is
// callable from the frontend.
type AppService struct {
	ctx               context.Context
	config            atomic.Pointer[GUIConfigData]
	startTime         time.Time
	configUpdater     ConfigUpdater
	themeValidator    ThemeValidator
	keyCountFunc      KeyCountFunc
	bridgeStatusFunc  BridgeStatusFunc
	serverConnectedFn ServerConnectedFunc
	serverAddressFn   ServerAddressFunc
	remoteKeyCountFn  RemoteKeyCountFunc
	oathCountFn       OATHCountFunc
	fido2CountFn      FIDO2CountFunc
	pivCertCountFn    PIVCertCountFunc
	tpmStatusFn       TPMStatusFunc
	storageStatusFn   StorageStatusFunc
	windowHideFunc    WindowHideFunc
	fido2ToggleFn     FIDO2ToggleFunc
	sealStatusFn      SealStatusFunc
	pinStatusFn       PINStatusFunc
	phoneStatusFn     PhoneStatusFunc
	auditLog          atomic.Pointer[audit.Logger]

	// policy is the enterprise policy section whose UserCanConfigureTheme,
	// UserCanToggleDevTools, DeveloperToolsEnabled, UserCanConfigureAutoUnseal
	// and AllowAutoUnseal fields gate SetTheme, SetDeveloperTools and
	// ToggleBarrierAutoUnseal. nil in personal mode, where none of these
	// operations is policy-gated. See SetPolicy.
	policy atomic.Pointer[config.PolicySection]
}

// NewAppService creates a new AppService with the provided configuration data.
func NewAppService(config *GUIConfigData) *AppService {
	svc := &AppService{
		startTime: time.Now(),
	}
	if config == nil {
		config = &GUIConfigData{
			Theme:            "system",
			WindowWidth:      1024,
			WindowHeight:     768,
			Notifications:    true,
			AutoTray:         true,
			ClipboardTimeout: 30,
			RequireAuth:      true,
		}
	}
	svc.config.Store(config)
	return svc
}

// SetConfigUpdater sets the callback used to persist configuration changes.
func (s *AppService) SetConfigUpdater(fn ConfigUpdater) {
	s.configUpdater = fn
}

// SetThemeValidator sets the callback used to validate theme strings.
func (s *AppService) SetThemeValidator(fn ThemeValidator) {
	s.themeValidator = fn
}

// SetKeyCountFunc sets the callback that returns the total managed key count.
func (s *AppService) SetKeyCountFunc(fn KeyCountFunc) {
	s.keyCountFunc = fn
}

// SetBridgeStatusFunc sets the callback that returns FIDO2 bridge status.
func (s *AppService) SetBridgeStatusFunc(fn BridgeStatusFunc) {
	s.bridgeStatusFunc = fn
}

// SetServerConnectedFunc sets the callback that returns server connection state.
func (s *AppService) SetServerConnectedFunc(fn ServerConnectedFunc) {
	s.serverConnectedFn = fn
}

// SetServerAddressFunc sets the callback that returns the server address.
func (s *AppService) SetServerAddressFunc(fn ServerAddressFunc) {
	s.serverAddressFn = fn
}

// SetRemoteKeyCountFunc sets the callback that returns the remote key count.
func (s *AppService) SetRemoteKeyCountFunc(fn RemoteKeyCountFunc) {
	s.remoteKeyCountFn = fn
}

// SetOATHCountFunc sets the callback that returns the OATH account count.
func (s *AppService) SetOATHCountFunc(fn OATHCountFunc) {
	s.oathCountFn = fn
}

// SetFIDO2CountFunc sets the callback that returns the FIDO2 credential count.
func (s *AppService) SetFIDO2CountFunc(fn FIDO2CountFunc) {
	s.fido2CountFn = fn
}

// SetPIVCertCountFunc sets the callback that returns the PIV certificate count.
func (s *AppService) SetPIVCertCountFunc(fn PIVCertCountFunc) {
	s.pivCertCountFn = fn
}

// SetTPMStatusFunc sets the callback that returns TPM availability and provisioned state.
func (s *AppService) SetTPMStatusFunc(fn TPMStatusFunc) {
	s.tpmStatusFn = fn
}

// SetStorageStatusFunc sets the callback that returns storage encrypted and mounted state.
func (s *AppService) SetStorageStatusFunc(fn StorageStatusFunc) {
	s.storageStatusFn = fn
}

// SetWindowHideFunc sets the callback used to hide the main application window.
func (s *AppService) SetWindowHideFunc(fn WindowHideFunc) {
	s.windowHideFunc = fn
}

// SetFIDO2ToggleFunc sets the callback used to toggle the FIDO2 authenticator.
func (s *AppService) SetFIDO2ToggleFunc(fn FIDO2ToggleFunc) {
	s.fido2ToggleFn = fn
}

// SetSealStatusFunc sets the callback that returns seal status information.
func (s *AppService) SetSealStatusFunc(fn SealStatusFunc) {
	s.sealStatusFn = fn
}

// SetPINStatusFunc sets the callback that returns PIN status information.
func (s *AppService) SetPINStatusFunc(fn PINStatusFunc) {
	s.pinStatusFn = fn
}

// SetPhoneStatusFunc sets the callback that returns phone connection status.
func (s *AppService) SetPhoneStatusFunc(fn PhoneStatusFunc) {
	s.phoneStatusFn = fn
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *AppService) SetAuditLogger(l audit.Logger) {
	s.auditLog.Store(&l)
}

// SetPolicy installs the enterprise policy section that gates SetTheme,
// SetDeveloperTools and ToggleBarrierAutoUnseal. The GUI calls this with
// config.DefaultPolicy() before SO login and the verified section
// afterward; see startupEnterprisePolicy and applyVerifiedEnterprisePolicy
// in pkg/gui/enterprise_policy.go. A nil policy (personal mode) leaves
// every one of these operations ungated.
func (s *AppService) SetPolicy(pol *config.PolicySection) {
	s.policy.Store(pol)
}

// denyPolicy logs a policy denial and returns the typed refusal. The
// request is refused either way, but OpPolicyDenied is SeveritySecurity: if
// the audit write itself fails, that failure is joined onto the denial so
// the caller sees both — the operation was denied, and that denial may not
// be durably recorded.
func (s *AppService) denyPolicy(field, operation string) error {
	err := &PolicyDeniedError{Field: field}
	if auditErr := s.logConfigEvent(audit.OpPolicyDenied, false, err, map[string]any{"operation": operation}); auditErr != nil {
		return errors.Join(err, auditErr)
	}
	return err
}

// logConfigEvent logs a configuration-related audit event. Callers must
// propagate a non-nil return: op.Severity() (audit package) decides
// whether that failure is required to fail the caller.
func (s *AppService) logConfigEvent(op audit.OperationType, success bool, err error, details map[string]any) error {
	p := s.auditLog.Load()
	if p == nil {
		return nil
	}
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	return (*p).Log(audit.Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *AppService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// GetStatus returns the current application status.
func (s *AppService) GetStatus() *AppStatus {
	uptime := time.Since(s.startTime).Truncate(time.Second)
	keyCount := 0
	if s.keyCountFunc != nil {
		keyCount = s.keyCountFunc()
	}
	bridgeRunning := false
	if s.bridgeStatusFunc != nil {
		bridgeRunning = s.bridgeStatusFunc()
	}
	serverConnected := false
	if s.serverConnectedFn != nil {
		serverConnected = s.serverConnectedFn()
	}
	serverAddress := ""
	if s.serverAddressFn != nil {
		serverAddress = s.serverAddressFn()
	}
	remoteKeyCount := 0
	if s.remoteKeyCountFn != nil {
		remoteKeyCount = s.remoteKeyCountFn()
	}

	oathAccountCount := 0
	if s.oathCountFn != nil {
		oathAccountCount = s.oathCountFn()
	}
	fido2CredCount := 0
	if s.fido2CountFn != nil {
		fido2CredCount = s.fido2CountFn()
	}
	pivCertCount := 0
	if s.pivCertCountFn != nil {
		pivCertCount = s.pivCertCountFn()
	}

	var tpmDeviceExists, tpmAvailable, tpmProvisioned bool
	if s.tpmStatusFn != nil {
		tpmDeviceExists, tpmAvailable, tpmProvisioned = s.tpmStatusFn()
	}

	var storageEncrypted, storageMounted bool
	if s.storageStatusFn != nil {
		storageEncrypted, storageMounted = s.storageStatusFn()
	}

	var sealed, hardwareBacked bool
	var sealStrategy string
	if s.sealStatusFn != nil {
		sealed, sealStrategy, hardwareBacked = s.sealStatusFn()
	}

	var pinConfigured, pinLocked bool
	var pinStrategy string
	if s.pinStatusFn != nil {
		pinConfigured, pinLocked, pinStrategy = s.pinStatusFn()
	}

	var phoneConnected bool
	var phoneDeviceName string
	if s.phoneStatusFn != nil {
		phoneConnected, phoneDeviceName = s.phoneStatusFn()
	}

	mode := "standalone"
	if serverConnected {
		mode = "xkmsd"
	}

	return &AppStatus{
		Version:          Version,
		Uptime:           uptime.String(),
		PhoneConnected:   phoneConnected,
		PhoneDeviceName:  phoneDeviceName,
		KeyCount:         keyCount,
		BridgeRunning:    bridgeRunning,
		Platform:         runtime.GOOS + "/" + runtime.GOARCH,
		GoVersion:        runtime.Version(),
		ServerConnected:  serverConnected,
		ServerAddress:    serverAddress,
		RemoteKeyCount:   remoteKeyCount,
		OATHAccountCount: oathAccountCount,
		FIDO2CredCount:   fido2CredCount,
		PIVCertCount:     pivCertCount,
		TPMAvailable:     tpmAvailable,
		TPMDeviceExists:  tpmDeviceExists,
		TPMProvisioned:   tpmProvisioned,
		StorageEncrypted: storageEncrypted,
		StorageMounted:   storageMounted,
		Mode:             mode,
		Sealed:           sealed,
		PINConfigured:    pinConfigured,
		PINLocked:        pinLocked,
		PINStrategy:      pinStrategy,
		SealStrategy:     sealStrategy,
		HardwareBacked:   hardwareBacked,
	}
}

// GetConfig returns the current GUI configuration data.
func (s *AppService) GetConfig() *GUIConfigData {
	return s.config.Load()
}

// UpdateConfig replaces the GUI configuration and persists it via
// the registered ConfigUpdater callback.
func (s *AppService) UpdateConfig(cfg *GUIConfigData) error {
	if cfg == nil {
		return ErrAppConfigNil
	}
	if s.configUpdater != nil {
		if err := s.configUpdater(cfg); err != nil {
			if auditErr := s.logConfigEvent(audit.OpConfigUpdated, false, err, nil); auditErr != nil {
				return auditErr
			}
			return err
		}
	}
	old := s.config.Load()
	s.config.Store(cfg)
	return s.logConfigEvent(audit.OpConfigUpdated, true, nil, map[string]any{
		"changed_fields": configChangedFields(old, cfg),
	})
}

// configChangedFields compares two config snapshots and returns a list of
// field names that differ. Only field names are returned, never values.
func configChangedFields(old, new *GUIConfigData) []string {
	if old == nil || new == nil {
		return nil
	}
	var fields []string
	if old.Theme != new.Theme {
		fields = append(fields, "theme")
	}
	if old.AutoTray != new.AutoTray {
		fields = append(fields, "auto_tray")
	}
	if old.StartMinimized != new.StartMinimized {
		fields = append(fields, "start_minimized")
	}
	if old.Notifications != new.Notifications {
		fields = append(fields, "notifications")
	}
	if old.ServerAddress != new.ServerAddress {
		fields = append(fields, "server_address")
	}
	if old.ServerProtocol != new.ServerProtocol {
		fields = append(fields, "server_protocol")
	}
	if old.ServerTLSEnabled != new.ServerTLSEnabled {
		fields = append(fields, "server_tls_enabled")
	}
	if old.ServerAutoConnect != new.ServerAutoConnect {
		fields = append(fields, "server_auto_connect")
	}
	if old.AutoUnsealEnabled != new.AutoUnsealEnabled {
		fields = append(fields, "auto_unseal_enabled")
	}
	if old.FIDO2AuthenticatorEnabled != new.FIDO2AuthenticatorEnabled {
		fields = append(fields, "fido2_authenticator_enabled")
	}
	if old.ClipboardTimeout != new.ClipboardTimeout {
		fields = append(fields, "clipboard_timeout")
	}
	if old.RequireAuth != new.RequireAuth {
		fields = append(fields, "require_auth")
	}
	if old.SetupComplete != new.SetupComplete {
		fields = append(fields, "setup_complete")
	}
	if old.StorageType != new.StorageType {
		fields = append(fields, "storage_type")
	}
	if old.BarrierStrategy != new.BarrierStrategy {
		fields = append(fields, "barrier_strategy")
	}
	if old.BarrierAutoUnsealEnabled != new.BarrierAutoUnsealEnabled {
		fields = append(fields, "barrier_auto_unseal_enabled")
	}
	if old.AppAutoLockMinutes != new.AppAutoLockMinutes {
		fields = append(fields, "app_auto_lock_minutes")
	}
	if old.AppLockOnScreenLock != new.AppLockOnScreenLock {
		fields = append(fields, "app_lock_on_screen_lock")
	}
	if old.BrowserExtensionEnabled != new.BrowserExtensionEnabled {
		fields = append(fields, "browser_extension_enabled")
	}
	if old.DeveloperTools != new.DeveloperTools {
		fields = append(fields, "developer_tools")
	}
	if old.Identity != new.Identity {
		fields = append(fields, "identity")
	}
	return fields
}

// GetTheme returns the current theme name.
func (s *AppService) GetTheme() string {
	return s.config.Load().Theme
}

// SetTheme updates the theme and persists the configuration. Returns a
// *PolicyDeniedError if enterprise policy's UserCanConfigureTheme is false.
func (s *AppService) SetTheme(theme string) error {
	if pol := s.policy.Load(); pol != nil && !pol.UserCanConfigureTheme {
		return s.denyPolicy("user_can_configure_theme", "set_theme")
	}
	if s.themeValidator != nil {
		if err := s.themeValidator(theme); err != nil {
			return err
		}
	}
	cfg := s.config.Load()
	updated := *cfg
	updated.Theme = theme
	return s.UpdateConfig(&updated)
}

// ToggleBarrierAutoUnseal enables or disables automatic barrier unsealing
// on startup. When enabled, the barrier is auto-unsealed via TPM PCR
// policy or sealed password. When disabled, the user must enter their PIN.
//
// Returns a *PolicyDeniedError if enterprise policy's
// UserCanConfigureAutoUnseal is false, or, when enabling, if AllowAutoUnseal
// is false -- the enterprise has not opted the deployment into the feature
// at all, independent of whether this user could otherwise configure it.
func (s *AppService) ToggleBarrierAutoUnseal(enabled bool) error {
	if pol := s.policy.Load(); pol != nil {
		if !pol.UserCanConfigureAutoUnseal {
			return s.denyPolicy("user_can_configure_auto_unseal", "toggle_barrier_auto_unseal")
		}
		if enabled && !pol.AllowAutoUnseal {
			return s.denyPolicy("allow_auto_unseal", "toggle_barrier_auto_unseal")
		}
	}
	cfg := s.config.Load()
	updated := *cfg
	updated.BarrierAutoUnsealEnabled = enabled
	return s.UpdateConfig(&updated)
}

// GetDeveloperTools returns whether the Developer Tools sidebar section is enabled.
func (s *AppService) GetDeveloperTools() bool {
	return s.config.Load().DeveloperTools
}

// SetDeveloperTools enables or disables the Developer Tools sidebar section
// and persists the configuration.
//
// Returns a *PolicyDeniedError if enterprise policy's UserCanToggleDevTools
// is false, or, when enabling, if DeveloperToolsEnabled is false -- the
// enterprise has disabled the subsystem entirely, independent of whether
// this user could otherwise toggle it.
func (s *AppService) SetDeveloperTools(enabled bool) error {
	if pol := s.policy.Load(); pol != nil {
		if !pol.UserCanToggleDevTools {
			return s.denyPolicy("user_can_toggle_dev_tools", "set_developer_tools")
		}
		if enabled && !pol.DeveloperToolsEnabled {
			return s.denyPolicy("developer_tools_enabled", "set_developer_tools")
		}
	}
	cfg := s.config.Load()
	updated := *cfg
	updated.DeveloperTools = enabled
	return s.UpdateConfig(&updated)
}

// GetIdentity returns the current identity configuration with default
// X.509 subject fields.
func (s *AppService) GetIdentity() IdentityConfig {
	cfg := s.config.Load()
	if cfg == nil {
		return IdentityConfig{}
	}
	return cfg.Identity
}

// UpdateIdentity updates the identity configuration and persists it.
func (s *AppService) UpdateIdentity(identity IdentityConfig) error {
	cfg := s.GetConfig()
	if cfg == nil {
		return ErrAppConfigNil
	}
	cfg.Identity = identity
	return s.UpdateConfig(cfg)
}

// MinimizeToTray hides the main application window to the system tray.
func (s *AppService) MinimizeToTray() {
	if s.windowHideFunc != nil {
		s.windowHideFunc()
	}
}

// ToggleFIDO2Authenticator enables or disables the virtual FIDO2 authenticator.
func (s *AppService) ToggleFIDO2Authenticator(enabled bool) error {
	if s.fido2ToggleFn == nil {
		return ErrAppFIDO2ToggleUnavailable
	}
	return s.fido2ToggleFn(enabled)
}

// SaveTextFile opens a native save dialog and writes the provided content
// to the chosen file path. Returns the saved file path, or an empty string
// if the user cancelled the dialog.
func (s *AppService) SaveTextFile(suggestedName string, content string) (string, error) {
	filePath, err := wailsruntime.SaveFileDialog(s.ctx, wailsruntime.SaveDialogOptions{
		DefaultFilename: suggestedName,
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "JSON Files", Pattern: "*.json"},
			{DisplayName: "Text Files", Pattern: "*.txt"},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
	if err != nil {
		return "", err
	}
	if filePath == "" {
		return "", nil // user cancelled
	}
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		return "", err
	}
	return filePath, nil
}

// SavePEMFile opens a native save dialog filtered for PEM-encoded artefacts
// (certificates, public keys, CSRs) and writes the provided content to the
// chosen file path. Returns the saved file path, or an empty string if the
// user cancelled the dialog.
func (s *AppService) SavePEMFile(suggestedName string, content string) (string, error) {
	filePath, err := wailsruntime.SaveFileDialog(s.ctx, wailsruntime.SaveDialogOptions{
		DefaultFilename: suggestedName,
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "PEM Files", Pattern: "*.pem"},
			{DisplayName: "Certificate Files", Pattern: "*.crt;*.cer"},
			{DisplayName: "CSR Files", Pattern: "*.csr"},
			{DisplayName: "Public Key Files", Pattern: "*.pub"},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
	if err != nil {
		return "", err
	}
	if filePath == "" {
		return "", nil // user cancelled
	}
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		return "", err
	}
	return filePath, nil
}
