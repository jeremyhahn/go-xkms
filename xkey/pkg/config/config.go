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

// Package config provides the unified configuration for xKey CLI and GUI.
package config

import (
	"fmt"
	"net"
	"strconv"
)

// Config is the top-level unified configuration for the xKey CLI and GUI
// applications. It merges all subsystem settings into a single struct that
// can be serialized to YAML/JSON and loaded via Viper.
type Config struct {
	Policy             PolicySection            `yaml:"policy" json:"policy" mapstructure:"policy"`
	Backend            BackendConfig            `yaml:"backend" json:"backend" mapstructure:"backend"`
	Backends           BackendsConfig           `yaml:"backends,omitempty" json:"backends,omitempty" mapstructure:"backends"`
	FIDO2              FIDO2Config              `yaml:"fido2" json:"fido2" mapstructure:"fido2"`
	OATH               OATHConfig               `yaml:"oath" json:"oath" mapstructure:"oath"`
	Phone              PhoneConfig              `yaml:"phone" json:"phone" mapstructure:"phone"`
	XKMSD              XKMSDConfig              `yaml:"xkmsd" json:"xkmsd" mapstructure:"xkmsd"`
	OIDC               OIDCConfig               `yaml:"oidc" json:"oidc" mapstructure:"oidc"`
	Agent              AgentConfig              `yaml:"agent" json:"agent" mapstructure:"agent"`
	TPM                TPMConfig                `yaml:"tpm" json:"tpm" mapstructure:"tpm"`
	PasswordProtection PasswordProtectionConfig `yaml:"password_protection" json:"password_protection" mapstructure:"password_protection"`
	Trust              TrustConfig              `yaml:"trust" json:"trust" mapstructure:"trust"`
	Attestation        AttestationConfig        `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
	Log                LogConfig                `yaml:"log" json:"log" mapstructure:"log"`
	GUI                GUISection               `yaml:"gui" json:"gui" mapstructure:"gui"`
	State              StateSection             `yaml:"state" json:"state" mapstructure:"state"`
}

// BackendConfig holds the cryptographic backend selection and TPM2
// subsystem parameters.
type BackendConfig struct {
	Default string        `yaml:"default" json:"default" mapstructure:"default"`
	TPM2    TPM2SubConfig `yaml:"tpm2" json:"tpm2" mapstructure:"tpm2"`
}

// TPM2SubConfig holds TPM2-specific backend parameters.
type TPM2SubConfig struct {
	Device    string `yaml:"device" json:"device" mapstructure:"device"`
	Simulator bool   `yaml:"simulator" json:"simulator" mapstructure:"simulator"`
	Hash      string `yaml:"hash" json:"hash" mapstructure:"hash"`
}

// FIDO2Config holds settings for the FIDO2/WebAuthn authenticator.
type FIDO2Config struct {
	Storage         string          `yaml:"storage" json:"storage" mapstructure:"storage"`
	StoragePath     string          `yaml:"storage_path" json:"storage_path" mapstructure:"storage_path"`
	Attestation     string          `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
	DeviceName      string          `yaml:"device_name" json:"device_name" mapstructure:"device_name"`
	RPIDHash        bool            `yaml:"rpid_hash" json:"rpid_hash" mapstructure:"rpid_hash"`
	AlwaysUV        bool            `yaml:"always_uv" json:"always_uv" mapstructure:"always_uv"`
	ResidentKey     bool            `yaml:"resident_key" json:"resident_key" mapstructure:"resident_key"`
	ConformanceMode bool            `yaml:"conformance_mode" json:"conformance_mode" mapstructure:"conformance_mode"`
	Extensions      map[string]bool `yaml:"extensions" json:"extensions" mapstructure:"extensions"`
}

// OATHConfig holds settings for the OATH TOTP/HOTP module.
type OATHConfig struct {
	Storage     string `yaml:"storage" json:"storage" mapstructure:"storage"`
	StoragePath string `yaml:"storage_path" json:"storage_path" mapstructure:"storage_path"`
	Algorithm   string `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Digits      int    `yaml:"digits" json:"digits" mapstructure:"digits"`
	Period      int    `yaml:"period" json:"period" mapstructure:"period"`
}

// PhoneConfig holds settings for the phone-as-a-token backend.
type PhoneConfig struct {
	Backend           string `yaml:"backend" json:"backend" mapstructure:"backend"`
	ServerAddress     string `yaml:"server_address" json:"server_address" mapstructure:"server_address"`
	ServerProtocol    string `yaml:"server_protocol" json:"server_protocol" mapstructure:"server_protocol"`
	ServerTLSEnabled  bool   `yaml:"server_tls_enabled" json:"server_tls_enabled" mapstructure:"server_tls_enabled"`
	DeviceFilter      string `yaml:"device_filter" json:"device_filter" mapstructure:"device_filter"`
	AttestationPolicy string `yaml:"attestation_policy" json:"attestation_policy" mapstructure:"attestation_policy"`

	// RelayListenAddress is the host:port `xkey device relay` binds for the
	// TCP pairing relay; a bare ":port" binds every interface. It is the
	// defaults-layer value `--listen` overrides.
	RelayListenAddress string `yaml:"relay_listen_address" json:"relay_listen_address" mapstructure:"relay_listen_address"`

	// TPMEnrollment offers TCG-CSR-IDEVID device enrollment from this host's
	// TPM over the phone bridge, so a paired phone acting as a Certificate
	// Authority can enroll this machine's device identity. Off by default:
	// enrollment exposes the EK certificate and runs TPM2_ActivateCredential
	// on the phone's behalf. The TPM is opened from tpm.device.
	TPMEnrollment bool `yaml:"tpm_enrollment" json:"tpm_enrollment" mapstructure:"tpm_enrollment"`
}

// XKMSDConfig holds connection settings for the xkmsd server.
type XKMSDConfig struct {
	Address       string `yaml:"address" json:"address" mapstructure:"address"`
	Protocol      string `yaml:"protocol" json:"protocol" mapstructure:"protocol"`
	TLSEnabled    bool   `yaml:"tls_enabled" json:"tls_enabled" mapstructure:"tls_enabled"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify" json:"tls_skip_verify" mapstructure:"tls_skip_verify"`
	TLSCAFile     string `yaml:"tls_ca_file" json:"tls_ca_file" mapstructure:"tls_ca_file"`
	TLSCertFile   string `yaml:"tls_cert_file" json:"tls_cert_file" mapstructure:"tls_cert_file"`
	TLSKeyFile    string `yaml:"tls_key_file" json:"tls_key_file" mapstructure:"tls_key_file"`
}

// OIDCConfig holds the local OAuth2 callback listener shared by the OIDC and
// AWS login flows. The listener binds CallbackHost: "localhost" (the default)
// binds both loopback families, since the browser may resolve the redirect
// host localhost to either; an address binds that address; "" binds every
// interface. CallbackPort is the port of the default redirect URL
// (http://localhost:<port>/callback, and http://127.0.0.1:<port>/oauth/callback
// for AWS, whose fixed 127.0.0.1 host the callback host must be able to
// serve), which is the URL registered with the provider, so an explicit
// --redirect-url keeps its own port.
type OIDCConfig struct {
	CallbackHost string `yaml:"callback_host" json:"callback_host" mapstructure:"callback_host"`
	CallbackPort int    `yaml:"callback_port" json:"callback_port" mapstructure:"callback_port"`
}

// AgentConfig holds the address `xkey agent start` serves enrolled agents
// on: host:port, where a bare ":port" binds every interface. It is the
// defaults-layer value `--listen` overrides.
type AgentConfig struct {
	ListenAddress string `yaml:"listen_address" json:"listen_address" mapstructure:"listen_address"`
}

// TPMConfig holds direct TPM access parameters.
type TPMConfig struct {
	Device          string `yaml:"device" json:"device" mapstructure:"device"`
	EncryptSessions bool   `yaml:"encrypt_sessions" json:"encrypt_sessions" mapstructure:"encrypt_sessions"`
	PlatformPCRBank string `yaml:"platform_pcr_bank" json:"platform_pcr_bank" mapstructure:"platform_pcr_bank"`
	SealPCRBank     string `yaml:"seal_pcr_bank" json:"seal_pcr_bank" mapstructure:"seal_pcr_bank"`
	SRKHandle       uint32 `yaml:"srk_handle" json:"srk_handle" mapstructure:"srk_handle"`
	EKHandle        uint32 `yaml:"ek_handle" json:"ek_handle" mapstructure:"ek_handle"`
}

// PasswordProtectionConfig holds barrier/encryption at-rest settings.
type PasswordProtectionConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Mode    string `yaml:"mode" json:"mode" mapstructure:"mode"`
}

// TrustConfig holds root certificate and system trust settings.
type TrustConfig struct {
	Roots       []string `yaml:"roots" json:"roots" mapstructure:"roots"`
	SystemTrust bool     `yaml:"system_trust" json:"system_trust" mapstructure:"system_trust"`
}

// AttestationConfig holds attestation authority settings.
type AttestationConfig struct {
	Mode   string `yaml:"mode" json:"mode" mapstructure:"mode"`
	CACert string `yaml:"ca_cert" json:"ca_cert" mapstructure:"ca_cert"`
	CAKey  string `yaml:"ca_key" json:"ca_key" mapstructure:"ca_key"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level string `yaml:"level" json:"level" mapstructure:"level"`
	File  string `yaml:"file" json:"file" mapstructure:"file"`
}

// GUISection holds all GUI-specific settings for the Wails desktop application.
type GUISection struct {
	Theme            string           `yaml:"theme" json:"theme" mapstructure:"theme"`
	AutoTray         bool             `yaml:"auto_tray" json:"auto_tray" mapstructure:"auto_tray"`
	StartMinimized   bool             `yaml:"start_minimized" json:"start_minimized" mapstructure:"start_minimized"`
	Notifications    bool             `yaml:"notifications" json:"notifications" mapstructure:"notifications"`
	ClipboardTimeout int              `yaml:"clipboard_timeout" json:"clipboard_timeout" mapstructure:"clipboard_timeout"`
	WindowWidth      int              `yaml:"window_width" json:"window_width" mapstructure:"window_width"`
	WindowHeight     int              `yaml:"window_height" json:"window_height" mapstructure:"window_height"`
	RememberPosition bool             `yaml:"remember_position" json:"remember_position" mapstructure:"remember_position"`
	WindowX          int              `yaml:"window_x" json:"window_x" mapstructure:"window_x"`
	WindowY          int              `yaml:"window_y" json:"window_y" mapstructure:"window_y"`
	FIDO2AuthEnabled bool             `yaml:"fido2_authenticator_enabled" json:"fido2_authenticator_enabled" mapstructure:"fido2_authenticator_enabled"`
	Server           GUIServerConfig  `yaml:"server" json:"server" mapstructure:"server"`
	AutoUnseal       AutoUnsealConfig `yaml:"auto_unseal" json:"auto_unseal" mapstructure:"auto_unseal"`
}

// GUIServerConfig holds the GUI's connection parameters for the xkmsd backend.
type GUIServerConfig struct {
	Address       string `yaml:"address" json:"address" mapstructure:"address"`
	Protocol      string `yaml:"protocol" json:"protocol" mapstructure:"protocol"`
	TLSEnabled    bool   `yaml:"tls_enabled" json:"tls_enabled" mapstructure:"tls_enabled"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify" json:"tls_skip_verify" mapstructure:"tls_skip_verify"`
	TLSCAFile     string `yaml:"tls_ca_file" json:"tls_ca_file" mapstructure:"tls_ca_file"`
	AutoConnect   bool   `yaml:"auto_connect" json:"auto_connect" mapstructure:"auto_connect"`
}

// AutoUnsealConfig holds TPM-based automatic unseal settings.
type AutoUnsealConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	BlobID     string `yaml:"blob_id" json:"blob_id" mapstructure:"blob_id"`
	PCRs       []int  `yaml:"pcrs" json:"pcrs" mapstructure:"pcrs"`
	PCRBank    string `yaml:"pcr_bank" json:"pcr_bank" mapstructure:"pcr_bank"`
	PolicyType string `yaml:"policy_type" json:"policy_type" mapstructure:"policy_type"`
	PolicyName string `yaml:"policy_name" json:"policy_name" mapstructure:"policy_name"`
	Backend    string `yaml:"backend" json:"backend" mapstructure:"backend"`
}

// BackendsConfig holds the multi-backend configuration for xkey.
// When this section is absent from the config file, xkey auto-populates
// it from the legacy Backend.Default field for backward compatibility.
type BackendsConfig struct {
	Defaults map[string]string     `yaml:"defaults,omitempty" json:"defaults,omitempty" mapstructure:"defaults"`
	Local    []LocalBackendConfig  `yaml:"local,omitempty" json:"local,omitempty" mapstructure:"local"`
	Remote   []RemoteBackendConfig `yaml:"remote,omitempty" json:"remote,omitempty" mapstructure:"remote"`
}

// LocalBackendConfig holds configuration for a local cryptographic backend.
type LocalBackendConfig struct {
	ID           string               `yaml:"id" json:"id" mapstructure:"id"`
	Category     string               `yaml:"category" json:"category" mapstructure:"category"`
	Name         string               `yaml:"name" json:"name" mapstructure:"name"`
	TPM2         *TPM2BackendConfig   `yaml:"tpm2,omitempty" json:"tpm2,omitempty" mapstructure:"tpm2"`
	PKCS11       *PKCS11BackendConfig `yaml:"pkcs11,omitempty" json:"pkcs11,omitempty" mapstructure:"pkcs11"`
	SealStrategy string               `yaml:"seal_strategy,omitempty" json:"seal_strategy,omitempty" mapstructure:"seal_strategy"`
}

// RemoteBackendConfig holds configuration for a remote xkms server backend.
type RemoteBackendConfig struct {
	ID          string `yaml:"id" json:"id" mapstructure:"id"`
	Name        string `yaml:"name" json:"name" mapstructure:"name"`
	Address     string `yaml:"address" json:"address" mapstructure:"address"`
	Protocol    string `yaml:"protocol" json:"protocol" mapstructure:"protocol"`
	TLSEnabled  bool   `yaml:"tls_enabled" json:"tls_enabled" mapstructure:"tls_enabled"`
	SPKIPin     string `yaml:"spki_pin,omitempty" json:"spki_pin,omitempty" mapstructure:"spki_pin"`
	AutoConnect bool   `yaml:"auto_connect" json:"auto_connect" mapstructure:"auto_connect"`
}

// TPM2BackendConfig holds TPM2-specific settings for a local backend.
type TPM2BackendConfig struct {
	Device    string `yaml:"device" json:"device" mapstructure:"device"`
	Simulator bool   `yaml:"simulator" json:"simulator" mapstructure:"simulator"`
}

// PKCS11BackendConfig holds PKCS#11-specific settings for a local backend.
type PKCS11BackendConfig struct {
	LibraryPath string `yaml:"library_path" json:"library_path" mapstructure:"library_path"`
	SlotID      int    `yaml:"slot_id" json:"slot_id" mapstructure:"slot_id"`
}

// StateSection holds runtime state persisted across application restarts.
type StateSection struct {
	SetupComplete bool   `yaml:"setup_complete" json:"setup_complete" mapstructure:"setup_complete"`
	StorageType   string `yaml:"storage_type" json:"storage_type" mapstructure:"storage_type"`
	// StorageEngine selects the go-qrdb storage engine backing all local
	// persistence: "file" (default, one flat file per key — identical to xkey's
	// historical layout), "pebble" (embedded LSM-tree), or "memory" (ephemeral).
	// It is orthogonal to StorageType, which chooses plain-disk vs LUKS at-rest
	// encryption for the data directory.
	StorageEngine      string `yaml:"storage_engine" json:"storage_engine" mapstructure:"storage_engine"`
	BarrierInitialized bool   `yaml:"barrier_initialized" json:"barrier_initialized" mapstructure:"barrier_initialized"`
	BarrierStrategy    string `yaml:"barrier_strategy" json:"barrier_strategy" mapstructure:"barrier_strategy"`
	Mode               string `yaml:"mode" json:"mode" mapstructure:"mode"`
}

// validLogLevels is the set of accepted log level strings.
var validLogLevels = map[string]struct{}{
	"trace": {},
	"debug": {},
	"info":  {},
	"warn":  {},
	"error": {},
}

// validBackends is the set of accepted backend identifiers.
var validBackends = map[string]struct{}{
	"software": {},
	"tpm2":     {},
	"pkcs11":   {},
	"phone":    {},
}

// validStorageEngines is the set of accepted go-qrdb storage engine
// identifiers for State.StorageEngine.
var validStorageEngines = map[string]struct{}{
	"file":   {},
	"pebble": {},
	"memory": {},
}

// validBackendCategories is the set of accepted backend categories.
var validBackendCategories = map[string]struct{}{
	"software": {},
	"tpm2":     {},
	"pkcs11":   {},
	"xkms":     {},
	"phone":    {},
}

// validModes is the set of accepted application modes.
var validModes = map[string]struct{}{
	"personal":   {},
	"enterprise": {},
}

// validRemoteProtocols is the set of accepted remote backend protocols.
var validRemoteProtocols = map[string]struct{}{
	"rest": {},
	"grpc": {},
	"quic": {},
	"unix": {},
	"mcp":  {},
}

// DefaultConfig returns a Config populated with sensible defaults suitable
// for first-run or development use.
func DefaultConfig() *Config {
	return &Config{
		Policy: *DefaultPolicy(),
		Backend: BackendConfig{
			Default: "software",
		},
		FIDO2: FIDO2Config{
			Storage:     "file",
			Attestation: "packed",
			DeviceName:  "xKey",
		},
		TPM: TPMConfig{
			Device:          "/dev/tpmrm0",
			EncryptSessions: true,
			PlatformPCRBank: "sha256",
		},
		OIDC: OIDCConfig{
			CallbackHost: "localhost",
			CallbackPort: 8085,
		},
		Agent: AgentConfig{
			ListenAddress: ":9443",
		},
		Phone: PhoneConfig{
			RelayListenAddress: ":8444",
		},
		Log: LogConfig{
			Level: "info",
		},
		GUI: GUISection{
			Theme:            "system",
			AutoTray:         true,
			Notifications:    true,
			ClipboardTimeout: 30,
			WindowWidth:      1024,
			WindowHeight:     768,
			FIDO2AuthEnabled: true,
		},
		State: StateSection{
			StorageEngine: "file",
		},
	}
}

// Validate checks the Config for semantic correctness and returns a typed
// error if any field contains an invalid value.
func (c *Config) Validate() error {
	if c.Log.Level != "" {
		if _, ok := validLogLevels[c.Log.Level]; !ok {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": log.level %q is not one of trace, debug, info, warn, error", c.Log.Level)}
		}
	}

	if c.GUI.ClipboardTimeout < 0 {
		return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": gui.clipboard_timeout must be >= 0, got %d", c.GUI.ClipboardTimeout)}
	}

	if c.GUI.WindowWidth <= 0 {
		return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": gui.window_width must be > 0, got %d", c.GUI.WindowWidth)}
	}

	if c.GUI.WindowHeight <= 0 {
		return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": gui.window_height must be > 0, got %d", c.GUI.WindowHeight)}
	}

	if c.OIDC.CallbackPort < 1 || c.OIDC.CallbackPort > 65535 {
		return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": oidc.callback_port must be between 1 and 65535, got %d", c.OIDC.CallbackPort)}
	}
	for key, addr := range map[string]string{
		"agent.listen_address":       c.Agent.ListenAddress,
		"phone.relay_listen_address": c.Phone.RelayListenAddress,
	} {
		if addr == "" {
			continue
		}
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": %s %q is not host:port: %v", key, addr, err)}
		}
		// SplitHostPort accepts an empty port, and a listener given ":" or
		// "127.0.0.1:" binds an ephemeral port; a typo must fail here, not
		// bind somewhere random.
		if n, convErr := strconv.Atoi(port); convErr != nil || n < 1 || n > 65535 {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": %s %q must name a port between 1 and 65535", key, addr)}
		}
	}
	if c.Backend.Default != "" {
		if _, ok := validBackends[c.Backend.Default]; !ok {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": backend.default %q is not one of software, tpm2, pkcs11, phone", c.Backend.Default)}
		}
	}

	// Validate backends config if present.
	if len(c.Backends.Local) > 0 || len(c.Backends.Remote) > 0 {
		if err := c.validateBackends(); err != nil {
			return err
		}
	}

	// Validate state mode if set.
	if c.State.Mode != "" {
		if _, ok := validModes[c.State.Mode]; !ok {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": state.mode %q is not one of personal, enterprise", c.State.Mode)}
		}
	}

	// Validate storage engine if set.
	if c.State.StorageEngine != "" {
		if _, ok := validStorageEngines[c.State.StorageEngine]; !ok {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": state.storage_engine %q is not one of file, pebble, memory", c.State.StorageEngine)}
		}
	}

	return nil
}

// validateBackends checks the BackendsConfig for semantic correctness.
func (c *Config) validateBackends() error {
	seen := make(map[string]struct{})

	for i, lb := range c.Backends.Local {
		if lb.ID == "" {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": backends.local[%d].id must not be empty", i)}
		}
		if _, ok := seen[lb.ID]; ok {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": backends.local[%d].id %q is a duplicate", i, lb.ID)}
		}
		seen[lb.ID] = struct{}{}
		if _, ok := validBackendCategories[lb.Category]; !ok {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": backends.local[%d].category %q is not valid", i, lb.Category)}
		}
		if lb.Category == "pkcs11" && lb.PKCS11 != nil && lb.PKCS11.LibraryPath == "" {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": backends.local[%d].pkcs11.library_path must not be empty", i)}
		}
	}

	for i, rb := range c.Backends.Remote {
		if rb.ID == "" {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": backends.remote[%d].id must not be empty", i)}
		}
		if _, ok := seen[rb.ID]; ok {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": backends.remote[%d].id %q is a duplicate", i, rb.ID)}
		}
		seen[rb.ID] = struct{}{}
		if rb.Address == "" {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": backends.remote[%d].address must not be empty", i)}
		}
		if rb.Protocol != "" {
			if _, ok := validRemoteProtocols[rb.Protocol]; !ok {
				return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": backends.remote[%d].protocol %q is not valid", i, rb.Protocol)}
			}
		}
	}

	// Validate default references point to registered backend IDs.
	for cap, backendID := range c.Backends.Defaults {
		if _, ok := seen[backendID]; !ok {
			return &DetailError{Err: ErrConfigInvalid, Detail: fmt.Sprintf(": backends.defaults[%q] references unknown backend %q", cap, backendID)}
		}
	}

	return nil
}

// AutoPopulateBackends creates a BackendsConfig from the legacy Backend.Default
// field when the Backends section has no local or remote entries. This ensures
// backward compatibility with older config files.
func (c *Config) AutoPopulateBackends() {
	if len(c.Backends.Local) > 0 || len(c.Backends.Remote) > 0 {
		return
	}

	defaultBackend := c.Backend.Default
	if defaultBackend == "" {
		defaultBackend = "software"
	}

	localBackend := LocalBackendConfig{
		ID:       defaultBackend,
		Category: defaultBackend,
		Name:     "Local " + defaultBackend,
	}

	// Populate backend-specific config from legacy fields.
	if defaultBackend == "tpm2" && c.Backend.TPM2.Device != "" {
		localBackend.TPM2 = &TPM2BackendConfig{
			Device:    c.Backend.TPM2.Device,
			Simulator: c.Backend.TPM2.Simulator,
		}
	}

	c.Backends.Local = []LocalBackendConfig{localBackend}

	if c.Backends.Defaults == nil {
		c.Backends.Defaults = make(map[string]string)
	}
}
