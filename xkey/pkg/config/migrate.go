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

package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// oldGUIConfig mirrors the flat JSON structure of the legacy GUI config
// file (~/.config/xkey/gui.json). It is used exclusively for deserialization
// during migration and is not exported.
type oldGUIConfig struct {
	Theme                     string `json:"theme"`
	AutoTray                  bool   `json:"auto_tray"`
	StartMinimized            bool   `json:"start_minimized"`
	Notifications             bool   `json:"notifications"`
	ClipboardTimeout          int    `json:"clipboard_timeout"`
	WindowWidth               int    `json:"window_width"`
	WindowHeight              int    `json:"window_height"`
	RememberPosition          bool   `json:"remember_position"`
	WindowX                   int    `json:"window_x"`
	WindowY                   int    `json:"window_y"`
	FIDO2AuthenticatorEnabled bool   `json:"fido2_authenticator_enabled"`
	ServerAddress             string `json:"server_address"`
	ServerProtocol            string `json:"server_protocol"`
	ServerTLSEnabled          bool   `json:"server_tls_enabled"`
	ServerTLSSkipVerify       bool   `json:"server_tls_skip_verify"`
	ServerTLSCAFile           string `json:"server_tls_ca_file"`
	ServerAutoConnect         bool   `json:"server_auto_connect"`
	AutoUnsealEnabled         bool   `json:"auto_unseal_enabled"`
	AutoUnsealBlobID          string `json:"auto_unseal_blob_id"`
	AutoUnsealPCRs            []int  `json:"auto_unseal_pcrs"`
	AutoUnsealPCRBank         string `json:"auto_unseal_pcr_bank"`
	AutoUnsealPolicyType      string `json:"auto_unseal_policy_type"`
	AutoUnsealPolicyName      string `json:"auto_unseal_policy_name"`
	AutoUnsealBackend         string `json:"auto_unseal_backend"`
	SetupComplete             bool   `json:"setup_complete"`
	StorageType               string `json:"storage_type"`
	BarrierInitialized        bool   `json:"barrier_initialized"`
	BarrierStrategy           string `json:"barrier_strategy"`
}

// Migrate checks for old config files and merges them into a unified config.
// It reads the old CLI YAML (~/.xkey/config.yaml) and old GUI JSON
// (~/.config/xkey/gui.json), merges their values into a new Config, and
// saves the unified config to ConfigPath(). Old files are NOT deleted so
// they remain available for rollback.
//
// Returns the merged config and whether migration actually occurred. If the
// unified config already exists or no legacy files are found, migration is
// skipped and (nil, false, nil) is returned.
func Migrate() (*Config, bool, error) {
	// If the unified config already exists, skip migration entirely.
	if _, err := os.Stat(ConfigPath()); err == nil {
		return nil, false, nil
	}

	cliPath := oldCLIConfigPath()
	guiPath := oldGUIConfigPath()

	cliExists := fileExists(cliPath)
	guiExists := fileExists(guiPath)

	// Nothing to migrate.
	if !cliExists && !guiExists {
		return nil, false, nil
	}

	cfg := DefaultConfig()

	if cliExists {
		if err := migrateCLIConfig(cfg, cliPath); err != nil {
			return nil, false, errors.Join(ErrConfigMigrationFailed, err)
		}
	}

	if guiExists {
		if err := migrateGUIConfig(cfg, guiPath); err != nil {
			return nil, false, errors.Join(ErrConfigMigrationFailed, err)
		}
	}

	if err := Save(cfg); err != nil {
		return nil, false, errors.Join(ErrConfigMigrationFailed, err)
	}

	return cfg, true, nil
}

// oldCLIConfigPath returns the legacy CLI config location: ~/.xkey/config.yaml
func oldCLIConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".xkey", "config.yaml")
	}
	return filepath.Join(home, ".xkey", "config.yaml")
}

// oldGUIConfigPath returns the legacy GUI config location: ~/.config/xkey/gui.json
func oldGUIConfigPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return filepath.Join(".config", "xkey", "gui.json")
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "xkey", "gui.json")
}

// migrateCLIConfig reads the old CLI YAML config and applies its values
// to the unified config. Only keys that are explicitly set in the old file
// override the defaults; unset keys are left at their DefaultConfig() values.
func migrateCLIConfig(cfg *Config, path string) error {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		return err
	}

	// Backend section.
	if v.IsSet("backend.default") {
		cfg.Backend.Default = v.GetString("backend.default")
	}
	if v.IsSet("backend.tpm2.device") {
		cfg.Backend.TPM2.Device = v.GetString("backend.tpm2.device")
	}
	if v.IsSet("backend.tpm2.simulator") {
		cfg.Backend.TPM2.Simulator = v.GetBool("backend.tpm2.simulator")
	}
	if v.IsSet("backend.tpm2.hash") {
		cfg.Backend.TPM2.Hash = v.GetString("backend.tpm2.hash")
	}

	// FIDO2 section.
	if v.IsSet("fido2.storage") {
		cfg.FIDO2.Storage = v.GetString("fido2.storage")
	}
	if v.IsSet("fido2.storage_path") {
		cfg.FIDO2.StoragePath = v.GetString("fido2.storage_path")
	}
	if v.IsSet("fido2.attestation") {
		cfg.FIDO2.Attestation = v.GetString("fido2.attestation")
	}
	if v.IsSet("fido2.device_name") {
		cfg.FIDO2.DeviceName = v.GetString("fido2.device_name")
	}
	if v.IsSet("fido2.rpid_hash") {
		cfg.FIDO2.RPIDHash = v.GetBool("fido2.rpid_hash")
	}
	if v.IsSet("fido2.always_uv") {
		cfg.FIDO2.AlwaysUV = v.GetBool("fido2.always_uv")
	}
	if v.IsSet("fido2.resident_key") {
		cfg.FIDO2.ResidentKey = v.GetBool("fido2.resident_key")
	}
	if v.IsSet("fido2.conformance_mode") {
		cfg.FIDO2.ConformanceMode = v.GetBool("fido2.conformance_mode")
	}

	// OATH section.
	if v.IsSet("oath.storage") {
		cfg.OATH.Storage = v.GetString("oath.storage")
	}
	if v.IsSet("oath.storage_path") {
		cfg.OATH.StoragePath = v.GetString("oath.storage_path")
	}
	if v.IsSet("oath.algorithm") {
		cfg.OATH.Algorithm = v.GetString("oath.algorithm")
	}
	if v.IsSet("oath.digits") {
		cfg.OATH.Digits = v.GetInt("oath.digits")
	}
	if v.IsSet("oath.period") {
		cfg.OATH.Period = v.GetInt("oath.period")
	}

	// Phone section.
	if v.IsSet("phone.backend") {
		cfg.Phone.Backend = v.GetString("phone.backend")
	}
	if v.IsSet("phone.server_address") {
		cfg.Phone.ServerAddress = v.GetString("phone.server_address")
	}
	if v.IsSet("phone.server_protocol") {
		cfg.Phone.ServerProtocol = v.GetString("phone.server_protocol")
	}
	if v.IsSet("phone.server_tls_enabled") {
		cfg.Phone.ServerTLSEnabled = v.GetBool("phone.server_tls_enabled")
	}
	if v.IsSet("phone.device_filter") {
		cfg.Phone.DeviceFilter = v.GetString("phone.device_filter")
	}
	if v.IsSet("phone.attestation_policy") {
		cfg.Phone.AttestationPolicy = v.GetString("phone.attestation_policy")
	}

	// XKMSD section.
	if v.IsSet("xkmsd.address") {
		cfg.XKMSD.Address = v.GetString("xkmsd.address")
	}
	if v.IsSet("xkmsd.protocol") {
		cfg.XKMSD.Protocol = v.GetString("xkmsd.protocol")
	}
	if v.IsSet("xkmsd.tls_enabled") {
		cfg.XKMSD.TLSEnabled = v.GetBool("xkmsd.tls_enabled")
	}
	if v.IsSet("xkmsd.tls_skip_verify") {
		cfg.XKMSD.TLSSkipVerify = v.GetBool("xkmsd.tls_skip_verify")
	}
	if v.IsSet("xkmsd.tls_ca_file") {
		cfg.XKMSD.TLSCAFile = v.GetString("xkmsd.tls_ca_file")
	}
	if v.IsSet("xkmsd.tls_cert_file") {
		cfg.XKMSD.TLSCertFile = v.GetString("xkmsd.tls_cert_file")
	}
	if v.IsSet("xkmsd.tls_key_file") {
		cfg.XKMSD.TLSKeyFile = v.GetString("xkmsd.tls_key_file")
	}

	// TPM section.
	if v.IsSet("tpm.device") {
		cfg.TPM.Device = v.GetString("tpm.device")
	}
	if v.IsSet("tpm.encrypt_sessions") {
		cfg.TPM.EncryptSessions = v.GetBool("tpm.encrypt_sessions")
	}
	if v.IsSet("tpm.platform_pcr_bank") {
		cfg.TPM.PlatformPCRBank = v.GetString("tpm.platform_pcr_bank")
	}
	if v.IsSet("tpm.seal_pcr_bank") {
		cfg.TPM.SealPCRBank = v.GetString("tpm.seal_pcr_bank")
	}
	if v.IsSet("tpm.srk_handle") {
		cfg.TPM.SRKHandle = uint32(v.GetUint64("tpm.srk_handle"))
	}
	if v.IsSet("tpm.ek_handle") {
		cfg.TPM.EKHandle = uint32(v.GetUint64("tpm.ek_handle"))
	}

	// Password protection section.
	if v.IsSet("password_protection.enabled") {
		cfg.PasswordProtection.Enabled = v.GetBool("password_protection.enabled")
	}
	if v.IsSet("password_protection.mode") {
		cfg.PasswordProtection.Mode = v.GetString("password_protection.mode")
	}

	// Trust section.
	if v.IsSet("trust.roots") {
		cfg.Trust.Roots = v.GetStringSlice("trust.roots")
	}
	if v.IsSet("trust.system_trust") {
		cfg.Trust.SystemTrust = v.GetBool("trust.system_trust")
	}

	// Attestation section.
	if v.IsSet("attestation.mode") {
		cfg.Attestation.Mode = v.GetString("attestation.mode")
	}
	if v.IsSet("attestation.ca_cert") {
		cfg.Attestation.CACert = v.GetString("attestation.ca_cert")
	}
	if v.IsSet("attestation.ca_key") {
		cfg.Attestation.CAKey = v.GetString("attestation.ca_key")
	}

	// Log section.
	if v.IsSet("log.level") {
		cfg.Log.Level = v.GetString("log.level")
	}
	if v.IsSet("log.file") {
		cfg.Log.File = v.GetString("log.file")
	}

	return nil
}

// migrateGUIConfig reads the old GUI JSON config and applies its values
// to the unified config. The old GUI config uses a flat field layout that
// is mapped into the nested GUISection and StateSection of the unified config.
func migrateGUIConfig(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var old oldGUIConfig
	if err := json.Unmarshal(data, &old); err != nil {
		return err
	}

	// GUI appearance and behavior.
	cfg.GUI.Theme = old.Theme
	cfg.GUI.AutoTray = old.AutoTray
	cfg.GUI.StartMinimized = old.StartMinimized
	cfg.GUI.Notifications = old.Notifications
	cfg.GUI.ClipboardTimeout = old.ClipboardTimeout
	cfg.GUI.WindowWidth = old.WindowWidth
	cfg.GUI.WindowHeight = old.WindowHeight
	cfg.GUI.RememberPosition = old.RememberPosition
	cfg.GUI.WindowX = old.WindowX
	cfg.GUI.WindowY = old.WindowY
	cfg.GUI.FIDO2AuthEnabled = old.FIDO2AuthenticatorEnabled

	// GUI server connection.
	cfg.GUI.Server.Address = old.ServerAddress
	cfg.GUI.Server.Protocol = old.ServerProtocol
	cfg.GUI.Server.TLSEnabled = old.ServerTLSEnabled
	cfg.GUI.Server.TLSSkipVerify = old.ServerTLSSkipVerify
	cfg.GUI.Server.TLSCAFile = old.ServerTLSCAFile
	cfg.GUI.Server.AutoConnect = old.ServerAutoConnect

	// GUI auto-unseal.
	cfg.GUI.AutoUnseal.Enabled = old.AutoUnsealEnabled
	cfg.GUI.AutoUnseal.BlobID = old.AutoUnsealBlobID
	cfg.GUI.AutoUnseal.PCRs = old.AutoUnsealPCRs
	cfg.GUI.AutoUnseal.PCRBank = old.AutoUnsealPCRBank
	cfg.GUI.AutoUnseal.PolicyType = old.AutoUnsealPolicyType
	cfg.GUI.AutoUnseal.PolicyName = old.AutoUnsealPolicyName
	cfg.GUI.AutoUnseal.Backend = old.AutoUnsealBackend

	// State section (persisted application state from old GUI config).
	cfg.State.SetupComplete = old.SetupComplete
	cfg.State.StorageType = old.StorageType
	cfg.State.BarrierInitialized = old.BarrierInitialized
	cfg.State.BarrierStrategy = old.BarrierStrategy

	return nil
}

// fileExists returns true if the path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
