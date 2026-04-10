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

// Package module provides a PKCS#11 module client that connects to the
// go-xkms server via gRPC. It implements the PKCS#11 interface by
// delegating cryptographic operations to a remote xkms service.
package module

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Default configuration values
const (
	// DefaultConfigPath is the default path to the configuration file.
	DefaultConfigPath = "/etc/xkms/pkcs11.conf"

	// DefaultTimeout is the default timeout for gRPC operations.
	DefaultTimeout = 30 * time.Second

	// DefaultTarget is the default gRPC target address.
	DefaultTarget = "unix:///var/run/xkms/xkms.sock"

	// DefaultBackend is the default cryptographic backend to use.
	DefaultBackend = "software"
)

// Environment variable names
const (
	EnvTarget         = "XKMS_PKCS11_TARGET"
	EnvTLSEnabled     = "XKMS_PKCS11_TLS_ENABLED"
	EnvTLSCert        = "XKMS_PKCS11_TLS_CERT"
	EnvTLSKey         = "XKMS_PKCS11_TLS_KEY"
	EnvTLSCA          = "XKMS_PKCS11_TLS_CA"
	EnvTimeout        = "XKMS_PKCS11_TIMEOUT"
	EnvDefaultBackend = "XKMS_PKCS11_DEFAULT_BACKEND"
	EnvSOPIN          = "XKMS_PKCS11_SO_PIN"
	EnvUserPIN        = "XKMS_PKCS11_USER_PIN"
	EnvTokenLabel     = "XKMS_PKCS11_TOKEN_LABEL"
	EnvAutoInitToken  = "XKMS_PKCS11_AUTO_INIT_TOKEN"
	EnvStorageType    = "XKMS_PKCS11_STORAGE_TYPE"
	EnvStoragePath    = "XKMS_PKCS11_STORAGE_PATH"
	EnvPIVBackends    = "XKMS_PKCS11_PIV_BACKENDS"
)

// Storage type constants
const (
	StorageTypeMemory = "memory"
	StorageTypeFile   = "file"
)

// TLSConfig contains TLS/mTLS configuration for secure gRPC connections.
type TLSConfig struct {
	// Enabled controls whether TLS is used for the gRPC connection.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// CertFile is the path to the client certificate file (PEM format).
	// Required for mTLS authentication.
	CertFile string `yaml:"cert_file" json:"cert_file" mapstructure:"cert_file"`

	// KeyFile is the path to the client private key file (PEM format).
	// Required for mTLS authentication.
	KeyFile string `yaml:"key_file" json:"key_file" mapstructure:"key_file"`

	// CAFile is the path to the CA certificate file (PEM format).
	// Used to verify the server's certificate.
	CAFile string `yaml:"ca_file" json:"ca_file" mapstructure:"ca_file"`
}

// Config contains the PKCS#11 module client configuration.
// It specifies how to connect to the go-xkms gRPC server.
type Config struct {
	// Target is the gRPC target address.
	// Formats:
	//   - unix:///path/to/socket (Unix domain socket)
	//   - dns:///host:port (DNS-based TCP connection)
	//   - host:port (direct TCP connection)
	Target string `yaml:"target" json:"target" mapstructure:"target"`

	// TLS contains TLS configuration for secure connections.
	TLS TLSConfig `yaml:"tls" json:"tls" mapstructure:"tls"`

	// Timeout is the timeout for gRPC operations.
	Timeout time.Duration `yaml:"timeout" json:"timeout" mapstructure:"timeout"`

	// DefaultBackend is the default cryptographic backend to use for key operations.
	// Common values: "software", "tpm2", "pkcs11"
	DefaultBackend string `yaml:"default_backend" json:"default_backend" mapstructure:"default_backend"`

	// Token configuration for auto-initialization (useful for testing)

	// AutoInitToken enables automatic token initialization on module load.
	// When true, the token will be initialized with SOPIN, UserPIN, and TokenLabel.
	AutoInitToken bool `yaml:"auto_init_token" json:"auto_init_token" mapstructure:"auto_init_token"`

	// SOPIN is the Security Officer PIN for token initialization.
	// Only used when AutoInitToken is true.
	SOPIN string `yaml:"so_pin" json:"so_pin" mapstructure:"so_pin"`

	// UserPIN is the user PIN for token initialization.
	// Only used when AutoInitToken is true.
	UserPIN string `yaml:"user_pin" json:"user_pin" mapstructure:"user_pin"`

	// TokenLabel is the label for the token.
	// Only used when AutoInitToken is true.
	TokenLabel string `yaml:"token_label" json:"token_label" mapstructure:"token_label"`

	// Storage configuration for persistent state

	// StorageType specifies the storage backend type.
	// Supported values: "memory" (default), "file"
	StorageType string `yaml:"storage_type" json:"storage_type" mapstructure:"storage_type"`

	// StoragePath is the path for file-based storage.
	// Required when StorageType is "file".
	StoragePath string `yaml:"storage_path" json:"storage_path" mapstructure:"storage_path"`

	// PIV configuration

	// PIVBackends lists backends to discover PIV certificates from during initialization.
	// When set, LoadPIVObjects is called for each backend after the module initializes,
	// creating PKCS#11 objects (certificate, public key, private key) for each occupied
	// PIV slot.
	PIVBackends []string `yaml:"piv_backends" json:"piv_backends" mapstructure:"piv_backends"`
}

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() *Config {
	return &Config{
		Target:         DefaultTarget,
		Timeout:        DefaultTimeout,
		DefaultBackend: DefaultBackend,
		StorageType:    StorageTypeMemory,
		TLS: TLSConfig{
			Enabled: false,
		},
	}
}

// SetDefaults sets default values for any zero-valued fields.
// This allows partial configuration while ensuring all fields have valid values.
func (c *Config) SetDefaults() {
	if c.Target == "" {
		c.Target = DefaultTarget
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.DefaultBackend == "" {
		c.DefaultBackend = DefaultBackend
	}
	if c.StorageType == "" {
		c.StorageType = StorageTypeMemory
	}
}

// Validate validates the configuration and returns an error if invalid.
// This should be called after SetDefaults() or after all fields are configured.
func (c *Config) Validate() error {
	if c == nil {
		return ErrNilConfig
	}

	if c.Target == "" {
		return ErrEmptyTarget
	}

	// Validate target format
	if err := validateTarget(c.Target); err != nil {
		return err
	}

	// Validate TLS configuration
	if c.TLS.Enabled {
		if err := c.validateTLS(); err != nil {
			return err
		}
	}

	// Validate timeout
	if c.Timeout < 0 {
		return ErrInvalidTimeout
	}

	// Validate storage configuration
	if err := c.validateStorage(); err != nil {
		return err
	}

	return nil
}

// validateStorage validates the storage configuration.
func (c *Config) validateStorage() error {
	switch c.StorageType {
	case StorageTypeMemory:
		// Memory storage requires no additional configuration
		return nil
	case StorageTypeFile:
		if c.StoragePath == "" {
			return ErrStoragePathRequired
		}
		return nil
	case "":
		// Empty storage type defaults to memory
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrInvalidStorageType, c.StorageType)
	}
}

// validateTLS validates the TLS configuration when TLS is enabled.
func (c *Config) validateTLS() error {
	// If mTLS is configured (cert and key provided), validate both are present
	if c.TLS.CertFile != "" || c.TLS.KeyFile != "" {
		if c.TLS.CertFile == "" {
			return ErrMissingTLSCert
		}
		if c.TLS.KeyFile == "" {
			return ErrMissingTLSKey
		}

		// Verify cert file exists
		if _, err := os.Stat(c.TLS.CertFile); os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrTLSCertNotFound, c.TLS.CertFile)
		}

		// Verify key file exists
		if _, err := os.Stat(c.TLS.KeyFile); os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrTLSKeyNotFound, c.TLS.KeyFile)
		}
	}

	// Verify CA file exists if specified
	if c.TLS.CAFile != "" {
		if _, err := os.Stat(c.TLS.CAFile); os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrTLSCANotFound, c.TLS.CAFile)
		}
	}

	return nil
}

// validateTarget validates the gRPC target format.
func validateTarget(target string) error {
	// Unix socket format: unix:///path/to/socket
	if strings.HasPrefix(target, "unix://") {
		path := strings.TrimPrefix(target, "unix://")
		if path == "" {
			return fmt.Errorf("%w: empty socket path", ErrInvalidTarget)
		}
		return nil
	}

	// DNS format: dns:///host:port
	if strings.HasPrefix(target, "dns://") {
		addr := strings.TrimPrefix(target, "dns://")
		addr = strings.TrimPrefix(addr, "/")
		if addr == "" {
			return fmt.Errorf("%w: empty DNS address", ErrInvalidTarget)
		}
		return nil
	}

	// Direct host:port format
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) != 2 {
			return fmt.Errorf("%w: invalid host:port format", ErrInvalidTarget)
		}
		if parts[0] == "" {
			return fmt.Errorf("%w: empty host", ErrInvalidTarget)
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%w: invalid port number", ErrInvalidTarget)
		}
		return nil
	}

	return fmt.Errorf("%w: unrecognized format", ErrInvalidTarget)
}

// LoadFromEnv loads configuration from environment variables.
// Environment variables take precedence over default values.
func LoadFromEnv() *Config {
	cfg := DefaultConfig()

	if target := os.Getenv(EnvTarget); target != "" {
		cfg.Target = target
	}

	if tlsEnabled := os.Getenv(EnvTLSEnabled); tlsEnabled != "" {
		cfg.TLS.Enabled = parseBool(tlsEnabled)
	}

	if tlsCert := os.Getenv(EnvTLSCert); tlsCert != "" {
		cfg.TLS.CertFile = tlsCert
	}

	if tlsKey := os.Getenv(EnvTLSKey); tlsKey != "" {
		cfg.TLS.KeyFile = tlsKey
	}

	if tlsCA := os.Getenv(EnvTLSCA); tlsCA != "" {
		cfg.TLS.CAFile = tlsCA
	}

	if timeout := os.Getenv(EnvTimeout); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			cfg.Timeout = d
		}
	}

	if backend := os.Getenv(EnvDefaultBackend); backend != "" {
		cfg.DefaultBackend = backend
	}

	// Token initialization settings
	if autoInit := os.Getenv(EnvAutoInitToken); autoInit != "" {
		cfg.AutoInitToken = parseBool(autoInit)
	}

	if soPin := os.Getenv(EnvSOPIN); soPin != "" {
		cfg.SOPIN = soPin
	}

	if userPin := os.Getenv(EnvUserPIN); userPin != "" {
		cfg.UserPIN = userPin
	}

	if tokenLabel := os.Getenv(EnvTokenLabel); tokenLabel != "" {
		cfg.TokenLabel = tokenLabel
	}

	// Storage configuration
	if storageType := os.Getenv(EnvStorageType); storageType != "" {
		cfg.StorageType = storageType
	}

	if storagePath := os.Getenv(EnvStoragePath); storagePath != "" {
		cfg.StoragePath = storagePath
	}

	// PIV configuration
	if pivBackends := os.Getenv(EnvPIVBackends); pivBackends != "" {
		cfg.PIVBackends = parsePIVBackends(pivBackends)
	}

	return cfg
}

// LoadFromFile loads configuration from an INI-format file.
// File format:
//
//	target = unix:///var/run/xkms/xkms.sock
//	tls_enabled = false
//	tls_cert = /path/to/cert.pem
//	tls_key = /path/to/key.pem
//	tls_ca = /path/to/ca.pem
//	timeout = 30s
//	default_backend = software
//	piv_backends = tpm2,pkcs11
func LoadFromFile(path string) (*Config, error) {
	// #nosec G304 - Config file path is provided by admin/user
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigFileOpen, err)
	}
	defer func() { _ = file.Close() }()

	cfg := DefaultConfig()
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse key = value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%w: line %d: invalid format", ErrConfigFileParse, lineNum)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove surrounding quotes if present
		value = trimQuotes(value)

		if err := cfg.setField(key, value); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrConfigFileParse, lineNum, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigFileRead, err)
	}

	return cfg, nil
}

// setField sets a configuration field from an INI key-value pair.
func (c *Config) setField(key, value string) error {
	switch strings.ToLower(key) {
	case "target":
		c.Target = value
	case "tls_enabled":
		c.TLS.Enabled = parseBool(value)
	case "tls_cert":
		c.TLS.CertFile = value
	case "tls_key":
		c.TLS.KeyFile = value
	case "tls_ca":
		c.TLS.CAFile = value
	case "timeout":
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid timeout duration: %v", err)
		}
		c.Timeout = d
	case "default_backend":
		c.DefaultBackend = value
	case "auto_init_token":
		c.AutoInitToken = parseBool(value)
	case "so_pin":
		c.SOPIN = value
	case "user_pin":
		c.UserPIN = value
	case "token_label":
		c.TokenLabel = value
	case "storage_type":
		c.StorageType = value
	case "storage_path":
		c.StoragePath = value
	case "piv_backends":
		c.PIVBackends = parsePIVBackends(value)
	default:
		return fmt.Errorf("unknown configuration key: %s", key)
	}
	return nil
}

// Load loads configuration with the following precedence (highest first):
// 1. Environment variables
// 2. Configuration file (if exists)
// 3. Default values
func Load() (*Config, error) {
	return LoadWithPath(DefaultConfigPath)
}

// LoadWithPath loads configuration from the specified file path,
// with environment variables taking precedence.
func LoadWithPath(path string) (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()

	// Load from file if it exists
	if _, err := os.Stat(path); err == nil {
		fileCfg, err := LoadFromFile(path)
		if err != nil {
			return nil, err
		}
		cfg = fileCfg
	}

	// Apply environment variable overrides
	applyEnvOverrides(cfg)

	// Set any remaining defaults
	cfg.SetDefaults()

	// Validate the final configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// applyEnvOverrides applies environment variable overrides to the configuration.
func applyEnvOverrides(cfg *Config) {
	if target := os.Getenv(EnvTarget); target != "" {
		cfg.Target = target
	}

	if tlsEnabled := os.Getenv(EnvTLSEnabled); tlsEnabled != "" {
		cfg.TLS.Enabled = parseBool(tlsEnabled)
	}

	if tlsCert := os.Getenv(EnvTLSCert); tlsCert != "" {
		cfg.TLS.CertFile = tlsCert
	}

	if tlsKey := os.Getenv(EnvTLSKey); tlsKey != "" {
		cfg.TLS.KeyFile = tlsKey
	}

	if tlsCA := os.Getenv(EnvTLSCA); tlsCA != "" {
		cfg.TLS.CAFile = tlsCA
	}

	if timeout := os.Getenv(EnvTimeout); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			cfg.Timeout = d
		}
	}

	if backend := os.Getenv(EnvDefaultBackend); backend != "" {
		cfg.DefaultBackend = backend
	}

	// Token initialization settings
	if autoInit := os.Getenv(EnvAutoInitToken); autoInit != "" {
		cfg.AutoInitToken = parseBool(autoInit)
	}

	if soPin := os.Getenv(EnvSOPIN); soPin != "" {
		cfg.SOPIN = soPin
	}

	if userPin := os.Getenv(EnvUserPIN); userPin != "" {
		cfg.UserPIN = userPin
	}

	if tokenLabel := os.Getenv(EnvTokenLabel); tokenLabel != "" {
		cfg.TokenLabel = tokenLabel
	}

	// Storage configuration
	if storageType := os.Getenv(EnvStorageType); storageType != "" {
		cfg.StorageType = storageType
	}

	if storagePath := os.Getenv(EnvStoragePath); storagePath != "" {
		cfg.StoragePath = storagePath
	}

	// PIV configuration
	if pivBackends := os.Getenv(EnvPIVBackends); pivBackends != "" {
		cfg.PIVBackends = parsePIVBackends(pivBackends)
	}
}

// String returns a string representation of the config with sensitive data masked.
func (c *Config) String() string {
	tlsStatus := "disabled"
	if c.TLS.Enabled {
		tlsStatus = "enabled"
	}

	return fmt.Sprintf("PKCS11ModuleConfig{Target: %s, TLS: %s, Timeout: %s, DefaultBackend: %s}",
		c.Target, tlsStatus, c.Timeout, c.DefaultBackend)
}

// parseBool parses a boolean value from a string.
// Accepts: true, false, 1, 0, yes, no (case-insensitive)
func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// trimQuotes removes surrounding single or double quotes from a string.
func trimQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// parsePIVBackends parses a comma-separated list of backend names.
func parsePIVBackends(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	backends := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			backends = append(backends, trimmed)
		}
	}
	return backends
}
