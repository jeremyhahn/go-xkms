// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the complete server configuration
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Protocols ProtocolsConfig `yaml:"protocols"`
	Unix      UnixConfig      `yaml:"unix"`
	Logging   LoggingConfig   `yaml:"logging"`
	TLS       TLSConfig       `yaml:"tls"`
	Auth      AuthConfig      `yaml:"auth"`
	RateLimit RateLimitConfig `yaml:"ratelimit"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Health    HealthConfig    `yaml:"health"`
	Storage   StorageConfig   `yaml:"storage"`
	RNG       RNGConfig       `yaml:"rng"`
	Default   DefaultConfig   `yaml:"default_backend"`
	Backends  BackendsConfig  `yaml:"backends"`
}

// ServerConfig contains server-level settings
type ServerConfig struct {
	Host     string `yaml:"host"`
	RESTPort int    `yaml:"rest_port"`
	GRPCPort int    `yaml:"grpc_port"`
	QUICPort int    `yaml:"quic_port"`
	MCPPort  int    `yaml:"mcp_port"`
}

// ProtocolsConfig controls which protocols are enabled
type ProtocolsConfig struct {
	// Unix enables the Unix domain socket for local IPC (default: true)
	Unix bool `yaml:"unix"`
	REST bool `yaml:"rest"`
	GRPC bool `yaml:"grpc"`
	QUIC bool `yaml:"quic"`
	MCP  bool `yaml:"mcp"`
}

// UnixConfig contains Unix domain socket server settings
type UnixConfig struct {
	// Enabled controls whether Unix socket is active (default: true)
	Enabled bool `yaml:"enabled"`
	// SocketPath is the path to the Unix socket file
	SocketPath string `yaml:"socket_path"`
	// SocketMode is the file permissions for the socket (default: 0660)
	SocketMode string `yaml:"socket_mode"`
	// Protocol specifies the protocol to use over the Unix socket
	// Valid values: "grpc", "http"
	// Default: "grpc"
	Protocol string `yaml:"protocol"`
}

// LoggingConfig controls logging behavior
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// TLSConfig controls TLS/SSL settings
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`

	// Client certificate verification (mTLS)
	ClientAuth string   `yaml:"client_auth"` // none, request, require, verify, require_and_verify
	ClientCAs  []string `yaml:"client_cas"`  // Additional client CA certificates

	// TLS version and cipher suites
	MinVersion          string   `yaml:"min_version"`           // TLS1.2, TLS1.3
	MaxVersion          string   `yaml:"max_version"`           // TLS1.2, TLS1.3
	CipherSuites        []string `yaml:"cipher_suites"`         // Specific cipher suites to allow
	PreferServerCiphers bool     `yaml:"prefer_server_ciphers"` // Server chooses cipher suite

	// Certificate rotation
	WatchCertFiles bool `yaml:"watch_cert_files"` // Auto-reload certificates on change
}

// AuthConfig controls authentication and authorization
type AuthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Type    string `yaml:"type"` // noop, apikey, mtls, jwt, custom

	// API Key authentication
	APIKeys map[string]APIKeyConfig `yaml:"api_keys,omitempty"` // key -> config mapping

	// JWT authentication
	JWT *JWTConfig `yaml:"jwt,omitempty"`

	// mTLS authentication
	MTLS bool `yaml:"mtls"` // Use mTLS from client certificates
}

// APIKeyConfig represents an API key and its associated identity
type APIKeyConfig struct {
	Subject     string                 `yaml:"subject"`
	Roles       []string               `yaml:"roles,omitempty"`
	Permissions []string               `yaml:"permissions,omitempty"`
	Claims      map[string]interface{} `yaml:"claims,omitempty"`
}

// JWTConfig controls JWT authentication
type JWTConfig struct {
	Secret        string   `yaml:"secret"`
	PublicKeyFile string   `yaml:"public_key_file"`
	Issuer        string   `yaml:"issuer"`
	Audience      []string `yaml:"audience"`
	Algorithm     string   `yaml:"algorithm"` // HS256, RS256, etc.
}

// RateLimitConfig controls rate limiting
type RateLimitConfig struct {
	// Enabled controls whether rate limiting is active
	Enabled bool `yaml:"enabled"`

	// RequestsPerMin sets the sustained rate limit (requests per minute)
	RequestsPerMin int `yaml:"requests_per_min"`

	// Burst allows short bursts above the sustained rate
	// If not set, defaults to RequestsPerMin
	Burst int `yaml:"burst"`

	// CleanupIntervalSec controls how often to remove idle clients (in seconds)
	// Defaults to 600 (10 minutes)
	CleanupIntervalSec int `yaml:"cleanup_interval_sec"`

	// MaxIdleSec is how long a client can be idle before cleanup (in seconds)
	// Defaults to 1800 (30 minutes)
	MaxIdleSec int `yaml:"max_idle_sec"`
}

// MetricsConfig controls metrics endpoint
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	Port    int    `yaml:"port"`
}

// HealthConfig controls health check endpoint
type HealthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// StorageConfig controls storage backend for metadata
type StorageConfig struct {
	Backend string `yaml:"backend"`
	Path    string `yaml:"path"`
}

// RNGConfig controls random number generation settings
type RNGConfig struct {
	// Mode specifies the RNG source to use.
	// Valid values: "auto", "software", "tpm2", "pkcs11"
	// Default: "auto" (automatically selects best available hardware RNG)
	Mode string `yaml:"mode"`

	// FallbackMode specifies the RNG source to use if primary mode fails.
	// Valid values: "software", "tpm2", "pkcs11", "" (empty means no fallback)
	// Default: "software"
	FallbackMode string `yaml:"fallback_mode"`

	// TPM2 contains TPM2-specific RNG settings (used when mode is "tpm2" or "auto")
	TPM2 *RNGTPM2Config `yaml:"tpm2,omitempty"`

	// PKCS11 contains PKCS#11-specific RNG settings (used when mode is "pkcs11" or "auto")
	PKCS11 *RNGPKCS11Config `yaml:"pkcs11,omitempty"`
}

// RNGTPM2Config contains TPM2-specific RNG settings
type RNGTPM2Config struct {
	// Device path to the TPM device (default: "/dev/tpm0")
	Device string `yaml:"device"`

	// UseSimulator indicates whether to connect to a TPM simulator
	UseSimulator bool `yaml:"use_simulator"`

	// SimulatorHost is the hostname of the TPM simulator (default: "localhost")
	SimulatorHost string `yaml:"simulator_host"`

	// SimulatorPort is the TCP port of the TPM simulator (default: 2321)
	SimulatorPort int `yaml:"simulator_port"`
}

// RNGPKCS11Config contains PKCS#11-specific RNG settings
type RNGPKCS11Config struct {
	// Module path to the PKCS#11 library
	Module string `yaml:"module"`

	// SlotID specifies the PKCS#11 slot containing the RNG
	SlotID uint `yaml:"slot_id"`

	// PINRequired indicates if the slot requires PIN authentication
	PINRequired bool `yaml:"pin_required"`

	// PIN is the authentication PIN (if PINRequired is true)
	// Note: Consider using environment variable KEYCHAIN_RNG_PKCS11_PIN instead
	PIN string `yaml:"pin,omitempty"`
}

// DefaultConfig specifies the default backend for key operations
type DefaultConfig string

// BackendsConfig contains configuration for all backend types
type BackendsConfig struct {
	Software *SoftwareConfig `yaml:"software,omitempty"`
	PKCS8    *PKCS8Config    `yaml:"pkcs8,omitempty"`
	TPM2     *TPM2Config     `yaml:"tpm2,omitempty"`
	PKCS11   *PKCS11Config   `yaml:"pkcs11,omitempty"`
	AWSKMS   *AWSKMSConfig   `yaml:"awskms,omitempty"`
	GCPKMS   *GCPKMSConfig   `yaml:"gcpkms,omitempty"`
	AzureKV  *AzureKVConfig  `yaml:"azurekv,omitempty"`
	Vault    *VaultConfig    `yaml:"vault,omitempty"`
}

// SoftwareConfig contains software backend settings (uses PKCS#8 internally)
type SoftwareConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// PKCS8Config contains PKCS#8 backend settings
type PKCS8Config struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// TPM2Config contains TPM 2.0 backend settings
type TPM2Config struct {
	Enabled    bool   `yaml:"enabled"`
	DevicePath string `yaml:"device_path"`
}

// PKCS11Config contains PKCS#11 backend settings
type PKCS11Config struct {
	Enabled bool   `yaml:"enabled"`
	Library string `yaml:"library"`
	Token   string `yaml:"token"`
	Pin     string `yaml:"pin"`
}

// AWSKMSConfig contains AWS KMS backend settings
type AWSKMSConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Region    string `yaml:"region"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Endpoint  string `yaml:"endpoint"`
}

// GCPKMSConfig contains GCP KMS backend settings
type GCPKMSConfig struct {
	Enabled     bool   `yaml:"enabled"`
	ProjectID   string `yaml:"project_id"`
	Location    string `yaml:"location"`
	KeyRing     string `yaml:"key_ring"`
	Credentials string `yaml:"credentials_file"`
}

// AzureKVConfig contains Azure Key Vault backend settings
type AzureKVConfig struct {
	Enabled      bool   `yaml:"enabled"`
	VaultURL     string `yaml:"vault_url"`
	TenantID     string `yaml:"tenant_id"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// VaultConfig contains HashiCorp Vault backend settings
type VaultConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Address   string `yaml:"address"`
	Token     string `yaml:"token"`
	Namespace string `yaml:"namespace"`
	MountPath string `yaml:"mount_path"`
}

// Load reads configuration from a YAML file and applies environment variable overrides
func Load(path string) (*Config, error) {
	// Read the config file
	// #nosec G304 - Config file path is provided by admin/user
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply environment variable overrides
	applyEnvOverrides(&cfg)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// applyEnvOverrides applies environment variable overrides to the configuration
func applyEnvOverrides(cfg *Config) {
	// Server settings
	if host := os.Getenv("KEYCHAIN_HOST"); host != "" {
		cfg.Server.Host = host
	}
	// Support legacy KEYSTORE_HOST
	if host := os.Getenv("KEYSTORE_HOST"); host != "" {
		cfg.Server.Host = host
	}

	if restPort := os.Getenv("KEYCHAIN_REST_PORT"); restPort != "" {
		if port, err := strconv.Atoi(restPort); err == nil && port >= 1 && port <= 65535 {
			cfg.Server.RESTPort = port
		}
	}
	// Support legacy KEYSTORE_REST_PORT
	if restPort := os.Getenv("KEYSTORE_REST_PORT"); restPort != "" {
		port, err := strconv.Atoi(restPort)
		if err != nil {
			log.Printf("Warning: invalid KEYSTORE_REST_PORT value %q, using default %d: %v",
				restPort, cfg.Server.RESTPort, err)
		} else if port < 1 || port > 65535 {
			log.Printf("Warning: invalid KEYSTORE_REST_PORT value %q (out of range 1-65535), using default %d",
				restPort, cfg.Server.RESTPort)
		} else {
			cfg.Server.RESTPort = port
		}
	}

	if grpcPort := os.Getenv("KEYCHAIN_GRPC_PORT"); grpcPort != "" {
		if port, err := strconv.Atoi(grpcPort); err == nil && port >= 1 && port <= 65535 {
			cfg.Server.GRPCPort = port
		}
	}
	// Support legacy KEYSTORE_GRPC_PORT
	if grpcPort := os.Getenv("KEYSTORE_GRPC_PORT"); grpcPort != "" {
		port, err := strconv.Atoi(grpcPort)
		if err != nil {
			log.Printf("Warning: invalid KEYSTORE_GRPC_PORT value %q, using default %d: %v",
				grpcPort, cfg.Server.GRPCPort, err)
		} else if port < 1 || port > 65535 {
			log.Printf("Warning: invalid KEYSTORE_GRPC_PORT value %q (out of range 1-65535), using default %d",
				grpcPort, cfg.Server.GRPCPort)
		} else {
			cfg.Server.GRPCPort = port
		}
	}

	if quicPort := os.Getenv("KEYCHAIN_QUIC_PORT"); quicPort != "" {
		if port, err := strconv.Atoi(quicPort); err == nil && port >= 1 && port <= 65535 {
			cfg.Server.QUICPort = port
		}
	}
	// Support legacy KEYSTORE_QUIC_PORT
	if quicPort := os.Getenv("KEYSTORE_QUIC_PORT"); quicPort != "" {
		port, err := strconv.Atoi(quicPort)
		if err != nil {
			log.Printf("Warning: invalid KEYSTORE_QUIC_PORT value %q, using default %d: %v",
				quicPort, cfg.Server.QUICPort, err)
		} else if port < 1 || port > 65535 {
			log.Printf("Warning: invalid KEYSTORE_QUIC_PORT value %q (out of range 1-65535), using default %d",
				quicPort, cfg.Server.QUICPort)
		} else {
			cfg.Server.QUICPort = port
		}
	}

	if mcpPort := os.Getenv("KEYCHAIN_MCP_PORT"); mcpPort != "" {
		if port, err := strconv.Atoi(mcpPort); err == nil && port >= 1 && port <= 65535 {
			cfg.Server.MCPPort = port
		}
	}
	// Support legacy KEYSTORE_MCP_PORT
	if mcpPort := os.Getenv("KEYSTORE_MCP_PORT"); mcpPort != "" {
		port, err := strconv.Atoi(mcpPort)
		if err != nil {
			log.Printf("Warning: invalid KEYSTORE_MCP_PORT value %q, using default %d: %v",
				mcpPort, cfg.Server.MCPPort, err)
		} else if port < 1 || port > 65535 {
			log.Printf("Warning: invalid KEYSTORE_MCP_PORT value %q (out of range 1-65535), using default %d",
				mcpPort, cfg.Server.MCPPort)
		} else {
			cfg.Server.MCPPort = port
		}
	}

	// Unix socket settings
	if socketPath := os.Getenv("KEYCHAIN_SOCKET_PATH"); socketPath != "" {
		cfg.Unix.SocketPath = socketPath
	}
	if socketMode := os.Getenv("KEYCHAIN_SOCKET_MODE"); socketMode != "" {
		cfg.Unix.SocketMode = socketMode
	}
	if protocol := os.Getenv("KEYCHAIN_UNIX_PROTOCOL"); protocol != "" {
		cfg.Unix.Protocol = protocol
	}

	// Logging
	if level := os.Getenv("KEYCHAIN_LOG_LEVEL"); level != "" {
		cfg.Logging.Level = level
	}
	// Support legacy KEYSTORE_LOG_LEVEL
	if level := os.Getenv("KEYSTORE_LOG_LEVEL"); level != "" {
		cfg.Logging.Level = level
	}

	if format := os.Getenv("KEYCHAIN_LOG_FORMAT"); format != "" {
		cfg.Logging.Format = format
	}
	// Support legacy KEYSTORE_LOG_FORMAT
	if format := os.Getenv("KEYSTORE_LOG_FORMAT"); format != "" {
		cfg.Logging.Format = format
	}

	// Storage
	if dataDir := os.Getenv("KEYCHAIN_DATA_DIR"); dataDir != "" {
		cfg.Storage.Path = dataDir
		// Also update backend paths relative to data dir
		if cfg.Backends.PKCS8 != nil && cfg.Backends.PKCS8.Path != "" {
			if !filepath.IsAbs(cfg.Backends.PKCS8.Path) {
				cfg.Backends.PKCS8.Path = filepath.Join(dataDir, "pkcs8")
			}
		}
	}
	// Support legacy KEYSTORE_DATA_DIR
	if dataDir := os.Getenv("KEYSTORE_DATA_DIR"); dataDir != "" {
		cfg.Storage.Path = dataDir
		// Also update backend paths relative to data dir
		if cfg.Backends.PKCS8 != nil && cfg.Backends.PKCS8.Path != "" {
			if !filepath.IsAbs(cfg.Backends.PKCS8.Path) {
				cfg.Backends.PKCS8.Path = filepath.Join(dataDir, "pkcs8")
			}
		}
	}

	// TPM2 settings
	if tpmPath := os.Getenv("TPM_DEVICE_PATH"); tpmPath != "" && cfg.Backends.TPM2 != nil {
		cfg.Backends.TPM2.DevicePath = tpmPath
	}

	// PKCS#11 settings
	if pkcs11Lib := os.Getenv("PKCS11_LIBRARY"); pkcs11Lib != "" && cfg.Backends.PKCS11 != nil {
		cfg.Backends.PKCS11.Library = pkcs11Lib
	}

	// AWS KMS settings
	if cfg.Backends.AWSKMS != nil {
		if region := os.Getenv("AWS_REGION"); region != "" {
			cfg.Backends.AWSKMS.Region = region
		}
		if accessKey := os.Getenv("AWS_ACCESS_KEY_ID"); accessKey != "" {
			cfg.Backends.AWSKMS.AccessKey = accessKey
		}
		if secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey != "" {
			cfg.Backends.AWSKMS.SecretKey = secretKey
		}
		if endpoint := os.Getenv("AWS_ENDPOINT"); endpoint != "" {
			cfg.Backends.AWSKMS.Endpoint = endpoint
		}
	}

	// GCP KMS settings
	if cfg.Backends.GCPKMS != nil {
		if projectID := os.Getenv("GCP_PROJECT_ID"); projectID != "" {
			cfg.Backends.GCPKMS.ProjectID = projectID
		}
		if credsFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); credsFile != "" {
			cfg.Backends.GCPKMS.Credentials = credsFile
		}
	}

	// Azure Key Vault settings
	if cfg.Backends.AzureKV != nil {
		if vaultURL := os.Getenv("AZURE_KEYVAULT_URL"); vaultURL != "" {
			cfg.Backends.AzureKV.VaultURL = vaultURL
		}
		if tenantID := os.Getenv("AZURE_TENANT_ID"); tenantID != "" {
			cfg.Backends.AzureKV.TenantID = tenantID
		}
		if clientID := os.Getenv("AZURE_CLIENT_ID"); clientID != "" {
			cfg.Backends.AzureKV.ClientID = clientID
		}
		if clientSecret := os.Getenv("AZURE_CLIENT_SECRET"); clientSecret != "" {
			cfg.Backends.AzureKV.ClientSecret = clientSecret
		}
	}

	// Vault settings
	if cfg.Backends.Vault != nil {
		if addr := os.Getenv("VAULT_ADDR"); addr != "" {
			cfg.Backends.Vault.Address = addr
		}
		if token := os.Getenv("VAULT_TOKEN"); token != "" {
			cfg.Backends.Vault.Token = token
		}
		if namespace := os.Getenv("VAULT_NAMESPACE"); namespace != "" {
			cfg.Backends.Vault.Namespace = namespace
		}
	}

	// Rate limiting settings
	if enabled := os.Getenv("KEYCHAIN_RATELIMIT_ENABLED"); enabled != "" {
		cfg.RateLimit.Enabled = strings.ToLower(enabled) == "true"
	}
	// Support legacy KEYSTORE_RATELIMIT_ENABLED
	if enabled := os.Getenv("KEYSTORE_RATELIMIT_ENABLED"); enabled != "" {
		cfg.RateLimit.Enabled = strings.ToLower(enabled) == "true"
	}

	if rpm := os.Getenv("KEYCHAIN_RATELIMIT_REQUESTS_PER_MIN"); rpm != "" {
		if val, err := strconv.Atoi(rpm); err == nil && val > 0 {
			cfg.RateLimit.RequestsPerMin = val
		}
	}
	// Support legacy KEYSTORE_RATELIMIT_REQUESTS_PER_MIN
	if rpm := os.Getenv("KEYSTORE_RATELIMIT_REQUESTS_PER_MIN"); rpm != "" {
		if val, err := strconv.Atoi(rpm); err == nil && val > 0 {
			cfg.RateLimit.RequestsPerMin = val
		}
	}

	if burst := os.Getenv("KEYCHAIN_RATELIMIT_BURST"); burst != "" {
		if val, err := strconv.Atoi(burst); err == nil && val > 0 {
			cfg.RateLimit.Burst = val
		}
	}
	// Support legacy KEYSTORE_RATELIMIT_BURST
	if burst := os.Getenv("KEYSTORE_RATELIMIT_BURST"); burst != "" {
		if val, err := strconv.Atoi(burst); err == nil && val > 0 {
			cfg.RateLimit.Burst = val
		}
	}

	// RNG settings
	if mode := os.Getenv("KEYCHAIN_RNG_MODE"); mode != "" {
		cfg.RNG.Mode = mode
	}
	if fallback := os.Getenv("KEYCHAIN_RNG_FALLBACK"); fallback != "" {
		cfg.RNG.FallbackMode = fallback
	}
	// TPM2 RNG settings
	if tpmDevice := os.Getenv("KEYCHAIN_RNG_TPM2_DEVICE"); tpmDevice != "" {
		if cfg.RNG.TPM2 == nil {
			cfg.RNG.TPM2 = &RNGTPM2Config{}
		}
		cfg.RNG.TPM2.Device = tpmDevice
	}
	if simHost := os.Getenv("KEYCHAIN_RNG_TPM2_SIMULATOR_HOST"); simHost != "" {
		if cfg.RNG.TPM2 == nil {
			cfg.RNG.TPM2 = &RNGTPM2Config{}
		}
		cfg.RNG.TPM2.SimulatorHost = simHost
		cfg.RNG.TPM2.UseSimulator = true
	}
	if simPort := os.Getenv("KEYCHAIN_RNG_TPM2_SIMULATOR_PORT"); simPort != "" {
		if val, err := strconv.Atoi(simPort); err == nil && val > 0 {
			if cfg.RNG.TPM2 == nil {
				cfg.RNG.TPM2 = &RNGTPM2Config{}
			}
			cfg.RNG.TPM2.SimulatorPort = val
			cfg.RNG.TPM2.UseSimulator = true
		}
	}
	// PKCS#11 RNG settings
	if pkcs11Module := os.Getenv("KEYCHAIN_RNG_PKCS11_MODULE"); pkcs11Module != "" {
		if cfg.RNG.PKCS11 == nil {
			cfg.RNG.PKCS11 = &RNGPKCS11Config{}
		}
		cfg.RNG.PKCS11.Module = pkcs11Module
	}
	if slotID := os.Getenv("KEYCHAIN_RNG_PKCS11_SLOT"); slotID != "" {
		if val, err := strconv.ParseUint(slotID, 10, 32); err == nil {
			if cfg.RNG.PKCS11 == nil {
				cfg.RNG.PKCS11 = &RNGPKCS11Config{}
			}
			cfg.RNG.PKCS11.SlotID = uint(val)
		}
	}
	if pin := os.Getenv("KEYCHAIN_RNG_PKCS11_PIN"); pin != "" {
		if cfg.RNG.PKCS11 == nil {
			cfg.RNG.PKCS11 = &RNGPKCS11Config{}
		}
		cfg.RNG.PKCS11.PIN = pin
		cfg.RNG.PKCS11.PINRequired = true
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate server ports
	if c.Protocols.REST && (c.Server.RESTPort < 1 || c.Server.RESTPort > 65535) {
		return fmt.Errorf("invalid REST port: %d", c.Server.RESTPort)
	}
	if c.Protocols.GRPC && (c.Server.GRPCPort < 1 || c.Server.GRPCPort > 65535) {
		return fmt.Errorf("invalid gRPC port: %d", c.Server.GRPCPort)
	}
	if c.Protocols.QUIC && (c.Server.QUICPort < 1 || c.Server.QUICPort > 65535) {
		return fmt.Errorf("invalid QUIC port: %d", c.Server.QUICPort)
	}
	if c.Protocols.MCP && (c.Server.MCPPort < 1 || c.Server.MCPPort > 65535) {
		return fmt.Errorf("invalid MCP port: %d", c.Server.MCPPort)
	}

	// Validate at least one protocol is enabled (Unix socket counts as a protocol)
	if !c.Protocols.Unix && !c.Protocols.REST && !c.Protocols.GRPC && !c.Protocols.QUIC && !c.Protocols.MCP {
		return fmt.Errorf("at least one protocol must be enabled")
	}

	// Validate Unix socket protocol
	if c.Unix.Enabled && c.Unix.Protocol != "" {
		validProtocols := map[string]bool{
			"grpc": true,
			"http": true,
		}
		if !validProtocols[strings.ToLower(c.Unix.Protocol)] {
			return fmt.Errorf("invalid Unix socket protocol: %s (must be grpc or http)", c.Unix.Protocol)
		}
	}

	// Validate logging level
	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	if !validLevels[strings.ToLower(c.Logging.Level)] {
		return fmt.Errorf("invalid log level: %s (must be debug, info, warn, error, or fatal)", c.Logging.Level)
	}

	// Validate logging format
	validFormats := map[string]bool{
		"json": true, "text": true, "console": true,
	}
	if !validFormats[strings.ToLower(c.Logging.Format)] {
		return fmt.Errorf("invalid log format: %s (must be json, text, or console)", c.Logging.Format)
	}

	// Validate TLS settings
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" {
			return fmt.Errorf("TLS cert_file is required when TLS is enabled")
		}
		if c.TLS.KeyFile == "" {
			return fmt.Errorf("TLS key_file is required when TLS is enabled")
		}
	}

	// Validate storage
	if c.Storage.Backend == "" {
		return fmt.Errorf("storage backend must be specified")
	}
	if c.Storage.Path == "" {
		return fmt.Errorf("storage path must be specified")
	}

	// Validate RNG mode
	if c.RNG.Mode != "" {
		validModes := map[string]bool{
			"auto": true, "software": true, "tpm2": true, "pkcs11": true,
		}
		if !validModes[strings.ToLower(c.RNG.Mode)] {
			return fmt.Errorf("invalid RNG mode: %s (must be auto, software, tpm2, or pkcs11)", c.RNG.Mode)
		}
	}
	if c.RNG.FallbackMode != "" {
		validModes := map[string]bool{
			"software": true, "tpm2": true, "pkcs11": true,
		}
		if !validModes[strings.ToLower(c.RNG.FallbackMode)] {
			return fmt.Errorf("invalid RNG fallback mode: %s (must be software, tpm2, or pkcs11)", c.RNG.FallbackMode)
		}
	}

	// Validate default backend
	if string(c.Default) == "" {
		return fmt.Errorf("default_backend must be specified")
	}

	// Validate at least one backend is enabled
	hasEnabledBackend := false
	if c.Backends.Software != nil && c.Backends.Software.Enabled {
		hasEnabledBackend = true
		if c.Backends.Software.Path == "" {
			return fmt.Errorf("software backend path is required when enabled")
		}
	}
	if c.Backends.PKCS8 != nil && c.Backends.PKCS8.Enabled {
		hasEnabledBackend = true
		if c.Backends.PKCS8.Path == "" {
			return fmt.Errorf("PKCS8 backend path is required when enabled")
		}
	}
	if c.Backends.TPM2 != nil && c.Backends.TPM2.Enabled {
		hasEnabledBackend = true
		if c.Backends.TPM2.DevicePath == "" {
			return fmt.Errorf("TPM2 device_path is required when enabled")
		}
	}
	if c.Backends.PKCS11 != nil && c.Backends.PKCS11.Enabled {
		hasEnabledBackend = true
		if c.Backends.PKCS11.Library == "" {
			return fmt.Errorf("PKCS11 library is required when enabled")
		}
	}
	if c.Backends.AWSKMS != nil && c.Backends.AWSKMS.Enabled {
		hasEnabledBackend = true
	}
	if c.Backends.GCPKMS != nil && c.Backends.GCPKMS.Enabled {
		hasEnabledBackend = true
	}
	if c.Backends.AzureKV != nil && c.Backends.AzureKV.Enabled {
		hasEnabledBackend = true
	}
	if c.Backends.Vault != nil && c.Backends.Vault.Enabled {
		hasEnabledBackend = true
	}

	if !hasEnabledBackend {
		return fmt.Errorf("at least one backend must be enabled")
	}

	return nil
}

// GetRateLimitConfig returns a ratelimit.Config from the configuration
// This provides a convenient way to create a rate limiter from config
func (c *Config) GetRateLimitConfig() *RateLimitConfig {
	return &c.RateLimit
}

// GetEnabledBackends returns a list of enabled backend names
func (c *Config) GetEnabledBackends() []string {
	var backends []string
	if c.Backends.Software != nil && c.Backends.Software.Enabled {
		backends = append(backends, "software")
	}
	if c.Backends.PKCS8 != nil && c.Backends.PKCS8.Enabled {
		backends = append(backends, "pkcs8")
	}
	if c.Backends.TPM2 != nil && c.Backends.TPM2.Enabled {
		backends = append(backends, "tpm2")
	}
	if c.Backends.PKCS11 != nil && c.Backends.PKCS11.Enabled {
		backends = append(backends, "pkcs11")
	}
	if c.Backends.AWSKMS != nil && c.Backends.AWSKMS.Enabled {
		backends = append(backends, "awskms")
	}
	if c.Backends.GCPKMS != nil && c.Backends.GCPKMS.Enabled {
		backends = append(backends, "gcpkms")
	}
	if c.Backends.AzureKV != nil && c.Backends.AzureKV.Enabled {
		backends = append(backends, "azurekv")
	}
	if c.Backends.Vault != nil && c.Backends.Vault.Enabled {
		backends = append(backends, "vault")
	}
	return backends
}

// GetRNGConfig returns the RNG configuration with defaults applied.
// The returned RNGConfig can be converted to pkg/crypto/rand.Config.
func (c *Config) GetRNGConfig() *RNGConfig {
	cfg := c.RNG

	// Apply defaults
	if cfg.Mode == "" {
		cfg.Mode = "auto"
	}
	if cfg.FallbackMode == "" {
		cfg.FallbackMode = "software"
	}

	return &cfg
}
