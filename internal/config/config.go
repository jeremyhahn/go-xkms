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
	Logging   LoggingConfig   `yaml:"logging"`
	TLS       TLSConfig       `yaml:"tls"`
	Auth      AuthConfig      `yaml:"auth"`
	RateLimit RateLimitConfig `yaml:"ratelimit"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Health    HealthConfig    `yaml:"health"`
	Storage   StorageConfig   `yaml:"storage"`
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
	REST bool `yaml:"rest"`
	GRPC bool `yaml:"grpc"`
	QUIC bool `yaml:"quic"`
	MCP  bool `yaml:"mcp"`
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
	Enabled        bool `yaml:"enabled"`
	RequestsPerMin int  `yaml:"requests_per_min"`
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

// DefaultConfig specifies the default backend for key operations
type DefaultConfig string

// BackendsConfig contains configuration for all backend types
type BackendsConfig struct {
	PKCS8   *PKCS8Config   `yaml:"pkcs8,omitempty"`
	TPM2    *TPM2Config    `yaml:"tpm2,omitempty"`
	PKCS11  *PKCS11Config  `yaml:"pkcs11,omitempty"`
	AWSKMS  *AWSKMSConfig  `yaml:"awskms,omitempty"`
	GCPKMS  *GCPKMSConfig  `yaml:"gcpkms,omitempty"`
	AzureKV *AzureKVConfig `yaml:"azurekv,omitempty"`
	Vault   *VaultConfig   `yaml:"vault,omitempty"`
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
	if host := os.Getenv("KEYSTORE_HOST"); host != "" {
		cfg.Server.Host = host
	}
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

	// Logging
	if level := os.Getenv("KEYSTORE_LOG_LEVEL"); level != "" {
		cfg.Logging.Level = level
	}
	if format := os.Getenv("KEYSTORE_LOG_FORMAT"); format != "" {
		cfg.Logging.Format = format
	}

	// Storage
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

	// Validate at least one protocol is enabled
	if !c.Protocols.REST && !c.Protocols.GRPC && !c.Protocols.QUIC && !c.Protocols.MCP {
		return fmt.Errorf("at least one protocol must be enabled")
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

	// Validate default backend
	if string(c.Default) == "" {
		return fmt.Errorf("default_backend must be specified")
	}

	// Validate at least one backend is enabled
	hasEnabledBackend := false
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

// GetEnabledBackends returns a list of enabled backend names
func (c *Config) GetEnabledBackends() []string {
	var backends []string
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
