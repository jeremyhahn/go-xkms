// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package service

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// Config is the top-level multi-account ACME client configuration.
type Config struct {
	TenantID     string                      `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty" mapstructure:"tenant_id"`
	Storage      StorageConfig               `yaml:"storage" json:"storage" mapstructure:"storage"`
	XKMS         XKMSConfig                  `yaml:"xkms" json:"xkms" mapstructure:"xkms"`
	Logging      LoggingConfig               `yaml:"logging" json:"logging" mapstructure:"logging"`
	Challenge    ChallengeConfig             `yaml:"challenge" json:"challenge" mapstructure:"challenge"`
	Accounts     map[string]*AccountConfig   `yaml:"accounts" json:"accounts" mapstructure:"accounts"`
	Certificates map[string]*CertificateSpec `yaml:"certificates" json:"certificates" mapstructure:"certificates"`

	// Deprecated: Client exists for backward compatibility with the single-account
	// ServiceImpl. It will be removed when ServiceImpl is replaced in Phase 4.
	Client ClientConfig `yaml:"-" json:"-"`

	// Deprecated: Renewal exists for backward compatibility with the single-account
	// ServiceImpl. It will be removed when ServiceImpl is replaced in Phase 4.
	Renewal RenewalConfig `yaml:"-" json:"-"`

	// Deprecated: SDK exists for backward compatibility with the single-account
	// SDKServiceImpl. It will be removed when SDKServiceImpl is replaced in Phase 4.
	SDK *SDKConfig `yaml:"-" json:"-"`
}

// AccountConfig holds per-account ACME settings including directory URL,
// contact information, key configuration, and transport options.
type AccountConfig struct {
	DirectoryURL        string     `yaml:"directory" json:"directory" mapstructure:"directory"`
	Email               string     `yaml:"email" json:"email" mapstructure:"email"`
	Key                 *KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	Transport           string     `yaml:"transport,omitempty" json:"transport,omitempty" mapstructure:"transport"`
	ServerAddr          string     `yaml:"server_addr,omitempty" json:"server_addr,omitempty" mapstructure:"server_addr"`
	EAB                 *EABConfig `yaml:"eab,omitempty" json:"eab,omitempty" mapstructure:"eab"`
	TrustedRoots        []string   `yaml:"trusted_roots,omitempty" json:"trusted_roots,omitempty" mapstructure:"trusted_roots"`
	RequestServerBundle bool       `yaml:"request_server_bundle,omitempty" json:"request_server_bundle,omitempty" mapstructure:"request_server_bundle"`
}

// KeyConfig defines cryptographic key parameters for account or certificate keys.
// It is independent of go-trusted-platform and maps directly to go-xkms KeyAttributes
// via the ToKeyAttributes() conversion method.
type KeyConfig struct {
	Algorithm string     `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Store     string     `yaml:"store" json:"store" mapstructure:"store"`
	Hash      string     `yaml:"hash,omitempty" json:"hash,omitempty" mapstructure:"hash"`
	ECC       *ECCConfig `yaml:"ecc,omitempty" json:"ecc,omitempty" mapstructure:"ecc"`
	RSA       *RSAConfig `yaml:"rsa,omitempty" json:"rsa,omitempty" mapstructure:"rsa"`
	Password  string     `yaml:"password,omitempty" json:"password,omitempty" mapstructure:"password"`
}

// ECCConfig holds elliptic curve cryptography parameters.
type ECCConfig struct {
	Curve string `yaml:"curve" json:"curve" mapstructure:"curve"`
}

// RSAConfig holds RSA key parameters.
type RSAConfig struct {
	KeySize int `yaml:"key_size" json:"key_size" mapstructure:"key_size"`
}

// EABConfig holds External Account Binding credentials for ACME registration.
type EABConfig struct {
	KID     string `yaml:"kid" json:"kid" mapstructure:"kid"`
	HMACKey string `yaml:"hmac_key" json:"hmac_key" mapstructure:"hmac_key"`
}

// CertificateSpec defines the desired state for a managed certificate including
// subject, SANs, key configuration, challenge type, and lifecycle settings.
type CertificateSpec struct {
	Account     string             `yaml:"account" json:"account" mapstructure:"account"`
	Subject     SubjectConfig      `yaml:"subject" json:"subject" mapstructure:"subject"`
	SANs        SANsConfig         `yaml:"sans,omitempty" json:"sans,omitempty" mapstructure:"sans"`
	Key         *KeyConfig         `yaml:"key" json:"key" mapstructure:"key"`
	Challenge   string             `yaml:"challenge" json:"challenge" mapstructure:"challenge"`
	ValidDays   int                `yaml:"valid,omitempty" json:"valid,omitempty" mapstructure:"valid"`
	Deploy      *DeployConfig      `yaml:"deploy,omitempty" json:"deploy,omitempty" mapstructure:"deploy"`
	Renewal     *CertRenewalConfig `yaml:"renewal,omitempty" json:"renewal,omitempty" mapstructure:"renewal"`
	CrossSigner *CrossSignerRef    `yaml:"cross_signer,omitempty" json:"cross_signer,omitempty" mapstructure:"cross_signer"`
}

// SubjectConfig holds X.509 subject distinguished name fields.
type SubjectConfig struct {
	CN           string   `yaml:"cn" json:"cn" mapstructure:"cn"`
	Organization []string `yaml:"organization,omitempty" json:"organization,omitempty" mapstructure:"organization"`
	Country      []string `yaml:"country,omitempty" json:"country,omitempty" mapstructure:"country"`
	Province     []string `yaml:"province,omitempty" json:"province,omitempty" mapstructure:"province"`
	Locality     []string `yaml:"locality,omitempty" json:"locality,omitempty" mapstructure:"locality"`
}

// SANsConfig holds Subject Alternative Name entries for certificate requests.
type SANsConfig struct {
	DNS   []string `yaml:"dns,omitempty" json:"dns,omitempty" mapstructure:"dns"`
	IP    []string `yaml:"ip,omitempty" json:"ip,omitempty" mapstructure:"ip"`
	Email []string `yaml:"email,omitempty" json:"email,omitempty" mapstructure:"email"`
	URI   []string `yaml:"uri,omitempty" json:"uri,omitempty" mapstructure:"uri"`
}

// DeployConfig specifies where to write issued certificates and keys,
// and an optional post-deployment hook command.
type DeployConfig struct {
	CertPath string `yaml:"cert_path" json:"cert_path" mapstructure:"cert_path"`
	KeyPath  string `yaml:"key_path" json:"key_path" mapstructure:"key_path"`
	PostHook string `yaml:"post_hook,omitempty" json:"post_hook,omitempty" mapstructure:"post_hook"`
}

// CertRenewalConfig controls automatic certificate renewal behavior.
type CertRenewalConfig struct {
	Auto       bool `yaml:"auto" json:"auto" mapstructure:"auto"`
	DaysBefore int  `yaml:"days_before" json:"days_before" mapstructure:"days_before"`
}

// CrossSignerRef identifies a secondary ACME account or directory to use
// for cross-signing a certificate.
type CrossSignerRef struct {
	Account   string `yaml:"account,omitempty" json:"account,omitempty" mapstructure:"account"`
	Directory string `yaml:"directory,omitempty" json:"directory,omitempty" mapstructure:"directory"`
	Challenge string `yaml:"challenge" json:"challenge" mapstructure:"challenge"`
}

// StorageConfig defines the backend used for persistent client state storage.
type StorageConfig struct {
	Backend string                 `yaml:"backend" json:"backend" mapstructure:"backend"`
	Options map[string]interface{} `yaml:"options" json:"options" mapstructure:"options"`
}

// XKMSConfig defines the backend used for cryptographic key management.
type XKMSConfig struct {
	Backend string                 `yaml:"backend" json:"backend" mapstructure:"backend"`
	Options map[string]interface{} `yaml:"options" json:"options" mapstructure:"options"`
}

// LoggingConfig controls the structured logging output for the ACME client.
type LoggingConfig struct {
	Level  string `yaml:"level" json:"level" mapstructure:"level"`
	Format string `yaml:"format" json:"format" mapstructure:"format"`
	Output string `yaml:"output" json:"output" mapstructure:"output"`
}

// ChallengeConfig holds settings for ACME challenge solvers.
type ChallengeConfig struct {
	HTTP01 HTTP01Config `yaml:"http01" json:"http01" mapstructure:"http01"`
	DNS01  DNS01Config  `yaml:"dns01" json:"dns01" mapstructure:"dns01"`
}

// HTTP01Config holds settings for the HTTP-01 ACME challenge solver.
type HTTP01Config struct {
	Port     string `yaml:"port" json:"port" mapstructure:"port"`
	WebRoot  string `yaml:"webRoot" json:"webRoot" mapstructure:"webRoot"`
	UseProxy bool   `yaml:"useProxy" json:"useProxy" mapstructure:"useProxy"`
}

// DNS01Config holds settings for the DNS-01 ACME challenge solver.
type DNS01Config struct {
	Provider    string            `yaml:"provider" json:"provider" mapstructure:"provider"`
	Credentials map[string]string `yaml:"credentials" json:"credentials" mapstructure:"credentials"`
	TTL         int               `yaml:"ttl" json:"ttl" mapstructure:"ttl"`
}

// ClientConfig holds ACME client connection settings.
// Deprecated: used by the single-account ServiceImpl. Will be removed in Phase 4.
type ClientConfig struct {
	DirectoryURL        string        `yaml:"directoryURL" json:"directoryURL"`
	AccountEmail        string        `yaml:"accountEmail" json:"accountEmail"`
	Timeout             time.Duration `yaml:"timeout" json:"timeout"`
	RequestServerBundle bool          `yaml:"requestServerBundle" json:"requestServerBundle"`
	TrustedRoots        []string      `yaml:"trustedRoots" json:"trustedRoots"`
	RetryAttempts       int           `yaml:"retryAttempts" json:"retryAttempts"`
	RetryDelay          time.Duration `yaml:"retryDelay" json:"retryDelay"`
	MaxRetryDelay       time.Duration `yaml:"maxRetryDelay" json:"maxRetryDelay"`
}

// RenewalConfig holds automatic certificate renewal settings.
// Deprecated: used by the single-account ServiceImpl. Will be removed in Phase 4.
type RenewalConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	CheckInterval    time.Duration `yaml:"checkInterval" json:"checkInterval"`
	RenewalThreshold float64       `yaml:"renewalThreshold" json:"renewalThreshold"`
	MaxRetries       int           `yaml:"maxRetries" json:"maxRetries"`
	RetryInterval    time.Duration `yaml:"retryInterval" json:"retryInterval"`
	NotifyOnSuccess  bool          `yaml:"notifyOnSuccess" json:"notifyOnSuccess"`
	NotifyOnFailure  bool          `yaml:"notifyOnFailure" json:"notifyOnFailure"`
}

// SDKConfig holds the configuration for the Trusted CA SDK transport.
// Deprecated: used by the single-account SDKServiceImpl. Will be removed in Phase 4.
type SDKConfig struct {
	Transport   string `yaml:"transport" json:"transport"`
	Address     string `yaml:"address" json:"address"`
	TLSCert     string `yaml:"tlsCert" json:"tlsCert"`
	TLSKey      string `yaml:"tlsKey" json:"tlsKey"`
	TLSCA       string `yaml:"tlsCA" json:"tlsCA"`
	TLSInsecure bool   `yaml:"tlsInsecure" json:"tlsInsecure"`
}

// RegisterRequest is the input for account registration.
type RegisterRequest struct {
	Email string
}

// RegisterResponse is the output of account registration.
type RegisterResponse struct {
	Status  string
	Contact []string
}

// CertRequest is the input for requesting a new certificate.
type CertRequest struct {
	Domain        string
	ChallengeType string
	KeyType       string
	KeySize       int
	OutputCert    string
	OutputKey     string
	Port          string
	WebRoot       string
}

// CertResponse is the output of a certificate request.
type CertResponse struct {
	Subject  string
	CertFile string
	KeyFile  string
}

// RenewRequest is the input for renewing an existing certificate.
type RenewRequest struct {
	CertFile      string
	KeyFile       string
	ChallengeType string
	KeyType       string
	OutputCert    string
	OutputKey     string
	Port          string
	WebRoot       string
}

// RenewResponse is the output of a certificate renewal.
type RenewResponse struct {
	Subject   string
	CertFile  string
	KeyFile   string
	NotBefore time.Time
	NotAfter  time.Time
}

// RevokeRequest is the input for revoking a certificate.
type RevokeRequest struct {
	CertFile string
	Reason   acme.CRLReasonCode
}

// EnrollRequest is the input for TPM device enrollment.
type EnrollRequest struct {
	DeviceID   string
	CommonName string
	Port       string
	OutputCert string
	OutputIAK  string
}

// EnrollResponse is the output of TPM device enrollment.
type EnrollResponse struct {
	DeviceID   string
	CommonName string
	CertFile   string
	IAKFile    string
}

// AttestRequest is the input for TPM device attestation.
type AttestRequest struct {
	DeviceID   string
	CommonName string
	Port       string
	PCRs       string
	OutputCert string
}

// AttestResponse is the output of TPM device attestation.
type AttestResponse struct {
	DeviceID   string
	CommonName string
	CertFile   string
	PCRIndices []int
}

// CertificateResult wraps a successfully obtained or renewed certificate
// along with its associated private key.
type CertificateResult struct {
	Certificate *x509.Certificate
	CertFile    string
	KeyFile     string
}

// DefaultConfig returns a Config populated with sensible default values
// for local development and testing.
func DefaultConfig() *Config {
	return &Config{
		Storage: StorageConfig{
			Backend: "filesystem",
			Options: map[string]interface{}{
				"path": "/var/lib/trusted-acme/client-storage",
			},
		},
		XKMS: XKMSConfig{
			Backend: "software",
			Options: map[string]interface{}{
				"path": "/var/lib/trusted-acme/client-keys",
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{
				Port: "80",
			},
			DNS01: DNS01Config{
				TTL: 300,
			},
		},
		Accounts:     make(map[string]*AccountConfig),
		Certificates: make(map[string]*CertificateSpec),
		// Deprecated legacy defaults
		Client: ClientConfig{
			DirectoryURL:  "http://localhost:8080/acme/directory",
			Timeout:       60 * time.Second,
			RetryAttempts: 3,
			RetryDelay:    1 * time.Second,
			MaxRetryDelay: 30 * time.Second,
		},
		Renewal: RenewalConfig{
			Enabled:          true,
			CheckInterval:    24 * time.Hour,
			RenewalThreshold: 0.33,
			MaxRetries:       5,
			RetryInterval:    1 * time.Hour,
			NotifyOnSuccess:  true,
			NotifyOnFailure:  true,
		},
	}
}

// Validate checks that the Config is well-formed and all required fields
// are present. It returns a typed error describing the first validation
// failure encountered.
func (c *Config) Validate() error {
	if len(c.Accounts) == 0 {
		return &ErrValidation{Field: "accounts", Reason: "at least one account must be defined"}
	}
	for name, acct := range c.Accounts {
		if acct.DirectoryURL == "" {
			return &ErrValidation{
				Field:  "accounts." + name + ".directory",
				Reason: "directory URL is required",
			}
		}
		if acct.Email == "" {
			return &ErrValidation{
				Field:  "accounts." + name + ".email",
				Reason: "email is required",
			}
		}
		if acct.Key == nil {
			return &ErrValidation{
				Field:  "accounts." + name + ".key",
				Reason: "key configuration is required",
			}
		}
		if acct.Key.Algorithm == "" {
			return &ErrValidation{
				Field:  "accounts." + name + ".key.algorithm",
				Reason: "key algorithm is required",
			}
		}
		if acct.Key.Store == "" {
			return &ErrValidation{
				Field:  "accounts." + name + ".key.store",
				Reason: "key store is required",
			}
		}
	}
	for name, spec := range c.Certificates {
		if _, ok := c.Accounts[spec.Account]; !ok {
			return &ErrValidation{
				Field:  "certificates." + name + ".account",
				Reason: "references unknown account: " + spec.Account,
			}
		}
		if spec.Subject.CN == "" {
			return &ErrValidation{
				Field:  "certificates." + name + ".subject.cn",
				Reason: "subject common name is required",
			}
		}
		if spec.Key == nil {
			return &ErrValidation{
				Field:  "certificates." + name + ".key",
				Reason: "key configuration is required",
			}
		}
	}
	return nil
}

// logLevelHandlers maps log level strings to their corresponding slog.Level values.
var logLevelHandlers = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

// InitLogger creates a structured logger from the provided LoggingConfig.
func InitLogger(config LoggingConfig) *slog.Logger {
	level, ok := logLevelHandlers[strings.ToLower(config.Level)]
	if !ok {
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var writer *os.File
	switch strings.ToLower(config.Output) {
	case "stderr":
		writer = os.Stderr
	default:
		writer = os.Stdout
	}

	var handler slog.Handler
	switch strings.ToLower(config.Format) {
	case "text":
		handler = slog.NewTextHandler(writer, opts)
	default:
		handler = slog.NewJSONHandler(writer, opts)
	}

	return slog.New(handler)
}

// ParsePCRIndices parses a comma-separated list of PCR indices (0-23).
func ParsePCRIndices(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	indices := make([]int, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var idx int
		if _, err := fmt.Sscanf(part, "%d", &idx); err != nil {
			return nil, ErrInvalidPCRFormat{Value: part}
		}
		if idx < 0 || idx > 23 {
			return nil, ErrInvalidPCRIndex{Index: idx}
		}
		indices = append(indices, idx)
	}

	return indices, nil
}
