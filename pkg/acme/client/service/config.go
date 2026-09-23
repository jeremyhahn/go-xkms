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

package service

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
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
	Devices      map[string]*DeviceSpec      `yaml:"devices,omitempty" json:"devices,omitempty" mapstructure:"devices"`
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

// DeviceSpec defines the desired state for a managed TPM device identity:
// the account used to enroll and attest it via the enroll-01 and
// device-attest-01 ACME challenges, the TPM to open, and the PCR selection
// used for attestation quotes.
type DeviceSpec struct {
	// Account names the AccountConfig this device enrolls and attests
	// through, exactly as CertificateSpec.Account does for certificates.
	Account string `yaml:"account" json:"account" mapstructure:"account"`

	// CommonName is the subject common name requested for the device's
	// IAK/IDevID certificate (enroll-01) or attestation certificate
	// (device-attest-01).
	CommonName string `yaml:"common-name" json:"common_name" mapstructure:"common-name"`

	// Identifier is the ACME permanent-identifier authorization value that
	// names this device to the CA — typically its IP address or hostname.
	// ${ENV_VAR} references are expanded at enrollment/attestation time.
	Identifier string `yaml:"identifier" json:"identifier" mapstructure:"identifier"`

	// TPM selects and configures the TPM 2.0 device, or the in-process
	// simulator, this spec enrolls and attests. Nil selects go-xkms's own
	// TPM2 defaults (the in-process simulator) — development and testing
	// only.
	TPM *DeviceTPMConfig `yaml:"tpm,omitempty" json:"tpm,omitempty" mapstructure:"tpm"`

	// PCRSelection lists the PCR indices (0-23) quoted for device-attest-01.
	PCRSelection []int `yaml:"pcr-selection,omitempty" json:"pcr_selection,omitempty" mapstructure:"pcr-selection"`

	// Challenge configures the local HTTP server enroll-01 and
	// device-attest-01 open to serve their challenge and
	// credential-activation endpoints.
	Challenge DeviceChallengeConfig `yaml:"challenge,omitempty" json:"challenge,omitempty" mapstructure:"challenge"`
}

// DeviceTPMConfig selects and opens the TPM used by a DeviceSpec.
type DeviceTPMConfig struct {
	// KeyDir is the directory where the opened TPM persists IAK and IDevID
	// key blobs. Empty uses a process-local temporary directory that is
	// removed when the TPM is closed — acceptable for the in-process
	// simulator, never for a real device, whose keys would not survive a
	// restart.
	KeyDir string `yaml:"key-dir,omitempty" json:"key_dir,omitempty" mapstructure:"key-dir"`

	// EKCertificatePEM optionally provisions a PEM-encoded Endorsement Key
	// certificate into the TPM's NVRAM before use. Real hardware normally
	// already carries a manufacturer-issued EK certificate and leaves this
	// empty; it exists for TPMs that have none but still need one to carry
	// in the TCG-CSR-IDEVID (TCG "TPM 2.0 Keys for Device Identity and
	// Attestation" v1.00 r12, section 6.2.2 step 4b) — including the
	// in-process simulator, which is self-provisioned with a throwaway
	// certificate when this is left empty (development and testing only).
	EKCertificatePEM string `yaml:"ek-certificate-pem,omitempty" json:"ek_certificate_pem,omitempty" mapstructure:"ek-certificate-pem"`

	// Config carries the complete go-xkms TPM2 configuration: device path
	// or in-process simulator, and the EK/IAK/SSRK/Platform SRK templates
	// and hierarchy authorizations. Nil selects go-xkms's own
	// xkmssdk.DefaultTPMConfig (the in-process simulator), which is
	// appropriate only for development and testing — a production device
	// must supply Config naming its real device path and already-provisioned
	// key templates; go-xkms never auto-provisions real hardware.
	Config *xkmssdk.TPMConfig `yaml:"config,omitempty" json:"config,omitempty" mapstructure:"config"`
}

// useSimulator reports whether c selects the in-process TPM simulator,
// including the case where c or its Config is nil and go-xkms's own
// xkmssdk.DefaultTPMConfig (simulator-backed) therefore applies.
func (c *DeviceTPMConfig) useSimulator() bool {
	if c == nil || c.Config == nil {
		return xkmssdk.DefaultTPMConfig.UseSimulator
	}
	return c.Config.UseSimulator
}

// keyDir returns the configured key directory, or "" when c is nil.
func (c *DeviceTPMConfig) keyDir() string {
	if c == nil {
		return ""
	}
	return c.KeyDir
}

// resolvedConfig returns the concrete *xkmssdk.TPMConfig this device opens
// with: c.Config when set, otherwise a copy of xkmssdk.DefaultTPMConfig.
func (c *DeviceTPMConfig) resolvedConfig() *xkmssdk.TPMConfig {
	if c != nil && c.Config != nil {
		return c.Config
	}
	cfg := xkmssdk.DefaultTPMConfig
	return &cfg
}

// DeviceChallengeConfig configures the local HTTP server enroll-01 and
// device-attest-01 open to serve their challenge and credential-activation
// endpoints, and the timeout applied to the overall operation.
type DeviceChallengeConfig struct {
	// ListenHost is the address the challenge server binds, joined with
	// Port through net.JoinHostPort. Empty binds every interface.
	ListenHost string        `yaml:"listen-host,omitempty" json:"listen_host,omitempty" mapstructure:"listen-host"`
	Port       string        `yaml:"port,omitempty" json:"port,omitempty" mapstructure:"port"`
	Timeout    time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty" mapstructure:"timeout"`
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
	// Host is the address the challenge server binds, joined with Port
	// through net.JoinHostPort. Empty, the defaults-layer value, binds every
	// interface; set it to bind one interface only (go-xkms#140).
	Host     string `yaml:"host" json:"host" mapstructure:"host"`
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
		Devices:      make(map[string]*DeviceSpec),
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
	for name, spec := range c.Devices {
		if _, ok := c.Accounts[spec.Account]; !ok {
			return &ErrValidation{
				Field:  "devices." + name + ".account",
				Reason: "references unknown account: " + spec.Account,
			}
		}
		if spec.Identifier == "" {
			return &ErrValidation{
				Field:  "devices." + name + ".identifier",
				Reason: "permanent identifier is required",
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
