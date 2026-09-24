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
	"errors"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Error types returned when validating the ACME configuration section.
var (
	// ErrACMEMissingHTTPSAddr is returned when acme.enabled is true but no
	// HTTPS listen address has been configured.
	ErrACMEMissingHTTPSAddr = errors.New("acme: https_addr is required when acme.enabled is true")

	// ErrACMEMissingExternalURL is returned when acme.enabled is true but no
	// external URL has been configured. The external URL is the base URL
	// advertised in the ACME directory and used for Location headers.
	ErrACMEMissingExternalURL = errors.New("acme: external_url is required when acme.enabled is true")

	// ErrACMEMissingKeystoreBackend is returned when acme.enabled is true but
	// no keystore backend has been configured for the ACME CA to use.
	ErrACMEMissingKeystoreBackend = errors.New("acme: keystore_backend is required when acme.enabled is true")

	// ErrACMEMissingTLS is returned when acme.enabled is true and no TLS
	// cert/key pair has been configured. The ACME listener always uses its
	// own dedicated TLS material.
	ErrACMEMissingTLS = errors.New("acme: tls.cert_file and tls.key_file are required when acme.enabled is true")

	// ErrACMEAuditNegativeRetention is returned when an audit rotation knob is
	// configured with a negative value. Zero selects the built-in default;
	// a negative value has no meaning.
	ErrACMEAuditNegativeRetention = errors.New("acme: audit rotation values (max_size_mb, max_age_days, max_backups, buffer_size, flush_interval_seconds) must not be negative")

	// ErrACMEAuditUnsupportedFormat is returned when acme.audit.format names a
	// serialization the audit trail cannot be written or queried in.
	ErrACMEAuditUnsupportedFormat = errors.New("acme: audit.format must be \"json\" (the only queryable audit trail format)")

	// ErrACMEMissingCAAIdentities is returned when acme.enabled is true but
	// no CAA identities have been configured. RFC 8555 Section 8.1 requires
	// ACME servers to check CAA (RFC 8659) records before issuing; without
	// at least one identity the CA has nothing to compare an issue/issuewild
	// record's value against, so a domain that publishes a restrictive CAA
	// record could never be distinguished from one that permits this CA.
	// There is no silent default: an operator names the identity or
	// identities their CA issues CAA records under.
	ErrACMEMissingCAAIdentities = errors.New("acme: caa_identities is required when acme.enabled is true")
)

// ACMEConfig configures the optional ACME (RFC 8555) server that xkmsd may
// host alongside its primary protocol surfaces. When Enabled is false the
// ACME subsystem is not initialized and incurs no runtime overhead.
//
// The ACME server is always served on a dedicated HTTPS listener because
// RFC 8555 clients expect a standalone directory resource. The listener is
// configured via HTTPSAddr and always uses its own certificate/key pair,
// configured through TLS below.
type ACMEConfig struct {
	// Enabled controls whether the ACME server is started. When false the
	// remainder of this config is ignored.
	Enabled bool `yaml:"enabled"`

	// HTTPSAddr is the listen address for the ACME HTTPS server (e.g. ":8443").
	HTTPSAddr string `yaml:"https_addr"`

	// ExternalURL is the externally-reachable base URL for the ACME server
	// (e.g. "https://acme.example.com"). This value is embedded in directory
	// responses and Location headers and must be reachable by ACME clients.
	ExternalURL string `yaml:"external_url"`

	// DirectoryPath is the path prefix mounted on the HTTPS listener. When
	// empty, "/acme" is used. All ACME endpoints are registered relative to
	// this prefix, e.g. "<DirectoryPath>/directory", "<DirectoryPath>/new-nonce".
	DirectoryPath string `yaml:"directory_path"`

	// TermsOfService is the URL advertised in the directory meta object.
	TermsOfService string `yaml:"terms_of_service"`

	// CAAIdentities is the list of issuer domain names this CA is known by
	// in CAA (RFC 8659) issue/issuewild records — the identities finalize
	// checks a domain's CAA RRset against before issuing, and the same
	// list advertised in the directory meta object per RFC 8555 Section
	// 9.7.6. Required whenever ACME is enabled: see Validate.
	CAAIdentities []string `yaml:"caa_identities"`

	// CAADNSServer optionally pins the recursive resolver (host:port, e.g.
	// "8.8.8.8:53") used for the CAA lookups performed at order finalize.
	// Empty uses the same default resolver the dns-01 challenge tooling
	// uses (pkg/acme/challenges/dns-01/providers.DefaultNameservers).
	CAADNSServer string `yaml:"caa_dns_server"`

	// ExternalAccountRequired indicates that newAccount requests MUST include
	// an externalAccountBinding per RFC 8555 Section 7.3.4.
	ExternalAccountRequired bool `yaml:"external_account_required"`

	// EndorseEABRequired indicates that endorse-01 challenges require EAB.
	EndorseEABRequired bool `yaml:"endorse_eab_required"`

	// EndorseDeviceIDMetaKey is the EAB metadata key used to validate device
	// identity in endorse-01 challenges. Empty disables device-id validation.
	EndorseDeviceIDMetaKey string `yaml:"endorse_device_id_meta_key"`

	// Challenges controls which challenge verifiers are registered. At least
	// one challenge type must be enabled when ACME is enabled.
	Challenges ACMEChallengesConfig `yaml:"challenges"`

	// KeystoreBackend identifies the xkmsd keystore backend that the ACME CA
	// uses for key storage (e.g. "software", "pkcs8", "tpm2"). This must
	// match one of the enabled backends in the server config.
	KeystoreBackend string `yaml:"keystore_backend"`

	// DataDir is the directory where ACME object state (certificates, nonces,
	// authorizations, orders, accounts) is persisted. When empty, defaults to
	// "<storage.path>/acme".
	DataDir string `yaml:"data_dir"`

	// TLS configures the ACME listener's TLS settings. Required when Enabled
	// is true.
	TLS ACMETLSConfig `yaml:"tls"`

	// Audit configures the ACME audit trail: the tamper-evident record of
	// every account, order, issuance, revocation, and enrollment decision the
	// ACME CA makes. It is on unless the operator turns it off; see
	// ACMEAuditConfig.
	Audit ACMEAuditConfig `yaml:"audit"`

	// Enrollment configures behavior specific to TPM-attestation enrollment
	// challenges (enroll-01/endorse-01/device-attest-01). See
	// ACMEEnrollmentConfig.
	Enrollment ACMEEnrollmentConfig `yaml:"enrollment"`

	// Policy configures the ACME identifier issuance policy engine: the
	// domain/FQDN/wildcard/CIDR blocklist, public-suffix and reserved-IP
	// enforcement, and per-identifier-type challenge selection. See
	// ACMEPolicyConfig.
	Policy ACMEPolicyConfig `yaml:"policy"`
}

// ACMEEnrollmentConfig configures behavior specific to TPM-attestation
// enrollment challenges (enroll-01/endorse-01/device-attest-01).
type ACMEEnrollmentConfig struct {
	// AllowLoopbackIdentifier permits an authorization's permanent-identifier
	// to be the loopback address 127.0.0.1, in which case the challenge
	// handler substitutes the request's client IP (or X-Forwarded-For) as
	// the validation target instead. This supports local development and
	// testing, where a device registers with a loopback identifier but the
	// actual challenge validation must reach the device at its real IP.
	// Off by default: a loopback identifier is otherwise refused.
	AllowLoopbackIdentifier bool `yaml:"allow_loopback_identifier"`
}

// Audit trail defaults. Zero-valued rotation knobs in the configuration select
// these, which match the defaults the audit logger itself applies.
const (
	// DefaultACMEAuditFileName is the audit log file created inside the ACME
	// data directory when acme.audit.log_path is not set.
	DefaultACMEAuditFileName = "audit.log"

	// DefaultACMEAuditMaxSizeMB rotates the live log once it reaches this size.
	DefaultACMEAuditMaxSizeMB = 100

	// DefaultACMEAuditMaxAgeDays retains rotated backups for one year, the
	// shortest retention the supported compliance regimes accept.
	DefaultACMEAuditMaxAgeDays = 365

	// DefaultACMEAuditMaxBackups is how many rotated backups are retained.
	DefaultACMEAuditMaxBackups = 10

	// DefaultACMEAuditBufferSize is how many events may be queued in memory
	// before writes become synchronous.
	DefaultACMEAuditBufferSize = 100

	// DefaultACMEAuditFlushIntervalSeconds is how often queued events are
	// forced to disk.
	DefaultACMEAuditFlushIntervalSeconds = 5

	// DefaultACMEAuditFormat is the only audit trail format that can be both
	// written and read back through the admin query API.
	DefaultACMEAuditFormat = "json"
)

// ACMEAuditConfig configures the ACME audit trail.
//
// The audit trail is a compliance control (FedRAMP AU-2/AU-3/AU-9, PCI-DSS v4
// 10.2, HIPAA 164.312(b)), so it is enabled by default whenever the ACME
// server is enabled: an absent "audit" section means the trail runs with the
// defaults below, not that it is off. Turning it off is an explicit act that
// Config.ComplianceGaps reports, and the daemon then refuses to start; there
// is no override.
type ACMEAuditConfig struct {
	// Enabled controls whether the audit trail is recorded. It is a pointer so
	// an omitted "enabled" key can be told apart from an explicit "false":
	// omitting it leaves the trail on. Use IsEnabled to read it.
	Enabled *bool `yaml:"enabled,omitempty"`

	// LogPath is the audit log file. When empty it defaults to
	// "<acme.data_dir>/audit.log", so the trail lives beside the ACME state it
	// describes. Rotated backups are written alongside it.
	LogPath string `yaml:"log_path,omitempty"`

	// MaxSizeMB is the size at which the live log rotates, in megabytes.
	// Zero selects DefaultACMEAuditMaxSizeMB.
	MaxSizeMB int `yaml:"max_size_mb,omitempty"`

	// MaxAgeDays is how long rotated backups are retained.
	// Zero selects DefaultACMEAuditMaxAgeDays.
	MaxAgeDays int `yaml:"max_age_days,omitempty"`

	// MaxBackups is how many rotated backups are retained.
	// Zero selects DefaultACMEAuditMaxBackups.
	MaxBackups int `yaml:"max_backups,omitempty"`

	// BufferSize is how many events may be queued before writes become
	// synchronous. Zero selects DefaultACMEAuditBufferSize. Events are never
	// dropped: a full buffer makes the emitting request write through.
	BufferSize int `yaml:"buffer_size,omitempty"`

	// FlushIntervalSeconds is how often queued events are forced to disk.
	// Zero selects DefaultACMEAuditFlushIntervalSeconds.
	FlushIntervalSeconds int `yaml:"flush_interval_seconds,omitempty"`

	// Compress gzips rotated backups. The audit query API reads compressed
	// backups transparently.
	Compress bool `yaml:"compress,omitempty"`

	// Format is the on-disk record format. Only "json" is supported, because
	// it is the only format the admin audit query API can read back.
	Format string `yaml:"format,omitempty"`
}

// IsEnabled reports whether the audit trail should be recorded. An omitted
// "enabled" key leaves the trail on, so only an explicit false disables it.
func (a ACMEAuditConfig) IsEnabled() bool {
	return a.Enabled == nil || *a.Enabled
}

// ResolveLogPath returns the audit log file, defaulting to "audit.log" inside
// the supplied ACME data directory when the operator did not name one.
func (a ACMEAuditConfig) ResolveLogPath(dataDir string) string {
	if a.LogPath != "" {
		return a.LogPath
	}
	return filepath.Join(dataDir, DefaultACMEAuditFileName)
}

// ResolveFormat returns the configured record format, defaulting to json.
func (a ACMEAuditConfig) ResolveFormat() string {
	if a.Format == "" {
		return DefaultACMEAuditFormat
	}
	return a.Format
}

// AuditConfig translates the audit section into the configuration the audit
// subsystem consumes, resolving the log path against the ACME data directory
// and substituting the documented defaults for unset rotation knobs. It is the
// single mapping between the daemon's YAML and the audit trail, so the logger
// and the query API are always configured from the same values.
func (a ACMEAuditConfig) AuditConfig(dataDir string) *audit.Config {
	cfg := &audit.Config{
		Enabled:              a.IsEnabled(),
		LogPath:              a.ResolveLogPath(dataDir),
		MaxSizeMB:            a.MaxSizeMB,
		MaxAgeDays:           a.MaxAgeDays,
		MaxBackups:           a.MaxBackups,
		BufferSize:           a.BufferSize,
		FlushIntervalSeconds: a.FlushIntervalSeconds,
		Compress:             a.Compress,
		Format:               a.ResolveFormat(),
	}

	if cfg.MaxSizeMB == 0 {
		cfg.MaxSizeMB = DefaultACMEAuditMaxSizeMB
	}
	if cfg.MaxAgeDays == 0 {
		cfg.MaxAgeDays = DefaultACMEAuditMaxAgeDays
	}
	if cfg.MaxBackups == 0 {
		cfg.MaxBackups = DefaultACMEAuditMaxBackups
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = DefaultACMEAuditBufferSize
	}
	if cfg.FlushIntervalSeconds == 0 {
		cfg.FlushIntervalSeconds = DefaultACMEAuditFlushIntervalSeconds
	}

	return cfg
}

// Validate checks the audit section. It is only meaningful when the trail is
// enabled; a disabled trail is reported by Config.ComplianceGaps instead.
func (a ACMEAuditConfig) Validate() error {
	if !a.IsEnabled() {
		return nil
	}
	if a.MaxSizeMB < 0 || a.MaxAgeDays < 0 || a.MaxBackups < 0 ||
		a.BufferSize < 0 || a.FlushIntervalSeconds < 0 {
		return ErrACMEAuditNegativeRetention
	}
	if a.ResolveFormat() != DefaultACMEAuditFormat {
		return ErrACMEAuditUnsupportedFormat
	}
	return nil
}

// ACMEChallengesConfig selects which challenge verifiers are registered.
type ACMEChallengesConfig struct {
	// HTTP01 enables the http-01 challenge verifier (RFC 8555 Section 8.3).
	HTTP01 bool `yaml:"http01"`

	// DNS01 enables the dns-01 challenge verifier (RFC 8555 Section 8.4).
	DNS01 bool `yaml:"dns01"`

	// Enroll01 enables the enroll-01 TPM-attestation challenge: TCG-CSR-IDEVID
	// device enrollment proven via TPM2_MakeCredential/ActivateCredential. The
	// issued IAK + IDevID certificates root device identity in the TPM.
	Enroll01 bool `yaml:"enroll01"`

	// Endorse01 enables the endorse-01 challenge: EK-certificate issuance for
	// TPMs without a manufacturer EK cert. Server-side verification is a no-op;
	// issuance is gated by External Account Binding (EAB).
	Endorse01 bool `yaml:"endorse01"`
}

// ACMETLSConfig configures TLS for the ACME listener.
type ACMETLSConfig struct {
	// CertFile is the PEM-encoded server certificate.
	CertFile string `yaml:"cert_file"`

	// KeyFile is the PEM-encoded server private key.
	KeyFile string `yaml:"key_file"`

	// MinVersion specifies the minimum TLS version ("TLS1.2" or "TLS1.3").
	// Empty defaults to TLS1.3.
	MinVersion string `yaml:"min_version"`

	// MaxVersion specifies the maximum TLS version. Empty places no cap.
	MaxVersion string `yaml:"max_version"`

	// ClientAuth controls mTLS behavior: none, request, require, verify,
	// require_and_verify. Empty defaults to "none".
	ClientAuth string `yaml:"client_auth"`

	// ClientCAs is a list of PEM files containing CAs that may sign client
	// certificates when ClientAuth is not "none".
	ClientCAs []string `yaml:"client_cas"`
}

// Validate checks that the ACME configuration is complete when enabled.
// When Enabled is false this method is a no-op.
func (c *ACMEConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if c.HTTPSAddr == "" {
		return ErrACMEMissingHTTPSAddr
	}
	if c.ExternalURL == "" {
		return ErrACMEMissingExternalURL
	}
	if c.KeystoreBackend == "" {
		return ErrACMEMissingKeystoreBackend
	}
	if len(c.CAAIdentities) == 0 {
		return ErrACMEMissingCAAIdentities
	}
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
		return ErrACMEMissingTLS
	}
	if !c.Challenges.HTTP01 && !c.Challenges.DNS01 && !c.Challenges.Enroll01 && !c.Challenges.Endorse01 {
		return &errs.Message{Msg: "acme: at least one challenge type must be enabled (challenges.http01, dns01, enroll01, or endorse01)"}
	}
	if err := c.Audit.Validate(); err != nil {
		return err
	}
	if err := c.Policy.Validate(); err != nil {
		return err
	}
	return nil
}
