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
	"time"

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

	// ErrACMERateLimitNegativeMaxRequests is returned when
	// acme.rate_limit.max_requests is configured with a negative value. Zero
	// selects the built-in default; a negative value has no meaning.
	ErrACMERateLimitNegativeMaxRequests = errors.New("acme: rate_limit.max_requests must not be negative")

	// ErrACMERateLimitNegativeInterval is returned when
	// acme.rate_limit.interval is configured with a negative duration. Zero
	// selects the built-in default; a negative duration has no meaning.
	ErrACMERateLimitNegativeInterval = errors.New("acme: rate_limit.interval must not be negative")
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

	// Resilience configures the circuit breakers guarding the ACME server's
	// outbound dependencies (the http-01 and dns-01 challenge verifiers, CT
	// log submission, the tenant KMS signer, and CA-bundle storage access)
	// and the degradation cache the directory and CA-bundle endpoints serve
	// from while CA-bundle storage access is unavailable. See
	// ACMEResilienceConfig.
	Resilience ACMEResilienceConfig `yaml:"resilience"`

	// Policy configures the ACME identifier issuance policy engine: the
	// domain/FQDN/wildcard/CIDR blocklist, public-suffix and reserved-IP
	// enforcement, and per-identifier-type challenge selection. See
	// ACMEPolicyConfig.
	Policy ACMEPolicyConfig `yaml:"policy"`

	// RateLimit configures the per-client request-rate admission control
	// applied to every ACME endpoint. It is on unless the operator turns it
	// off; see ACMERateLimitConfig.
	RateLimit ACMERateLimitConfig `yaml:"rate_limit"`
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

// Rate-limit defaults. A zero-valued acme.rate_limit.max_requests or
// .interval selects these. They match the standalone TrustedCA's long-
// standing built-in default (20 requests/second per client), so xkmsd and
// the standalone CA throttle identically out of the box.
const (
	// DefaultACMERateLimitMaxRequests is the number of requests a single
	// client (JWS KID, or client IP before an account exists) may make
	// within DefaultACMERateLimitInterval.
	DefaultACMERateLimitMaxRequests = 20

	// DefaultACMERateLimitInterval is the sliding window
	// DefaultACMERateLimitMaxRequests is measured over.
	DefaultACMERateLimitInterval = time.Second

	// DefaultACMETenantRateLimitMaxRequests is the number of requests every
	// account belonging to the same tenant may make, combined, within
	// DefaultACMETenantRateLimitInterval. It matches the per-client overall
	// default so a single-tenant deployment throttles identically to today.
	DefaultACMETenantRateLimitMaxRequests = 20

	// DefaultACMETenantRateLimitInterval is the sliding window
	// DefaultACMETenantRateLimitMaxRequests is measured over.
	DefaultACMETenantRateLimitInterval = time.Second

	// DefaultACMENewAccountRateLimitMaxRequests is the number of accounts a
	// single client IP may create within DefaultACMENewAccountRateLimitInterval.
	// Matches the standalone TrustedCA's and Let's Encrypt's long-standing
	// convention.
	DefaultACMENewAccountRateLimitMaxRequests = 10

	// DefaultACMENewAccountRateLimitInterval is the sliding window
	// DefaultACMENewAccountRateLimitMaxRequests is measured over.
	DefaultACMENewAccountRateLimitInterval = time.Hour

	// DefaultACMENewOrderRateLimitMaxRequests is the number of orders a
	// single account may create within DefaultACMENewOrderRateLimitInterval.
	DefaultACMENewOrderRateLimitMaxRequests = 300

	// DefaultACMENewOrderRateLimitInterval is the sliding window
	// DefaultACMENewOrderRateLimitMaxRequests is measured over.
	DefaultACMENewOrderRateLimitInterval = 3 * time.Hour

	// DefaultACMECertificateRateLimitMaxRequests is the number of
	// certificates a single account may have issued within
	// DefaultACMECertificateRateLimitInterval.
	DefaultACMECertificateRateLimitMaxRequests = 50

	// DefaultACMECertificateRateLimitInterval is the sliding window
	// DefaultACMECertificateRateLimitMaxRequests is measured over.
	DefaultACMECertificateRateLimitInterval = 3 * time.Hour

	// DefaultACMEFailedValidationRateLimitMaxRequests is the number of failed
	// challenge validations a single account may accrue within
	// DefaultACMEFailedValidationRateLimitInterval before further validation
	// attempts are refused.
	DefaultACMEFailedValidationRateLimitMaxRequests = 5

	// DefaultACMEFailedValidationRateLimitInterval is the sliding window
	// DefaultACMEFailedValidationRateLimitMaxRequests is measured over.
	DefaultACMEFailedValidationRateLimitInterval = time.Hour
)

// ACMERateLimitConfig configures the per-client (JWS KID once an ACME
// account exists, otherwise the client IP) request-rate admission control
// applied to every endpoint on the ACME listener. Per RFC 8555 Section 6.6,
// an exceeded limit is reported as HTTP 429 with a Retry-After header and an
// urn:ietf:params:acme:error:rateLimited problem document
// (pkg/acme/server/rate_limiter.go).
//
// This is the only barrier between a public ACME endpoint and unbounded
// new-account/new-order/challenge traffic, so it is enabled by default
// whenever ACME is enabled: an absent "rate_limit" section means the
// listener throttles with the defaults below, not that it is unthrottled.
// Turning it off is an explicit act that Config.ComplianceGaps reports, and
// the daemon then refuses to start; there is no override.
type ACMERateLimitConfig struct {
	// Enabled controls whether the ACME listener enforces a request-rate
	// cap. It is a pointer so an omitted "enabled" key can be told apart
	// from an explicit "false": omitting it leaves the limiter on. Use
	// IsEnabled to read it.
	Enabled *bool `yaml:"enabled,omitempty"`

	// MaxRequests is the number of requests a single client may make within
	// Interval before receiving HTTP 429. Zero selects
	// DefaultACMERateLimitMaxRequests.
	MaxRequests int `yaml:"max_requests,omitempty"`

	// Interval is the sliding window MaxRequests is measured over. Zero
	// selects DefaultACMERateLimitInterval.
	Interval time.Duration `yaml:"interval,omitempty"`

	// Tenant configures the per-tenant OVERALL admission-control quota,
	// shared across every account belonging to the same tenant, applied on
	// top of (never instead of) the per-client limiter above. The tenant
	// bucket is keyed exclusively from an authenticated JWS "kid" resolved
	// and verified by handlers.RestService.TenantAuthMiddleware — never from
	// a client-asserted header, host, or path — so it cannot be spoofed or
	// used to escape another tenant's quota. Meaningful only for a
	// multi-tenant deployment (accounts created with an External Account
	// Binding that names a TenantID); a request whose account has no tenant
	// is bucketed under the empty tenant ID, which behaves as one shared
	// bucket for every non-tenant account. See ACMECategoryRateLimitConfig.
	Tenant ACMECategoryRateLimitConfig `yaml:"tenant,omitempty"`

	// NewAccount configures the RFC 8555 Section 6.6 new-account category:
	// how many accounts a single client IP may create in a window. The
	// tenant is never known at this point (no account exists yet), so this
	// category is always keyed by client IP, never by tenant. See
	// ACMECategoryRateLimitConfig.
	NewAccount ACMECategoryRateLimitConfig `yaml:"new_account,omitempty"`

	// NewOrder configures the RFC 8555 Section 6.6 new-order category: how
	// many orders a single account may create in a window, scoped within its
	// tenant when the account has one. See ACMECategoryRateLimitConfig.
	NewOrder ACMECategoryRateLimitConfig `yaml:"new_order,omitempty"`

	// Certificate configures the RFC 8555 Section 6.6 certificate-issuance
	// category, enforced at order finalize: how many certificates a single
	// account may have issued in a window, scoped within its tenant when the
	// account has one. See ACMECategoryRateLimitConfig.
	Certificate ACMECategoryRateLimitConfig `yaml:"certificate,omitempty"`

	// FailedValidation configures the RFC 8555 Section 6.6 failed-validation
	// category: how many failed challenge validations a single account may
	// accrue in a window, scoped within its tenant when the account has one,
	// before further validation attempts are refused. See
	// ACMECategoryRateLimitConfig.
	FailedValidation ACMECategoryRateLimitConfig `yaml:"failed_validation,omitempty"`
}

// IsEnabled reports whether the ACME listener should enforce a request-rate
// cap. An omitted "enabled" key leaves the limiter on, so only an explicit
// false disables it.
func (r ACMERateLimitConfig) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// ResolveMaxRequests returns the configured request cap, defaulting to
// DefaultACMERateLimitMaxRequests when unset.
func (r ACMERateLimitConfig) ResolveMaxRequests() int {
	if r.MaxRequests > 0 {
		return r.MaxRequests
	}
	return DefaultACMERateLimitMaxRequests
}

// ResolveInterval returns the configured rate-limit window, defaulting to
// DefaultACMERateLimitInterval when unset.
func (r ACMERateLimitConfig) ResolveInterval() time.Duration {
	if r.Interval > 0 {
		return r.Interval
	}
	return DefaultACMERateLimitInterval
}

// TenantIsEnabled reports whether the per-tenant overall quota is enforced.
func (r ACMERateLimitConfig) TenantIsEnabled() bool { return r.Tenant.IsEnabled() }

// TenantResolveMaxRequests returns the configured per-tenant request cap,
// defaulting to DefaultACMETenantRateLimitMaxRequests when unset.
func (r ACMERateLimitConfig) TenantResolveMaxRequests() int {
	return r.Tenant.resolveMaxRequests(DefaultACMETenantRateLimitMaxRequests)
}

// TenantResolveInterval returns the configured per-tenant rate-limit window,
// defaulting to DefaultACMETenantRateLimitInterval when unset.
func (r ACMERateLimitConfig) TenantResolveInterval() time.Duration {
	return r.Tenant.resolveInterval(DefaultACMETenantRateLimitInterval)
}

// NewAccountIsEnabled reports whether the new-account category is enforced.
func (r ACMERateLimitConfig) NewAccountIsEnabled() bool { return r.NewAccount.IsEnabled() }

// NewAccountResolveMaxRequests returns the configured new-account request
// cap, defaulting to DefaultACMENewAccountRateLimitMaxRequests when unset.
func (r ACMERateLimitConfig) NewAccountResolveMaxRequests() int {
	return r.NewAccount.resolveMaxRequests(DefaultACMENewAccountRateLimitMaxRequests)
}

// NewAccountResolveInterval returns the configured new-account rate-limit
// window, defaulting to DefaultACMENewAccountRateLimitInterval when unset.
func (r ACMERateLimitConfig) NewAccountResolveInterval() time.Duration {
	return r.NewAccount.resolveInterval(DefaultACMENewAccountRateLimitInterval)
}

// NewOrderIsEnabled reports whether the new-order category is enforced.
func (r ACMERateLimitConfig) NewOrderIsEnabled() bool { return r.NewOrder.IsEnabled() }

// NewOrderResolveMaxRequests returns the configured new-order request cap,
// defaulting to DefaultACMENewOrderRateLimitMaxRequests when unset.
func (r ACMERateLimitConfig) NewOrderResolveMaxRequests() int {
	return r.NewOrder.resolveMaxRequests(DefaultACMENewOrderRateLimitMaxRequests)
}

// NewOrderResolveInterval returns the configured new-order rate-limit
// window, defaulting to DefaultACMENewOrderRateLimitInterval when unset.
func (r ACMERateLimitConfig) NewOrderResolveInterval() time.Duration {
	return r.NewOrder.resolveInterval(DefaultACMENewOrderRateLimitInterval)
}

// CertificateIsEnabled reports whether the certificate category is enforced.
func (r ACMERateLimitConfig) CertificateIsEnabled() bool { return r.Certificate.IsEnabled() }

// CertificateResolveMaxRequests returns the configured certificate request
// cap, defaulting to DefaultACMECertificateRateLimitMaxRequests when unset.
func (r ACMERateLimitConfig) CertificateResolveMaxRequests() int {
	return r.Certificate.resolveMaxRequests(DefaultACMECertificateRateLimitMaxRequests)
}

// CertificateResolveInterval returns the configured certificate rate-limit
// window, defaulting to DefaultACMECertificateRateLimitInterval when unset.
func (r ACMERateLimitConfig) CertificateResolveInterval() time.Duration {
	return r.Certificate.resolveInterval(DefaultACMECertificateRateLimitInterval)
}

// FailedValidationIsEnabled reports whether the failed-validation category
// is enforced.
func (r ACMERateLimitConfig) FailedValidationIsEnabled() bool {
	return r.FailedValidation.IsEnabled()
}

// FailedValidationResolveMaxRequests returns the configured
// failed-validation request cap, defaulting to
// DefaultACMEFailedValidationRateLimitMaxRequests when unset.
func (r ACMERateLimitConfig) FailedValidationResolveMaxRequests() int {
	return r.FailedValidation.resolveMaxRequests(DefaultACMEFailedValidationRateLimitMaxRequests)
}

// FailedValidationResolveInterval returns the configured failed-validation
// rate-limit window, defaulting to
// DefaultACMEFailedValidationRateLimitInterval when unset.
func (r ACMERateLimitConfig) FailedValidationResolveInterval() time.Duration {
	return r.FailedValidation.resolveInterval(DefaultACMEFailedValidationRateLimitInterval)
}

// Validate checks the rate-limit section, including every per-tenant and
// per-category sub-section. It is only meaningful for a sub-section that is
// enabled; a disabled one is reported by Config.ComplianceGaps instead.
func (r ACMERateLimitConfig) Validate() error {
	if r.IsEnabled() {
		if r.MaxRequests < 0 {
			return ErrACMERateLimitNegativeMaxRequests
		}
		if r.Interval < 0 {
			return ErrACMERateLimitNegativeInterval
		}
	}
	for _, category := range []ACMECategoryRateLimitConfig{
		r.Tenant, r.NewAccount, r.NewOrder, r.Certificate, r.FailedValidation,
	} {
		if err := category.validate(); err != nil {
			return err
		}
	}
	return nil
}

// ACMECategoryRateLimitConfig configures one RFC 8555 Section 6.6 rate-limit
// category, or the per-tenant overall quota. It follows the same tri-state,
// secure-by-default pattern as ACMERateLimitConfig: an explicit
// enabled=false is the only way to turn it off, and Config.ComplianceGaps
// reports it.
type ACMECategoryRateLimitConfig struct {
	// Enabled controls whether this category is enforced. It is a pointer so
	// an omitted "enabled" key can be told apart from an explicit "false":
	// omitting it leaves the category on. Use IsEnabled to read it.
	Enabled *bool `yaml:"enabled,omitempty"`

	// MaxRequests is the number of requests allowed within Interval before
	// receiving HTTP 429. Zero selects this category's own default.
	MaxRequests int `yaml:"max_requests,omitempty"`

	// Interval is the sliding window MaxRequests is measured over. Zero
	// selects this category's own default.
	Interval time.Duration `yaml:"interval,omitempty"`
}

// IsEnabled reports whether this category is enforced. An omitted "enabled"
// key leaves it on, so only an explicit false disables it.
func (c ACMECategoryRateLimitConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// resolveMaxRequests returns the configured request cap, defaulting to def
// when unset.
func (c ACMECategoryRateLimitConfig) resolveMaxRequests(def int) int {
	if c.MaxRequests > 0 {
		return c.MaxRequests
	}
	return def
}

// resolveInterval returns the configured rate-limit window, defaulting to
// def when unset.
func (c ACMECategoryRateLimitConfig) resolveInterval(def time.Duration) time.Duration {
	if c.Interval > 0 {
		return c.Interval
	}
	return def
}

// validate checks the category. It is only meaningful when the category is
// enabled; a disabled category is reported by Config.ComplianceGaps instead.
func (c ACMECategoryRateLimitConfig) validate() error {
	if !c.IsEnabled() {
		return nil
	}
	if c.MaxRequests < 0 {
		return ErrACMERateLimitNegativeMaxRequests
	}
	if c.Interval < 0 {
		return ErrACMERateLimitNegativeInterval
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
	if err := c.Resilience.Validate(); err != nil {
		return err
	}
	if err := c.Policy.Validate(); err != nil {
		return err
	}
	if err := c.RateLimit.Validate(); err != nil {
		return err
	}
	return nil
}
