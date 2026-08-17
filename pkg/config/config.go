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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/trust/resolver"
)

// Config represents the complete server configuration
type Config struct {
	Server      ServerConfig              `yaml:"server"`
	Protocols   ProtocolsConfig           `yaml:"protocols"`
	Unix        UnixConfig                `yaml:"unix"`
	Logging     LoggingConfig             `yaml:"logging"`
	TLS         TLSConfig                 `yaml:"tls"`
	Auth        AuthConfig                `yaml:"auth"`
	WebAuthn    *WebAuthnConfig           `yaml:"webauthn,omitempty"`
	CORS        CORSConfig                `yaml:"cors"`
	UI          UIConfig                  `yaml:"ui"`
	RateLimit   RateLimitConfig           `yaml:"ratelimit"`
	Metrics     MetricsConfig             `yaml:"metrics"`
	Health      HealthConfig              `yaml:"health"`
	Storage     StorageConfig             `yaml:"storage"`
	Crypto      CryptoConfig              `yaml:"crypto"`
	Cluster     ClusterConfig             `yaml:"cluster"`
	RNG         RNGConfig                 `yaml:"rng"`
	Default     DefaultConfig             `yaml:"default_backend"`
	Backends    BackendsConfig            `yaml:"backends"`
	Bootstrap   BootstrapConfig           `yaml:"bootstrap"`
	Barrier     BarrierConfig             `yaml:"barrier"`
	PIN         PINConfig                 `yaml:"pin"`
	Credentials CredentialsConfig         `yaml:"credentials"`
	CA          *ca.MultiIdentityCAConfig `yaml:"ca,omitempty"`
	ACME        *ACMEConfig               `yaml:"acme,omitempty"`
	// Attestation configures the hardware-attestation trust anchors used to
	// verify attestation chains presented with a CSR. When nil, attestation-
	// gated CSR signing fails closed.
	Attestation *AttestationConfig `yaml:"attestation,omitempty"`
	// Trust configures the ordered strategy-chain trust resolver. When
	// nil, trust resolution falls back to the OS system trust store.
	Trust *resolver.Config `yaml:"trust,omitempty"`
}

// CryptoConfig carries process-wide cryptographic policy.
//
// A configuration setting here can only ever choose within what the deployed
// binary already permits: FIPS mode is selected by the Go toolchain (GOFIPS140
// at build time, GODEBUG=fips140=on|only at run time), pkg/types reads it from
// crypto/fips140.Enabled(), and the validated module's approved-algorithm
// boundary overrides anything written in YAML. What this struct decides is the
// posture of a NON-FIPS deployment, which would otherwise have no way to say
// whether it needs the legacy mechanisms its peers still use.
type CryptoConfig struct {
	// AllowWeakHashes re-admits the collision-broken digests (MD4, MD5, SHA-1,
	// MD5+SHA1, RIPEMD-160) to the general-purpose hash tables in pkg/types,
	// and therefore to the signing, certificate, and TPM attestation paths.
	//
	// It defaults to false: a signature over a broken digest is forgeable by
	// anyone who can influence the signed message, so refusing is the only safe
	// default. Setting it true is the documented escape hatch for legacy
	// interop and for PKCS#11 conformance deployments, which must be able to
	// perform the SHA-1/MD5 mechanisms the specification defines. server.New
	// applies it to pkg/types before any transport starts, and the daemon logs
	// the re-admitted digests by name on every start.
	//
	// In FIPS mode it is ignored; types.SetAllowWeakHashes refuses to loosen
	// the policy inside the validated module's boundary.
	AllowWeakHashes bool `yaml:"allow_weak_hashes"`

	// AllowLegacyKeyWrap re-admits the key-wrap constructions that
	// authenticate nothing — RSA_PKCS1_V1_5 (CKM_RSA_PKCS), AES_CBC_PAD
	// (CKM_AES_CBC_PAD) and AES_CBC (CKM_AES_CBC) — to C_WrapKey and
	// C_UnwrapKey.
	//
	// It defaults to false for a sharper reason than the digests: C_UnwrapKey
	// is reachable over every transport with a caller-designated key and a
	// caller-supplied blob, so each of these is a remote decryption oracle.
	// PKCS#1 v1.5 is the Bleichenbacher/Marvin shape; PKCS#7 unpadding is the
	// Vaudenay padding-oracle shape (measured in this codebase: 215 random
	// blobs before one was accepted); unpadded CBC checks nothing at all, so a
	// random blob unwraps into attacker-chosen plaintext as a usable key on
	// the first try.
	//
	// PKCS#11 v3.2 sanctions all three, so refusing them is a deployment
	// policy rather than a conformance deviation, and an operator who must
	// interoperate with an application that requires one can set it true.
	// server.New applies it to pkg/types before any transport starts.
	//
	// In FIPS mode it is ignored, and it never re-admits RSAES_OAEP_SHA_1,
	// which stays refused in both postures.
	AllowLegacyKeyWrap bool `yaml:"allow_legacy_key_wrap"`
}

// BarrierConfig configures the barrier (seal/unseal) subsystem. The barrier is
// the go-qrdb node's own StorageBarrier: when Enabled, the node encrypts its
// data-plane KV (encfs, AES-256-GCM) so every value at rest — including the
// crypto backends' key stores — is encrypted, and it auto-unseals at boot per
// the resolved Strategy + Passphrase. This is the same barrier go-quicbaas uses;
// xkms provisions its own instance through this config (config/CLI/env), the
// same shared mechanism every product in the stack drives through its own
// front door.
type BarrierConfig struct {
	// Enabled turns the node barrier on. When false the node boots unsealed
	// with a plaintext data plane, which ComplianceGaps reports and the daemon
	// refuses to start on — there is no override.
	Enabled bool `yaml:"enabled"`

	// Strategy selects the seal strategy using the canonical stack vocabulary:
	// none | passphrase | shamir | tpm2 | pkcs11 | awskms | gcpkms | azurekv |
	// vault. Empty defaults to passphrase. Hardware/cloud strategies are
	// resolved and injected as a SealingStrategy; passphrase/shamir/none map to
	// the node's native SealConfig.Strategy.
	Strategy string `yaml:"strategy,omitempty"`

	// RootKeyPath is the barrier root-key location in the seal store.
	RootKeyPath string `yaml:"root_key_path,omitempty"`

	// Passphrase supplies the boot-time unseal secret for the passphrase
	// strategy (and the auto-unseal fallback). Supports credential:// references
	// and ${ENV} expansion, resolved at boot. Hardware strategies need no
	// passphrase (PCR-policy / empty-creds auto-unseal). Prefer the
	// XKMS_SEAL_PASSPHRASE env var or a credential:// reference over a literal.
	Passphrase string `yaml:"passphrase,omitempty"`

	// ShamirThreshold and ShamirTotal configure the Shamir M-of-N quorum for the
	// shamir strategy. Shamir never auto-unseals (operator quorum required).
	ShamirThreshold int `yaml:"shamir_threshold,omitempty"`
	ShamirTotal     int `yaml:"shamir_total,omitempty"`

	// PreferenceOrder retains the hardware-strategy ordering used when resolving
	// which configured hardware backend seals the barrier. Optional.
	PreferenceOrder []string `yaml:"preference_order,omitempty"`
}

// SealStrategy returns the configured strategy, defaulting to "passphrase" when
// unset (matching the node's SealConfig default).
func (b BarrierConfig) SealStrategy() string {
	if b.Strategy == "" {
		return "passphrase"
	}
	return b.Strategy
}

// IsHardwareSealStrategy reports whether the configured strategy is a
// hardware/cloud strategy (resolved via a SealingStrategy) rather than one of
// the node's native passphrase/shamir/none strategies.
func (b BarrierConfig) IsHardwareSealStrategy() bool {
	switch b.SealStrategy() {
	case "tpm2", "pkcs11", "awskms", "gcpkms", "azurekv", "vault":
		return true
	default:
		return false
	}
}

// PINConfig configures the PIN management subsystem.
type PINConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Strategy        string `yaml:"strategy"`
	MaxAttempts     int    `yaml:"max_attempts"`
	LockoutDuration string `yaml:"lockout_duration"`
}

// CredentialsConfig configures how backend credentials (PKCS#11 User PIN, TPM2 auth, etc.)
// are sealed at rest. Uses the same seal strategies as the barrier via PlatformStore/PlatformSealer.
// NOTE: SO PIN is NEVER stored -- always verified against the actual backend.
type CredentialsConfig struct {
	// SealStrategy determines how backend credentials are sealed at rest.
	// Valid values: manual, barrier, tpm2, pkcs11, aws_kms, gcp_kms, azure_kv, vault, software
	// "manual" (default): credentials NOT stored -- operator enters at each startup.
	SealStrategy string `yaml:"seal_strategy" json:"seal_strategy"`
}

// ServerConfig contains server-level settings
type ServerConfig struct {
	Host      string `yaml:"host"`
	RESTPort  int    `yaml:"rest_port"`
	GRPCPort  int    `yaml:"grpc_port"`
	QUICPort  int    `yaml:"quic_port"`
	MCPPort   int    `yaml:"mcp_port"`
	NoisePort int    `yaml:"noise_port"`
}

// NetworkServing reports whether any network protocol is enabled. Network
// serving runs exclusively on the unified API server: the embedded qrdb
// node's multi-protocol server takes the ports above and serves the xkms
// capability plane through the registered ServiceModule (pkg/apimodule).
// It therefore requires storage.backend "qrdb" and explicit TLS material
// (qrdb's transports are TLS-only and the xkms CA is not yet composed when
// the node starts). QUIC is served as HTTP/3 on the REST port (advertised
// via Alt-Svc); the Unix socket and the loopback desktop engine are local
// IPC, not network serving.
func (c *Config) NetworkServing() bool {
	return c.Protocols.REST || c.Protocols.GRPC || c.Protocols.QUIC || c.Protocols.MCP
}

// ProtocolsConfig controls which protocols are enabled
type ProtocolsConfig struct {
	// Unix enables the Unix domain socket for local IPC (default: true)
	Unix  bool `yaml:"unix"`
	REST  bool `yaml:"rest"`
	GRPC  bool `yaml:"grpc"`
	QUIC  bool `yaml:"quic"`
	MCP   bool `yaml:"mcp"`
	Noise bool `yaml:"noise"`
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
	// Valid values: "grpc"
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

	// ServerCN is the Common Name for the server TLS certificate.
	// Used with CA-backed TLS to identify which certificate to load.
	ServerCN string `yaml:"server_cn" json:"server_cn"`

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
	Type    string `yaml:"type"` // noop, mtls, jwt, adaptive, composite

	// JWT authentication
	JWT *JWTConfig `yaml:"jwt,omitempty"`

	// mTLS authentication
	MTLS bool `yaml:"mtls"` // Use mTLS from client certificates

	// RBAC enables role-based access control
	EnableRBAC bool `yaml:"enable_rbac"`

	// Composite authentication (chains multiple authenticators)
	Composite *CompositeAuthConfig `yaml:"composite,omitempty"`

	// Audit logging
	Audit *AuditConfig `yaml:"audit,omitempty"`

	// PIVLogin enables the browser cert-login exchange: a TLS client
	// certificate (PIV smart card or mTLS identity) is exchanged for a
	// bearer token pair at POST /api/v1/auth/login/piv.
	PIVLogin *PIVLoginConfig `yaml:"piv_login,omitempty"`

	// Session tunes the token pairs minted by the login flows (WebAuthn
	// passkey login, PIV/mTLS cert login).
	Session *SessionConfig `yaml:"session,omitempty"`
}

// PIVLoginConfig configures the TLS-client-certificate login exchange.
type PIVLoginConfig struct {
	// Enabled turns the endpoint on. Requires tls.client_auth to request
	// client certificates ("verify", "require", or "request").
	Enabled bool `yaml:"enabled"`

	// TrustedIssuers optionally restricts which certificate issuer
	// distinguished names are accepted (exact string match on the issuer DN).
	// Empty means any issuer the TLS layer verified.
	TrustedIssuers []string `yaml:"trusted_issuers,omitempty"`
}

// SessionConfig tunes issued token lifetimes and login rate limiting.
type SessionConfig struct {
	// AccessTokenTTL is the access token lifetime (Go duration, e.g. "15m").
	AccessTokenTTL string `yaml:"access_token_ttl"`

	// RefreshTokenTTL is the rotating refresh token lifetime (e.g. "8h").
	RefreshTokenTTL string `yaml:"refresh_token_ttl"`

	// LoginRatePerMin caps per-client login and refresh attempts per minute.
	// Zero uses the default (10).
	LoginRatePerMin int `yaml:"login_rate_per_min"`
}

// CompositeAuthConfig configures composite authentication that chains
// multiple authenticators. A request is authenticated if any method succeeds.
type CompositeAuthConfig struct {
	// Methods lists the authentication methods to chain (e.g., ["jwt", "mtls"]).
	Methods []string `yaml:"methods"`
}

// AuditConfig configures audit logging for authentication and authorization events.
type AuditConfig struct {
	// Enabled controls whether audit logging is active.
	Enabled bool `yaml:"enabled"`
	// Path is the file path for the audit log.
	Path string `yaml:"path"`
}

// WebAuthnConfig controls WebAuthn/FIDO2 authentication
type WebAuthnConfig struct {
	// Enabled controls whether WebAuthn is active
	Enabled bool `yaml:"enabled"`

	// RPID is the relying party identifier (e.g., "localhost" or "example.com")
	RPID string `yaml:"rp_id"`

	// RPOrigins are the allowed origins for WebAuthn requests
	RPOrigins []string `yaml:"rp_origins"`

	// RPDisplayName is the human-readable name shown to users
	RPDisplayName string `yaml:"rp_display_name"`

	// AttestationPreference controls attestation requirements
	// Values: "none", "indirect", "direct", "enterprise"
	AttestationPreference string `yaml:"attestation_preference"`

	// AuthenticatorSelection controls which authenticators are allowed
	AuthenticatorAttachment string `yaml:"authenticator_attachment"` // "platform", "cross-platform", ""
	ResidentKey             string `yaml:"resident_key"`             // "discouraged", "preferred", "required"
	UserVerification        string `yaml:"user_verification"`        // "discouraged", "preferred", "required"

	// AllowPublicRegistration controls whether an unknown email may create an
	// account through the WebAuthn registration ceremony (open self-service
	// sign-up). Unset means true: the platform is intended to be publicly
	// reachable, so omitting the key leaves registration open.
	//
	// A *bool, not a bool: with a plain bool the zero value is false, so every
	// config written before this field existed would silently switch to closed
	// registration on upgrade.
	//
	// Turning it off still lets accounts provisioned through the authorized
	// user-creation path enroll their first passkey; only implicit account
	// creation is withheld.
	AllowPublicRegistration *bool `yaml:"allow_public_registration,omitempty"`

	// JWT settings for token generation after successful authentication
	JWTKeyID     string   `yaml:"jwt_key_id"`     // Key ID in xkms for JWT signing
	JWTIssuer    string   `yaml:"jwt_issuer"`     // JWT issuer claim
	JWTAudience  []string `yaml:"jwt_audience"`   // JWT audience claim
	JWTExpiresIn string   `yaml:"jwt_expires_in"` // JWT expiration duration (e.g., "24h")
}

// JWTConfig controls JWT authentication
type JWTConfig struct {
	Secret        string   `yaml:"secret"`
	PublicKeyFile string   `yaml:"public_key_file"`
	Issuer        string   `yaml:"issuer"`
	Audience      []string `yaml:"audience"`
	Algorithm     string   `yaml:"algorithm"` // HS256, RS256, etc.
}

// CORSConfig controls cross-origin browser access to the REST API. Disabled
// by default: the embedded web UI is served same-origin from the daemon, so
// no CORS headers are needed and none are emitted. Enable it only when a
// browser client is intentionally served from another origin. Listing the
// wildcard "*" is reported as a compliance gap.
type CORSConfig struct {
	// Enabled turns CORS header emission on.
	Enabled bool `yaml:"enabled"`

	// AllowedOrigins lists the exact origins (scheme://host[:port]) allowed
	// to make cross-origin requests.
	AllowedOrigins []string `yaml:"allowed_origins"`

	// AllowCredentials sets Access-Control-Allow-Credentials for allowed
	// origins. Ignored for the wildcard origin per the Fetch standard.
	AllowCredentials bool `yaml:"allow_credentials"`

	// MaxAgeSeconds caps how long browsers may cache preflight responses.
	// Values <= 0 default to 3600.
	MaxAgeSeconds int `yaml:"max_age_seconds"`
}

// UIConfig configures the embedded web UI served by the REST transport.
type UIConfig struct {
	// Enabled toggles the UI mount. A nil value means enabled, so existing
	// configuration files without a ui section keep serving the UI; only an
	// explicit `enabled: false` turns it off.
	Enabled *bool `yaml:"enabled,omitempty"`

	// PathPrefix is the URL prefix the UI is mounted under. Empty selects
	// the default "/ui/".
	PathPrefix string `yaml:"path_prefix,omitempty"`

	// RedirectRoot redirects GET / to the UI prefix.
	RedirectRoot bool `yaml:"redirect_root,omitempty"`
}

// UIEnabled reports whether the embedded web UI should be served. An unset
// (nil) flag means enabled so configurations predating the ui section do not
// silently disable the UI.
func (c *Config) UIEnabled() bool {
	if c.UI.Enabled == nil {
		return true
	}
	return *c.UI.Enabled
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

// StorageConfig controls storage backend for metadata.
// Valid backends: "file", "memory", "pebble", "qrdb".
type StorageConfig struct {
	Backend string     `yaml:"backend"`
	Path    string     `yaml:"path"`
	QRDB    QRDBConfig `yaml:"qrdb"`
}

// QRDBConfig configures the QRDB distributed storage backend.
type QRDBConfig struct {
	// Address is the QRDB cluster endpoint (e.g., "https://localhost:63002").
	Address string `yaml:"address"`

	// Transport specifies the SDK transport type: "rest", "grpc", or "embedded".
	Transport string `yaml:"transport"`

	// TLS configures the TLS settings for the QRDB connection.
	TLS TLSConfig `yaml:"tls"`
}

// ErrClusterRaftTLSIncomplete is returned when cluster Raft mTLS is partially
// configured. The CA certificate, certificate, and key file paths must either
// all be set (mTLS enabled) or all be empty (mTLS disabled).
var ErrClusterRaftTLSIncomplete = errors.New(
	"cluster: raft_tls requires ca_cert_file, cert_file, and key_file to all be set or all be empty")

// ClusterConfig configures Raft clustering for high availability. When enabled,
// xkms hosts a clustered go-qrdb node (via NewClusteredNode) so all datastore
// state — keys, users, RBAC, custodian, shares, CA serials/revocations, etc. —
// is replicated across nodes. Clustering requires the embedded "qrdb" storage
// backend (PebbleDB-backed). These fields map onto go-qrdb's Raft config.
type ClusterConfig struct {
	// Enabled turns on Raft clustering. Requires Storage.Backend == "qrdb".
	Enabled bool `yaml:"enabled"`

	// NodeID is this node's Raft replica ID within the shard. Must be unique
	// across the cluster and non-zero.
	NodeID uint64 `yaml:"node_id"`

	// ShardID is the Raft shard (group) identifier. Defaults to 1.
	ShardID uint64 `yaml:"shard_id"`

	// DeploymentID isolates clusters that share a network. Optional.
	DeploymentID uint64 `yaml:"deployment_id"`

	// RaftAddress is this node's advertised address for Raft peer communication
	// (e.g., "10.0.0.1:63001").
	RaftAddress string `yaml:"raft_address"`

	// ListenAddress is the Raft bind address. Defaults to RaftAddress.
	ListenAddress string `yaml:"listen_address"`

	// AdvertiseHost is the host or IP that clients should use to reach THIS
	// node's xkms APIs. It is published into the cluster registry alongside the
	// ports of the enabled protocols, so a client that has been told "you are
	// talking to a follower, the leader is replica N" can turn N into an
	// address it can actually dial.
	//
	// It is distinct from Server.Host, which is a bind address and is commonly
	// a wildcard that no remote client can dial. When AdvertiseHost is unset the
	// node falls back to the host portion of RaftAddress, which is by definition
	// an address peers already use to reach this node. Deployments where the
	// API and Raft planes are reached over different addresses (NAT, split
	// networking) must set it explicitly.
	//
	// When neither AdvertiseHost nor a concrete RaftAddress host is available,
	// the node advertises nothing rather than an address no client can dial;
	// clients then see no endpoint and fall back to the leader hint alone.
	AdvertiseHost string `yaml:"advertise_host"`

	// Peers lists the initial cluster members as comma-separated
	// "nodeID=address" pairs (e.g., "1=10.0.0.1:63001,2=10.0.0.2:63001").
	// Must include this node's own NodeID=RaftAddress when bootstrapping.
	Peers string `yaml:"peers"`

	// Join indicates this node is joining an existing cluster rather than
	// bootstrapping a new one.
	Join bool `yaml:"join"`

	// RaftTLS configures mutual TLS for the inter-node Raft transport. It is
	// meaningful only for multi-node clusters (more than one peer). The PEM
	// material is operator-supplied and MUST NOT be the runtime xkms CA: the
	// CA is hosted by the very node the Raft transport replicates, so binding
	// Raft mTLS to it would be circular. When RaftTLS is set it takes precedence
	// over RaftEnrollment.
	RaftTLS RaftTLSConfig `yaml:"raft_tls"`

	// RaftEnrollment auto-provisions the inter-node Raft mTLS material when
	// RaftTLS files are not supplied. A multi-node Raft transport always
	// requires mTLS (it is mandatory in the transport layer), so without either
	// RaftTLS or RaftEnrollment a multi-node node fails to start. Enrollment is
	// delegated to go-qrdb's shared cluster-TLS toolkit (a dedicated self-signed
	// cluster CA, distinct from the runtime xkms CA): the first node generates
	// the CA and advertises it; joining nodes fetch it.
	RaftEnrollment RaftEnrollmentConfig `yaml:"raft_enrollment"`
}

// RaftTLSConfig holds the operator-supplied PEM file paths for mutual TLS on
// the inter-node Raft transport. Either all three fields are set (mTLS on) or
// all three are empty (mTLS off); a partial configuration is rejected at
// validation time. The files are read at boot, not at validation time, so they
// need not exist when Validate runs.
type RaftTLSConfig struct {
	// CACertFile is the path to the PEM-encoded CA certificate used to verify
	// peer Raft certificates.
	CACertFile string `yaml:"ca_cert_file"`

	// CertFile is the path to this node's PEM-encoded Raft certificate.
	CertFile string `yaml:"cert_file"`

	// KeyFile is the path to this node's PEM-encoded Raft private key.
	KeyFile string `yaml:"key_file"`
}

// Enabled reports whether Raft mTLS is configured. It is true only when all
// three PEM file paths are set; IsComplete distinguishes a partial (invalid)
// configuration from a fully-disabled one.
func (r RaftTLSConfig) Enabled() bool {
	return r.CACertFile != "" && r.CertFile != "" && r.KeyFile != ""
}

// IsComplete reports whether the configuration is internally consistent: all
// three fields set, or all three empty. A partial configuration returns false.
func (r RaftTLSConfig) IsComplete() bool {
	set := 0
	if r.CACertFile != "" {
		set++
	}
	if r.CertFile != "" {
		set++
	}
	if r.KeyFile != "" {
		set++
	}
	return set == 0 || set == 3
}

// RaftEnrollmentConfig configures automatic provisioning of the inter-node Raft
// mTLS material when RaftTLS files are not supplied. xkms delegates the
// provisioning to go-qrdb's shared cluster-TLS enrollment: the first node
// generates a dedicated self-signed cluster CA and advertises it over a Noise
// NK channel; joining nodes fetch it and issue their own node leaf. All fields
// are optional and default at boot.
type RaftEnrollmentConfig struct {
	// TrustDomain is the SPIFFE trust domain stamped into node certificates.
	// Defaults to "xkms.cluster".
	TrustDomain string `yaml:"trust_domain"`

	// KeyBackend selects the xkms crypto backend that generates and holds this
	// node's Raft TLS signing key. When set to a hardware backend ("tpm2" /
	// "pkcs11"), the private key is generated inside and never leaves the
	// device, and the Raft transport uses a signer-backed certificate (the node
	// leaf is issued from the cluster CA for the hardware key's public part).
	// When empty, the node key is a software key managed by the cluster-TLS
	// toolkit (the default).
	KeyBackend string `yaml:"key_backend"`

	// AdvertiseNoisePort is the TCP port the first (bootstrapping) node serves
	// the Noise NK bootstrap endpoint on for peer enrollment. Defaults to 63006.
	AdvertiseNoisePort int `yaml:"advertise_noise_port"`

	// Bootstrap configures how a JOINING node fetches the cluster CA bundle from
	// an existing node. Leave empty on the first (bootstrapping) node, which
	// generates the CA instead of fetching it.
	Bootstrap RaftBootstrapConfig `yaml:"bootstrap"`

	// ACME switches node-certificate issuance to TPM-attested ACME enroll-01:
	// the TrustedCA is the cluster trust anchor, node certificates are
	// TrustedCA-signed with a SPIFFE node SAN, and joining nodes prove their
	// identity via TPM attestation instead of receiving a shared CA key.
	ACME RaftACMEEnrollmentConfig `yaml:"acme"`

	// ClusterCACN names the CA identity (a dedicated intermediate) that issues
	// Raft transport certificates in ACME-attested mode. It must match a
	// Subject.CommonName in the CA configuration. When empty the CA's issuing
	// identity (SelectedCA) is used. Keeping transport issuance on a dedicated
	// intermediate (root signs intermediates only) is the recommended
	// FedRAMP/PCI posture.
	ClusterCACN string `yaml:"cluster_ca_cn"`

	// CAKeyProtection selects how the node-local cluster CA signing keystore
	// is protected at rest, using the canonical seal vocabulary:
	//   "" (auto) — TPM/HSM-sealed when available, else passphrase, else refuse
	//   "tpm2" / "pkcs11" — random key sealed to the TPM/HSM (unattended)
	//   "passphrase" — PBES2 with an operator passphrase
	//   "none" — plaintext PKCS#8 (development/testing only; refused in secure mode)
	// The cluster CA keys must exist before the replicated datastore, so they
	// live node-local and cannot be protected by the barrier; this reuses the
	// stack's standard seal strategies instead.
	CAKeyProtection string `yaml:"ca_key_protection"`

	// CAKeyPassphrase supplies the operator passphrase for the "passphrase"
	// protection mode (and the passphrase fallback in auto mode). Supports
	// credential:// references resolved at boot.
	CAKeyPassphrase string `yaml:"ca_key_passphrase"`

	// CAKeyStrategy selects how the cluster CA signing key is made available
	// across the cluster so that (per the custody model) the appropriate node(s)
	// can issue node certificates:
	//   "" / "barrier" — key in the replicated barrier-encrypted datastore; any
	//                    node loads it and can issue (the default, software HA).
	//   "hsm"          — key kept inside a shared PKCS#11 HSM; never leaves it.
	//   "tpm-kek"      — replicated key wrapped under a KEK derived from a cluster
	//                    seed sealed to each node's local TPM.
	CAKeyStrategy string `yaml:"ca_key_strategy"`
}

// RaftACMEEnrollmentConfig configures TPM-attested Raft node enrollment via
// ACME enroll-01. In this mode the xkms TrustedCA signs every Raft node
// certificate (it IS the cluster CA): the first node issues its own node
// certificate in-process from the local TrustedCA and advertises the
// TrustedCA trust anchor (certificates only, never a key) over the Noise NK
// bootstrap channel; joining nodes fetch the anchor, then obtain their node
// certificate through the ACME enroll-01 challenge (TCG-CSR-IDEVID +
// TPM2_MakeCredential/ActivateCredential) against an existing node's ACME
// server. Requires RaftEnrollment.KeyBackend "tpm2".
type RaftACMEEnrollmentConfig struct {
	// Enabled switches Raft node certificate provisioning to ACME-attested
	// mode. Requires KeyBackend "tpm2" and, on nodes serving enrollment, an
	// ACME server with the enroll-01 challenge enabled.
	Enabled bool `yaml:"enabled"`

	// DirectoryURL is the ACME directory endpoint of an existing cluster node
	// (e.g. "https://node1:8443/api/v1/acme/directory"). Required on JOINING
	// nodes; ignored on the first node, which issues in-process from the
	// local TrustedCA.
	DirectoryURL string `yaml:"directory_url"`

	// ChallengePort is the local HTTP port this node serves the enroll-01
	// credential-activation exchange on while enrolling; the ACME server
	// dials back to it. Defaults to "8080", matching the server default.
	ChallengePort string `yaml:"challenge_port"`
}

// Validate checks the attested-enrollment configuration against the rest of
// the enrollment config. The key backend is accepted for context: ACME-
// attested issuance works for any backend on the first node (in-process
// issuance stamps a key-provenance OID), and a JOINING node's challenge is
// selected by backend at runtime (tpm2 → enroll-01 TPM attestation; other
// backends → CSR enrollment). A software-only cluster is therefore valid;
// the runtime surfaces a precise error if a not-yet-implemented joiner path
// is reached.
func (a RaftACMEEnrollmentConfig) Validate(keyBackend string) error {
	if !a.Enabled {
		return nil
	}
	return nil
}

// RaftACMEConfigError is returned when the ACME-attested Raft enrollment
// configuration is invalid.
type RaftACMEConfigError struct {
	// Field names the offending configuration field.
	Field string
	// Reason describes why the value is invalid.
	Reason string
}

// Error returns the error message.
func (e *RaftACMEConfigError) Error() string {
	return "cluster: raft_enrollment.acme." + e.Field + ": " + e.Reason
}

// RaftBootstrapConfig holds the join-side bootstrap source a node uses to fetch
// the cluster CA bundle from an existing cluster member. The methods mirror
// go-qrdb's truststrap dispatch (Noise / SPKI-pinned HTTPS / DANE / Direct);
// configure whichever the bootstrapping node advertises.
type RaftBootstrapConfig struct {
	// NoiseKey is the hex Curve25519 public key of an existing node's Noise NK
	// bootstrap server (the first node logs it at startup).
	NoiseKey string `yaml:"noise_key"`

	// NoiseAddr is the host:port of that Noise NK bootstrap server.
	NoiseAddr string `yaml:"noise_addr"`

	// SPKIPin is a hex SHA-256 SPKI pin used to fetch the bundle over HTTPS.
	SPKIPin string `yaml:"spki_pin"`

	// ServerAddr is the host:port of the bootstrap HTTPS server (SPKI/DANE).
	ServerAddr string `yaml:"server_addr"`

	// DANEDNS is the DNS server used for DANE TLSA validation of the bootstrap
	// server certificate.
	DANEDNS string `yaml:"dane_dns"`

	// DANEDoT enables DNS-over-TLS for the DANE lookup.
	DANEDoT bool `yaml:"dane_dot"`

	// DirectURL fetches the bundle over plain HTTPS using the system trust
	// store. Last-resort fallback for trusted networks.
	DirectURL string `yaml:"direct_url"`
}

// Configured reports whether any join-side bootstrap source is set, indicating
// this node should fetch the cluster CA rather than generate it.
func (b RaftBootstrapConfig) Configured() bool {
	return b.NoiseKey != "" || b.NoiseAddr != "" || b.SPKIPin != "" ||
		b.DANEDNS != "" || b.DirectURL != ""
}

// Members parses Peers into the replicaID→address map that go-qrdb's
// NewClusteredNode expects. It returns a typed error for malformed entries.
func (c ClusterConfig) Members() (map[uint64]string, error) {
	members := make(map[uint64]string)
	for _, entry := range strings.Split(c.Peers, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, addr, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, &errs.Message{Msg: fmt.Sprintf("cluster: peer %q is not in nodeID=address form", entry)}
		}
		replicaID, err := strconv.ParseUint(strings.TrimSpace(id), 10, 64)
		if err != nil || replicaID == 0 {
			return nil, &errs.Message{Msg: fmt.Sprintf("cluster: peer %q has an invalid node ID", entry)}
		}
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return nil, &errs.Message{Msg: fmt.Sprintf("cluster: peer %q has an empty address", entry)}
		}
		members[replicaID] = addr
	}
	return members, nil
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
	// Note: Consider using environment variable XKMS_RNG_PKCS11_PIN instead
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
	Phone    *PhoneConfig    `yaml:"phone,omitempty"`
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

	// UseSimulator selects the in-process/TCP TPM simulator instead of a
	// hardware device — for development and testing. SimulatorHost/Port target
	// an external swtpm when set.
	UseSimulator  bool   `yaml:"use_simulator,omitempty"`
	SimulatorHost string `yaml:"simulator_host,omitempty"`
	SimulatorPort int    `yaml:"simulator_port,omitempty"`

	// SRKHandle is the persistent Storage Root Key handle (default 0x81000001).
	SRKHandle uint32 `yaml:"srk_handle,omitempty"`

	// PlatformPolicy binds sealed objects to a PCR policy; PlatformPCR /
	// PlatformPCRBank select the PCR index and bank.
	PlatformPolicy  bool   `yaml:"platform_policy,omitempty"`
	PlatformPCR     uint   `yaml:"platform_pcr,omitempty"`
	PlatformPCRBank string `yaml:"platform_pcr_bank,omitempty"`
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

// PhoneConfig contains phone backend settings for proxying key operations
// to an Android phone via BLE or TCP (ADB USB forwarding) using
// Noise-encrypted JSON-RPC.
type PhoneConfig struct {
	// Enabled controls whether the phone backend is active
	Enabled bool `yaml:"enabled"`

	// Transport specifies the transport type: "ble" or "tcp" (for ADB USB forwarding)
	Transport string `yaml:"transport"`

	// DeviceAddress is the BLE MAC address or TCP address (host:port) of the phone
	DeviceAddress string `yaml:"device_address"`

	// NoiseStaticKey is the hex-encoded Noise static private key for this host
	NoiseStaticKey string `yaml:"noise_static_key"`

	// PhoneStaticKey is the hex-encoded Noise static public key of the paired phone
	PhoneStaticKey string `yaml:"phone_static_key"`

	// RequestTimeout is the per-operation timeout for JSON-RPC requests to the phone.
	// If zero, the phone backend applies its default (30s).
	RequestTimeout time.Duration `yaml:"request_timeout"`

	// ConfigPath is the path to a pairing config file (alternative to inline config)
	ConfigPath string `yaml:"config_path"`
}

// BootstrapConfig controls secure CA bundle bootstrapping.
// Bootstrap enables new nodes to securely obtain CA certificates
// before TLS is configured (chicken-and-egg problem).
type BootstrapConfig struct {
	Noise NoiseBootstrapConfig `yaml:"noise"`
	SPKI  SPKIBootstrapConfig  `yaml:"spki"`
	DANE  DANEBootstrapConfig  `yaml:"dane"`
}

// NoiseBootstrapConfig configures the Noise_NK bootstrap server/client.
type NoiseBootstrapConfig struct {
	// Enabled controls whether Noise bootstrap is active
	Enabled bool `yaml:"enabled"`

	// StaticKeyFile is the path to the hex-encoded Noise static private key file
	StaticKeyFile string `yaml:"static_key_file"`

	// StaticKeyHex is an inline hex-encoded Noise static private key
	StaticKeyHex string `yaml:"static_key_hex"`

	// MaxConnections is the maximum concurrent bootstrap connections (default: 100)
	MaxConnections int `yaml:"max_connections"`

	// ReadTimeout is the per-read timeout (default: 10s)
	ReadTimeout string `yaml:"read_timeout"`

	// WriteTimeout is the per-write timeout (default: 10s)
	WriteTimeout string `yaml:"write_timeout"`
}

// SPKIBootstrapConfig configures SPKI-pinned TLS bootstrap.
type SPKIBootstrapConfig struct {
	// Enabled controls whether SPKI-pinned TLS bootstrap is available
	Enabled bool `yaml:"enabled"`

	// PinSHA256 is the hex-encoded SHA-256 hash of the server's SubjectPublicKeyInfo
	PinSHA256 string `yaml:"pin_sha256"`
}

// DANEBootstrapConfig configures DANE/TLSA-based certificate verification for bootstrap.
type DANEBootstrapConfig struct {
	// Enabled controls whether DANE bootstrap is active
	Enabled bool `yaml:"enabled"`

	// Hostname is the target hostname for TLSA record lookups
	Hostname string `yaml:"hostname"`

	// Port is the target port for TLSA record lookups (default: 443)
	Port int `yaml:"port"`

	// DNSServer is the DNS server to use for TLSA lookups (e.g., "8.8.8.8:53").
	// If empty, the system default resolver is used.
	DNSServer string `yaml:"dns_server"`
}

// Load reads configuration from a YAML file and applies environment variable overrides
func Load(path string) (*Config, error) {
	// Read the config file
	// #nosec G304 - Config file path is provided by admin/user
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read config file", Err: err}
	}

	// Parse YAML
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse config file", Err: err}
	}

	// Apply environment variable overrides
	applyEnvOverrides(&cfg)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid configuration", Err: err}
	}

	return &cfg, nil
}

// applyEnvOverrides applies environment variable overrides to the configuration
func applyEnvOverrides(cfg *Config) {
	// Server settings
	if host := os.Getenv("XKMS_HOST"); host != "" {
		cfg.Server.Host = host
	}

	if restPort := os.Getenv("XKMS_REST_PORT"); restPort != "" {
		if port, err := strconv.Atoi(restPort); err == nil && port >= 1 && port <= 65535 {
			cfg.Server.RESTPort = port
		}
	}

	if grpcPort := os.Getenv("XKMS_GRPC_PORT"); grpcPort != "" {
		if port, err := strconv.Atoi(grpcPort); err == nil && port >= 1 && port <= 65535 {
			cfg.Server.GRPCPort = port
		}
	}

	if quicPort := os.Getenv("XKMS_QUIC_PORT"); quicPort != "" {
		if port, err := strconv.Atoi(quicPort); err == nil && port >= 1 && port <= 65535 {
			cfg.Server.QUICPort = port
		}
	}

	if mcpPort := os.Getenv("XKMS_MCP_PORT"); mcpPort != "" {
		if port, err := strconv.Atoi(mcpPort); err == nil && port >= 1 && port <= 65535 {
			cfg.Server.MCPPort = port
		}
	}

	// Storage settings
	if v := os.Getenv("XKMS_STORAGE_BACKEND"); v != "" {
		cfg.Storage.Backend = v
	}
	if v := os.Getenv("XKMS_STORAGE_PATH"); v != "" {
		cfg.Storage.Path = v
	}

	// Clustering settings
	if v := os.Getenv("XKMS_CLUSTER_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Cluster.Enabled = b
		}
	}
	if v := os.Getenv("XKMS_CLUSTER_NODE_ID"); v != "" {
		if id, err := strconv.ParseUint(v, 10, 64); err == nil {
			cfg.Cluster.NodeID = id
		}
	}
	if v := os.Getenv("XKMS_CLUSTER_SHARD_ID"); v != "" {
		if id, err := strconv.ParseUint(v, 10, 64); err == nil {
			cfg.Cluster.ShardID = id
		}
	}
	if v := os.Getenv("XKMS_CLUSTER_RAFT_ADDRESS"); v != "" {
		cfg.Cluster.RaftAddress = v
	}
	if v := os.Getenv("XKMS_CLUSTER_LISTEN_ADDRESS"); v != "" {
		cfg.Cluster.ListenAddress = v
	}
	if v := os.Getenv("XKMS_CLUSTER_PEERS"); v != "" {
		cfg.Cluster.Peers = v
	}
	if v := os.Getenv("XKMS_CLUSTER_JOIN"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Cluster.Join = b
		}
	}
	if v := os.Getenv("XKMS_CLUSTER_RAFT_CA_CERT"); v != "" {
		cfg.Cluster.RaftTLS.CACertFile = v
	}
	if v := os.Getenv("XKMS_CLUSTER_RAFT_CERT"); v != "" {
		cfg.Cluster.RaftTLS.CertFile = v
	}
	if v := os.Getenv("XKMS_CLUSTER_RAFT_KEY"); v != "" {
		cfg.Cluster.RaftTLS.KeyFile = v
	}

	// Unix socket settings
	if socketPath := os.Getenv("XKMS_SOCKET_PATH"); socketPath != "" {
		cfg.Unix.SocketPath = socketPath
	}
	if socketMode := os.Getenv("XKMS_SOCKET_MODE"); socketMode != "" {
		cfg.Unix.SocketMode = socketMode
	}
	if protocol := os.Getenv("XKMS_UNIX_PROTOCOL"); protocol != "" {
		cfg.Unix.Protocol = protocol
	}

	// Logging
	if level := os.Getenv("XKMS_LOG_LEVEL"); level != "" {
		cfg.Logging.Level = level
	}

	if format := os.Getenv("XKMS_LOG_FORMAT"); format != "" {
		cfg.Logging.Format = format
	}

	// Storage
	if dataDir := os.Getenv("XKMS_DATA_DIR"); dataDir != "" {
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

	// Phone backend settings
	if cfg.Backends.Phone != nil {
		if transport := os.Getenv("XKMS_PHONE_TRANSPORT"); transport != "" {
			cfg.Backends.Phone.Transport = transport
		}
		if deviceAddr := os.Getenv("XKMS_PHONE_DEVICE_ADDRESS"); deviceAddr != "" {
			cfg.Backends.Phone.DeviceAddress = deviceAddr
		}
		if noiseKey := os.Getenv("XKMS_PHONE_NOISE_STATIC_KEY"); noiseKey != "" {
			cfg.Backends.Phone.NoiseStaticKey = noiseKey
		}
		if phoneKey := os.Getenv("XKMS_PHONE_STATIC_KEY"); phoneKey != "" {
			cfg.Backends.Phone.PhoneStaticKey = phoneKey
		}
		if configPath := os.Getenv("XKMS_PHONE_CONFIG_PATH"); configPath != "" {
			cfg.Backends.Phone.ConfigPath = configPath
		}
		if timeout := os.Getenv("XKMS_PHONE_REQUEST_TIMEOUT"); timeout != "" {
			if d, err := time.ParseDuration(timeout); err == nil && d > 0 {
				cfg.Backends.Phone.RequestTimeout = d
			}
		}
	}

	// Bootstrap settings - Noise
	if noiseEnabled := os.Getenv("XKMS_NOISE_ENABLED"); noiseEnabled != "" {
		cfg.Bootstrap.Noise.Enabled = strings.EqualFold(noiseEnabled, "true")
	}
	if noiseKey := os.Getenv("XKMS_NOISE_STATIC_KEY"); noiseKey != "" {
		cfg.Bootstrap.Noise.StaticKeyHex = noiseKey
	}
	if noiseKeyFile := os.Getenv("XKMS_NOISE_STATIC_KEY_FILE"); noiseKeyFile != "" {
		cfg.Bootstrap.Noise.StaticKeyFile = noiseKeyFile
	}
	if noisePort := os.Getenv("XKMS_NOISE_PORT"); noisePort != "" {
		if port, err := strconv.Atoi(noisePort); err == nil && port >= 1 && port <= 65535 {
			cfg.Server.NoisePort = port
		}
	}

	// Bootstrap settings - SPKI
	if spkiPin := os.Getenv("XKMS_SPKI_PIN"); spkiPin != "" {
		cfg.Bootstrap.SPKI.PinSHA256 = spkiPin
		cfg.Bootstrap.SPKI.Enabled = true
	}

	// Bootstrap settings - DANE
	if daneEnabled := os.Getenv("XKMS_DANE_ENABLED"); daneEnabled != "" {
		cfg.Bootstrap.DANE.Enabled = strings.EqualFold(daneEnabled, "true")
	}
	if daneHostname := os.Getenv("XKMS_DANE_HOSTNAME"); daneHostname != "" {
		cfg.Bootstrap.DANE.Hostname = daneHostname
	}
	if danePort := os.Getenv("XKMS_DANE_PORT"); danePort != "" {
		if port, err := strconv.Atoi(danePort); err == nil && port >= 1 && port <= 65535 {
			cfg.Bootstrap.DANE.Port = port
		}
	}
	if daneDNS := os.Getenv("XKMS_DANE_DNS_SERVER"); daneDNS != "" {
		cfg.Bootstrap.DANE.DNSServer = daneDNS
	}

	// Rate limiting settings
	if enabled := os.Getenv("XKMS_RATELIMIT_ENABLED"); enabled != "" {
		cfg.RateLimit.Enabled = strings.EqualFold(enabled, "true")
	}

	if rpm := os.Getenv("XKMS_RATELIMIT_REQUESTS_PER_MIN"); rpm != "" {
		if val, err := strconv.Atoi(rpm); err == nil && val > 0 {
			cfg.RateLimit.RequestsPerMin = val
		}
	}

	if burst := os.Getenv("XKMS_RATELIMIT_BURST"); burst != "" {
		if val, err := strconv.Atoi(burst); err == nil && val > 0 {
			cfg.RateLimit.Burst = val
		}
	}

	// RNG settings
	if mode := os.Getenv("XKMS_RNG_MODE"); mode != "" {
		cfg.RNG.Mode = mode
	}
	if fallback := os.Getenv("XKMS_RNG_FALLBACK"); fallback != "" {
		cfg.RNG.FallbackMode = fallback
	}
	// TPM2 RNG settings
	if tpmDevice := os.Getenv("XKMS_RNG_TPM2_DEVICE"); tpmDevice != "" {
		if cfg.RNG.TPM2 == nil {
			cfg.RNG.TPM2 = &RNGTPM2Config{}
		}
		cfg.RNG.TPM2.Device = tpmDevice
	}
	if simHost := os.Getenv("XKMS_RNG_TPM2_SIMULATOR_HOST"); simHost != "" {
		if cfg.RNG.TPM2 == nil {
			cfg.RNG.TPM2 = &RNGTPM2Config{}
		}
		cfg.RNG.TPM2.SimulatorHost = simHost
		cfg.RNG.TPM2.UseSimulator = true
	}
	if simPort := os.Getenv("XKMS_RNG_TPM2_SIMULATOR_PORT"); simPort != "" {
		if val, err := strconv.Atoi(simPort); err == nil && val > 0 {
			if cfg.RNG.TPM2 == nil {
				cfg.RNG.TPM2 = &RNGTPM2Config{}
			}
			cfg.RNG.TPM2.SimulatorPort = val
			cfg.RNG.TPM2.UseSimulator = true
		}
	}
	// PKCS#11 RNG settings
	if pkcs11Module := os.Getenv("XKMS_RNG_PKCS11_MODULE"); pkcs11Module != "" {
		if cfg.RNG.PKCS11 == nil {
			cfg.RNG.PKCS11 = &RNGPKCS11Config{}
		}
		cfg.RNG.PKCS11.Module = pkcs11Module
	}
	if slotID := os.Getenv("XKMS_RNG_PKCS11_SLOT"); slotID != "" {
		if val, err := strconv.ParseUint(slotID, 10, 32); err == nil {
			if cfg.RNG.PKCS11 == nil {
				cfg.RNG.PKCS11 = &RNGPKCS11Config{}
			}
			cfg.RNG.PKCS11.SlotID = uint(val)
		}
	}
	if pin := os.Getenv("XKMS_RNG_PKCS11_PIN"); pin != "" {
		if cfg.RNG.PKCS11 == nil {
			cfg.RNG.PKCS11 = &RNGPKCS11Config{}
		}
		cfg.RNG.PKCS11.PIN = pin
		cfg.RNG.PKCS11.PINRequired = true
	}

	// Credentials seal strategy
	if strategy := os.Getenv("XKMS_CREDENTIALS_SEAL_STRATEGY"); strategy != "" {
		cfg.Credentials.SealStrategy = strategy
	}

	// Barrier / seal overrides. XKMS_SEAL_PASSPHRASE is the primary unattended
	// auto-unseal secret source; XKMS_SEAL_STRATEGY selects the strategy.
	if strategy := os.Getenv("XKMS_SEAL_STRATEGY"); strategy != "" {
		cfg.Barrier.Strategy = strategy
	}
	if pass := os.Getenv("XKMS_SEAL_PASSPHRASE"); pass != "" {
		cfg.Barrier.Passphrase = pass
	}
}

// ComplianceGaps reports security settings that fall short of the
// secure-by-default posture required for FedRAMP (SC-8, SC-28, IA-2),
// PCI-DSS v4 (3.5, 4.2, 8.x), and HIPAA (§164.312(a)(2)(iv), (e)(1))
// deployments: encryption at rest (the barrier), TLS in transit, authenticated
// access, and a CA for certificate provisioning / mTLS trust. An empty slice
// means the configuration meets the baseline. The daemon uses this to refuse an
// insecure start unless the operator explicitly opts into development mode.
func (c *Config) ComplianceGaps() []string {
	var gaps []string
	if !c.Barrier.Enabled {
		gaps = append(gaps, "encryption-at-rest disabled (barrier.enabled=false): data is stored in plaintext")
	} else if strings.EqualFold(c.Storage.Backend, "qrdb") && c.barrierLeavesKeysPlaintext() {
		// On an embedded qrdb node the barrier encrypts the data plane (and thus
		// the crypto backends' key stores) only when it can auto-unseal at boot —
		// a TPM/hardware strategy or a boot passphrase. A passphrase strategy with
		// no boot secret cannot auto-unseal, so the node falls back to a plaintext
		// data plane; the backend key stores would be written in the clear.
		gaps = append(gaps, "barrier cannot auto-unseal (barrier.strategy=\""+c.Barrier.SealStrategy()+
			"\" with no passphrase and no hardware backend): the embedded data plane — including backend key stores — "+
			"would be stored in plaintext. Provide XKMS_SEAL_PASSPHRASE (or barrier.passphrase), or configure a TPM/HSM seal strategy")
	}
	if !c.TLS.Enabled {
		gaps = append(gaps, "TLS disabled (tls.enabled=false): traffic is sent in cleartext")
	}
	if !c.Auth.Enabled {
		gaps = append(gaps, "authentication disabled (auth.enabled=false): access is anonymous")
	} else if t := strings.ToLower(strings.TrimSpace(c.Auth.Type)); t == "" || t == "noop" || t == "none" {
		// auth.enabled=true but the type resolves to the no-op authenticator
		// (see config/auth.go: "noop"/"none"/"" all map to NewNoOpAuthenticator),
		// so every request is admitted without credentials — indistinguishable
		// from disabled auth for FedRAMP IA-2 / PCI 8.x / HIPAA.
		gaps = append(gaps, "authentication is no-op (auth.type=\""+c.Auth.Type+"\"): access is effectively anonymous")
	}
	// RBAC is the authorization engine for every transport (REST, gRPC, QUIC,
	// MCP), and it is backed exclusively by the qrdb identity plane, which only
	// exists when qrdb is the storage backend. Enabling RBAC against any other
	// backend leaves the Authorizer nil, so each transport falls back to
	// allow-all: every authenticated caller gets every permission, regardless of
	// role. That is an access control the operator explicitly asked for that
	// silently does nothing — FedRAMP AC-3/AC-6, PCI-DSS v4 7.x, and HIPAA
	// §164.312(a)(1) all require it to actually be enforced.
	if c.Auth.EnableRBAC && !strings.EqualFold(strings.TrimSpace(c.Storage.Backend), "qrdb") {
		gaps = append(gaps, "RBAC enabled without an identity plane (auth.enable_rbac=true, storage.backend=\""+
			c.Storage.Backend+"\"): the qrdb-backed authorizer cannot be built, so every transport authorizes "+
			"all requests. Set storage.backend=\"qrdb\" or disable auth.enable_rbac")
	}
	if c.CA == nil {
		gaps = append(gaps, "no CA configured (ca is unset): no certificate provisioning or mTLS trust anchor")
	}
	// A wildcard CORS origin lets any website script drive the API with the
	// victim's ambient network position (and, with credentials, their session).
	// FedRAMP AC-4/SC-7 boundary-protection controls and PCI-DSS v4 6.4.x
	// require the access boundary to be explicit, not "every origin".
	if c.CORS.Enabled {
		for _, origin := range c.CORS.AllowedOrigins {
			if strings.TrimSpace(origin) == "*" {
				gaps = append(gaps, "CORS allows every origin (cors.allowed_origins contains \"*\"): "+
					"any website can script cross-origin requests against the API. List explicit origins instead")
				break
			}
		}
	}
	// Algorithm policy is deliberately NOT a compliance gap. Which algorithms
	// are approved is a property of the deployed binary and its runtime, not
	// of a configuration file: build with GOFIPS140=<version> and/or run with
	// GODEBUG=fips140=on|only, and the Go validated module refuses the
	// non-approved digests and key-wrap constructions itself
	// (pkg/types.FIPSMode reports it). xkms is not a FIPS-only implementation
	// — PKCS#11 and TLS both define SHA-1/MD5 mechanisms, and a
	// conformance-complete module has to be able to offer them outside FIPS
	// mode — so refusing them here would make the daemon unable to serve its
	// own specification while doing nothing a FIPS deployment does not
	// already do at the module boundary.
	// The cluster ACME node-local CA signing keystore lives outside the barrier
	// (it must exist before the replicated datastore) and is protected by the
	// standard seal strategies instead. Plaintext ("none") protection writes the
	// cluster CA private key to disk in the clear — refused unless the operator
	// explicitly opts into development mode.
	if c.Cluster.Enabled && c.Cluster.RaftEnrollment.ACME.Enabled &&
		strings.EqualFold(strings.TrimSpace(c.Cluster.RaftEnrollment.CAKeyProtection), "none") {
		gaps = append(gaps, "cluster CA key protection is plaintext (cluster.raft_enrollment.ca_key_protection=\"none\"): "+
			"the node-local cluster CA signing key would be stored in the clear. Use \"tpm2\"/\"pkcs11\", \"passphrase\", or auto")
	}
	// An ACME CA that issues and revokes certificates without recording who
	// asked for what has no accountability record: FedRAMP AU-2/AU-3/AU-9,
	// PCI-DSS v4 10.2, and HIPAA 164.312(b) all require one. The trail is on
	// by default, so this only fires when the operator explicitly turned it off.
	if c.ACME != nil && c.ACME.Enabled && !c.ACME.Audit.IsEnabled() {
		gaps = append(gaps, "ACME audit trail disabled (acme.audit.enabled=false): certificate issuance, "+
			"revocation, account creation, and TPM enrollment would go unrecorded")
	}
	return gaps
}

// barrierLeavesKeysPlaintext reports whether the configured barrier would leave
// the qrdb node's data plane unencrypted because it cannot auto-unseal at boot:
// a passphrase/software/none strategy with no boot passphrase and no hardware
// backend to seal against. A hardware strategy (tpm2/pkcs11/cloud) or a
// configured passphrase can auto-unseal, so the data plane is encrypted.
func (c *Config) barrierLeavesKeysPlaintext() bool {
	if c.Barrier.IsHardwareSealStrategy() {
		return false
	}
	switch c.Barrier.SealStrategy() {
	case "passphrase":
		return c.Barrier.Passphrase == ""
	case "none":
		return true
	default: // shamir and anything else never auto-unseals at boot
		return true
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate server ports
	// Network serving runs exclusively on the unified API server: the
	// embedded qrdb node takes xkmsd's ports and serves the capability
	// plane through the registered ServiceModule. The node is the single
	// core, so network protocols require qrdb storage; and qrdb's
	// transports are TLS-only while xkms's CA cannot auto-provision the
	// node's certificate (the CA composes after — and stores into — the
	// node), so explicit TLS material is required. Fail closed at
	// validation rather than at node construction. Local IPC (the Unix
	// socket and the loopback desktop engine) is exempt.
	if c.NetworkServing() {
		if c.Storage.Backend != "qrdb" {
			return &errs.Message{Msg: fmt.Sprintf("network protocols require storage.backend \"qrdb\" (the embedded qrdb node is the unified API server); got %q — local-only deployments disable rest/grpc/quic/mcp and use the unix socket", c.Storage.Backend)}
		}
		if !c.TLS.Enabled {
			return &errs.Message{Msg: "network protocols require tls.enabled: the unified API server's transports are TLS-only (explicit cert_file/key_file are optional — without them a bootstrap certificate serves until the CA issues the real one)"}
		}
	}

	if c.Protocols.REST && (c.Server.RESTPort < 1 || c.Server.RESTPort > 65535) {
		return &errs.Message{Msg: fmt.Sprintf("invalid REST port: %d", c.Server.RESTPort)}
	}
	if c.Protocols.GRPC && (c.Server.GRPCPort < 1 || c.Server.GRPCPort > 65535) {
		return &errs.Message{Msg: fmt.Sprintf("invalid gRPC port: %d", c.Server.GRPCPort)}
	}
	if c.Protocols.QUIC && (c.Server.QUICPort < 1 || c.Server.QUICPort > 65535) {
		return &errs.Message{Msg: fmt.Sprintf("invalid QUIC port: %d", c.Server.QUICPort)}
	}
	if c.Protocols.MCP && (c.Server.MCPPort < 1 || c.Server.MCPPort > 65535) {
		return &errs.Message{Msg: fmt.Sprintf("invalid MCP port: %d", c.Server.MCPPort)}
	}
	if c.Protocols.Noise && (c.Server.NoisePort < 1 || c.Server.NoisePort > 65535) {
		return &errs.Message{Msg: fmt.Sprintf("invalid Noise port: %d", c.Server.NoisePort)}
	}

	// Validate at least one protocol is enabled (Unix socket counts as a protocol)
	if !c.Protocols.Unix && !c.Protocols.REST && !c.Protocols.GRPC && !c.Protocols.QUIC && !c.Protocols.MCP && !c.Protocols.Noise {
		return &errs.Message{Msg: "at least one protocol must be enabled"}
	}

	// Validate Unix socket protocol
	if c.Unix.Enabled && c.Unix.Protocol != "" {
		validProtocols := map[string]bool{
			"grpc": true,
			"http": true,
		}
		if !validProtocols[strings.ToLower(c.Unix.Protocol)] {
			return &errs.Message{Msg: fmt.Sprintf("invalid Unix socket protocol: %s (must be grpc or http)", c.Unix.Protocol)}
		}
	}

	// Validate logging level
	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	if !validLevels[strings.ToLower(c.Logging.Level)] {
		return &errs.Message{Msg: fmt.Sprintf("invalid log level: %s (must be debug, info, warn, error, or fatal)", c.Logging.Level)}
	}

	// Validate logging format
	validFormats := map[string]bool{
		"json": true, "text": true, "console": true,
	}
	if !validFormats[strings.ToLower(c.Logging.Format)] {
		return &errs.Message{Msg: fmt.Sprintf("invalid log format: %s (must be json, text, or console)", c.Logging.Format)}
	}

	// PIV/mTLS cert login exchanges a TLS-verified client certificate for a
	// bearer token, so the TLS layer must actually request client certs —
	// otherwise the endpoint can never succeed and the operator config is a
	// contradiction. "verify" (VerifyClientCertIfGiven) is the web posture:
	// passkey-only users are not blocked by the handshake.
	if c.Auth.PIVLogin != nil && c.Auth.PIVLogin.Enabled {
		switch strings.ToLower(strings.TrimSpace(c.TLS.ClientAuth)) {
		case "", "none":
			return &errs.Message{Msg: "auth.piv_login.enabled requires tls.client_auth to request client certificates (use \"verify\", \"request\", or \"require_and_verify\")"}
		}
		if !c.TLS.Enabled {
			return &errs.Message{Msg: "auth.piv_login.enabled requires tls.enabled"}
		}
	}

	// Session TTLs must parse as Go durations when set.
	if c.Auth.Session != nil {
		if v := c.Auth.Session.AccessTokenTTL; v != "" {
			if _, err := time.ParseDuration(v); err != nil {
				return &errs.Message{Msg: fmt.Sprintf("invalid auth.session.access_token_ttl: %s", v)}
			}
		}
		if v := c.Auth.Session.RefreshTokenTTL; v != "" {
			if _, err := time.ParseDuration(v); err != nil {
				return &errs.Message{Msg: fmt.Sprintf("invalid auth.session.refresh_token_ttl: %s", v)}
			}
		}
	}

	// Validate TLS settings.
	// cert_file/key_file are not required when a CA is configured (TLS
	// certificates are generated from the CA, hardware-backed
	// crypto.Signer) nor on the unified API server (a persisted bootstrap
	// certificate serves until the CA issues the real one — see
	// pkg/server/unified_tls.go). Only a TLS-enabled local-IPC deployment
	// with neither a CA nor the unified server has no certificate source
	// and must supply files.
	if c.TLS.Enabled && c.CA == nil && !c.NetworkServing() {
		if c.TLS.CertFile == "" {
			return &errs.Message{Msg: "TLS cert_file is required when TLS is enabled without CA"}
		}
		if c.TLS.KeyFile == "" {
			return &errs.Message{Msg: "TLS key_file is required when TLS is enabled without CA"}
		}
	}

	// Validate storage. An unspecified backend defaults to durable PebbleDB
	// rather than failing — production paths must never silently fall back to a
	// non-durable store. Deployments that want plain files set backend "file"
	// explicitly (respected, not migrated).
	if c.Storage.Backend == "" {
		c.Storage.Backend = "pebble"
	}
	switch strings.ToLower(c.Storage.Backend) {
	case "qrdb":
		// Default the transport to "embedded" so a standalone qrdb backend
		// works without specifying a transport.
		if c.Storage.QRDB.Transport == "" {
			c.Storage.QRDB.Transport = "embedded"
		}
		switch strings.ToLower(c.Storage.QRDB.Transport) {
		case "embedded":
			// Embedded qrdb persists data under the storage path, so a path
			// is required but a cluster address is not.
			if c.Storage.Path == "" {
				return &errs.Message{Msg: "storage path must be specified for embedded qrdb"}
			}
		case "rest", "grpc":
			// Remote qrdb dials a cluster endpoint, so an address is required.
			if c.Storage.QRDB.Address == "" {
				return &errs.Message{Msg: "qrdb storage address is required for remote qrdb transport"}
			}
		default:
			return &errs.Message{Msg: fmt.Sprintf("invalid qrdb transport: %s (must be embedded, rest, or grpc)", c.Storage.QRDB.Transport)}
		}
	default:
		if c.Storage.Path == "" {
			return &errs.Message{Msg: "storage path must be specified"}
		}
	}

	// Validate RNG mode
	if c.RNG.Mode != "" {
		validModes := map[string]bool{
			"auto": true, "software": true, "tpm2": true, "pkcs11": true,
		}
		if !validModes[strings.ToLower(c.RNG.Mode)] {
			return &errs.Message{Msg: fmt.Sprintf("invalid RNG mode: %s (must be auto, software, tpm2, or pkcs11)", c.RNG.Mode)}
		}
	}
	if c.RNG.FallbackMode != "" {
		validModes := map[string]bool{
			"software": true, "tpm2": true, "pkcs11": true,
		}
		if !validModes[strings.ToLower(c.RNG.FallbackMode)] {
			return &errs.Message{Msg: fmt.Sprintf("invalid RNG fallback mode: %s (must be software, tpm2, or pkcs11)", c.RNG.FallbackMode)}
		}
	}

	// Validate default backend
	if string(c.Default) == "" {
		return &errs.Message{Msg: "default_backend must be specified"}
	}

	// Validate at least one backend is enabled
	hasEnabledBackend := false
	if c.Backends.Software != nil && c.Backends.Software.Enabled {
		hasEnabledBackend = true
		if c.Backends.Software.Path == "" {
			return &errs.Message{Msg: "software backend path is required when enabled"}
		}
	}
	if c.Backends.PKCS8 != nil && c.Backends.PKCS8.Enabled {
		hasEnabledBackend = true
		if c.Backends.PKCS8.Path == "" {
			return &errs.Message{Msg: "PKCS8 backend path is required when enabled"}
		}
	}
	if c.Backends.TPM2 != nil && c.Backends.TPM2.Enabled {
		hasEnabledBackend = true
		if c.Backends.TPM2.DevicePath == "" {
			return &errs.Message{Msg: "TPM2 device_path is required when enabled"}
		}
	}
	if c.Backends.PKCS11 != nil && c.Backends.PKCS11.Enabled {
		hasEnabledBackend = true
		if c.Backends.PKCS11.Library == "" {
			return &errs.Message{Msg: "PKCS11 library is required when enabled"}
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
	if c.Backends.Phone != nil && c.Backends.Phone.Enabled {
		hasEnabledBackend = true
		if c.Backends.Phone.Transport == "" {
			return &errs.Message{Msg: "phone backend transport is required when enabled (ble or tcp)"}
		}
		validTransports := map[string]bool{
			"ble": true, "tcp": true,
		}
		if !validTransports[strings.ToLower(c.Backends.Phone.Transport)] {
			return &errs.Message{Msg: fmt.Sprintf("invalid phone backend transport: %s (must be ble or tcp)", c.Backends.Phone.Transport)}
		}
	}

	if !hasEnabledBackend {
		return &errs.Message{Msg: "at least one backend must be enabled"}
	}

	// Validate ACME configuration (no-op unless acme.enabled is true).
	if err := c.ACME.Validate(); err != nil {
		return err
	}

	// Validate clustering. When enabled it requires the embedded, replicated
	// "qrdb" backend and a complete, parseable membership.
	if c.Cluster.Enabled {
		if c.Cluster.ShardID == 0 {
			c.Cluster.ShardID = 1
		}
		if !strings.EqualFold(c.Storage.Backend, "qrdb") {
			return &errs.Message{Msg: fmt.Sprintf("cluster.enabled requires storage.backend \"qrdb\" (got %q)", c.Storage.Backend)}
		}
		if c.Cluster.NodeID == 0 {
			return &errs.Message{Msg: "cluster.node_id is required and must be non-zero"}
		}
		if c.Cluster.RaftAddress == "" {
			return &errs.Message{Msg: "cluster.raft_address is required"}
		}
		members, err := c.Cluster.Members()
		if err != nil {
			return err
		}
		if len(members) == 0 {
			return &errs.Message{Msg: "cluster.peers must list at least this node (nodeID=address)"}
		}
		if !c.Cluster.Join {
			if _, ok := members[c.Cluster.NodeID]; !ok {
				return &errs.Message{Msg: fmt.Sprintf("cluster.peers must include this node's own node_id (%d) when bootstrapping", c.Cluster.NodeID)}
			}
		}
		// Raft mTLS is all-or-nothing: a partial configuration (some but not
		// all of CA/cert/key set) is a hard error. The PEM files are loaded at
		// boot, so their existence is not checked here.
		if !c.Cluster.RaftTLS.IsComplete() {
			return ErrClusterRaftTLSIncomplete
		}
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
	if c.Backends.Phone != nil && c.Backends.Phone.Enabled {
		backends = append(backends, "phone")
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
