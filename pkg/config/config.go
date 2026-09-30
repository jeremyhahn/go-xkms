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
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/escrow"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/trust/resolver"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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
	Datastore   DatastoreConfig           `yaml:"datastore"`
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
	// Escrow configures the optional external key escrow subsystem
	// (pkg/escrow). When nil or Enabled is false, no escrow agents are
	// constructed and the escrow servicer methods return ErrNotConfigured.
	Escrow *escrow.Config `yaml:"escrow,omitempty"`
	// Attestation configures the hardware-attestation trust anchors used to
	// verify attestation chains presented with a CSR. When nil, attestation-
	// gated CSR signing fails closed.
	Attestation *AttestationConfig `yaml:"attestation,omitempty"`
	// Trust configures the ordered strategy-chain trust resolver. When
	// nil, trust resolution falls back to the OS system trust store.
	Trust *resolver.Config `yaml:"trust,omitempty"`

	// Invite configures administrator-issued user enrollment invitations
	// (go-xkms#1294 part B). When nil, invitations use qrdb's own defaults
	// and the invite link is built from an empty public base URL, which is
	// never useful in production — an operator serving invitations over the
	// network must set PublicBaseURL.
	Invite *InviteConfig `yaml:"invite,omitempty"`

	// LoopbackDesktop marks this Config as backing the in-process loopback
	// desktop engine (pkg/server/loopback), not a network-facing deployment.
	// desktopConfig forces Protocols.REST on so the SPA can reach the engine
	// over 127.0.0.1, which makes NetworkServing report true; Validate uses
	// this field to skip, for that one launch shape only, the
	// datastore.mode "standalone" and tls.enabled requirements
	// NetworkServing's doc comment describes as exempt for local IPC. No
	// other check is affected: a loopback config still needs a valid port,
	// a configured datastore, and everything else Validate enforces.
	//
	// It is a pure embedder signal, never a deployment setting: yaml:"-"
	// keeps it unreachable from any config file, environment variable, or
	// flag, so only trusted Go code in this process can set it. Today that is
	// exactly one call site, desktopConfig, which builds the copy handed to
	// server.New and never round-trips it through YAML.
	LoopbackDesktop bool `yaml:"-"`
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
// crypto backends' key stores — is encrypted. It auto-unseals at boot only
// through a registered hardware seal strategy (tpm2/pkcs11) or the explicit
// "none" strategy; software strategies (passphrase/shamir) never auto-unseal
// from configuration — matching go-qrdb's own SealConfig, which carries no
// passphrase field at all. An operator supplies the passphrase or Shamir
// quorum at Initialize/Unseal time through `xkmsctl barrier unseal` (or
// `unseal-shares`) or the equivalent API call, every time the process
// restarts. This is the same barrier go-quicbaas uses; xkms provisions its
// own instance through this config (config/CLI/env), the same shared
// mechanism every product in the stack drives through its own front door.
type BarrierConfig struct {
	// Enabled turns the node barrier on. When false the node boots unsealed
	// with a plaintext data plane, which ComplianceGaps reports and the daemon
	// refuses to start on — there is no override.
	Enabled bool `yaml:"enabled"`

	// Strategy selects the seal strategy using the canonical stack vocabulary:
	// none | passphrase | shamir | tpm2 | pkcs11 | awskms | gcpkms | azurekv |
	// vault. Empty defaults to passphrase. Hardware/cloud strategies are
	// resolved and injected as a SealingStrategy; passphrase/shamir/none map to
	// the node's native SealConfig.Strategy. A "passphrase" or "shamir"
	// strategy never auto-unseals from configuration: there is no config field
	// for the secret. It is supplied by the operator at Initialize/Unseal time
	// (see BarrierConfig's doc comment).
	Strategy string `yaml:"strategy,omitempty"`

	// RootKeyPath is the barrier root-key location in the seal store.
	RootKeyPath string `yaml:"root_key_path,omitempty"`

	// ShamirThreshold and ShamirTotal configure the Shamir M-of-N quorum for the
	// shamir strategy. Shamir never auto-unseals (operator quorum required).
	ShamirThreshold int `yaml:"shamir_threshold,omitempty"`
	ShamirTotal     int `yaml:"shamir_total,omitempty"`

	// PreferenceOrder retains the hardware-strategy ordering used when resolving
	// which configured hardware backend seals the barrier. Optional.
	PreferenceOrder []string `yaml:"preference_order,omitempty"`

	// SealedWindowAllowRemote permits the node's pre-boot sealed-window
	// listener (opened when node-owned auto-unseal does not succeed at
	// startup — a wrong boot passphrase or a TPM PCR mismatch) to bind a
	// non-loopback Server.Host. It defaults to false: while the barrier is
	// sealed, the listener's allowlisted init verbs (barrier status,
	// initialize, unseal, ceremony, credentials) are DELIBERATELY
	// unauthenticated — possession of the unseal credential is the
	// authorization, Vault-style — so binding that window to a public
	// interface exposes barrier status and an unseal race to anyone who can
	// reach it. Set this only when Server.Host is already restricted to a
	// trusted management network and remote init is required; the same
	// Server.Host also serves the full API once unsealed.
	SealedWindowAllowRemote bool `yaml:"sealed_window_allow_remote,omitempty"`

	// SealedWindowTimeout bounds how long the sealed-window listener waits
	// for an operator to complete unseal before node construction fails and
	// the daemon exits (SIGTERM/SIGINT during the window also ends it — see
	// pkg/server's ServeSealedWindow caller). Empty defaults to
	// DefaultSealedWindowTimeout; "0" (or "none"/"disabled") waits
	// indefinitely, matching the qrdb daemon's own unseal listener. Any
	// other value is parsed by time.ParseDuration (e.g. "10m", "1h").
	SealedWindowTimeout string `yaml:"sealed_window_timeout,omitempty"`
}

// DefaultSealedWindowTimeout is the sealed-window listener's default wait
// bound: long enough for an operator to be paged and drive the unseal
// ceremony by hand, short enough that a forgotten init does not hold the
// process (and the port) open indefinitely.
const DefaultSealedWindowTimeout = 15 * time.Minute

// SealedWindowTimeoutDuration resolves SealedWindowTimeout to a
// time.Duration: DefaultSealedWindowTimeout when unset, zero (no deadline)
// for "0"/"none"/"disabled", or the parsed duration otherwise. It returns an
// error for a value time.ParseDuration rejects or a negative duration.
func (b BarrierConfig) SealedWindowTimeoutDuration() (time.Duration, error) {
	switch strings.ToLower(strings.TrimSpace(b.SealedWindowTimeout)) {
	case "":
		return DefaultSealedWindowTimeout, nil
	case "0", "none", "disabled":
		return 0, nil
	}
	d, err := time.ParseDuration(b.SealedWindowTimeout)
	if err != nil {
		return 0, &errs.Message{Msg: fmt.Sprintf("barrier.sealed_window_timeout: %q is not a valid duration: %s", b.SealedWindowTimeout, err)}
	}
	if d < 0 {
		return 0, &errs.Message{Msg: fmt.Sprintf("barrier.sealed_window_timeout: %q must not be negative", b.SealedWindowTimeout)}
	}
	return d, nil
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

// NodeFlipWired reports whether the configured strategy can be driven
// through the qrdb node's OWN barrier (pkg/server's "flip") — go-qrdb's
// node-embedded seal subsystem (sdk/go/node's buildNodeSealSubsystem)
// natively handles "none", "passphrase" (deferred) and "shamir" from
// SealConfig alone, and xkms additionally wires "tpm2" by injecting a
// pre-built hardware SealingStrategy built directly from
// Backends.TPM2 (pkg/server/node_seal.go's resolveNodeSeal). The
// remaining hardware/cloud strategies (pkcs11, awskms, gcpkms, azurekv,
// vault) are not wired through the flip: each needs credentials that are
// only resolvable once the credential service exists, which — for a
// strategy that would also need to seal the very barrier that credential
// service sits behind — is a cycle (pkcs11), or needs cloud-KMS wiring
// that has not been scoped (the rest). A strategy this reports false for
// falls back to xkms's own (non-node) barrier: the qrdb node's own data
// plane is NOT encrypted in that case, only whatever the fallback barrier
// separately protects — see resolveNodeSeal and Config.ComplianceGaps,
// which both consult this so the two stay in lock-step by construction.
func (b BarrierConfig) NodeFlipWired() bool {
	switch b.SealStrategy() {
	case "none", "passphrase", "shamir", "tpm2":
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
	// Valid values: manual, barrier, tpm2, pkcs11, awskms, gcpkms, azurekv, vault, passphrase.
	// "manual" (default): credentials NOT stored -- operator enters at each startup.
	//
	// "barrier" requires CredentialsBarrierStrategySupported(): the credential
	// service is constructed, and resolves every backend's credential:// secret
	// (pkg/server's resolveConfigSecrets), before the general (non-node) xkms
	// barrier can exist -- that barrier's own hardware seal strategies are built
	// from already-initialized backends (buildHardwareSealStrategies), which is
	// the exact set "barrier" would need to unseal first. Only the qrdb node's
	// OWN barrier (Datastore.Mode=="standalone", with a strategy
	// BarrierConfig.NodeFlipWired reports true for) is built independently of
	// backend initialization and is therefore available in time. Every other
	// configuration is refused at Validate() with a typed error rather than
	// failing deep inside Server.New (go-xkms#812).
	SealStrategy string `yaml:"seal_strategy" json:"seal_strategy"`
}

// CredentialsBarrierStrategySupported reports whether
// Credentials.SealStrategy "barrier" can be satisfied by this configuration.
//
// The credential service is constructed, and resolves every backend's
// credential:// secret, before the general (non-node) xkms barrier can exist
// -- initializeBarrier builds that barrier's hardware seal strategies from
// ALREADY-INITIALIZED backends, the same backends whose own credentials a
// "barrier" strategy would need the barrier to unseal first. That is a
// structural cycle, not an ordering bug.
//
// The one barrier that IS available before backend initialization is the
// qrdb node's own (the "flip", see pkg/server/node_seal.go's resolveNodeSeal
// and BarrierConfig.NodeFlipWired): it is built directly from
// Backends.TPM2/SealConfig, never from already-initialized backends, and is
// adopted before the credential service is constructed. That requires
// Datastore.Mode=="standalone" (a remote/clustered qrdb deployment dials out
// instead of hosting the node that would adopt the barrier), Barrier.Enabled,
// and a strategy NodeFlipWired reports true for.
func (c *Config) CredentialsBarrierStrategySupported() bool {
	mode := strings.ToLower(strings.TrimSpace(c.Datastore.Mode))
	if mode != "" && mode != "standalone" {
		return false
	}
	return c.Barrier.Enabled && c.Barrier.NodeFlipWired()
}

// DefaultServerHost is the defaults-layer value of server.host: the empty
// host, which net.JoinHostPort renders as ":port" so every listener binds all
// interfaces, dual-stack. It is deliberately not "0.0.0.0": that literal is
// IPv4-only and, because Server.Host also seeds the local certificate SANs and
// the Raft Noise bind host, it would leak into places a wildcard must never
// appear. Operators pin a host through server.host, XKMS_SERVER_HOST, or the
// xkmsd --host flag, in that ascending precedence.
const DefaultServerHost = ""

// ServerConfig contains server-level settings
type ServerConfig struct {
	// Host is the bind host shared by every network listener xkmsd opens
	// (REST/HTTP3, gRPC, MCP, metrics, Noise bootstrap) and handed to the
	// embedded qrdb node's unified API server. Empty (DefaultServerHost)
	// binds all interfaces. Resolved flags > env > file > defaults by Load
	// plus the xkmsd --host flag.
	Host      string `yaml:"host"`
	RESTPort  int    `yaml:"rest_port"`
	GRPCPort  int    `yaml:"grpc_port"`
	QUICPort  int    `yaml:"quic_port"`
	MCPPort   int    `yaml:"mcp_port"`
	NoisePort int    `yaml:"noise_port"`

	// TrustedProxies lists the reverse proxies (IP addresses or CIDR
	// prefixes) allowed to name the client in X-Forwarded-For / X-Real-IP.
	// The REST rate limiters key on the client IP; a request from any other
	// peer is keyed on its transport address, so a client cannot pick its
	// own bucket by sending a forwarding header. Empty (the default) trusts
	// no proxy. Parsed by ratelimit.ParseTrustedProxies.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
}

// NetworkServing reports whether any network protocol is enabled. Network
// serving runs exclusively on the unified API server: the embedded qrdb
// node's multi-protocol server takes the ports above and serves the xkms
// capability plane through the registered ServiceModule (pkg/apimodule).
// It therefore requires datastore.mode "standalone" (the node this process
// hosts) and explicit TLS material (qrdb's transports are TLS-only and the
// xkms CA is not yet composed when the node starts) -- see Validate. QUIC
// is served as HTTP/3 on the REST
// port (advertised via Alt-Svc); the Unix socket is local IPC and never sets
// a protocol this method looks at, so it never makes NetworkServing true.
//
// The loopback desktop engine (pkg/server/loopback) is also local IPC, but
// it does so by forcing Protocols.REST on for a 127.0.0.1 listener, so this
// method reports true for it same as a real network deployment; Validate is
// what carves it back out, via Config.LoopbackDesktop.
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

	// ExtraSANs are additional subject alternative names (DNS names or IP
	// addresses) included in the auto-issued TLS server certificate, for
	// deployments where clients reach the server by names beyond the CN
	// and machine hostname (load-balancer aliases, split-horizon DNS).
	ExtraSANs []string `yaml:"extra_sans" json:"extra_sans"`

	// IncludeLocalhostSANs adds localhost, 127.0.0.1 and ::1 to the
	// auto-issued TLS server certificate (bootstrap and CA-issued), so local
	// clients pass hostname verification. The defaults layer sets it true;
	// a deployment that must not present loopback names sets it false. It
	// is the only source of those names: no SAN is ever a literal (#140).
	IncludeLocalhostSANs bool `yaml:"include_localhost_sans" json:"include_localhost_sans"`

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

	// AttestationRoots is the PEM bundle of the PIV attestation CA(s) a
	// login must prove its key against (for YubiKeys, the Yubico PIV
	// Attestation root). A login is hardware-backed only when a certificate
	// the client presents chains to this bundle and carries the login
	// certificate's public key. Required when enabled, unless
	// allow_unattested is set.
	AttestationRoots string `yaml:"attestation_roots,omitempty"`

	// AttestationIntermediates optionally lists PEM files of vendor
	// intermediates the device does not present itself.
	AttestationIntermediates []string `yaml:"attestation_intermediates,omitempty"`

	// AllowUnattested accepts logins whose key nothing attests; the minted
	// token records attest_level "unattested". Off by default.
	AllowUnattested bool `yaml:"allow_unattested,omitempty"`
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
	// sign-up). Unset means false: registration is invite-only unless the
	// operator explicitly opens it, per the stack-wide registration model
	// (canonical flag iam.self_service_registration.enabled, default off) and
	// the company secure-by-default convention (go-xkms#184).
	//
	// A *bool, not a bool: nil records that the operator never considered the
	// setting, which a compliance profile needs in order to flag an explicit
	// open, and which lets a composed host (go-quicbaas ServiceModule
	// projection) write its own registration decision through this field
	// authoritatively.
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

// InviteConfig controls administrator-issued user enrollment invitations
// (go-xkms#1294 part B): an admin creates a PENDING user, xkms mints a
// single-use invitation through qrdb's canonical invite store, and the
// invitee redeems it to enroll their first WebAuthn passkey or PIV
// credential, which activates the account.
type InviteConfig struct {
	// PublicBaseURL is the externally reachable origin (and any UI path
	// prefix) the invitation link is built from, e.g.
	// "https://kms.example.com/ui". It is a configured value, NEVER derived
	// from a request's Host header: the WebAuthn ceremony's RP ID must stay
	// the fixed value the operator configured for WebAuthnConfig.RPOrigins,
	// and an admin's own client address must not leak into a link mailed to
	// someone else. Empty produces a link with no origin, which is only
	// useful for tests that inspect the token directly.
	PublicBaseURL string `yaml:"public_base_url"`

	// DefaultTTL is how long an invitation stays redeemable when the caller
	// does not specify one, as a Go duration string (e.g. "24h"). Empty
	// defaults to qrdb's own DefaultInviteTTL (24h).
	DefaultTTL string `yaml:"default_ttl"`

	// MaxTTL caps an operator-requested TTL, as a Go duration string. Empty
	// defaults to 7 days. A request above the cap is clamped, not refused.
	MaxTTL string `yaml:"max_ttl"`
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

// DatastoreConfig configures xkms's single global datastore. Every
// subsystem -- keys, users, RBAC, custodian state, shares, CA serials and
// revocations, ACME state, everything -- is stored through this ONE
// qrdb-backed datastore (see pkg/server/storage_factory.go); nothing is
// written to disk outside it by default, and no subsystem hardcodes its own
// storage engine.
//
// Engine selects the local storage engine xkms uses when it hosts the
// datastore itself (Mode "standalone"); it maps directly onto go-qrdb's own
// per-database Backend vocabulary (qrdbsdk.DaemonDatabaseConfig.Backend), so
// xkms never invents a parallel engine enum. Mode selects the datastore's
// topology: "standalone" hosts the qrdb engine in this process (optionally
// as a Raft cluster member -- see ClusterConfig), or "remote" dials an
// already-running qrdb cluster instead of hosting one here. Barrier
// encryption-at-rest is configured independently via BarrierConfig; it
// applies uniformly to the datastore regardless of Engine or Mode.
type DatastoreConfig struct {
	// Engine selects the local qrdb storage engine: "memory", "file", or
	// "pebble" (default). Only meaningful when Mode is "standalone"; a
	// "remote" datastore's engine is whatever the remote cluster runs.
	Engine string `yaml:"engine"`

	// Path is the on-disk data directory for a standalone datastore, and
	// for the small set of genuinely pre-datastore material that must exist
	// before the datastore itself (the node's own Raft data directory,
	// TPM-sealed pre-barrier blobs, the bootstrap TLS certificate cache --
	// see docs/datastore/architecture.md). Required whenever Mode is
	// "standalone", for every Engine including "memory": go-qrdb roots the
	// node's on-disk state (its vector-storage subsystem in particular)
	// under this directory regardless of the primary KV engine, so there is
	// no engine choice that lets a standalone node run with no directory at
	// all. Not used for datastore mode "remote".
	Path string `yaml:"path"`

	// Mode selects the datastore topology: "standalone" (default) hosts the
	// qrdb engine in this process; "remote" dials an already-running qrdb
	// cluster instead (see Remote).
	Mode string `yaml:"mode"`

	// Remote configures the connection to an external qrdb cluster. Only
	// used when Mode is "remote".
	Remote DatastoreRemoteConfig `yaml:"remote"`
}

// DatastoreRemoteConfig configures a connection to an already-running,
// external qrdb cluster (DatastoreConfig.Mode == "remote").
type DatastoreRemoteConfig struct {
	// Address is the remote qrdb cluster endpoint (e.g., "https://host:63002").
	Address string `yaml:"address"`

	// Transport specifies the SDK transport type: "rest" or "grpc".
	Transport string `yaml:"transport"`

	// TLS configures the TLS settings for the connection.
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
// is replicated across nodes. Clustering requires Datastore.Mode ==
// "standalone" (this process hosts the node); the local engine (pebble,
// typically) is Datastore.Engine. These fields map onto go-qrdb's Raft config.
type ClusterConfig struct {
	// Enabled turns on Raft clustering. Requires Datastore.Mode == "standalone".
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

	// AdvertiseNoiseHost is the BIND host for that endpoint, in the same sense
	// as Server.Host, and it defaults to Server.Host. go-qrdb's clusterenroll
	// refuses to choose one (go-qrdb#167): the enrollment listener is the one
	// socket a joining node reaches before it holds any credential, so a node
	// contained to a single interface must not have it quietly opened on every
	// interface, and only this configuration layer knows which containment the
	// operator asked for.
	//
	// It is NOT Cluster.AdvertiseHost, which is the address CLIENTS dial and is
	// deliberately not a bind address.
	AdvertiseNoiseHost string `yaml:"advertise_noise_host"`

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
	//   "none" — plaintext PKCS#8 (reported by ComplianceGaps, so cmd/xkmsd
	//            refuses it; reachable only by embedded/test callers)
	// The cluster CA keys must exist before the replicated datastore, so they
	// live node-local and cannot be protected by the barrier; this reuses the
	// stack's standard seal strategies instead.
	CAKeyProtection string `yaml:"ca_key_protection"`

	// CAKeyPassphrase supplies the operator passphrase for the "passphrase"
	// protection mode (and the passphrase fallback in auto mode). Supports
	// credential:// references resolved at boot. Declared as a
	// types.SecretValue rather than a plain string so the resolved
	// plaintext lives in its own memguard enclave rather than an unwipeable
	// Go string; see types.SecretValue and the CA identity password
	// resolution in Server.initializeCA for the same pattern.
	CAKeyPassphrase *types.SecretValue `yaml:"ca_key_passphrase"`

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
	// The listener binds server.host, like every other daemon listener.
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

	// PIN is the authentication PIN (if PINRequired is true). Decodes from,
	// and re-encodes to, a plain reference string in YAML/JSON; the resolved
	// plaintext is sealed into this field's own memguard enclave rather than
	// kept as a plain Go string. See types.SecretValue and
	// types.SecretValueBytes.
	// Note: Consider using environment variable XKMS_RNG_PKCS11_PIN instead
	PIN *types.SecretValue `yaml:"pin,omitempty"`
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
	Frost    *FrostConfig    `yaml:"frost,omitempty"`
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

	// PlatformPCR / PlatformPCRBank select the PCR index and bank of the
	// built-in "platform" TPM policy. An unset PlatformPCR resolves to
	// tpm2.DefaultPlatformPCR (16) and an unset bank to sha256, the same
	// defaults xkey applies -- zero never selects PCR 0. Which policy a key
	// or sealed object is bound to is a per-object reference (its TPM
	// policy name), not a backend setting.
	PlatformPCR     uint   `yaml:"platform_pcr,omitempty"`
	PlatformPCRBank string `yaml:"platform_pcr_bank,omitempty"`

	// VTPM configures the per-tenant virtual TPMs (swtpm) of tenants in
	// vtpm TPM mode. vTPMs are off unless enabled here: a tenant set to vtpm
	// mode is then refused (tpmpolicy.ErrVTPMUnavailable).
	VTPM *VTPMConfig `yaml:"vtpm,omitempty"`
}

// VTPMConfig configures the node's per-tenant vTPM supervisor
// (pkg/tpm2/vtpm), which runs one swtpm process per vtpm-mode tenant.
type VTPMConfig struct {
	// Enabled turns vtpm mode on. It must be set explicitly.
	Enabled bool `yaml:"enabled"`

	// StateDir holds one vTPM state directory per tenant. Default
	// <storage.path>/vtpm.
	StateDir string `yaml:"state_dir,omitempty"`

	// RunDir holds the vTPM sockets and is created with mode 0700. Default
	// <storage.path>/vtpm-run. A Unix socket path is limited to 107 bytes,
	// so a deep storage path needs a shorter run_dir.
	RunDir string `yaml:"run_dir,omitempty"`

	// Binary is the swtpm executable. Default "swtpm", resolved from PATH.
	Binary string `yaml:"binary,omitempty"`
}

// PKCS11Config contains PKCS#11 backend settings
type PKCS11Config struct {
	Enabled bool   `yaml:"enabled"`
	Library string `yaml:"library"`
	// Token is the PKCS#11 token label used to select the slot; it names a
	// slot rather than authorizing use of it, so it is not secret-bearing.
	Token string `yaml:"token"`
	// Pin is the PKCS#11 user PIN. Decodes from, and re-encodes to, a plain
	// reference string in YAML/JSON; the resolved plaintext is sealed into
	// this field's own memguard enclave rather than kept as a plain Go
	// string. See types.SecretValue and types.SecretValueBytes.
	Pin *types.SecretValue `yaml:"pin"`
}

// AWSKMSConfig contains AWS KMS backend settings
type AWSKMSConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Region    string `yaml:"region"`
	AccessKey string `yaml:"access_key"`
	// SecretKey is the AWS secret access key. Decodes from, and re-encodes
	// to, a plain reference string in YAML/JSON; the resolved plaintext is
	// sealed into this field's own memguard enclave rather than kept as a
	// plain Go string. See types.SecretValue and types.SecretValueBytes.
	SecretKey *types.SecretValue `yaml:"secret_key"`
	Endpoint  string             `yaml:"endpoint"`

	// KeyID is the operator-supplied identifier of an existing AWS KMS
	// customer master key to use as the barrier's seal key, instead of one
	// xkmsd provisions itself on first init. Accepts a key ID, a key ARN, an
	// alias name, or an alias ARN. Optional -- when empty, xkmsd creates and
	// persists a new CMK (go-xkms#839, go-xkms#842).
	KeyID string `yaml:"key_id,omitempty"`
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
	Enabled  bool   `yaml:"enabled"`
	VaultURL string `yaml:"vault_url"`
	TenantID string `yaml:"tenant_id"`
	ClientID string `yaml:"client_id"`
	// ClientSecret is the Azure service principal client secret. Decodes
	// from, and re-encodes to, a plain reference string in YAML/JSON; the
	// resolved plaintext is sealed into this field's own memguard enclave
	// rather than kept as a plain Go string. See types.SecretValue and
	// types.SecretValueBytes.
	ClientSecret *types.SecretValue `yaml:"client_secret"`

	// AllowLocalVaultURL permits VaultURL to name localhost or 127.0.0.1
	// instead of an Azure vault domain, for local development against an
	// emulator or mock. Off by default; a local vault URL otherwise fails
	// validation (#140).
	AllowLocalVaultURL bool `yaml:"allow_local_vault_url"`
}

// VaultConfig contains HashiCorp Vault backend settings
type VaultConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	// Token is the Vault authentication token. Decodes from, and re-encodes
	// to, a plain reference string in YAML/JSON; the resolved plaintext is
	// sealed into this field's own memguard enclave rather than kept as a
	// plain Go string. See types.SecretValue and types.SecretValueBytes.
	Token     *types.SecretValue `yaml:"token"`
	Namespace string             `yaml:"namespace"`
	MountPath string             `yaml:"mount_path"`
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

	// NoiseStaticKey is the hex-encoded Noise static private key for this
	// host. Decodes from, and re-encodes to, a plain reference string in
	// YAML/JSON; the resolved plaintext is sealed into this field's own
	// memguard enclave rather than kept as a plain Go string. See
	// types.SecretValue and types.SecretValueBytes.
	NoiseStaticKey *types.SecretValue `yaml:"noise_static_key"`

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

// NoiseBootstrapConfig configures the bootstrap listener.
//
// The listener speaks two handshake suites and selects per connection on the
// suite byte in the client's first frame, so this struct carries a static key
// for each: Noise_NK (Curve25519) and TSBOOT1_P256_AESGCM_SHA256. The name is
// historical -- it predates the second suite -- and is kept because it is the
// `bootstrap.noise` YAML key operators already have in their configs.
//
// A suite whose key is absent is simply not offered. A FIPS build cannot run
// Noise_NK at all (X25519 is not approved under SP 800-56A Rev. 3), so there
// the P-256 key is the only one that has any effect.
type NoiseBootstrapConfig struct {
	// Enabled controls whether Noise bootstrap is active
	Enabled bool `yaml:"enabled"`

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

// ComplianceGaps reports security settings that fall short of the
// secure-by-default posture required for FedRAMP (SC-8, SC-28, IA-2),
// PCI-DSS v4 (3.5, 4.2, 8.x), and HIPAA (§164.312(a)(2)(iv), (e)(1))
// deployments: encryption at rest (the barrier), TLS in transit, authenticated
// access, and a CA for certificate provisioning / mTLS trust. An empty slice
// means the configuration meets the baseline. cmd/xkmsd refuses to start, and
// refuses to reload, on any reported gap; there is no override flag,
// environment variable, or build tag. The library itself stays permissive so
// embedded and test callers can construct whatever posture they need.
func (c *Config) ComplianceGaps() []string {
	var gaps []string
	datastoreMode := strings.ToLower(strings.TrimSpace(c.Datastore.Mode))
	if !c.Barrier.Enabled {
		gaps = append(gaps, "encryption-at-rest disabled (barrier.enabled=false): data is stored in plaintext")
	} else if (datastoreMode == "" || datastoreMode == "standalone") && c.barrierLeavesKeysPlaintext() {
		// On an embedded qrdb node the barrier encrypts the data plane (and
		// thus the crypto backends' key stores) whenever the strategy is
		// wired through the node's own barrier (BarrierConfig.NodeFlipWired:
		// none, passphrase, shamir, tpm2) — "none" and a provisioned tpm2
		// auto-unseal unattended; "passphrase"/"shamir" encrypt exactly the
		// same way, they just block boot behind the sealed-window listener
		// until an operator drives `xkmsctl barrier unseal` (or
		// `unseal-shares`) — genuinely encrypted-then-gated, not plaintext.
		// A strategy NOT wired through the flip (pkcs11, awskms, gcpkms,
		// azurekv, vault) falls back to xkms's own (non-node) barrier, which
		// does not protect the qrdb node's own data plane at all: that is
		// the actual plaintext case this gap reports.
		gaps = append(gaps, "barrier strategy \""+c.Barrier.SealStrategy()+
			"\" is not wired to the qrdb node's own barrier: the embedded data plane — including backend "+
			"key stores — would be stored in plaintext. Use \"none\", \"passphrase\", \"shamir\" or \"tpm2\"")
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
	// MCP), and it is backed by the one qrdb identity plane every deployment
	// now has (standalone or remote), so there is no longer a configuration
	// that enables RBAC without an identity plane to back it.
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
	// cluster CA private key to disk in the clear, so it is reported and
	// cmd/xkmsd refuses it; there is no override.
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
	// A public ACME endpoint with no admission control accepts unlimited
	// new-account/new-order/challenge requests. The limiter is on by
	// default, so this only fires when the operator explicitly turned it off.
	if c.ACME != nil && c.ACME.Enabled && !c.ACME.RateLimit.IsEnabled() {
		gaps = append(gaps, "ACME rate limiting disabled (acme.rate_limit.enabled=false): the ACME endpoint "+
			"would accept unlimited new-account, new-order, and challenge requests")
	}
	// The per-tenant overall quota is the only thing standing between one
	// tenant's traffic and every other tenant's share of the ACME endpoint
	// in a multi-tenant deployment. It is on by default, so this only fires
	// when the operator explicitly turned it off.
	if c.ACME != nil && c.ACME.Enabled && !c.ACME.RateLimit.TenantIsEnabled() {
		gaps = append(gaps, "ACME tenant rate limiting disabled (acme.rate_limit.tenant.enabled=false): a "+
			"multi-tenant deployment's accounts would share no per-tenant quota, so one tenant's traffic is "+
			"unbounded by any other tenant's")
	}
	// RFC 8555 Section 6.6 names four rate-limit categories (new-account,
	// new-order, certificate, failed-validation); each is on by default, so
	// this only fires for a category the operator explicitly turned off.
	if c.ACME != nil && c.ACME.Enabled {
		var disabledCategories []string
		if !c.ACME.RateLimit.NewAccountIsEnabled() {
			disabledCategories = append(disabledCategories, "new_account")
		}
		if !c.ACME.RateLimit.NewOrderIsEnabled() {
			disabledCategories = append(disabledCategories, "new_order")
		}
		if !c.ACME.RateLimit.CertificateIsEnabled() {
			disabledCategories = append(disabledCategories, "certificate")
		}
		if !c.ACME.RateLimit.FailedValidationIsEnabled() {
			disabledCategories = append(disabledCategories, "failed_validation")
		}
		if len(disabledCategories) > 0 {
			gaps = append(gaps, "ACME per-category rate limiting disabled ("+strings.Join(disabledCategories, ", ")+
				"): the RFC 8555 Section 6.6 quota for the listed categories would not be enforced")
		}
	}
	return gaps
}

// barrierLeavesKeysPlaintext reports whether the configured barrier would
// leave the qrdb node's data plane unencrypted: true exactly when the
// strategy is NOT wired through the node's own barrier
// (BarrierConfig.NodeFlipWired is false — pkcs11, awskms, gcpkms, azurekv,
// vault today). "none", "passphrase", "shamir" and "tpm2" are all wired: the
// node's own barrier genuinely encrypts the data plane for every one of
// them, whether it auto-unseals unattended ("none", a provisioned "tpm2")
// or requires an operator to complete the sealed-window ceremony
// ("passphrase", "shamir") — gated access to encrypted data, not plaintext.
func (c *Config) barrierLeavesKeysPlaintext() bool {
	return !c.Barrier.NodeFlipWired()
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate the datastore first: several later checks (network serving,
	// the credentials "barrier" seal strategy, clustering) read
	// c.Datastore.Mode and need it already defaulted.
	//
	// Engine defaults to durable PebbleDB rather than failing — production
	// paths must never silently fall back to a non-durable store.
	// Deployments that want an in-memory engine (tests, ephemeral
	// deployments) or plain files set engine "memory" / "file" explicitly.
	if c.Datastore.Engine == "" {
		c.Datastore.Engine = "pebble"
	}
	switch strings.ToLower(c.Datastore.Engine) {
	case "memory", "file", "pebble":
	default:
		return &errs.Message{Msg: fmt.Sprintf("invalid datastore.engine: %s (must be memory, file, or pebble)", c.Datastore.Engine)}
	}
	if c.Datastore.Mode == "" {
		c.Datastore.Mode = "standalone"
	}
	switch strings.ToLower(c.Datastore.Mode) {
	case "standalone":
		// A standalone datastore hosts the embedded qrdb node in this
		// process, and go-qrdb roots the node's on-disk state (including its
		// vector-storage subsystem) under one data directory regardless of
		// the primary KV engine -- there is no engine choice, "memory"
		// included, that lets a standalone node run with no directory at
		// all. Adopting that contract exactly (rather than working around
		// it) means datastore.path is unconditionally required for
		// datastore.mode "standalone".
		if c.Datastore.Path == "" {
			return &errs.Message{Msg: fmt.Sprintf("datastore.path must be specified for datastore.mode \"standalone\" (required for every datastore.engine, including %q: go-qrdb roots the node's on-disk state under it regardless of the primary KV engine)", c.Datastore.Engine)}
		}
	case "remote":
		// A remote datastore dials an already-running qrdb cluster instead
		// of hosting one here, so an address and transport are required.
		if c.Datastore.Remote.Address == "" {
			return &errs.Message{Msg: "datastore.remote.address is required for datastore.mode \"remote\""}
		}
		switch strings.ToLower(c.Datastore.Remote.Transport) {
		case "rest", "grpc":
		default:
			return &errs.Message{Msg: fmt.Sprintf("invalid datastore.remote.transport: %s (must be rest or grpc)", c.Datastore.Remote.Transport)}
		}
	default:
		return &errs.Message{Msg: fmt.Sprintf("invalid datastore.mode: %s (must be standalone or remote)", c.Datastore.Mode)}
	}

	// Validate server ports
	// Network serving runs exclusively on the unified API server: the
	// embedded qrdb node takes xkmsd's ports and serves the capability
	// plane through the registered ServiceModule. The node is the single
	// core, so network protocols require this process to host it
	// (datastore.mode "standalone"); and qrdb's transports are TLS-only
	// while xkms's CA cannot auto-provision the node's certificate (the CA
	// composes after — and stores into — the node), so explicit TLS
	// material is required. Fail closed at validation rather than at node
	// construction. Local IPC (the Unix socket and the loopback desktop
	// engine) is exempt: the Unix socket never sets a NetworkServing
	// protocol, and the loopback desktop engine opts out explicitly via
	// LoopbackDesktop, which only trusted embedder code
	// (pkg/server/loopback) can set.
	if c.NetworkServing() && !c.LoopbackDesktop {
		if !strings.EqualFold(c.Datastore.Mode, "standalone") {
			return &errs.Message{Msg: fmt.Sprintf("network protocols require datastore.mode \"standalone\" (the embedded qrdb node is the unified API server); got %q — local-only deployments disable rest/grpc/quic/mcp and use the unix socket", c.Datastore.Mode)}
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

	if _, err := ratelimit.ParseTrustedProxies(c.Server.TrustedProxies); err != nil {
		return &errs.Wrapped{Msg: "invalid server.trusted_proxies", Err: err}
	}

	if _, err := c.Barrier.SealedWindowTimeoutDuration(); err != nil {
		return err
	}

	// credentials.seal_strategy "barrier" is refused unless this deployment's
	// barrier IS the qrdb node's own (see CredentialsBarrierStrategySupported):
	// every other configuration builds the general xkms barrier from
	// already-initialized backends, which is a structural cycle against a
	// credential service that must resolve those same backends' credentials
	// first (go-xkms#812).
	if strings.EqualFold(c.Credentials.SealStrategy, "barrier") && !c.CredentialsBarrierStrategySupported() {
		return &errs.Message{Msg: "credentials.seal_strategy \"barrier\" requires an embedded qrdb-hosted " +
			"barrier: datastore.mode \"standalone\" (or unset), " +
			"barrier.enabled true, and a barrier.strategy the node barrier supports (none, passphrase, " +
			"shamir, or tpm2) -- got datastore.mode " + fmt.Sprintf("%q", c.Datastore.Mode) +
			", barrier.enabled " + fmt.Sprintf("%t", c.Barrier.Enabled) +
			", barrier.strategy " + fmt.Sprintf("%q", c.Barrier.SealStrategy()) +
			". The credential service resolves backend credentials before the general xkms barrier " +
			"exists, so a barrier-backed credential store in any other configuration cannot unseal in time"}
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
		// A login that cannot prove a smartcard must not be assumed to be
		// one: without an anchor the exchange has nothing to verify against,
		// so the operator either supplies the vendor's attestation CA or says
		// explicitly that software keys are accepted on this route.
		if c.Auth.PIVLogin.AttestationRoots == "" && !c.Auth.PIVLogin.AllowUnattested {
			return &errs.Message{Msg: "auth.piv_login.enabled requires attestation_roots (the PIV attestation CA bundle) or allow_unattested: true"}
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
		// UseSimulator selects the in-process/TCP TPM simulator instead of a
		// hardware device (TPM2Config's own doc comment), so it needs no
		// device_path; device_path is required only for the real hardware
		// path this check otherwise guards.
		if c.Backends.TPM2.DevicePath == "" && !c.Backends.TPM2.UseSimulator {
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

	if c.Backends.Frost != nil && c.Backends.Frost.Enabled {
		hasEnabledBackend = true
		if err := c.Backends.Frost.Validate(); err != nil {
			return err
		}
		// The named secret backend is a reference to a sibling backend
		// section, so only Config.Validate (which holds the full
		// BackendsConfig) can check it; FrostConfig.Validate cannot see
		// beyond its own fields. Fail closed rather than let a FROST backend
		// come up pointing at a backend that was never configured.
		if !c.Backends.enabledBackendNamed(c.Backends.Frost.SecretBackend) {
			return &FrostConfigError{
				Field:   "secret_backend",
				Message: fmt.Sprintf("backend %q is not configured and enabled under backends", c.Backends.Frost.SecretBackend),
			}
		}
	}

	if !hasEnabledBackend {
		return &errs.Message{Msg: "at least one backend must be enabled"}
	}

	// Validate ACME configuration (no-op unless acme.enabled is true).
	if err := c.ACME.Validate(); err != nil {
		return err
	}

	// Validate escrow configuration (no-op unless escrow.enabled is true).
	if err := c.Escrow.Validate(); err != nil {
		return err
	}

	// Validate clustering. When enabled it requires this process to host the
	// datastore (datastore.mode "standalone") and a complete, parseable
	// membership.
	if c.Cluster.Enabled {
		if c.Cluster.ShardID == 0 {
			c.Cluster.ShardID = 1
		}
		if !strings.EqualFold(c.Datastore.Mode, "standalone") {
			return &errs.Message{Msg: fmt.Sprintf("cluster.enabled requires datastore.mode \"standalone\" (got %q)", c.Datastore.Mode)}
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
