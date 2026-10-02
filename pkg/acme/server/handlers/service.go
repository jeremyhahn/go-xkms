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

package handlers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	acmenonce "github.com/jeremyhahn/go-xkms/pkg/acme/nonce"
	"github.com/jeremyhahn/go-xkms/pkg/acme/policy"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/degradation"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

var (
	// ErrKIDAndJWKNotAllowed is returned when both KID and JWK are present in JWS header
	ErrKIDAndJWKNotAllowed = errors.New("handlers: both kid and jwk not allowed in JWS header")

	// ErrInvalidAccountID is returned when the account ID cannot be parsed
	ErrInvalidAccountID = errors.New("handlers: invalid account ID")

	// ErrAccountNotFound is returned when an account cannot be found
	ErrAccountNotFound = errors.New("handlers: account not found")

	// ErrAccountDeactivated is returned when a deactivated account tries to make requests
	// RFC 8555 Section 7.3.6: "Once an account is deactivated, the server MUST NOT
	// accept further requests authorized by that account's key."
	ErrAccountDeactivated = errors.New("handlers: account deactivated")

	// ErrInvalidJWSSignature is returned when JWS signature verification fails
	ErrInvalidJWSSignature = errors.New("handlers: invalid JWS signature")

	// ErrFailedToGenerateID is returned when ID generation fails
	ErrFailedToGenerateID = errors.New("handlers: failed to generate ID")

	// ErrFailedToGenerateToken is returned when token generation fails
	ErrFailedToGenerateToken = errors.New("handlers: failed to generate token")

	// ErrUnsupportedKeyType is returned for unsupported public key types
	ErrUnsupportedKeyType = errors.New("handlers: unsupported key type")

	// ErrJWSURLMismatch is returned when the JWS "url" header field does not match
	// the request URL per RFC 8555 Section 6.3
	ErrJWSURLMismatch = errors.New("handlers: JWS url header does not match request URL")

	// ErrLoopbackIdentifierNotAllowed is returned when an enrollment
	// challenge's permanent-identifier is the loopback address 127.0.0.1 but
	// the server is not configured to allow it
	// (acme.enrollment.allow_loopback_identifier).
	ErrLoopbackIdentifierNotAllowed = errors.New("handlers: loopback identifier not allowed for enrollment challenge")

	// randReader is the random reader used for ID and token generation.
	// This is a package-level variable to allow testing with mock readers.
	randReader io.Reader = rand.Reader

	// ErrNonceKeyGenerate is returned when a random nonce encryption key
	// cannot be generated because the entropy source failed.
	ErrNonceKeyGenerate = errors.New("handlers: failed to generate nonce encryption key")

	// ErrNonceServiceCreate is returned when the underlying pkg/acme/nonce
	// service cannot be constructed from the configured key, prefix, and
	// per-epoch redeemed-nonce cap.
	ErrNonceServiceCreate = errors.New("handlers: failed to create nonce service")
)

// ErrNonceServiceInit wraps a failure to stand up the ACME nonce service
// during NewRestService. Sentinel is one of ErrNonceKeyGenerate (the random
// key could not be generated) or ErrNonceServiceCreate (pkg/acme/nonce
// rejected the resolved key/prefix/max-used).
type ErrNonceServiceInit struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *ErrNonceServiceInit) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause, so errors.Is(err, ErrNonceKeyGenerate)
// and errors.Is(err, ErrNonceServiceCreate) both work against Sentinel, and
// errors.As reaches whatever concrete type Cause is.
func (e *ErrNonceServiceInit) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

// nonceClock is the time source epoch rotation reads to decide whether the
// current nonce-signing epoch has outlived NonceLifetime. Production never
// reassigns it; tests do, the same seam randReader provides for ID/token
// generation, so epoch rotation is deterministic instead of sleep-dependent.
var nonceClock = time.Now

// nonceKeyLen is the AES-128 key size pkg/acme/nonce.Service requires.
const nonceKeyLen = 16

// NonceGeneratorFunc is a function type for generating nonces.
// This allows dependency injection for testing error paths.
type NonceGeneratorFunc func() (string, error)

// RestServicer defines the interface for ACME REST service handlers.
// Each handler corresponds to an ACME protocol endpoint per RFC 8555.
type RestServicer interface {
	// AccountHandler retrieves account information
	AccountHandler(w http.ResponseWriter, r *http.Request)

	// TenantAuthMiddleware resolves the ACME tenant for admission control
	// from a fully verified JWS "kid" and publishes it via
	// server.WithTenantID for any TenantRateLimiter mounted after it in the
	// middleware chain. It never consults a client-asserted header, host, or
	// path. See tenant_auth.go for the full contract.
	TenantAuthMiddleware(next http.Handler) http.Handler

	// AuthorizationHandler retrieves authorization status
	AuthorizationHandler(w http.ResponseWriter, r *http.Request)

	// CertificateHandler downloads a certificate
	CertificateHandler(w http.ResponseWriter, r *http.Request)

	// ChallengeHandler initiates or retrieves challenge status
	ChallengeHandler(w http.ResponseWriter, r *http.Request)

	// DirectoryHandler provides ACME directory endpoints
	DirectoryHandler(w http.ResponseWriter, r *http.Request)

	// NewAccountHandler creates a new ACME account
	NewAccountHandler(w http.ResponseWriter, r *http.Request)

	// NewNonceHandler generates a new nonce
	NewNonceHandler(w http.ResponseWriter, r *http.Request)

	// NewOrderHandler creates a new certificate order
	NewOrderHandler(w http.ResponseWriter, r *http.Request)

	// OrderHandler retrieves order status
	OrderHandler(w http.ResponseWriter, r *http.Request)

	// OrdersListHandler lists orders for an account
	OrdersListHandler(w http.ResponseWriter, r *http.Request)

	// OrderFinalizeHandler finalizes an order with a CSR
	OrderFinalizeHandler(w http.ResponseWriter, r *http.Request)

	// RevokeCertHandler revokes a certificate
	RevokeCertHandler(w http.ResponseWriter, r *http.Request)

	// KeyChangeHandler performs account key rollover
	KeyChangeHandler(w http.ResponseWriter, r *http.Request)

	// CABundleHandler returns the CA bundle (non-RFC 8555 compliant)
	CABundleHandler(w http.ResponseWriter, r *http.Request)

	// HealthHandler reports the ACME server's health, including the state of
	// every circuit breaker registered on Params.Breakers and whether the
	// directory and CA-bundle endpoints are currently serving degraded
	// (cached) responses. Non-RFC 8555.
	HealthHandler(w http.ResponseWriter, r *http.Request)
}

const (
	nonceSize = 16
)

// Params contains the configuration parameters for the ACME REST service.
type Params struct {
	// BaseRESTURI is the base URL for ACME endpoints (e.g., "https://acme.example.com")
	BaseRESTURI string

	// CA is the certificate authority for issuing certificates
	CA ca.TCGCA

	// CAAIdentities are the CAA identities for this server
	CAAIdentities []string

	// CAAValidator performs CAA validation before certificate issuance
	// If nil, CAA validation will be disabled
	CAAValidator CAAValidatorInterface

	// ChallengeMap maps challenge types to their verifier functions. It
	// serves http-01, dns-01 and tls-alpn-01. A function registered here for
	// an attestation challenge type (enroll-01, endorse-01, device-attest-01)
	// cannot report the identity it attested, so ChallengeHandler refuses the
	// challenge; attestation verifiers register in AttestingVerifiers.
	ChallengeMap map[string]common.ChallengeVerifierFunc

	// AttestingVerifiers maps the attestation challenge types (enroll-01,
	// endorse-01, device-attest-01) to the verifier that reports the identity
	// the device attested (go-xkms#828). ChallengeHandler fails closed: an
	// attestation challenge with no entry here is refused.
	AttestingVerifiers map[string]common.AttestingVerifier

	// EndorseEABRequired is retained for source compatibility and has no
	// effect on its own: EAB is required for endorse-01 unless
	// EndorseEABOptional is set (go-xkms#1392). Setting it true is redundant.
	//
	// Deprecated: EAB is required by default. Set EndorseEABOptional to waive it.
	EndorseEABRequired bool

	// EndorseEABOptional waives the External Account Binding requirement for
	// endorse-01 challenges. THE ZERO VALUE REQUIRES IT, so a server built
	// without setting anything fails closed (go-xkms#1392).
	//
	// With EAB required, an account attempting endorse-01 must have been
	// registered with an EAB of purpose "endorse-01" that binds the EK it asks
	// to have certified (see EndorseEABValidator). With it waived, ANY account
	// can obtain an EK certificate for ANY public key: endorse-01 proves
	// nothing about the key (an EK is decrypt-only and the server holds no
	// proof of possession) and the EAB is its only control. Waive it only for a
	// closed lab, never on a server reachable by accounts you do not control.
	EndorseEABOptional bool

	// EndorseDeviceIDMetaKey is the metadata key used to validate device identity
	// in EAB for endorse-01 challenges. If empty, device ID validation is skipped.
	// Common values: "device_id", "ek_pubkey_hash", "serial_number"
	EndorseDeviceIDMetaKey string

	// ExternalAccountRequired indicates whether external account binding is required
	// per RFC 8555 Section 7.3.4. When true, newAccount requests MUST include an
	// externalAccountBinding field associating the new account with an external account.
	ExternalAccountRequired bool

	// Logger is the structured logger
	Logger *slog.Logger

	// NonceGenerator is the function used to mint a Replay-Nonce.
	// If nil, uses the RestService's own pkg/acme/nonce-backed generator
	// (see NoncePrefix, NonceKey, NonceLifetime, NonceMaxUsed). This allows
	// tests to inject a failing generator for error path testing.
	NonceGenerator NonceGeneratorFunc

	// NoncePrefix identifies this node's issued nonces in a load-balanced,
	// multi-node ACME deployment. It is one input (with NonceKey and each
	// signing epoch's start time — see nonceEpochPrefix) to the actual
	// per-epoch prefix pkg/acme/nonce.MultiService routes nonce redemption
	// by, so nonces minted here stay distinguishable from ones minted by
	// another node across every epoch rotation. Derive it from a stable
	// per-node identifier (e.g. the Raft NodeID). Empty is fine for a
	// standalone node: NonceKey and the epoch start time alone already make
	// each epoch's derived prefix unique.
	NoncePrefix string

	// NonceKey is the 16-byte AES-128 key pkg/acme/nonce.Service uses to
	// encrypt and validate nonces. It MUST be identical on every node in a
	// load-balanced deployment: a nonce minted on one node only decrypts on
	// another node holding the same key. When nil, NewRestService generates
	// a random key for this process — correct for a single-node deployment,
	// but nonces minted by one process never validate on another.
	NonceKey []byte

	// NonceLifetime bounds how long a nonce-signing epoch lives before
	// RestService rotates to a fresh pkg/acme/nonce.Service counter window,
	// retiring every nonce still outstanding from the previous epoch. This
	// is how a wall-clock lifetime is enforced on a scheme that otherwise
	// tracks validity by a monotonic counter, not a per-nonce timestamp.
	// Zero selects DefaultNonceLifetime.
	NonceLifetime time.Duration

	// NonceMaxUsed bounds the number of redeemed nonces tracked within a
	// single signing epoch (see NonceLifetime) before the oldest is
	// retired — the defense against an unbounded-memory nonce flood. Zero
	// selects nonce.DefaultMaxUsed.
	NonceMaxUsed int

	// StorageFactory creates DAO instances for persistence
	StorageFactory storage.Factory

	// TermsOfService is the URL to the terms of service
	TermsOfService string

	// OrderFinalizeHooks is the registry of hooks to execute upon successful order finalization
	// Applications can register custom hooks to perform actions like DNS registration,
	// device inventory updates, notifications, etc.
	OrderFinalizeHooks *OrderFinalizeHookRegistry

	// PreIssuanceHooks is the registry of hooks to execute BEFORE certificate signing.
	// These hooks can validate compliance, attestation, or any other criteria and
	// return an error to block certificate issuance.
	PreIssuanceHooks *PreIssuanceHookRegistry

	// GlobalComplianceConfig is the server-wide default compliance configuration.
	// This is used as a fallback when tenants don't have their own compliance config.
	GlobalComplianceConfig *GlobalComplianceConfig

	// KMSService provides key management for tenant CA signing.
	// When configured, the service can sign certificates using tenant-specific CA keys
	// managed by QRDB KMS instead of the global CA.
	// If nil, all certificates are signed by the global CA.
	KMSService kms.KMSService

	// OrderPreSignHooks is the registry of hooks to execute immediately before the CA
	// signs the certificate. Hooks return additional X.509 extensions (e.g. the SDN
	// network-zone extension OIDTPNetworkZone) that are appended to ExtraExtensions in
	// registration order. A hook error aborts finalization fail-closed.
	OrderPreSignHooks *OrderPreSignHookRegistry

	// AuditLogger records the security-relevant decisions this service makes:
	// account creation, order creation, certificate issuance and revocation,
	// account key rollover, TPM enrollment, and rejected authentication. When
	// nil the service records to a no-op logger and keeps no audit trail, which
	// is only appropriate outside a compliance-controlled deployment.
	AuditLogger audit.AuditLogger

	// ClusterCACN, when set, routes TCG-CSR-IDEVID (enroll-01) issuance through
	// the named CA identity — a dedicated cluster intermediate — instead of the
	// CA's default issuing identity. This keeps Raft node transport certificates
	// on a purpose-built intermediate (root signs intermediates only), the
	// recommended FedRAMP/PCI posture. Empty preserves default issuance. The CA
	// must implement ca.IdentityIssuer for this to take effect.
	ClusterCACN string

	// AllowLoopbackIdentifier permits an authorization's permanent-identifier
	// to be the loopback address 127.0.0.1 for enrollment challenges
	// (enroll-01/endorse-01/device-attest-01), substituting the request's
	// client IP as the validation target. This supports local development
	// and testing; it is a development switch and is off by default
	// (acme.enrollment.allow_loopback_identifier).
	AllowLoopbackIdentifier bool

	// Breakers is the shared circuit breaker manager backing the ACME
	// server's resilience layer. NewRestService uses it to create the
	// storage breaker (see StorageBreaker) and, when KMSService is set, to
	// wrap KMSService with the KMS breaker (see KMSBreaker) -- so
	// HealthHandler can report both from one place. A caller that wraps its
	// own ChallengeMap entries or a CT submitter
	// (circuitbreaker.WrapChallengeVerifier, WrapLogSubmitter) should use
	// this same Manager so those breakers are reported too.
	//
	// A nil Manager disables circuit breaking and degradation entirely:
	// CABundleHandler and DirectoryHandler always compute fresh, KMSService
	// is used unwrapped, and HealthHandler reports no breakers. This is the
	// default for a RestService built without opting in.
	Breakers *circuitbreaker.Manager

	// StorageBreaker configures the circuit breaker RestService creates from
	// Breakers to guard its own CA/keystore-backed certificate storage
	// access (CABundleHandler's call to CA.CABundleFiltered). Nil selects
	// circuitbreaker.DefaultConfig("storage"). Ignored when Breakers is nil.
	StorageBreaker *circuitbreaker.Config

	// KMSBreaker configures the circuit breaker NewRestService creates from
	// Breakers to wrap KMSService with, guarding every tenant KMS signing
	// operation RestService performs. Nil selects
	// circuitbreaker.DefaultConfig("kms"). Ignored when Breakers or
	// KMSService is nil.
	KMSBreaker *circuitbreaker.Config

	// DegradationCacheTTL is how long the directory and CA-bundle
	// degradation caches serve a cached response as fresh before it is
	// considered stale. Zero selects degradation.DefaultConfig's CacheTTL
	// (one minute). Ignored when Breakers is nil.
	DegradationCacheTTL time.Duration

	// DegradationStaleTTL is how much longer, past DegradationCacheTTL, a
	// cached response may still be served -- as stale -- while the storage
	// breaker is open. Zero selects degradation.DefaultConfig's StaleTTL
	// (five minutes). Ignored when Breakers is nil.
	DegradationStaleTTL time.Duration

	// DegradationMaxCacheSize caps the number of entries each degradation
	// cache holds. Zero selects a size of 8 -- the directory and CA-bundle
	// caches hold one entry each in practice. Ignored when Breakers is nil.
	DegradationMaxCacheSize int

	// Policy configures the ACME identifier issuance policy engine
	// (pkg/acme/policy): the domain/FQDN/wildcard/CIDR blocklist, public
	// suffix and reserved-IP enforcement, and per-identifier-type challenge
	// selection. A nil Policy applies no blocklist and no reserved-IP or
	// public-suffix restriction beyond RFC 1035/8738 format validation,
	// which is the permissive configuration test callers get by default.
	// Identifier types absent from Policy.IdentifierChallengeTypes keep
	// go-xkms's default challenge candidates (see
	// xkmsDefaultIdentifierChallengeTypes).
	Policy *policy.PolicyConfig

	// FailedValidationRateLimiter enforces the RFC 8555 Section 6.6
	// failed-validation category (pkg/acme/server/tenant_rate_limiter.go).
	// Unlike the other per-category limiters this cannot be mounted as
	// blanket route middleware — it must only count actual validation
	// failures — so ChallengeHandler calls its Allow method directly once a
	// challenge has failed. A nil value (the caller's explicit choice to
	// disable it; Config.ComplianceGaps reports that) disables the check.
	FailedValidationRateLimiter *server.TenantRateLimiter
}

// CAAValidatorInterface defines the interface for CAA validation.
// This allows for dependency injection and testing with mock validators.
//
// accountURI is the requesting ACME account's URI and validationMethod is
// the RFC 8657 method-label of the challenge that validated the
// identifier's authorization (e.g. "http-01"); both are enforced against a
// matching issue/issuewild record's accounturi and validationmethods
// parameters (RFC 8657).
type CAAValidatorInterface interface {
	Validate(ctx context.Context, domain string, isWildcard bool, accountURI string, validationMethod string) error
}

// DefaultNonceLifetime is the epoch lifetime NewRestService applies when
// Params.NonceLifetime is zero. It matches the TTL the previous in-memory
// nonce store used.
const DefaultNonceLifetime = 10 * time.Minute

// RestService implements the ACME REST service handlers.
type RestService struct {
	allowLoopbackIdentifier bool
	auditLog                audit.AuditLogger
	baseRESTURI             string
	blocklist               *policy.Blocklist
	ca                      ca.TCGCA
	caaIdentities           []string
	caaValidator            CAAValidatorInterface
	challengeMap            map[string]common.ChallengeVerifierFunc
	attestingVerifiers      map[string]common.AttestingVerifier
	challengePolicy         *policy.ChallengePolicy
	clusterCACN             string
	endorseEABRequired      bool
	endorseDeviceIDMetaKey  string
	externalAccountRequired bool
	failedValidationLimiter *server.TenantRateLimiter
	globalComplianceConfig  *GlobalComplianceConfig
	kmsService              kms.KMSService
	logger                  *slog.Logger
	nonceGenerator          NonceGeneratorFunc

	// nonceService routes a nonce's redemption to the epoch registered under
	// its prefix (see nonceEpoch and nonceRotateMu). It always holds exactly
	// this process's current epoch as its local/default service; remote-node
	// registration in a load-balanced deployment is future work.
	nonceService *acmenonce.MultiService
	// nonceEpoch holds the signing epoch minting currently goes through,
	// paired with the time it began. Both fields of nonceEpochRecord are
	// swapped together in a single atomic.Pointer store so a reader can
	// never observe a fresh epoch alongside a stale start time (or vice
	// versa) — see nonceEpochRecord and rotateNonceEpoch. This is an
	// atomic.Pointer, not a lock, so the hot mint/redeem path never blocks;
	// only rotation itself (rare, gated by nonceLifetime) takes
	// nonceRotateMu.
	nonceEpoch atomic.Pointer[nonceEpochRecord]
	// nonceRotateMu serializes epoch rotation so concurrent requests that
	// all observe an expired epoch do not each construct and register a
	// separate replacement.
	nonceRotateMu sync.Mutex
	nonceKey      []byte
	noncePrefix   string
	nonceLifetime time.Duration
	nonceMaxUsed  int

	orderFinalizeHooks  *OrderFinalizeHookRegistry
	params              *Params
	preIssuanceHooks    *PreIssuanceHookRegistry
	preSignHooks        *OrderPreSignHookRegistry
	rejectReservedIPs   bool
	requirePublicSuffix bool
	storageFactory      storage.Factory
	termsOfService      string

	// Resilience: nil breakers and caches when Params.Breakers is nil, which
	// is the default. See serveOrDegrade and serveCachedWhenOpen in
	// resilience.go.
	breakers            *circuitbreaker.Manager
	storageBreaker      *circuitbreaker.CircuitBreaker
	directoryCache      *degradation.Cache
	caBundleCache       *degradation.Cache
	degradationCacheTTL time.Duration
	degradationStaleTTL time.Duration

	RestServicer
}

// nonceEpochRecord pairs a signing epoch with the time it began. See
// RestService.nonceEpoch: the two fields are always read and written
// together through a single atomic.Pointer[nonceEpochRecord] store, never as
// separate atomics, so a concurrent reader can never pair a fresh epoch with
// a stale start time.
type nonceEpochRecord struct {
	epoch *acmenonce.Service
	at    time.Time
}

// newNonceEpoch constructs the pkg/acme/nonce.Service for one signing epoch:
// the same key every epoch in this process uses (so a shared Params.NonceKey
// keeps validating cross-node nonces across rotations), and a fresh, empty
// counter window under a prefix unique to this epoch.
//
// The prefix MUST change every rotation. AES-GCM authenticates a nonce
// against the key alone, not against which *Service instance minted it, so
// two epochs sharing both a key and a prefix are indistinguishable to
// decrypt(): a still-well-formed nonce from a retired epoch would decrypt
// cleanly against the new epoch and be checked against its bounds/used-map
// instead of being rejected outright — exactly the stale-nonce acceptance
// NonceLifetime exists to prevent. Deriving the prefix from the epoch's own
// start time closes that: decrypt()'s prefix check alone rejects a
// retired-epoch nonce once nonceService.SetLocal has moved the registry on.
func newNonceEpoch(key []byte, prefix string, maxUsed int) (*acmenonce.Service, error) {
	opts := []acmenonce.Option{acmenonce.WithKey(key), acmenonce.WithMaxUsed(maxUsed), acmenonce.WithPrefix(prefix)}
	return acmenonce.NewService(opts...)
}

// nonceEpochPrefix derives the per-epoch prefix newNonceEpoch requires:
// deterministic given (node identity, key, epoch start), but unique across
// epochs because epochStartNano is. node is Params.NoncePrefix (empty for a
// standalone node); key is the shared nonce encryption key, reused here as
// the HMAC key since it is already the one secret every node in a
// load-balanced deployment holds in common.
func nonceEpochPrefix(node string, key []byte, epochStartNano int64) string {
	return acmenonce.DerivePrefix(node+":"+strconv.FormatInt(epochStartNano, 10), key)
}

// xkmsDefaultIdentifierChallengeTypes returns go-xkms's default candidate
// challenge types per identifier type. These preserve the challenge sets the
// ACME handlers offered before the policy engine (pkg/acme/policy) was
// wired in: standard web-PKI challenges for DNS identifiers. Permanent
// identifiers keep the policy package's device-attestation default. An
// operator can restore RFC 8738 semantics, or any other set, via
// PolicyConfig.IdentifierChallengeTypes.
//
// "ip" offers no challenge (go-xkms#828): enroll-01, endorse-01 and
// device-attest-01 are attestation challenges, and an attestation challenge
// never authorizes an "ip" identifier -- a device's attested identity is not
// a network address, and mapping one to the other is the hole #828 closes.
// ChallengeHandler refuses it; offering the challenge would advertise one
// that can never validate. Devices authorize with "permanent-identifier".
func xkmsDefaultIdentifierChallengeTypes() map[string][]string {
	return map[string][]string{
		policy.IdentifierTypeDNS: {policy.ChallengeTypeHTTP01, policy.ChallengeTypeDNS01},
		policy.IdentifierTypeIP:  {},
	}
}

// defaultPolicyConfig returns the PolicyConfig NewRestService applies when
// Params.Policy is nil: every identifier type and challenge type enabled,
// go-xkms's default challenge candidates, no blocklist, and no reserved-IP
// or public-suffix enforcement beyond RFC 1035/8738 format validation. This
// is the permissive configuration test callers get by default.
func defaultPolicyConfig() *policy.PolicyConfig {
	return &policy.PolicyConfig{
		EnabledIdentifierTypes: map[string]bool{
			policy.IdentifierTypeDNS:                 true,
			policy.IdentifierTypeIP:                  true,
			policy.IdentifierTypePermanentIdentifier: true,
		},
		EnabledChallengeTypes: map[string]bool{
			policy.ChallengeTypeHTTP01:         true,
			policy.ChallengeTypeDNS01:          true,
			policy.ChallengeTypeTLSALPN01:      true,
			policy.ChallengeTypeDeviceAttest01: true,
			policy.ChallengeTypeEnroll01:       true,
			policy.ChallengeTypeEndorse01:      true,
		},
		AllowWildcards: true,
	}
}

// buildIdentifierPolicy constructs the blocklist and challenge policy engine
// from params.Policy, defaulting to defaultPolicyConfig() when the caller
// did not supply one. go-xkms's default challenge candidates
// (xkmsDefaultIdentifierChallengeTypes) are always layered beneath the
// supplied configuration's IdentifierChallengeTypes so a caller that does
// not override a given identifier type keeps today's behavior for it.
func buildIdentifierPolicy(params *Params) (*policy.Blocklist, *policy.ChallengePolicy, bool, bool, error) {
	cfg := params.Policy
	if cfg == nil {
		cfg = defaultPolicyConfig()
	}

	merged := xkmsDefaultIdentifierChallengeTypes()
	for k, v := range cfg.IdentifierChallengeTypes {
		merged[k] = v
	}
	cfgWithDefaults := *cfg
	cfgWithDefaults.IdentifierChallengeTypes = merged

	challengePolicy := policy.NewChallengePolicyFromConfig(&cfgWithDefaults)

	blocklist := policy.NewBlocklistWithLogger(params.Logger)
	blocklistCfg := cfg.Blocklist
	if err := blocklist.LoadFromConfig(&blocklistCfg); err != nil {
		return nil, nil, false, false, err
	}

	return blocklist, challengePolicy, cfg.RequirePublicSuffix, cfg.RejectReservedIPs, nil
}

// NewRestService creates a new ACME REST service with the provided parameters.
func NewRestService(params *Params) (RestServicer, error) {
	if params == nil {
		return nil, caerrors.MalformedError("handlers: params cannot be nil")
	}

	if params.BaseRESTURI == "" {
		return nil, caerrors.MalformedError("handlers: BaseRESTURI is required")
	}

	if params.CA == nil {
		return nil, caerrors.MalformedError("handlers: CA is required")
	}

	if params.Logger == nil {
		return nil, caerrors.MalformedError("handlers: Logger is required")
	}

	if params.StorageFactory == nil {
		return nil, caerrors.MalformedError("handlers: StorageFactory is required")
	}

	// Default challenge map if not provided
	if params.ChallengeMap == nil {
		params.ChallengeMap = make(map[string]common.ChallengeVerifierFunc)
	}

	// The audit trail is always present so call sites never branch on nil; a
	// service configured without a logger records to the no-op logger.
	auditLog := params.AuditLogger
	if auditLog == nil {
		auditLog = audit.NewNoOpLogger()
	}

	// The nonce encryption key MUST be identical on every node for a nonce
	// minted on one node to validate on another. Params.NonceKey is that
	// shared secret when the caller has one; absent it, a key is generated
	// for this process alone, which keeps a single-node deployment correct
	// but does not make nonces portable across nodes.
	nonceKey := params.NonceKey
	if len(nonceKey) == 0 {
		generated := make([]byte, nonceKeyLen)
		if _, err := rand.Read(generated); err != nil {
			return nil, &ErrNonceServiceInit{Sentinel: ErrNonceKeyGenerate, Cause: err}
		}
		nonceKey = generated
	}

	nonceMaxUsed := params.NonceMaxUsed
	if nonceMaxUsed <= 0 {
		nonceMaxUsed = acmenonce.DefaultMaxUsed
	}

	nonceLifetime := params.NonceLifetime
	if nonceLifetime <= 0 {
		nonceLifetime = DefaultNonceLifetime
	}

	epochAt := nonceClock()
	epoch, err := newNonceEpoch(nonceKey, nonceEpochPrefix(params.NoncePrefix, nonceKey, epochAt.UnixNano()), nonceMaxUsed)
	if err != nil {
		return nil, &ErrNonceServiceInit{Sentinel: ErrNonceServiceCreate, Cause: err}
	}

	// Resilience is opt-in: a nil Manager leaves storageBreaker and the
	// degradation caches nil, and CABundleHandler/DirectoryHandler compute
	// fresh on every request exactly as they did before this existed.
	var storageBreaker *circuitbreaker.CircuitBreaker
	var directoryCache, caBundleCache *degradation.Cache
	if params.Breakers != nil {
		storageBreakerCfg := params.StorageBreaker
		if storageBreakerCfg == nil {
			storageBreakerCfg = circuitbreaker.DefaultConfig("storage")
		}
		storageBreaker = params.Breakers.GetOrCreate(storageBreakerCfg)

		maxCacheSize := params.DegradationMaxCacheSize
		if maxCacheSize <= 0 {
			maxCacheSize = 8
		}
		directoryCache = degradation.NewCache("acme-directory", maxCacheSize)
		caBundleCache = degradation.NewCache("acme-ca-bundle", maxCacheSize)
	}

	// Wrap the KMS signer with its own breaker, guarding every tenant KMS
	// signing operation this service performs (getTenantCASigner,
	// tenantIssuerCertificate in order_finalize.go). Left unwrapped when
	// either Breakers or KMSService is nil.
	kmsService := params.KMSService
	if params.Breakers != nil && kmsService != nil {
		kmsBreakerCfg := params.KMSBreaker
		if kmsBreakerCfg == nil {
			kmsBreakerCfg = circuitbreaker.DefaultConfig("kms")
		}
		kmsService = circuitbreaker.WrapKMSService(params.Breakers.GetOrCreate(kmsBreakerCfg), kmsService)
	}

	degradationDefaults := degradation.DefaultConfig()
	degradationCacheTTL := params.DegradationCacheTTL
	if degradationCacheTTL <= 0 {
		degradationCacheTTL = degradationDefaults.CacheTTL
	}
	degradationStaleTTL := params.DegradationStaleTTL
	if degradationStaleTTL <= 0 {
		degradationStaleTTL = degradationDefaults.StaleTTL
	}

	blocklist, challengePolicy, requirePublicSuffix, rejectReservedIPs, err := buildIdentifierPolicy(params)
	if err != nil {
		return nil, caerrors.MalformedError("handlers: failed to build identifier policy: %v", err)
	}

	svc := &RestService{
		allowLoopbackIdentifier: params.AllowLoopbackIdentifier,
		auditLog:                auditLog,
		baseRESTURI:             params.BaseRESTURI,
		blocklist:               blocklist,
		ca:                      params.CA,
		caaIdentities:           params.CAAIdentities,
		caaValidator:            params.CAAValidator,
		challengeMap:            params.ChallengeMap,
		attestingVerifiers:      params.AttestingVerifiers,
		challengePolicy:         challengePolicy,
		clusterCACN:             params.ClusterCACN,
		endorseEABRequired:      params.EndorseEABRequired || !params.EndorseEABOptional,
		endorseDeviceIDMetaKey:  params.EndorseDeviceIDMetaKey,
		externalAccountRequired: params.ExternalAccountRequired,
		failedValidationLimiter: params.FailedValidationRateLimiter,
		globalComplianceConfig:  params.GlobalComplianceConfig,
		kmsService:              kmsService,
		logger:                  params.Logger,
		nonceGenerator:          params.NonceGenerator,
		nonceService:            acmenonce.NewMultiService(epoch),
		nonceKey:                nonceKey,
		noncePrefix:             params.NoncePrefix,
		nonceLifetime:           nonceLifetime,
		nonceMaxUsed:            nonceMaxUsed,
		orderFinalizeHooks:      params.OrderFinalizeHooks,
		params:                  params,
		preIssuanceHooks:        params.PreIssuanceHooks,
		preSignHooks:            params.OrderPreSignHooks,
		rejectReservedIPs:       rejectReservedIPs,
		requirePublicSuffix:     requirePublicSuffix,
		storageFactory:          params.StorageFactory,
		termsOfService:          params.TermsOfService,
		breakers:                params.Breakers,
		storageBreaker:          storageBreaker,
		directoryCache:          directoryCache,
		caBundleCache:           caBundleCache,
		degradationCacheTTL:     degradationCacheTTL,
		degradationStaleTTL:     degradationStaleTTL,
	}
	svc.nonceEpoch.Store(&nonceEpochRecord{epoch: epoch, at: epochAt})
	if svc.nonceGenerator == nil {
		svc.nonceGenerator = svc.mintNonce
	}

	return svc, nil
}

// GetStorageFactory returns the storage factory for creating DAOs.
// This is useful for tests that need to verify storage state.
func (s *RestService) GetStorageFactory() storage.Factory {
	return s.storageFactory
}

// GetNonceService returns the nonce service backing replay protection
// (RFC 8555 Section 6.5). Tests that need a nonce a request will accept
// should call generateNonce/mintNonce rather than construct one by hand:
// pkg/acme/nonce nonces are encrypted counters, not opaque tokens, so only
// this service can mint one its own Redeem/Valid will later accept.
func (s *RestService) GetNonceService() *acmenonce.MultiService {
	return s.nonceService
}

// SetOrderFinalizeHooks sets the order finalize hook registry.
// This allows tests to register custom hooks for order finalization.
func (s *RestService) SetOrderFinalizeHooks(registry *OrderFinalizeHookRegistry) {
	s.orderFinalizeHooks = registry
	// Also update params for handler code that checks s.params.OrderFinalizeHooks
	if s.params != nil {
		s.params.OrderFinalizeHooks = registry
	}
}

// GetOrderFinalizeHooks returns the order finalize hook registry.
func (s *RestService) GetOrderFinalizeHooks() *OrderFinalizeHookRegistry {
	return s.orderFinalizeHooks
}

// SetPreIssuanceHooks sets the pre-issuance hook registry.
// This allows applications to register hooks that execute BEFORE certificate signing.
func (s *RestService) SetPreIssuanceHooks(registry *PreIssuanceHookRegistry) {
	s.preIssuanceHooks = registry
	// Also update params for handler code that checks s.params.PreIssuanceHooks
	if s.params != nil {
		s.params.PreIssuanceHooks = registry
	}
}

// GetPreIssuanceHooks returns the pre-issuance hook registry.
func (s *RestService) GetPreIssuanceHooks() *PreIssuanceHookRegistry {
	return s.preIssuanceHooks
}

// SetOrderPreSignHooks sets the pre-sign extension hook registry.
// Hooks registered here fire immediately before the CA signs each certificate
// and may inject additional X.509 extensions into the issued certificate.
func (s *RestService) SetOrderPreSignHooks(registry *OrderPreSignHookRegistry) {
	s.preSignHooks = registry
	if s.params != nil {
		s.params.OrderPreSignHooks = registry
	}
}

// GetOrderPreSignHooks returns the pre-sign extension hook registry.
func (s *RestService) GetOrderPreSignHooks() *OrderPreSignHookRegistry {
	return s.preSignHooks
}

// SetGlobalComplianceConfig sets the global compliance configuration.
// This allows applications to configure server-wide compliance settings.
func (s *RestService) SetGlobalComplianceConfig(config *GlobalComplianceConfig) {
	s.globalComplianceConfig = config
	// Also update params for handler code that checks s.params.GlobalComplianceConfig
	if s.params != nil {
		s.params.GlobalComplianceConfig = config
	}
}

// GetGlobalComplianceConfig returns the global compliance configuration.
func (s *RestService) GetGlobalComplianceConfig() *GlobalComplianceConfig {
	return s.globalComplianceConfig
}

// SetCAAValidator sets the CAA validator.
// This allows tests to inject mock validators.
func (s *RestService) SetCAAValidator(validator CAAValidatorInterface) {
	s.caaValidator = validator
}

// GetCAAValidator returns the CAA validator.
func (s *RestService) GetCAAValidator() CAAValidatorInterface {
	return s.caaValidator
}

// SetNonceGenerator sets the nonce generator function.
// This allows tests to inject a failing generator for error path testing.
func (s *RestService) SetNonceGenerator(gen NonceGeneratorFunc) {
	s.nonceGenerator = gen
}

// GetNonceGenerator returns the nonce generator function.
func (s *RestService) GetNonceGenerator() NonceGeneratorFunc {
	return s.nonceGenerator
}

// generateNonce mints a Replay-Nonce using the configured generator. This
// internal method allows all nonce generation to be controlled via
// dependency injection (see SetNonceGenerator).
func (s *RestService) generateNonce() (string, error) {
	return s.nonceGenerator()
}

// mintNonce is the default NonceGeneratorFunc: it rotates the signing epoch
// when NonceLifetime has elapsed, then mints from whichever epoch is
// current.
func (s *RestService) mintNonce() (string, error) {
	return s.currentNonceEpoch().Generate()
}

// redeemNonce validates and consumes nonce (RFC 8555 Section 6.5), routing
// through nonceService so a correctly-prefixed nonce from another node in a
// load-balanced deployment is handled per MultiService's routing semantics
// rather than always compared against this process's own epoch.
func (s *RestService) redeemNonce(nonce string) error {
	return s.nonceService.Redeem(nonce)
}

// currentNonceEpoch returns the signing epoch minting should use, rotating
// to a fresh one first if the current epoch has outlived nonceLifetime.
// Reading nonceEpoch never blocks; only rotation itself takes nonceRotateMu,
// and only when the epoch has actually expired.
func (s *RestService) currentNonceEpoch() *acmenonce.Service {
	record := s.nonceEpoch.Load()
	if nonceClock().Sub(record.at) < s.nonceLifetime {
		return record.epoch
	}
	return s.rotateNonceEpoch(record)
}

// rotateNonceEpoch replaces stale with a freshly-counted epoch built from
// the same key under a new, epoch-unique prefix (see newNonceEpoch).
// SetLocal moves pkg/acme/nonce.MultiService's registration from stale's
// prefix to fresh's, so a nonce still outstanding from the previous epoch no
// longer decrypts against a registered prefix and is rejected instead of
// being checked against the new epoch's unrelated counter state.
//
// stale is the *nonceEpochRecord currentNonceEpoch observed as expired, not
// just its epoch: comparing whole records (rather than epoch pointers) for
// the re-check below is what makes the re-check sound. nonceEpoch's epoch
// and at fields are swapped together as one record, so nonceEpoch never
// holds a fresh epoch paired with a stale at — the pairing that previously
// let a second goroutine, having loaded the fresh epoch but not yet the
// fresh timestamp, mistake the just-rotated epoch for expired and pass it
// back in here as "stale", defeating the pointer re-check and causing a
// second, illegitimate rotation.
//
// A rotation failure (only reachable if the process is out of entropy for
// AES-GCM setup, since the key is already validated) logs and keeps serving
// stale rather than losing nonce issuance entirely.
func (s *RestService) rotateNonceEpoch(stale *nonceEpochRecord) *acmenonce.Service {
	s.nonceRotateMu.Lock()
	defer s.nonceRotateMu.Unlock()

	// Another goroutine may have rotated already while this one waited for
	// the lock.
	if current := s.nonceEpoch.Load(); current != stale {
		return current.epoch
	}

	epochAt := nonceClock()
	fresh, err := newNonceEpoch(s.nonceKey, nonceEpochPrefix(s.noncePrefix, s.nonceKey, epochAt.UnixNano()), s.nonceMaxUsed)
	if err != nil {
		s.logger.Error("acme: failed to rotate nonce epoch, continuing on the previous epoch",
			slog.String("error", err.Error()))
		return stale.epoch
	}

	s.nonceService.SetLocal(fresh)
	s.nonceEpoch.Store(&nonceEpochRecord{epoch: fresh, at: epochAt})
	return fresh
}

// respondWithAccount writes an ACME account response to the HTTP response writer.
func (s *RestService) respondWithAccount(
	w http.ResponseWriter, account *entities.ACMEAccount, statusCode int) {

	nonce, err := s.generateNonce()
	if err != nil {
		writeError(w, common.ServerInternal("Unable to generate nonce"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", fmt.Sprintf("%s/acme/directory>;rel=\"index\"", s.baseRESTURI))
	w.Header().Set("Location", s.accountURL(account))
	w.WriteHeader(statusCode)

	// Per RFC 8555 Section 7.1.2, account response includes externalAccountBinding
	// when the account was created with one
	clientAccount := struct {
		Status                 string      `json:"status"`
		Contact                []string    `json:"contact,omitempty"`
		Orders                 string      `json:"orders"`
		ExternalAccountBinding interface{} `json:"externalAccountBinding,omitempty"`
	}{
		Status:                 account.Status,
		Contact:                account.Contact,
		Orders:                 account.Orders,
		ExternalAccountBinding: account.ExternalAccountBinding,
	}

	s.encodeJSON(w, clientAccount)
}

// accountURL returns the URL for an account resource.
func (s *RestService) accountURL(account *entities.ACMEAccount) string {
	return fmt.Sprintf("%s/acme/account/%d", s.baseRESTURI, account.ID)
}

// ValidateContactURLs validates ACME contact URLs per RFC 8555.
// Only mailto URLs are currently supported.
func ValidateContactURLs(contacts []string) *entities.Error {
	for _, contact := range contacts {
		if strings.HasPrefix(contact, "mailto:") {
			emailAddress := strings.TrimPrefix(contact, "mailto:")
			// Check for 'hfields' and multiple 'addr-spec'
			if strings.Contains(emailAddress, "?") {
				return common.InvalidContact("Invalid mailto URL: contains hfields")
			}
			if strings.Contains(emailAddress, ",") {
				return common.InvalidContact("Invalid mailto URL: contains multiple addr-spec")
			}
			if _, err := mail.ParseAddress(emailAddress); err != nil {
				return common.InvalidContact("Invalid mailto URL: invalid email address")
			}
		} else {
			return common.UnsupportedContact("Unsupported contact URL scheme")
		}
	}
	return nil
}

// orderResponse writes an ACME order response to the HTTP response writer.
func (s *RestService) orderResponse(w http.ResponseWriter, order *entities.ACMEOrder) {
	nonce, err := s.generateNonce()
	if err != nil {
		writeError(w, common.ServerInternal("Unable to generate nonce"))
		return
	}

	clientOrder := struct {
		Status         string                    `json:"status"`
		Expires        string                    `json:"expires,omitempty"`
		Identifiers    []entities.ACMEIdentifier `json:"identifiers"`
		NotBefore      string                    `json:"notBefore,omitempty"`
		NotAfter       string                    `json:"notAfter,omitempty"`
		Error          *entities.Error           `json:"error,omitempty"`
		Authorizations []string                  `json:"authorizations"`
		Finalize       string                    `json:"finalize"`
		Certificate    string                    `json:"certificate,omitempty"`
	}{
		Status:         order.Status,
		Expires:        order.Expires,
		Identifiers:    order.Identifiers,
		NotBefore:      order.NotBefore,
		NotAfter:       order.NotAfter,
		Error:          order.Error,
		Authorizations: order.Authorizations,
		Finalize:       order.Finalize,
		Certificate:    order.Certificate,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", s.baseRESTURI))
	s.encodeJSON(w, clientOrder)
}

// encodeJSON encodes the value as JSON to the response writer and logs any errors.
// This helper ensures JSON encoding errors are never silently ignored.
func (s *RestService) encodeJSON(w http.ResponseWriter, v any) {
	encodeJSONWithLogger(w, v, s.logger)
}

// encodeJSONWithLogger encodes JSON and logs errors using the provided logger.
// If logger is nil, uses slog.Default().
func encodeJSONWithLogger(w http.ResponseWriter, v any, logger *slog.Logger) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("failed to encode JSON response",
			slog.String("error", err.Error()))
	}
}

// challengeResponse writes an ACME challenge response to the HTTP response writer.
func challengeResponse(w http.ResponseWriter, challenge *entities.ACMEChallenge) {
	clientChallenge := struct {
		Type      string          `json:"type"`
		URL       string          `json:"url"`
		Status    string          `json:"status"`
		Token     string          `json:"token"`
		Validated string          `json:"validated,omitempty"`
		Error     *entities.Error `json:"error,omitempty"`
	}{
		Type:      challenge.Type,
		URL:       challenge.URL,
		Status:    challenge.Status,
		Token:     challenge.Token,
		Validated: challenge.Validated,
		Error:     challenge.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	encodeJSONWithLogger(w, clientChallenge, nil)
}

// writeError writes an ACME error response to the HTTP response writer.
func writeError(w http.ResponseWriter, err *entities.Error) {
	w.Header().Set("Content-Type", "application/problem+json")
	if err.Status == 0 {
		err.Status = http.StatusInternalServerError
	}
	w.WriteHeader(err.Status)
	encodeJSONWithLogger(w, err, nil)
}

// requestURL reconstructs the full request URL from the base REST URI and
// the request path. When ACME routes are mounted under a path prefix
// (e.g., /api/v1), r.URL.Path includes the full prefix while baseRESTURI
// already contains it. This method strips the overlapping prefix to avoid
// doubling (e.g., https://host/api/v1/api/v1/acme/new-account).
func (s *RestService) requestURL(r *http.Request) (string, error) {
	parsedBase, err := url.Parse(s.baseRESTURI)
	if err != nil {
		return "", caerrors.InternalServerError("failed to parse base URI: %v", err)
	}
	relPath := strings.TrimPrefix(r.URL.Path, parsedBase.Path)
	return s.baseRESTURI + relPath, nil
}

// parseSignedRequest parses the request body as a JWS with at least one
// signature, without verifying it. The body comes from server.RequestBody, so
// it is the one capped copy RequestBodyMiddleware read, never a second read of
// the connection.
func parseSignedRequest(r *http.Request) (*jose.JSONWebSignature, error) {
	body, err := server.RequestBody(r)
	if err != nil {
		return nil, caerrors.MalformedError("failed to read request body: %v", err)
	}

	jws, err := jose.ParseSigned(strings.TrimSpace(string(body)), server.AllowedJOSEAlgorithms)
	if err != nil {
		return nil, caerrors.MalformedError("failed to parse JWS: %v", err)
	}

	if len(jws.Signatures) == 0 {
		return nil, caerrors.MalformedError("no signatures found in JWS")
	}
	return jws, nil
}

// parseKID parses a JWS request with a KID (Key ID) in the protected header.
// It validates the JWS signature, nonce, and retrieves the associated account.
//
// If TenantAuthMiddleware already performed this exact verification for the
// request (it must, to resolve the tenant before dispatch), ctx carries the
// cached result and it is returned unchanged instead of re-verifying: the
// JWS replay-nonce is single-use (common.NonceStore.Exists deletes it on
// first check), so a second live verification would spuriously fail with
// badNonce.
func (s *RestService) parseKID(ctx context.Context, r *http.Request) (*entities.ACMEAccount, []byte, error) {
	if cached, ok := authenticatedJWSFromContext(ctx); ok {
		return cached.account, cached.payload, cached.err
	}

	jws, err := parseSignedRequest(r)
	if err != nil {
		return nil, nil, err
	}

	protectedHeader := jws.Signatures[0].Header

	if protectedHeader.JSONWebKey != nil && protectedHeader.KeyID != "" {
		return nil, nil, ErrKIDAndJWKNotAllowed
	}

	if protectedHeader.KeyID == "" {
		return nil, nil, caerrors.MalformedError("KID not found in JWS header")
	}

	if err := s.redeemNonce(protectedHeader.Nonce); err != nil {
		if auditErr := s.recordAudit(audit.EventInvalidNonce, s.auditLog.LogWithContext(auditContext(r),
			audit.EventInvalidNonce,
			"unknown",
			"acme:nonce",
			"validate",
			audit.ResultFailure,
			map[string]interface{}{"reason": "invalid or missing replay-nonce"},
		)); auditErr != nil {
			return nil, nil, auditErr
		}
		return nil, nil, common.BadNonce("Invalid or missing Replay-Nonce")
	}

	// RFC 8555 Section 6.3: Validate that the JWS "url" header field matches
	// the request URL. This prevents replay attacks where a signed JWS intended
	// for one endpoint is submitted to a different endpoint.
	expectedURL, urlErr := s.requestURL(r)
	if urlErr != nil {
		return nil, nil, urlErr
	}
	jwsURL, ok := protectedHeader.ExtraHeaders["url"].(string)
	if !ok || jwsURL != expectedURL {
		return nil, nil, caerrors.MalformedError("JWS url header does not match request URL")
	}

	accountID, err := ParseAccountID(protectedHeader.KeyID)
	if err != nil {
		return nil, nil, ErrInvalidAccountID
	}

	accountDAO, err := s.storageFactory.AccountDAO()
	if err != nil {
		return nil, nil, caerrors.StorageFailureError("failed to create account DAO")
	}

	account, err := accountDAO.Get(ctx, accountID)
	if err != nil {
		// Distinguish between "not found" and storage errors
		if qrdbsdk.IsDAONotFound(err) {
			return nil, nil, ErrAccountNotFound
		}
		// For storage failures, return a more specific error
		return nil, nil, caerrors.StorageFailureError("storage error retrieving account: %v", err)
	}

	// RFC 8555 Section 7.3.6: Reject requests from deactivated accounts
	// "Once an account is deactivated, the server MUST NOT accept further
	// requests authorized by that account's key."
	if account.Status == common.StatusDeactivated {
		return nil, nil, ErrAccountDeactivated
	}

	publicKey, err := xkmssdk.DecodePublicKeyPEM([]byte(account.Key))
	if err != nil {
		return nil, nil, caerrors.MalformedError("failed to decode account public key")
	}

	payload, err := jws.Verify(publicKey)
	if err != nil {
		if auditErr := s.recordAudit(audit.EventInvalidSignature, s.auditLog.LogWithContext(auditContext(r),
			audit.EventInvalidSignature,
			auditAccountRef(account.ID),
			"acme:jws",
			"verify",
			audit.ResultFailure,
			map[string]interface{}{"reason": err.Error()},
		)); auditErr != nil {
			return nil, nil, auditErr
		}
		return nil, nil, ErrInvalidJWSSignature
	}

	return account, payload, nil
}

// parseJWS parses a JWS request with a JWK (JSON Web Key) in the protected header.
// This is used for new account creation where no KID exists yet.
func (s *RestService) parseJWS(r *http.Request) (*jose.JSONWebKey, []byte, error) {
	jws, err := parseSignedRequest(r)
	if err != nil {
		return nil, nil, err
	}

	protectedHeader := jws.Signatures[0].Header

	if protectedHeader.JSONWebKey == nil {
		return nil, nil, caerrors.MalformedError("JWK not found in JWS header")
	}

	if err := s.redeemNonce(protectedHeader.Nonce); err != nil {
		if auditErr := s.recordAudit(audit.EventInvalidNonce, s.auditLog.LogWithContext(auditContext(r),
			audit.EventInvalidNonce,
			"unknown",
			"acme:nonce",
			"validate",
			audit.ResultFailure,
			map[string]interface{}{"reason": "invalid or missing replay-nonce"},
		)); auditErr != nil {
			return nil, nil, auditErr
		}
		return nil, nil, common.BadNonce("Invalid or missing Replay-Nonce")
	}

	// RFC 8555 Section 6.3: Validate that the JWS "url" header field matches
	// the request URL. This prevents replay attacks where a signed JWS intended
	// for one endpoint is submitted to a different endpoint.
	expectedURL, urlErr := s.requestURL(r)
	if urlErr != nil {
		return nil, nil, urlErr
	}
	jwsURL, ok := protectedHeader.ExtraHeaders["url"].(string)
	if !ok || jwsURL != expectedURL {
		return nil, nil, caerrors.MalformedError("JWS url header does not match request URL")
	}

	jwk := protectedHeader.JSONWebKey
	payload, err := jws.Verify(jwk)
	if err != nil {
		if auditErr := s.recordAudit(audit.EventInvalidSignature, s.auditLog.LogWithContext(auditContext(r),
			audit.EventInvalidSignature,
			"unknown",
			"acme:jws",
			"verify",
			audit.ResultFailure,
			map[string]interface{}{"reason": err.Error()},
		)); auditErr != nil {
			return nil, nil, auditErr
		}
		return nil, nil, ErrInvalidJWSSignature
	}

	return jwk, payload, nil
}

// KeyAuthorization computes the key authorization for a challenge token.
// Format: token.thumbprint where thumbprint is the JWK thumbprint.
func KeyAuthorization(token string, accountKey crypto.PublicKey) (string, error) {
	jwkThumbprint, err := JWKThumbprint(accountKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, jwkThumbprint), nil
}

// JWKThumbprint computes the JWK thumbprint of a public key per RFC 7638.
// The thumbprint is base64url(SHA-256(UTF8(JWK canonical JSON))).
func JWKThumbprint(pubKey crypto.PublicKey) (string, error) {
	var jwk map[string]interface{}

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		nBytes := key.N.Bytes()
		eBytes := big.NewInt(int64(key.E)).Bytes()
		jwk = map[string]interface{}{
			"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		}
	case *ecdsa.PublicKey:
		// Use ECDH conversion to avoid deprecated ecdsa.PublicKey.X/Y fields.
		// ECDH().Bytes() returns the uncompressed point encoding (0x04 || X || Y)
		// with fixed-length, zero-padded coordinates.
		ecdhKey, err := key.ECDH()
		if err != nil {
			return "", caerrors.InternalServerError("failed to convert ECDSA key to ECDH: %v", err)
		}
		raw := ecdhKey.Bytes()
		// Uncompressed point format: 0x04 || X || Y
		coordLen := (len(raw) - 1) / 2
		xBytes := raw[1 : 1+coordLen]
		yBytes := raw[1+coordLen:]
		jwk = map[string]interface{}{
			"crv": key.Curve.Params().Name,
			"kty": "EC",
			"x":   base64.RawURLEncoding.EncodeToString(xBytes),
			"y":   base64.RawURLEncoding.EncodeToString(yBytes),
		}
	case ed25519.PublicKey:
		jwk = map[string]interface{}{
			"crv": "Ed25519",
			"kty": "OKP",
			"x":   base64.RawURLEncoding.EncodeToString(key),
		}
	default:
		return "", ErrUnsupportedKeyType
	}

	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return "", caerrors.SerializationFailureError("failed to marshal JWK: %v", err)
	}

	hasher := sha256.New()
	hasher.Write(jwkJSON)
	digest := hasher.Sum(nil)

	thumbprint := base64.RawURLEncoding.EncodeToString(digest)
	return thumbprint, nil
}

// ParseAccountID extracts the account ID from an account URL.
func ParseAccountID(accountURL string) (uint64, error) {
	pieces := strings.Split(accountURL, "/")
	accountID, err := strconv.ParseUint(pieces[len(pieces)-1], 10, 64)
	if err != nil {
		return 0, ErrInvalidAccountID
	}
	return accountID, nil
}

// AccountIDFromPublicKey generates a deterministic account ID from a public key.
// It uses the SHA-256 hash of the JWK thumbprint to create a uint64 ID.
func AccountIDFromPublicKey(pubKey crypto.PublicKey) (uint64, error) {
	thumbprint, err := JWKThumbprint(pubKey)
	if err != nil {
		return 0, err
	}
	// Use SHA-256 of thumbprint to generate deterministic uint64
	hash := sha256.Sum256([]byte(thumbprint))
	return binary.BigEndian.Uint64(hash[:8]), nil
}

// GenerateID generates a cryptographically secure random ID.
func GenerateID() (uint64, error) {
	return generateIDWithReader(randReader)
}

// generateIDWithReader generates a cryptographically secure random ID using the provided reader.
// This internal function allows for testing with mock readers.
func generateIDWithReader(reader io.Reader) (uint64, error) {
	id := make([]byte, nonceSize)
	n, err := reader.Read(id)
	if err != nil {
		return 0, err
	}
	if n != nonceSize {
		return 0, ErrFailedToGenerateID
	}
	// Convert first 8 bytes to uint64
	return binary.BigEndian.Uint64(id[:8]), nil
}

// GenerateToken generates a cryptographically secure random token.
func GenerateToken() (string, error) {
	return generateTokenWithReader(randReader)
}

// generateTokenWithReader generates a cryptographically secure random token using the provided reader.
// This internal function allows for testing with mock readers.
func generateTokenWithReader(reader io.Reader) (string, error) {
	id := make([]byte, nonceSize)
	n, err := reader.Read(id)
	if err != nil {
		return "", err
	}
	if n != nonceSize {
		return "", ErrFailedToGenerateToken
	}
	return base64.RawURLEncoding.EncodeToString(id), nil
}
