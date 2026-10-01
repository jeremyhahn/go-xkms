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

package xkms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/escrow"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11state"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/signing/store"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// Compile-time interface compliance check: XKMSService implements
// the full XKMSServicer interface used by the embedded SDK transport.
var _ transport.XKMSServicer = (*XKMSService)(nil)

// Service singleton instance
var (
	service  *XKMSService
	initOnce sync.Once
	initMu   sync.RWMutex
)

// XKMSService provides a simplified API for xkms operations
// across multiple backends. Applications and services use this instead of managing
// Backend instances directly, preventing leaky abstractions.
//
// When optional subsystem setters are called (SetBarrier, SetWebAuthn, etc.),
// XKMSService implements the full transport.XKMSServicer interface, enabling
// direct in-process access via the SDK's embedded transport.
type XKMSService struct {
	backends       map[string]Backend // full-service backend name -> Backend
	keyProviders   map[string]Backend // partial key provider name -> Backend
	defaultBackend string             // default backend to use
	mu             sync.RWMutex

	// Optional subsystems — when set via Set* methods, XKMSService implements
	// the full transport.XKMSServicer interface. Each field starts nil (returning
	// ErrNotConfigured) until wired by the server or application.
	barrier subsystem[*seal.Barrier]

	// encMigrator enables at-rest encryption on a previously-unencrypted
	// barrier by migrating it to a keyed strategy in place. It is the embedded
	// go-qrdb node (which satisfies EncryptionMigrator). Nil in wiring that has
	// no migratable backend, in which case BarrierEnableEncryption reports
	// ErrNotConfigured.
	encMigrator EncryptionMigrator

	// migrationsInFlight tracks enable-encryption migrations currently running,
	// keyed by barrier scope, so BarrierEnableEncryption is single-flight per
	// scope. Concurrent migrations on the same scope would race on the barrier's
	// swap/in-place rewrite and corrupt it. The zero value is ready to use;
	// entries are added before the goroutine launches and removed when it exits.
	migrationsInFlight sync.Map

	// tenantService is go-qrdb's canonical TenantService, composed over the
	// barrier registry with xkms hardware seal strategies injected. It owns
	// tenant lifecycle: entitlement-gated isolation modes, system-managed
	// auto-unseal, quotas, and per-tenant hardware/cloud barrier sealing. Every
	// tenant servicer method requires it; when nil they return
	// ErrTenantServiceNotConfigured. There is no fallback to direct
	// barrier-registry operations.
	tenantService qrdbsdk.ServiceTenantServicer

	pinManager    subsystem[qrdbsdk.PINBackend]
	passwordStore subsystem[*staticpw.BackendStore]

	// pkcs11StateStore persists a remote-mode PKCS#11 module's durable token and
	// object state (token metadata, PIN hashes, lockout counters, object
	// metadata, handle counter) in the embedded qrdb node. Nil unless the
	// deployment enables it.
	pkcs11StateStore *pkcs11state.Store

	// users and roles are the embedded qrdb node's identity clients. xkms
	// presents its own user-management API on top of them, so callers only
	// ever see xkms users; qrdb is an internal implementation detail.
	users           qrdbtransport.UserClient
	roles           qrdbtransport.RoleClient
	platformStore   subsystem[seal.PlatformStore]
	tpmPolicies     subsystem[*tpmpolicy.Service]
	keyVersions     subsystem[*keyversion.Store]
	oidcCredentials subsystem[*credential.Service]
	webauthnService *webauthn.Service
	custodians      subsystem[qrdbtransport.CustodianGroupClient]
	shares          subsystem[qrdbtransport.ShareClient]
	userAuthFactors qrdbtransport.UserAuthFactorClient

	// tokenIssuer mints and revokes the browser/desktop session token
	// pairs behind the WebAuthn, PIV, and mTLS login flows. DisableUser and
	// DeleteUser use it to revoke every refresh-token session an affected
	// account holds the moment the lifecycle change lands (go-xkms#1297).
	// Nil when the deployment did not wire one (SetTokenIssuer not
	// called), in which case those methods still update the qrdb account
	// but revoke no session directly; the refresh-time re-check
	// (pkg/auth.QRDBUserResolver, consulted by pkg/auth/token.Issuer on
	// every refresh) is the enforcement backstop either way.
	tokenIssuer *token.Issuer

	// audit is the embedded qrdb node's audit client, used READ-ONLY here:
	// QueryAudit serves the audit viewer. Emission goes through pkg/audit's
	// Logger seam instead, so an API caller can never write to the chain.
	audit             qrdbtransport.AuditClient
	credentialService subsystem[*credentialspkg.Service]

	// authorizer is the process's single qrdb-backed Authorizer, the same one
	// every transport gates on. The service consults it only where a decision
	// depends on more than the transport's route permission: QueryAudit asks it
	// whether a system-tenant caller holds audit:read:cross. Nil (or disabled)
	// means RBAC is off, and the service then honours the configured
	// allow-all intent exactly as the transports do.
	authorizer *auth.Authorizer

	// escrow holds the configured external key-escrow agents (pkg/escrow).
	// Nil when escrow is not configured, in which case every EscrowServicer
	// method returns ErrNotConfigured.
	escrow *escrow.Registry

	// cluster is the embedded go-qrdb node's cluster client, used to resolve
	// the leader's dialable API endpoint for not-leader write redirects
	// (ClusterLeaderEndpoint). It is nil when the node runs standalone
	// (non-clustered), in which case no redirect target exists.
	cluster ClusterClient

	// clusterShardID is the Raft shard (group) identifier leader-endpoint
	// resolution operates on. It is sourced from xkms Config.Cluster.ShardID
	// (default 1).
	clusterShardID uint64

	// clusterNodeID is this node's Raft replica identifier. Zero when
	// standalone.
	clusterNodeID uint64

	// passwordStoreManager manages per-tenant password stores with
	// session lock state and TenantBarrier-backed encryption.
	passwordStoreManager subsystem[*staticpw.TenantPasswordStoreManager]

	// ceremonyService is stored as any to break the import cycle:
	// xkms -> init -> ca -> xkms. The concrete type is *initialize.CeremonyService.
	// Callers retrieve it via CeremonyService() and type-assert as needed.
	ceremonyService any

	// ca is the Certificate Authority provider. Uses the provider.CA interface
	// from pkg/ca/provider to break the import cycle (pkg/ca imports pkg/xkms).
	// The concrete type is *ca.CA which implements provider.CA (and optionally
	// provider.TCGCA for TCG operations).
	ca subsystem[provider.CA]

	// attestationVerifiers holds the hardware-attestation verifiers keyed by
	// normalized attestation format ("tpm2", "yubikey-piv", ...). Each verifier
	// carries the trust anchors for that format's device vendor, so a YubiKey
	// chain can only be anchored by a YubiKey anchor and a TPM chain only by a
	// TPM manufacturer anchor. The map is nil until wired by the server from
	// operator config; attestation-gated CSR signing fails closed while it is
	// nil or lacks an entry for the requested format.
	attestationVerifiers map[string]*attestation.Verifier

	// attestationClock supplies the instant attestation certificate chains are
	// validated against. It is nil everywhere a server is built, which leaves
	// the verifier on time.Now(); only tests set it, so that a captured chain's
	// validity window does not put an expiry date on the suite. Keeping it
	// unexported is what stops the injection reaching a deployment: no
	// configuration path can pin a CA's clock and quietly accept dead evidence.
	attestationClock func() time.Time

	// androidEnrollmentPolicy gates CSRs presenting Android key attestation.
	// Nil makes every such CSR fail closed: chain provenance alone does not
	// say the evidence is fresh, covers the key being certified, or comes
	// from an application this CA has agreed to enroll.
	androidEnrollmentPolicy *AndroidEnrollmentPolicy

	// allowUnboundAttestation permits formats whose key-binding mechanism this
	// server does not verify. Off by default; see
	// AllowUnboundAttestationFormats for why it should stay off.
	allowUnboundAttestation bool

	// spiffeTrustDomain is the operator-configured SPIFFE trust domain used to
	// stamp tenant-scoped SPIFFE SANs onto broker-issued client certificates.
	// When empty, no SPIFFE SAN is synthesized (legacy behavior). Set via
	// SetSPIFFETrustDomain at server startup from operator config.
	spiffeTrustDomain string

	// bootstrapListenerKeys holds the trust-bootstrap listener's public keys
	// and SPKI pins, published by pkg/server once the listener's Start
	// succeeds (see SetBootstrapListenerKeys). Unlike the other optional
	// subsystems above, publication happens from a goroutine independent of
	// whatever wires the rest of XKMSService, so this field carries its own
	// mutex rather than relying on the single-assignment-before-use pattern
	// the Set* methods otherwise share.
	bootstrapListenerKeys bootstrapListenerKeyState

	// inviteStore mints and redeems the single-use enrollment invitations
	// issued by CreateUser (go-xkms#1294 part B). Nil until SetInviteStore
	// is called, in which case CreateUser refuses to create an invited
	// account with ErrNotConfigured rather than create one no invitation
	// can ever activate.
	//
	// InviteStore is satisfied by two implementations pkg/server chooses
	// between: qrdb's own *qrdbsdk.TenantInviteStore when the embedded node
	// exposes a per-tenant StoreResolver (barrier registry configured —
	// invitations then live under each tenant's own barrier, same as the
	// rest of that tenant's identity data), and a createStorage-backed one
	// otherwise, so a default deployment with no barrier registry still has
	// invitations — see pkg/server/invite_store.go.
	inviteStore InviteStore

	// inviteConfig holds the operator-configured invitation link base URL
	// and TTL bounds. The zero value is usable: an empty PublicBaseURL
	// yields a link with no origin, and empty TTL bounds fall back to
	// qrdbsdk.DefaultInviteTTL and a 7-day cap (see effectiveInviteTTL).
	inviteConfig InviteConfig
}

// ServiceConfig configures the xkms service
type ServiceConfig struct {
	// Backends is a map of full-service backend name to Backend.
	// Full-service backends support sign, verify, encrypt, decrypt, certs, seal/unseal.
	Backends map[string]Backend

	// KeyProviders is a map of partial key provider name to Backend.
	// Key providers support key generation and limited crypto ops,
	// composed into full-service backends (e.g., pkcs8, symmetric, quantum, frost, threshold).
	KeyProviders map[string]Backend

	// DefaultBackend is the name of the default backend to use
	// when no backend is specified in the key ID
	DefaultBackend string
}

// Get returns the initialized XKMSService singleton.
// Returns ErrNotInitialized if Initialize has not been called.
func Get() (*XKMSService, error) {
	initMu.RLock()
	defer initMu.RUnlock()
	if service == nil {
		return nil, ErrNotInitialized
	}
	return service, nil
}

// SetSPIFFETrustDomain sets the operator-configured SPIFFE trust domain used
// to stamp tenant-scoped SPIFFE SANs onto broker-issued client certificates.
// An empty trust domain disables SPIFFE SAN synthesis.
func (s *XKMSService) SetSPIFFETrustDomain(trustDomain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.spiffeTrustDomain = trustDomain
}

// SPIFFETrustDomain returns the configured SPIFFE trust domain.
func (s *XKMSService) SPIFFETrustDomain() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.spiffeTrustDomain
}

// SetBarrier sets the barrier subsystem for seal/unseal operations.
func (s *XKMSService) SetBarrier(b *seal.Barrier) { s.barrier.store(b) }

// SetEncryptionMigrator sets the encryption-migration subsystem used by
// BarrierEnableEncryption. It is the embedded go-qrdb node.
func (s *XKMSService) SetEncryptionMigrator(m EncryptionMigrator) { s.encMigrator = m }

// SetPINManager sets the PIN backend subsystem.
func (s *XKMSService) SetPINManager(p qrdbsdk.PINBackend) { s.pinManager.store(p) }

// SetPasswordStore sets the static password management subsystem.
func (s *XKMSService) SetPasswordStore(p *staticpw.BackendStore) { s.passwordStore.store(p) }

// SetPKCS11StateStore wires the remote-mode PKCS#11 state persistence store.
func (s *XKMSService) SetPKCS11StateStore(p *pkcs11state.Store) { s.pkcs11StateStore = p }

// SetUserClients wires the embedded qrdb node's user and role clients into the
// service so xkms can present its own user-management API backed by qrdb.
func (s *XKMSService) SetUserClients(users qrdbtransport.UserClient, roles qrdbtransport.RoleClient) {
	s.users = users
	s.roles = roles
}

// SetTokenIssuer wires the session-token issuer so DisableUser and
// DeleteUser can revoke every refresh-token session belonging to the
// affected account (go-xkms#1297).
func (s *XKMSService) SetTokenIssuer(issuer *token.Issuer) { s.tokenIssuer = issuer }

// SetPlatformStore sets the sealed platform credential store subsystem.
func (s *XKMSService) SetPlatformStore(p seal.PlatformStore) { s.platformStore.store(p) }

// SetEscrowRegistry wires the external key-escrow agent registry
// (pkg/escrow) into the service.
func (s *XKMSService) SetEscrowRegistry(r *escrow.Registry) { s.escrow = r }

// SetWebAuthn sets the WebAuthn/FIDO2 subsystem.
func (s *XKMSService) SetWebAuthn(w *webauthn.Service) { s.webauthnService = w }

// SetInviteStore wires the per-tenant enrollment-invitation store
// (go-xkms#1294 part B) into the service. Nil leaves invitations
// unconfigured: CreateUser then refuses to create an account it cannot
// issue an activation link for, and every invite-redemption entry point
// reports ErrNotConfigured.
func (s *XKMSService) SetInviteStore(store InviteStore) { s.inviteStore = store }

// SetInviteConfig wires the operator-configured invitation link base URL
// and TTL bounds. The zero value is usable (see InviteConfig).
func (s *XKMSService) SetInviteConfig(cfg InviteConfig) { s.inviteConfig = cfg }

// SetCustodianClient wires the embedded qrdb node's custodian group client
// into the service. xkms presents its own custodian API on top of it; qrdb is
// an internal implementation detail.
func (s *XKMSService) SetCustodianClient(c qrdbtransport.CustodianGroupClient) {
	s.custodians.store(c)
}

// SetShareClient wires the embedded qrdb node's share client into the service.
// xkms presents its own Shamir share API on top of it; qrdb is an internal
// implementation detail.
func (s *XKMSService) SetShareClient(c qrdbtransport.ShareClient) {
	s.shares.store(c)
}

// SetUserAuthFactorClient wires the embedded qrdb node's user-side auth-factor
// client into the service. Identity is qrdb's to own, so xkms stores no factor
// state; it presents the surface on its own API so an operator reaches one
// endpoint instead of two.
func (s *XKMSService) SetUserAuthFactorClient(c qrdbtransport.UserAuthFactorClient) {
	s.userAuthFactors = c
}

// SetAuditClient wires the embedded qrdb node's audit client into the service
// so the audit chain can be queried. Only the read half is exposed on the
// xkms API; events are emitted through pkg/audit's Logger seam.
func (s *XKMSService) SetAuditClient(c qrdbtransport.AuditClient) {
	s.audit = c
}

// SetAuthorizer wires the process's qrdb-backed Authorizer into the service
// for the decisions that are made below the transport gate (see QueryAudit).
// Pass the same Authorizer the transports use; nil means RBAC is disabled.
func (s *XKMSService) SetAuthorizer(a *auth.Authorizer) {
	s.authorizer = a
}

// AuthorizeCaller reports whether the identity ctx carries holds
// resource:action, for a decision made below the transport gate (for example
// ssh:service, which only a request's scope reveals is needed). It returns nil
// when allowed; with no Authorizer wired, RBAC is disabled and every request
// is allowed, as at the transport gate.
func (s *XKMSService) AuthorizeCaller(ctx context.Context, resource, action string) error {
	return s.authorizer.Authorize(ctx, auth.GetIdentity(ctx), resource, action)
}

// SetClusterClient wires the embedded qrdb node's cluster client into the
// service along with the Raft shard and this node's replica identifier. The
// service uses it solely to resolve the leader's dialable API endpoint for
// not-leader write redirects (ClusterLeaderEndpoint); cluster management
// itself is qrdb's own control plane. Passing a nil client configures the
// service for a standalone (non-clustered) node, in which case
// ClusterLeaderEndpoint reports no endpoint.
func (s *XKMSService) SetClusterClient(c ClusterClient, shardID, nodeID uint64) {
	s.cluster = c
	s.clusterShardID = shardID
	s.clusterNodeID = nodeID
}

// Clustered reports whether this node runs as part of a Raft cluster
// (go-qrdb's NewClusteredNode with clustering enabled) rather than the
// standalone single-node engine. Transports use it to decide whether cluster
// membership mutation is possible at all (ClusterAddReplica/
// ClusterRemoveReplica fail closed on a standalone node) and whether to
// advertise the capability to callers; ClusterStatus and ClusterMembers
// themselves stay callable either way, degrading to the standalone view.
func (s *XKMSService) Clustered() bool {
	return s.cluster != nil
}

// SetTenantService injects go-qrdb's TenantService so the tenant servicer
// delegates lifecycle (entitlement-gated isolation, system-managed auto-unseal,
// quotas, per-tenant hardware barrier sealing) to the canonical implementation.
// Every tenant servicer method requires this to be set; there is no
// barrier-registry fallback.
func (s *XKMSService) SetTenantService(t qrdbsdk.ServiceTenantServicer) { s.tenantService = t }

// TenantService returns the composed go-qrdb TenantService, or nil when it has
// not been wired.
func (s *XKMSService) TenantService() qrdbsdk.ServiceTenantServicer { return s.tenantService }

// SetPasswordStoreManager sets the per-tenant password store manager.
func (s *XKMSService) SetPasswordStoreManager(m *staticpw.TenantPasswordStoreManager) {
	s.passwordStoreManager.store(m)
}

// SetCredentialService sets the credential management subsystem.
func (s *XKMSService) SetCredentialService(svc *credentialspkg.Service) {
	s.credentialService.store(svc)
}

// SetCeremonyService sets the init ceremony subsystem. The value is stored as
// any to break the import cycle (xkms -> init -> ca -> xkms). The concrete
// type is *initialize.CeremonyService; callers type-assert after retrieval.
func (s *XKMSService) SetCeremonyService(svc any) {
	s.ceremonyService = svc
}

// CeremonyService returns the ceremony service. Callers must type-assert
// to *initialize.CeremonyService.
func (s *XKMSService) CeremonyService() any {
	return s.ceremonyService
}

// SetCA sets the Certificate Authority provider. The concrete type is *ca.CA
// which implements provider.CA (and optionally provider.TCGCA for TCG ops).
func (s *XKMSService) SetCA(ca provider.CA) {
	s.ca.store(ca)
}

// CA returns the Certificate Authority provider, or nil if not configured.
func (s *XKMSService) CA() provider.CA {
	return s.ca.load()
}

// LookupBackend returns the raw Backend instance for the given name.
// Unlike GetBackend (which is part of the transport.XKMSServicer interface and
// returns a DTO), LookupBackend returns the Backend interface for direct use.
func (s *XKMSService) LookupBackend(name string) (Backend, error) {
	if err := validation.ValidateBackendName(name); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.backends[name]
	if !ok {
		return nil, &ErrBackendLookup{
			Sentinel: ErrBackendNotFound,
			Name:     validation.SanitizeForLog(name),
		}
	}
	return b, nil
}

// LookupTenantBackend returns the named backend viewed through tenantID, so
// every key lookup made against it sees only that tenant's keys. It is the
// tenant-aware form of LookupBackend, for transports that hold a backend name
// and the caller's tenant and resolve keys by common name — a name that is
// unique only within a tenant.
//
// The system tenant resolves to the unscoped backend; see ScopeBackendToTenant.
func (s *XKMSService) LookupTenantBackend(name, tenantID string) (Backend, error) {
	base, err := s.LookupBackend(name)
	if err != nil {
		return nil, err
	}
	return ScopeBackendToTenant(base, tenantID)
}

// DefaultBackendName returns the resolved default backend name, or the empty
// string when none is configured.
func (s *XKMSService) DefaultBackendName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.defaultBackend
}

// LookupDefaultBackend returns the raw Backend interface for the configured
// default backend. Callers that need the backend for direct crypto operations
// should use this instead of the DTO-returning transport interface method.
func (s *XKMSService) LookupDefaultBackend() (Backend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.defaultBackend == "" {
		return nil, ErrNoDefaultBackend
	}
	b, ok := s.backends[s.defaultBackend]
	if !ok {
		return nil, &ErrBackendLookup{
			Sentinel: ErrBackendNotFound,
			Name:     s.defaultBackend,
		}
	}
	return b, nil
}

// BackendNames returns the names of all registered backends on this service instance.
func (s *XKMSService) BackendNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.backends))
	for name := range s.backends {
		names = append(names, name)
	}
	return names
}

// CanSealDirect returns true if the specified backend supports sealing operations.
// If backendName is empty, checks the default backend. This is the low-level
// boolean check; the transport interface's CanSeal returns a structured response.
func (s *XKMSService) CanSealDirect(backendName ...string) bool {
	var b Backend
	var err error
	if len(backendName) > 0 && backendName[0] != "" {
		b, err = s.LookupBackend(backendName[0])
	} else {
		b, err = s.LookupDefaultBackend()
	}
	if err != nil {
		return false
	}
	return b.CanSeal()
}

// validateTenantAccess checks that the TenantID in KeyAttributes is valid.
// Returns nil when TenantID is empty (single-tenant mode).
func validateTenantAccess(attrs *types.KeyAttributes) error {
	if attrs == nil || attrs.TenantID == "" {
		return nil // single-tenant mode
	}
	return storage.ValidateTenantID(attrs.TenantID)
}

// validateConfiguredBackendNames checks every name in a service configuration
// against the canonical backend-name validator.
//
// Both maps are checked: a key provider is addressed by name exactly as a
// backend is, and validating only one would leave the gap half open. The name
// is reported through SanitizeForLog because it came from a caller.
func validateConfiguredBackendNames(config *ServiceConfig) error {
	for _, named := range []struct {
		kind string
		set  map[string]Backend
	}{
		{"backend", config.Backends},
		{"key provider", config.KeyProviders},
	} {
		for name := range named.set {
			if err := validation.ValidateBackendName(name); err != nil {
				return &ErrBackendLookup{
					Sentinel: ErrInvalidBackendName,
					Name:     named.kind + " " + validation.SanitizeForLog(name),
				}
			}
		}
	}
	return nil
}

// Initialize sets up the xkms service.
// This should be called once at application startup.
// Subsequent calls are no-ops due to sync.Once semantics.
func Initialize(config *ServiceConfig) error {
	var initErr error

	initOnce.Do(func() {
		if config == nil {
			initErr = ErrNilConfig
			return
		}

		if len(config.Backends) == 0 {
			initErr = ErrNoBackendsConfigured
			return
		}

		// Validate every configured name before anything is registered.
		//
		// RegisterServiceBackend validates the single name it is handed, and
		// LookupBackend validates on every lookup, so a name that reaches the
		// service through those paths has been checked. Initialize assigned
		// its maps verbatim, which left the bulk entry point — exported to
		// embedders as ServiceInitialize — as the one way to install a name no
		// other path would have admitted.
		//
		// The canonical charset is lowercase, so this also makes a
		// fold-collision unconstructible rather than merely unlikely: two
		// names differing only by case cannot both be valid, and downstream
		// code that compares names case-insensitively (pkg/api/mcp's import
		// guard does) can no longer be pointed at the wrong backend by
		// registering both.
		if initErr = validateConfiguredBackendNames(config); initErr != nil {
			return
		}

		// Resolve the default backend deterministically. A name the caller
		// configured is authoritative and must be present — substituting some
		// other store for a default that was named but not loaded hides an
		// operator error and changes where keys land. Only when no default is
		// configured does the package fallback rule apply.
		//
		// Ranging config.Backends to take "the first" entry read Go's
		// randomized map iteration order, so an embedder that supplied several
		// backends and no default got a different one on each start, and keys
		// written before a restart were looked for in another store after it.
		defaultBackend := config.DefaultBackend
		if defaultBackend == "" {
			defaultBackend = ResolveDefaultBackend("", config.Backends)
		}

		// Verify default backend exists
		if _, ok := config.Backends[defaultBackend]; !ok {
			initErr = &ErrBackendLookup{
				Sentinel: ErrDefaultBackendNotFound,
				Name:     validation.SanitizeForLog(defaultBackend),
			}
			return
		}

		service = &XKMSService{
			backends:       config.Backends,
			keyProviders:   config.KeyProviders,
			defaultBackend: defaultBackend,
		}
	})

	return initErr
}

// Reset clears the service (useful for testing)
func Reset() {
	initMu.Lock()
	defer initMu.Unlock()

	if service != nil {
		service.mu.Lock()
		for _, b := range service.backends {
			if closeErr := b.Close(); closeErr != nil {
				log.Printf("failed to close backend during reset: %v", closeErr)
			}
		}
		for _, kp := range service.keyProviders {
			if closeErr := kp.Close(); closeErr != nil {
				log.Printf("failed to close key provider during reset: %v", closeErr)
			}
		}
		service.backends = nil
		service.keyProviders = nil
		service.mu.Unlock()
	}

	service = nil
	initOnce = sync.Once{}
}

// IsInitialized returns whether the service has been initialized
func IsInitialized() bool {
	initMu.RLock()
	defer initMu.RUnlock()
	return service != nil
}

// UnregisterBackend removes a backend from the service. This is used when
// a backend needs to be replaced (e.g., after a PKCS#11 token reconnection).
func UnregisterBackend(name string) {
	if !IsInitialized() {
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	delete(service.backends, name)
}

func GetBackend(name string) (Backend, error) {
	// Validate backend name to prevent injection attacks
	if err := validation.ValidateBackendName(name); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	b, ok := service.backends[name]
	if !ok {
		return nil, &ErrBackendLookup{
			Sentinel: ErrBackendNotFound,
			Name:     validation.SanitizeForLog(name),
		}
	}

	return b, nil
}

// DefaultBackend returns the default backend
func DefaultBackend() (Backend, error) {
	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	if service.defaultBackend == "" {
		return nil, ErrNoDefaultBackend
	}

	b, ok := service.backends[service.defaultBackend]
	if !ok {
		return nil, &ErrBackendLookup{
			Sentinel: ErrBackendNotFound,
			Name:     service.defaultBackend,
		}
	}

	return b, nil
}

// BackendFor returns the appropriate backend for the given key attributes.
// If Backend is specified in attrs, returns that backend by its registry
// name. Otherwise returns the default backend.
// This centralizes backend resolution logic to avoid scattered conditionals.
func BackendFor(attrs *types.KeyAttributes) (Backend, error) {
	if attrs == nil {
		return DefaultBackend()
	}

	// Validate tenant access before resolving backend
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	return resolveBackendFromAttrs(attrs)
}

// resolveBackendFromAttrs resolves the registered Backend that owns attrs,
// keyed by name -- the model go-xkms#312 settled on: the registry has
// always been service.backends[name], and StoreType is a label the resolved
// backend reports, not a second name for the same map.
//
// attrs.Backend, when set, names the registered backend directly. Every
// producer of KeyAttributes that has a name to give it sets this field --
// ParseKeyIDToAttributes from the Key ID string's backend segment, the
// Simplified API's ListKeys from the registry name it listed under (see
// stampBackendName) -- so there is no supported path left that carries a
// backend selection only in StoreType. Attributes with no Backend resolve
// to DefaultBackend, exactly as attributes with neither field set always
// have.
func resolveBackendFromAttrs(attrs *types.KeyAttributes) (Backend, error) {
	if attrs == nil {
		return DefaultBackend()
	}

	if attrs.Backend != "" {
		return GetBackend(attrs.Backend)
	}

	return DefaultBackend()
}

// ParseCertificateID parses a certificate ID string into KeyAttributes.
// This uses the unified 4-part Key ID format: backend:type:algo:keyname
// All segments except keyname are optional.
//
// Examples:
//   - "my-key" - shorthand for just keyname (uses defaults)
//   - ":::my-key" - explicit form of above
//   - "pkcs11:::my-key" - specify backend only
//   - "pkcs11:signing:ecdsa-p256:my-key" - full specification
func ParseCertificateID(kid string) (*types.KeyAttributes, error) {
	return ParseKeyIDToAttributes(kid)
}

// RegisterServiceBackend dynamically adds a backend to the running xkms service.
// This allows backends discovered after startup (e.g., PKCS#11 tokens
// connected via the admin area) to participate in key operations and PIV.
func RegisterServiceBackend(name string, backend Backend) error {
	if !IsInitialized() {
		return ErrNotInitialized
	}
	if err := validation.ValidateBackendName(name); err != nil {
		return &ErrBackendNameValidation{Err: err}
	}

	service.mu.Lock()
	defer service.mu.Unlock()

	service.backends[name] = backend
	return nil
}

// Backends returns the names of all registered backends
func Backends() []string {
	if !IsInitialized() {
		return nil
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	backends := make([]string, 0, len(service.backends))
	for name := range service.backends {
		backends = append(backends, name)
	}

	return backends
}

// KeyProviders returns the names of all registered key providers.
// Key providers are partial implementations (key generation + limited ops)
// that are composed into full-service backends.
func KeyProviders() []string {
	if !IsInitialized() {
		return nil
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	providers := make([]string, 0, len(service.keyProviders))
	for name := range service.keyProviders {
		providers = append(providers, name)
	}

	return providers
}

// GetKeyProvider returns a specific key provider by name.
func GetKeyProvider(name string) (Backend, error) {
	if err := validation.ValidateBackendName(name); err != nil {
		return nil, &ErrKeyProviderNameValidation{Err: err}
	}

	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	kp, ok := service.keyProviders[name]
	if !ok {
		return nil, &ErrBackendLookup{
			Sentinel: ErrKeyProviderNotFound,
			Name:     validation.SanitizeForLog(name),
		}
	}

	return kp, nil
}

// getBackendForKID determines which backend to use for a given key ID (kid).
// It parses the 4-part kid format (backend:type:algo:keyname) and returns the
// appropriate backend along with the parsed KeyAttributes.
//
// The kid format supports optional segments:
//   - "my-key" - shorthand for just keyname (uses default backend)
//   - ":::my-key" - explicit form of above
//   - "pkcs11:::my-key" - specify backend only
//   - "pkcs11:signing:ecdsa-p256:my-key" - full specification
func getBackendForKID(kid string) (Backend, *types.KeyAttributes, error) {
	if !IsInitialized() {
		return nil, nil, ErrNotInitialized
	}

	attrs, err := ParseKeyIDToAttributes(kid)
	if err != nil {
		return nil, nil, err
	}

	b, err := resolveBackendFromAttrs(attrs)
	if err != nil {
		return nil, nil, err
	}

	return b, attrs, nil
}

// loadStoredKeyAttrs resolves cn's PERSISTED key attributes from b's own
// record, rather than the ones ParseKeyIDToAttributes reconstructs from a kid
// string alone.
//
// The kid format "backend:type:algo:keyname" cannot encode Exportable -- or
// any other field the identifier does not carry -- so a caller that only
// parsed the kid always got the zero value for those fields back. That is
// why ExportKey by kid could never succeed even for a key created with
// Exportable: true, and why RotateKey by kid silently downgraded a rotated
// key to Exportable: false regardless of what the original key had (#925).
//
// It reuses findKeyAttrs (servicer_helpers.go), the servicer's CN lookup
// over ListKeys, and translates its miss to backend.ErrKeyNotFound, the
// not-found sentinel every other Simplified API function in this file
// surfaces for an unknown kid.
func loadStoredKeyAttrs(ctx context.Context, b Backend, cn string) (*types.KeyAttributes, error) {
	attrs, err := findKeyAttrs(ctx, b, cn)
	if errors.Is(err, ErrKeyNotFound) {
		return nil, backend.ErrKeyNotFound
	}
	return attrs, err
}

// Simplified API - applications use these functions directly

// stampKeyOrigin sets the key's provenance from the code path that is running,
// discarding whatever the caller supplied.
//
// This is the same rule PKCS#11 applies to CKA_LOCAL: provenance is recorded
// by the system, never accepted as input, and a caller's template has the
// token-computed attributes stripped "so a caller cannot forge provenance"
// (pkg/pkcs11/module/object.go). A provenance field a caller can set is worse
// than no field at all, because a verifier would read it as authoritative when
// it is merely asserted.
//
// It mutates attrs in place: every caller here owns the value it passes for
// the duration of the operation, and the stamped value is what reaches the
// backend's persisted record.
func stampKeyOrigin(attrs *types.KeyAttributes, origin types.KeyOrigin) {
	if attrs == nil {
		return
	}
	attrs.KeyOrigin = origin
}

// GenerateKey generates a new key with the given attributes.
// Uses BackendFor(attrs) to resolve the correct backend based on StoreType.
func GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}
	stampKeyOrigin(attrs, types.KeyOriginGenerated)

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	// Route to appropriate generation method based on algorithm
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return b.GenerateRSA(ctx, attrs)
	case x509.ECDSA:
		return b.GenerateECDSA(ctx, attrs)
	case x509.Ed25519:
		return b.GenerateEd25519(ctx, attrs)
	default:
		return nil, &ErrUnsupportedPublicKeyAlgorithm{Algorithm: attrs.KeyAlgorithm}
	}
}

// Key retrieves a key by its attributes.
// Uses BackendFor(attrs) to resolve the correct backend based on StoreType.
func Key(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return b.GetKey(ctx, attrs)
}

// Signer returns a crypto.Signer for the specified key attributes.
// This is the primary method - use SignerByID for string-based lookups.
func Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return b.Signer(ctx, attrs)
}

// Decrypter returns a crypto.Decrypter for the specified key attributes.
// This is the primary method - use DecrypterByID for string-based lookups.
func Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return b.Decrypter(ctx, attrs)
}

// DeleteKey deletes a key by its attributes.
// This is the primary method - use DeleteKeyByID for string-based lookups.
func DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if err := validateTenantAccess(attrs); err != nil {
		return err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return b.DeleteKey(ctx, attrs)
}

// Certificate retrieves a certificate by key attributes.
// This is the primary method - use CertificateByID for string-based lookups.
func Certificate(ctx context.Context, attrs *types.KeyAttributes) (*x509.Certificate, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return b.GetCert(ctx, attrs.CertificateID())
}

// SaveCertificate saves a certificate using key attributes.
// This is the primary method - use SaveCertificateByID for string-based lookups.
func SaveCertificate(ctx context.Context, attrs *types.KeyAttributes, cert *x509.Certificate) error {
	if err := validateTenantAccess(attrs); err != nil {
		return err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return b.SaveCert(ctx, attrs.CertificateID(), cert)
}

// DeleteCertificate deletes a certificate by key attributes.
// This is the primary method - use DeleteCertificateByID for string-based lookups.
func DeleteCertificate(ctx context.Context, attrs *types.KeyAttributes) error {
	if err := validateTenantAccess(attrs); err != nil {
		return err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return b.DeleteCert(ctx, attrs.CertificateID())
}

// CertificateChain retrieves a certificate chain by key attributes.
// This is the primary method - use CertificateChainByID for string-based lookups.
func CertificateChain(ctx context.Context, attrs *types.KeyAttributes) ([]*x509.Certificate, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return b.GetCertChain(ctx, attrs.CertificateID())
}

// SaveCertificateChain saves a certificate chain using key attributes.
// This is the primary method - use SaveCertificateChainByID for string-based lookups.
func SaveCertificateChain(ctx context.Context, attrs *types.KeyAttributes, chain []*x509.Certificate) error {
	if err := validateTenantAccess(attrs); err != nil {
		return err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return b.SaveCertChain(ctx, attrs.CertificateID(), chain)
}

// CertificateExists checks if a certificate exists for the given key attributes.
// This is the primary method - use CertificateExistsByID for string-based lookups.
func CertificateExists(ctx context.Context, attrs *types.KeyAttributes) (bool, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return false, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return false, err
	}

	return b.CertExists(ctx, attrs.CertificateID())
}

// TLSCertificate returns a complete tls.Certificate for the given key attributes.
// This is the primary method - use TLSCertificateByID for string-based lookups.
func TLSCertificate(ctx context.Context, attrs *types.KeyAttributes) (tls.Certificate, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return tls.Certificate{}, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return tls.Certificate{}, err
	}

	return b.GetTLSCertificate(ctx, attrs.CertificateID(), attrs)
}

// ========================================================================
// Secondary API - String-based lookups (use primary KeyAttributes methods when possible)
// ========================================================================

// KeyByID retrieves a key by its key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Key(attrs) for type-safe lookups.
func KeyByID(ctx context.Context, kid string) (crypto.PrivateKey, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.GetKeyByID(ctx, kid)
}

// SignerByID returns a signer for the specified key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Signer(attrs) for type-safe lookups.
func SignerByID(ctx context.Context, kid string) (crypto.Signer, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.GetSignerByID(ctx, kid)
}

// DecrypterByID returns a decrypter for the specified key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Decrypter(attrs) for type-safe lookups.
func DecrypterByID(ctx context.Context, kid string) (crypto.Decrypter, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.GetDecrypterByID(ctx, kid)
}

// DeleteKeyByID deletes a key by its key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer DeleteKey(attrs) for type-safe lookups.
func DeleteKeyByID(ctx context.Context, kid string) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return err
	}

	return b.DeleteKey(ctx, attrs)
}

// ListKeys lists all keys across all backends or from a specific backend
func ListKeys(ctx context.Context, backendName ...string) ([]*types.KeyAttributes, error) {
	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	// Validate backend name if provided
	if len(backendName) > 0 && backendName[0] != "" {
		if err := validation.ValidateBackendName(backendName[0]); err != nil {
			return nil, &ErrBackendNameValidation{Err: err}
		}
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	var allKeys []*types.KeyAttributes

	if len(backendName) > 0 && backendName[0] != "" {
		// List from specific backend
		b, ok := service.backends[backendName[0]]
		if !ok {
			return nil, &ErrBackendLookup{
				Sentinel: ErrBackendNotFound,
				Name:     validation.SanitizeForLog(backendName[0]),
			}
		}

		keys, err := b.ListKeys(ctx)
		if err != nil {
			return nil, err
		}
		stampBackendName(keys, backendName[0])
		return keys, nil
	}

	// List from all backends
	for name, b := range service.backends {
		keys, err := b.ListKeys(ctx)
		if err != nil {
			// Log error but continue with other backends
			continue
		}
		stampBackendName(keys, name)
		allKeys = append(allKeys, keys...)
	}

	return allKeys, nil
}

// stampBackendName sets attrs.Backend to name on every listed key.
//
// A backend's own ListKeys cannot know its registered name -- that mapping
// lives only in service.backends, one layer up -- so a key read back via
// ListKeys otherwise carries no Backend at all (go-xkms#312). This is the
// one place in the Simplified API that knows both the keys and the name
// they were listed under, and every caller that lists keys and then passes
// one to Key/Signer/Decrypter/DeleteKey (as the PIV slot lookups do) depends
// on the attributes it hands back resolving to the same backend the listing
// came from.
func stampBackendName(keys []*types.KeyAttributes, name string) {
	for _, k := range keys {
		if k != nil {
			k.Backend = name
		}
	}
}

// SaveCertificateByID saves a certificate by key ID.
// Format: "backend:key-id" or just "key-id" (uses default backend).
// Prefer SaveCertificate(attrs, cert) for type-safe lookups.
func SaveCertificateByID(ctx context.Context, kid string, cert *x509.Certificate) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return err
	}

	return b.SaveCert(ctx, kid, cert)
}

// CertificateByID retrieves a certificate by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Certificate(attrs) for type-safe lookups.
func CertificateByID(ctx context.Context, kid string) (*x509.Certificate, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.GetCert(ctx, kid)
}

// DeleteCertificateByID deletes a certificate by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer DeleteCertificate(attrs) for type-safe lookups.
func DeleteCertificateByID(ctx context.Context, kid string) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return err
	}

	return b.DeleteCert(ctx, kid)
}

// ListCertificates lists all certificate IDs across all backends or from a specific backend
func ListCertificates(ctx context.Context, backendName ...string) ([]string, error) {
	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	// Validate backend name if provided
	if len(backendName) > 0 && backendName[0] != "" {
		if err := validation.ValidateBackendName(backendName[0]); err != nil {
			return nil, &ErrBackendNameValidation{Err: err}
		}
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	var allCerts []string

	if len(backendName) > 0 && backendName[0] != "" {
		// List from specific backend
		b, ok := service.backends[backendName[0]]
		if !ok {
			return nil, &ErrBackendLookup{
				Sentinel: ErrBackendNotFound,
				Name:     validation.SanitizeForLog(backendName[0]),
			}
		}

		return b.ListCerts(ctx)
	}

	// List from all backends
	for _, b := range service.backends {
		certs, err := b.ListCerts(ctx)
		if err != nil {
			// Log error but continue with other backends
			continue
		}
		allCerts = append(allCerts, certs...)
	}

	return allCerts, nil
}

// Close closes all backends (called at application shutdown)
func Close() error {
	if !IsInitialized() {
		return nil
	}

	service.mu.Lock()
	defer service.mu.Unlock()

	var errs []error
	for name, b := range service.backends {
		if err := b.Close(); err != nil {
			errs = append(errs, &ErrBackendCloseItem{Backend: name, Err: err})
		}
	}

	if len(errs) > 0 {
		return &ErrBackendClose{Errs: errs}
	}

	return nil
}

// ========================================================================
// Sealing Operations
// ========================================================================

// Seal encrypts/protects data using the specified backend's sealing mechanism.
// The backendName parameter specifies which backend to use for sealing.
// If backendName is empty, the default backend is used.
//
// Different backends provide different security guarantees:
//   - TPM2: PCR-bound hardware sealing (strongest)
//   - PKCS#11: HSM-backed AES-GCM encryption
//   - AWS/Azure/GCP KMS: Cloud-managed envelope encryption
//   - PKCS#8: Software-based HKDF + AES-GCM (portable but weaker)
//
// Example:
//
//	// Seal with default backend
//	sealed, err := xkms.Seal(ctx, secretData, &types.SealOptions{
//	    KeyAttributes: keyAttrs,
//	})
//
//	// Seal with specific backend
//	sealed, err := xkms.SealWithBackend(ctx, "tpm2", secretData, opts)
func Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	b, err := DefaultBackend()
	if err != nil {
		return nil, err
	}

	return b.Seal(ctx, data, opts)
}

// SealWithBackend seals data using a specific backend.
// This is useful when you need to seal with a non-default backend.
func SealWithBackend(ctx context.Context, backendName string, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	// Validate backend name to prevent injection attacks
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	return b.Seal(ctx, data, opts)
}

// Unseal decrypts/recovers data that was previously sealed.
// The sealed data's backend type determines which backend is used for unsealing.
// The backendName is optional; if provided it must match the sealed data's backend.
//
// Example:
//
//	// Unseal - backend is determined from sealed data
//	plaintext, err := xkms.Unseal(ctx, sealed, &types.UnsealOptions{
//	    KeyAttributes: keyAttrs,
//	})
func Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, ErrInvalidSealedData
	}

	// Find the backend that matches the sealed data's backend type
	service.mu.RLock()
	defer service.mu.RUnlock()

	for _, b := range service.backends {
		if b.KeyProvider().Type() == sealed.Backend {
			return b.Unseal(ctx, sealed, opts)
		}
	}

	return nil, &ErrUnsealBackendNotFound{BackendType: sealed.Backend}
}

// UnsealWithBackend unseals data using a specific backend.
// The backend must match the sealed data's backend type.
func UnsealWithBackend(ctx context.Context, backendName string, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	// Validate backend name to prevent injection attacks
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	return b.Unseal(ctx, sealed, opts)
}

// CanSeal returns true if the specified backend supports sealing operations.
// If backendName is empty, checks the default backend.
func CanSeal(backendName ...string) bool {
	var b Backend
	var err error

	if len(backendName) > 0 && backendName[0] != "" {
		b, err = GetBackend(backendName[0])
	} else {
		b, err = DefaultBackend()
	}

	if err != nil {
		return false
	}

	return b.CanSeal()
}

// ========================================================================
// Backend Information
// ========================================================================

// BackendInfo contains information about a backend.
type BackendInfo struct {
	// ID is the backend's unique identifier/name
	ID string

	// Type is the backend type (e.g., "pkcs8", "pkcs11", "tpm2", etc.)
	Type types.BackendType

	// HardwareBacked indicates if keys are stored in hardware
	HardwareBacked bool

	// Capabilities describes what features the backend supports
	Capabilities types.Capabilities
}

// GetBackendInfo returns information about a specific backend.
func GetBackendInfo(name string) (*BackendInfo, error) {
	if err := validation.ValidateBackendName(name); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(name)
	if err != nil {
		return nil, err
	}

	kp := b.KeyProvider()
	caps := kp.Capabilities()

	return &BackendInfo{
		ID:             name,
		Type:           kp.Type(),
		HardwareBacked: caps.HardwareBacked,
		Capabilities:   caps,
	}, nil
}

// GetBackendCapabilities returns the capabilities of a specific backend.
func GetBackendCapabilities(name string) (types.Capabilities, error) {
	if err := validation.ValidateBackendName(name); err != nil {
		return types.Capabilities{}, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(name)
	if err != nil {
		return types.Capabilities{}, err
	}

	return b.KeyProvider().Capabilities(), nil
}

// ========================================================================
// Extended Key Operations
// ========================================================================

// GenerateKeyWithBackend generates a new key on a specific backend.
func GenerateKeyWithBackend(ctx context.Context, backendName string, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}
	stampKeyOrigin(attrs, types.KeyOriginGenerated)

	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return b.GenerateRSA(ctx, attrs)
	case x509.ECDSA:
		return b.GenerateECDSA(ctx, attrs)
	case x509.Ed25519:
		return b.GenerateEd25519(ctx, attrs)
	default:
		return nil, &ErrUnsupportedPublicKeyAlgorithm{Algorithm: attrs.KeyAlgorithm}
	}
}

// RotateKey creates the next version of the key a kid names and makes it
// current, exactly as XKMSService.RotateKey does: the new version is a new
// backend key "<keyname>--v<n>" with the key's algorithm and attributes, and
// every earlier version is kept. It returns the new version's private key
// (nil for a symmetric key, whose material is not handed out).
//
// The kid format is "backend:type:algo:keyname" with optional segments, or
// just "keyname" (uses defaults). The key is resolved on the unscoped backend,
// as every kid operation is. It needs the key-version store; without one it
// returns ErrKeyVersionsNotConfigured.
func RotateKey(ctx context.Context, kid string) (crypto.PrivateKey, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	svc, err := Get()
	if err != nil {
		return nil, err
	}
	backendName := attrs.Backend
	if backendName == "" {
		backendName = svc.defaultBackendName()
	}

	rotated, err := svc.rotateKey(ctx, b, backendName, attrs.CN)
	if errors.Is(err, ErrKeyNotFound) {
		// A kid operation reports a missing key as the backend sentinel,
		// as loadStoredKeyAttrs does.
		return nil, backend.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return rotated.key, nil
}

// ========================================================================
// Signing and Verification
// ========================================================================

// SignOptions contains options for signing operations.
type SignOptions struct {
	// Hash is the hash algorithm to use (default: SHA256)
	Hash crypto.Hash

	// PSSOptions for RSA-PSS signatures (optional)
	PSSOptions *rsa.PSSOptions

	// BlobCN, when set, persists the produced digest and signature through
	// the backend's SignerStore, keyed by the signing key's CN and this blob
	// CN. A later Verify call against the same key with the same
	// VerifyOpts.BlobCN and VerifyOpts.IntegrityCheck set confirms the
	// digest presented for verification against this persisted record.
	BlobCN string
}

// Sign signs data using the specified key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func Sign(ctx context.Context, kid string, data []byte, opts *SignOptions) ([]byte, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	signer, err := b.Signer(ctx, attrs)
	if err != nil {
		return nil, &ErrCryptoOperation{Operation: "signer", Err: err}
	}

	if opts == nil {
		opts = &SignOptions{}
	}

	var digest, signature []byte

	// Ed25519 uses pure signing (no prehashing) by default. The signer
	// expects the raw message and crypto.Hash(0) as SignerOpts; the digest
	// persisted for BlobCN is the raw message itself in this case, matching
	// how signing.SignerOpts.GetDigest treats a zero Hash.
	if attrs.KeyAlgorithm == x509.Ed25519 {
		digest = data
		signature, err = signer.Sign(nil, data, crypto.Hash(0))
	} else {
		if opts.Hash == 0 {
			opts.Hash = crypto.SHA256
		}

		hasher := opts.Hash.New()
		hasher.Write(data)
		digest = hasher.Sum(nil)

		var signerOpts crypto.SignerOpts = opts.Hash
		if opts.PSSOptions != nil {
			signerOpts = opts.PSSOptions
		}

		signature, err = signer.Sign(nil, digest, signerOpts)
	}
	if err != nil {
		return nil, err
	}

	if opts.BlobCN != "" {
		if saveErr := b.SignerStore().SaveSignature(&store.SignerOpts{KeyAttributes: attrs, BlobCN: opts.BlobCN}, signature, digest); saveErr != nil {
			return nil, saveErr
		}
	}

	return signature, nil
}

// Verify verifies a signature against data using the specified key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func Verify(ctx context.Context, kid string, data, signature []byte, opts *types.VerifyOpts) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return err
	}

	privKey, err := b.GetKey(ctx, attrs)
	if err != nil {
		return &ErrKeyOperation{Operation: "get key", Err: err}
	}

	var pubKey crypto.PublicKey
	if signer, ok := privKey.(crypto.Signer); ok {
		pubKey = signer.Public()
	} else {
		return ErrKeySigningNotSupported
	}

	if opts == nil {
		opts = &types.VerifyOpts{Hash: crypto.SHA256}
	}
	if opts.IntegrityCheck {
		// The store's Checksum keys its lookup by KeyAttributes.CN; the
		// caller names the key through kid, not through opts, so attrs
		// resolved from kid fills this in when the caller left it unset.
		if opts.KeyAttributes == nil {
			opts.KeyAttributes = attrs
		}
		if opts.ChecksumProvider == nil {
			opts.ChecksumProvider = b.SignerStore()
		}
	}

	// Ed25519 uses pure verification (no prehashing) by default. Verify
	// against the raw message, not a hash. A local copy carries BlobCN,
	// IntegrityCheck and ChecksumProvider through without mutating the
	// caller's opts.
	if attrs.KeyAlgorithm == x509.Ed25519 {
		edOpts := *opts
		edOpts.Hash = crypto.Hash(0)
		verifier := types.NewVerifier(&edOpts)
		return verifier.Verify(pubKey, data, signature)
	}

	if opts.Hash == 0 {
		opts.Hash = crypto.SHA256
	}

	hasher := opts.Hash.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	verifier := types.NewVerifier(opts)
	return verifier.Verify(pubKey, digest, signature)
}

// ========================================================================
// Symmetric Encryption/Decryption
// ========================================================================

// Encrypt encrypts data using a symmetric key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func Encrypt(ctx context.Context, kid string, data []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported}
	}

	encrypter, err := symBackend.SymmetricEncrypter(ctx, attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "failed to get symmetric encrypter", Err: err}
	}

	return encrypter.Encrypt(data, opts)
}

// Decrypt decrypts data using a symmetric key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func Decrypt(ctx context.Context, kid string, data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported}
	}

	encrypter, err := symBackend.SymmetricEncrypter(ctx, attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrDecryptionFailed, Detail: "failed to get symmetric encrypter", Err: err}
	}

	return encrypter.Decrypt(data, opts)
}

// ========================================================================
// Certificate Chain Operations (String-based - prefer KeyAttributes versions)
// ========================================================================

// SaveCertificateChainByID saves a certificate chain by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer SaveCertificateChain(attrs, chain) for type-safe lookups.
func SaveCertificateChainByID(ctx context.Context, kid string, chain []*x509.Certificate) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return err
	}

	return b.SaveCertChain(ctx, kid, chain)
}

// CertificateChainByID retrieves a certificate chain by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer CertificateChain(attrs) for type-safe lookups.
func CertificateChainByID(ctx context.Context, kid string) ([]*x509.Certificate, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.GetCertChain(ctx, kid)
}

// CertificateExistsByID checks if a certificate exists for the given key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer CertificateExists(attrs) for type-safe lookups.
func CertificateExistsByID(ctx context.Context, kid string) (bool, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return false, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return false, err
	}

	return b.CertExists(ctx, kid)
}

// ========================================================================
// TLS Operations (String-based - prefer KeyAttributes versions)
// ========================================================================

// TLSCertificateByID returns a complete tls.Certificate by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer TLSCertificate(attrs) for type-safe lookups.
func TLSCertificateByID(ctx context.Context, kid string) (tls.Certificate, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return tls.Certificate{}, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return tls.Certificate{}, err
	}

	return b.GetTLSCertificate(ctx, kid, attrs)
}

// ========================================================================
// Import/Export Operations
// ========================================================================

// GetImportParameters retrieves parameters needed to import a key into a backend.
func GetImportParameters(ctx context.Context, backendName string, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	importer, ok := importBackendFor(b)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Backend:  backendName,
			Detail:   "does not support import operations",
		}
	}

	return importer.GetImportParameters(ctx, attrs, algorithm)
}

// WrapKey wraps key material for secure transport using the specified parameters.
func WrapKey(ctx context.Context, backendName string, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	importer, ok := importBackendFor(b)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Backend:  backendName,
			Detail:   "does not support import operations",
		}
	}

	return importer.WrapKey(ctx, keyMaterial, params)
}

// UnwrapKey unwraps key material that was previously wrapped.
func UnwrapKey(ctx context.Context, backendName string, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	importer, ok := importBackendFor(b)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Backend:  backendName,
			Detail:   "does not support import operations",
		}
	}

	return importer.UnwrapKey(ctx, wrapped, params)
}

// WrapKeyByID wraps a server-side target key with a server-side wrapping key,
// both identified by key ID and backend, delegating to the initialized
// XKMSService singleton. See XKMSService.WrapKeyByID (servicer_key.go) for
// the operation itself; this is the process-singleton entry point used by
// in-process callers such as the embedded PKCS#11 transport.
func WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	s, err := Get()
	if err != nil {
		return nil, err
	}

	return s.WrapKeyByID(ctx, req)
}

// UnwrapKeyByID unwraps key material with a server-side unwrapping key and
// imports the result as a new key, delegating to the initialized XKMSService
// singleton. See XKMSService.UnwrapKeyByID (servicer_key.go) for the
// operation itself; this is the process-singleton entry point used by
// in-process callers such as the embedded PKCS#11 transport.
func UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	s, err := Get()
	if err != nil {
		return nil, err
	}

	return s.UnwrapKeyByID(ctx, req)
}

// ImportKey imports externally generated key material into a backend.
func ImportKey(ctx context.Context, backendName string, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if err := validateTenantAccess(attrs); err != nil {
		return err
	}
	// Whatever the caller claimed, this is the import path.
	stampKeyOrigin(attrs, types.KeyOriginImported)

	if err := validation.ValidateBackendName(backendName); err != nil {
		return &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return err
	}

	importer, ok := importBackendFor(b)
	if !ok {
		return &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Backend:  backendName,
			Detail:   "does not support import operations",
		}
	}

	return importer.ImportKey(ctx, attrs, wrapped)
}

// ExportKey exports a key in wrapped form for secure transport.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func ExportKey(ctx context.Context, kid string, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	exporter, ok := exportBackendFor(b)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Detail:   "does not support export operations",
		}
	}

	// attrs is reconstructed purely from the kid string, so its Exportable is
	// always the zero value; the backend's ExportKey refuses on exactly that
	// field. Load the stored record so a key generated with Exportable: true
	// exports (#925).
	storedAttrs, err := loadStoredKeyAttrs(ctx, b, attrs.CN)
	if err != nil {
		return nil, err
	}

	return exporter.ExportKey(ctx, storedAttrs, algorithm)
}

// ========================================================================
// Cross-Backend Operations
// ========================================================================

// CopyKey copies a key from one backend to another.
// The sourceKID format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func CopyKey(ctx context.Context, sourceKID string, destBackend string, destAttrs *types.KeyAttributes) error {
	if err := validation.ValidateKeyReference(sourceKID); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	if err := validateTenantAccess(destAttrs); err != nil {
		return err
	}

	if err := validation.ValidateBackendName(destBackend); err != nil {
		return &ErrBackendNameValidation{Err: err}
	}

	sourceB, sourceAttrs, err := getBackendForKID(sourceKID)
	if err != nil {
		return &ErrCopyKeyBackend{Role: "source", Err: err}
	}

	// sourceAttrs is reconstructed purely from sourceKID, so its Exportable is
	// always the zero value; ExportKeyTo below refuses on exactly that field.
	// Load the source backend's own record so a key generated with
	// Exportable: true copies (#925).
	sourceAttrs, err = loadStoredKeyAttrs(ctx, sourceB, sourceAttrs.CN)
	if err != nil {
		return &ErrCopyKeyBackend{Role: "source", Err: err}
	}

	destB, err := GetBackend(destBackend)
	if err != nil {
		return &ErrCopyKeyBackend{Role: "destination", Err: err}
	}

	sourceExporter, ok := exportBackendFor(sourceB)
	if !ok {
		return &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Detail:   "source backend does not support export operations",
		}
	}

	destImporter, ok := importBackendFor(destB)
	if !ok {
		return &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Detail:   "destination backend does not support import operations",
		}
	}

	if destAttrs == nil {
		destAttrs = sourceAttrs
	}

	algorithm := backend.WrappingAlgorithmRSAES_OAEP_SHA_256
	importParams, err := destImporter.GetImportParameters(ctx, destAttrs, algorithm)
	if err != nil {
		return &ErrImportExportOperation{Operation: "get import parameters", Err: err}
	}

	// The material is wrapped for the DESTINATION's own import parameters via
	// ExportKeyTo, never for a wrapping key the source mints and tracks for
	// itself. Overwriting a plain ExportKey's ImportToken field with the
	// destination's token (this function's own former behaviour) pointed
	// ImportKey at a wrapping key the material was never wrapped under: the
	// token named the destination's key, but the ciphertext was still
	// encrypted under the source's self-minted one, so the destination's
	// unwrap failed for every backend that honours its tokens (go-xkms#154).
	wrappedKey, err := sourceExporter.ExportKeyTo(ctx, sourceAttrs, importParams)
	if err != nil {
		return &ErrImportExportOperation{Operation: "export key", Err: err}
	}

	return destImporter.ImportKey(ctx, destAttrs, wrappedKey)
}

// ========================================================================
// Symmetric Key Operations
// ========================================================================

// GenerateSymmetricKey generates a new symmetric key.
func GenerateSymmetricKey(ctx context.Context, backendName string, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrSymmetricNotSupported,
			Backend:  backendName,
		}
	}

	return symBackend.GenerateSymmetricKey(ctx, attrs)
}

// GetSymmetricKey retrieves an existing symmetric key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func GetSymmetricKey(ctx context.Context, kid string) (types.SymmetricKey, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported}
	}

	return symBackend.GetSymmetricKey(ctx, attrs)
}
