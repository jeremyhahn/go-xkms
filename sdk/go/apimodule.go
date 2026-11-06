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
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/apimodule"
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// go-xkms's qrdb ServiceModule surface, re-exported so downstream hosts
// (go-quicbaas, go-trusted-platform) that embed a qrdb node can register the
// xkms hardware crypto + identity plane via qrdbsdk.WithModule without
// importing go-xkms/pkg. The stack-wide convention is one module per provider
// project, named after the project; xkms's registers as ModuleName ("xkms").

// ServiceModuleName is the unique name xkms's module registers under.
const ServiceModuleName = apimodule.ModuleName

// ServiceModule is go-xkms's hardware crypto + identity plane as a qrdb
// ServiceModule.
type ServiceModule = apimodule.Module

// ServiceModuleOption configures optional ServiceModule behavior at
// construction time.
type ServiceModuleOption = apimodule.Option

// ServiceModuleResolver returns the composed *XKMSService, or nil while the
// host is still composing it; the module binds lazily on the first RPC.
type ServiceModuleResolver = apimodule.ServiceResolver

// ServiceModuleSSHResolver returns the SSH SDK client for the module's SSH
// RPCs, or nil when the SSH subsystem is unavailable.
type ServiceModuleSSHResolver = apimodule.SSHClientResolver

// NewServiceModule builds go-xkms's ServiceModule around the XKMSService
// resolver. A nil resolver is a composition error and fails construction.
var NewServiceModule = apimodule.NewModule

// WithServiceModuleSSHClient wires the SSH SDK client resolver used by the
// module's SSH RPC handlers.
var WithServiceModuleSSHClient = apimodule.WithSSHClient

// ---------------------------------------------------------------------------
// Host self-build surface
//
// A host that composes the module via NewServiceModule with only a
// ServiceModuleResolver (no WithServiceModuleRESTServer -- there is no SDK
// re-export for that hook, and none is needed) gets NO REST/HTTP surface
// registered for free: the module used to return immediately from
// RegisterHTTP with nothing wired. The module now self-builds a
// non-listening REST surface (pkg/api/rest NewHostServer) around the
// resolved XKMSService whenever no WithServiceModuleRESTServer resolver is
// configured. These options feed that self-build path; absent all of them
// the module still registers its full route table (so a host's routes are
// never silently missing), just with the login-plane route families
// disabled exactly as when a resolver-supplied server has no qrdb client.
// ---------------------------------------------------------------------------

// ServiceModuleQRDBClientResolver returns the host's embedded/dialed qrdb
// node client, or nil while it is not yet available. It backs the module's
// self-built REST surface: WebAuthn user/credential persistence,
// refresh-token storage, and the mTLS/PIV login identity plane all resolve
// through it.
type ServiceModuleQRDBClientResolver = apimodule.QRDBClientResolver

// WithServiceModuleQRDBClient wires the host's qrdb client resolver.
// Absent one, the module's self-built REST surface still serves the
// crypto-operation surface (keys, certs, seal, ...) from the resolved
// XKMSService, but the WebAuthn and mTLS/PIV login route families stay
// disabled.
var WithServiceModuleQRDBClient = apimodule.WithQRDBClient

// WithServiceModuleServiceContext wires the host's service-context binder:
// every call the module's storage makes into the host's qrdb node --
// database initialisation and each later DAO call -- runs on the context it
// derives. Pass an embedded node's Node.ServiceContext; a node that enforces
// authentication refuses the module's storage without it.
var WithServiceModuleServiceContext = apimodule.WithServiceContext

// ServiceModuleWebAuthnConfig is the operator-facing WebAuthn configuration
// shape (rp_id, rp_origins, rp_display_name, ...) -- the same section
// xkmsd's own config file uses. Distinct from WebAuthnConfig (this SDK's
// alias for the lower-level pkg/webauthn relying-party Config), which is
// what this type converts into internally.
type ServiceModuleWebAuthnConfig = config.WebAuthnConfig

// WithServiceModuleWebAuthn enables the module's self-built WebAuthn
// relying-party surface. Requires WithServiceModuleQRDBClient; without one
// the WebAuthn routes stay unmounted.
var WithServiceModuleWebAuthn = apimodule.WithWebAuthnConfig

// ServiceModuleWebAuthnCredentialStoreDecorator wraps the qrdb-backed
// WebAuthn credential store the module's self-built relying party persists
// passkeys through. A composer uses it to attach its own registration side
// effects — an identity-plane auth factor, an audit record — to credentials
// enrolled through the module's own ceremony routes, so that surface agrees
// with the composer's own. The returned store must honour the wrapped
// store's persistence semantics and must not be nil.
type ServiceModuleWebAuthnCredentialStoreDecorator = rest.WebAuthnCredentialStoreDecorator

// WithServiceModulePasswordVaultRelyingParty sets the WebAuthn relying party
// ID (the host console's domain) password-vault passkeys are created for;
// unset, the module uses WithServiceModuleWebAuthn's.
var WithServiceModulePasswordVaultRelyingParty = apimodule.WithPasswordVaultRelyingParty

// WithServiceModuleWebAuthnCredentialStoreDecorator wraps the module's
// self-built WebAuthn credential store. Requires
// WithServiceModuleWebAuthn and WithServiceModuleQRDBClient; unset leaves
// the qrdb-backed store xkms builds in place unchanged.
var WithServiceModuleWebAuthnCredentialStoreDecorator = apimodule.WithWebAuthnCredentialStoreDecorator

// ServiceModuleSessionOptions tunes the module's self-built JWT signing
// key, token claims/TTLs, the access token typ header (AccessTokenType:
// empty keeps "JWT", "at+jwt" per RFC 9068 §2.1; at+jwt also requires
// ClientID, the RFC 9068 §2.2 client_id claim), and login rate limiting.
// The zero value uses the same defaults xkmsd itself derives.
type ServiceModuleSessionOptions = rest.SessionOptions

// WithServiceModuleSession configures the module's self-built session/JWT
// plane.
var WithServiceModuleSession = apimodule.WithSessionOptions

// ServiceModuleSessionSigningJWK returns the public JWK (RFC 7517) of the
// ES256 key that signs the module's session tokens, given the XKMSService
// the ServiceModuleResolver returns and the ServiceModuleSessionOptions
// passed to WithServiceModuleSession (nil for the defaults). Its Kid is the
// kid every session token's header carries, so a composer publishes it in
// its own JWKS to verify go-xkms logins; the private key stays in the
// backend. The key is read, never generated: call it once the module's REST
// surface is up.
var ServiceModuleSessionSigningJWK = rest.SessionSigningJWK

// ServiceModuleSessionSigningKeyMissingError reports that the session
// signing key is not on the default backend (or there is no default
// backend).
type ServiceModuleSessionSigningKeyMissingError = rest.SessionSigningKeyMissingError

// ServiceModuleSessionSigningKeyExportError reports that the backend cannot
// export the session signing key's public half.
type ServiceModuleSessionSigningKeyExportError = rest.SessionSigningKeyExportError

// ServiceModuleSessionSigningKeyTypeError reports that the session signing
// key is not the ECDSA P-256 key an ES256 JWK describes.
type ServiceModuleSessionSigningKeyTypeError = rest.SessionSigningKeyTypeError

// ErrServiceModuleSessionSigningKeyNoPublicKey is wrapped in a
// ServiceModuleSessionSigningKeyExportError when the backend's signer
// reports no public key.
var ErrServiceModuleSessionSigningKeyNoPublicKey = rest.ErrSessionSigningKeyNoPublicKey

// ServiceModulePIVLoginOptions configures the module's self-built
// TLS-client-certificate login exchange at POST /api/v1/auth/login/piv.
type ServiceModulePIVLoginOptions = rest.PIVLoginOptions

// WithServiceModulePIVLogin enables the module's self-built PIV/mTLS login
// exchange.
var WithServiceModulePIVLogin = apimodule.WithPIVLogin

// ---------------------------------------------------------------------------
// Host composition surface
//
// A self-built module composes xkms's store-backed features -- the Password
// Manager, platform sealed-secret store, backend credential service, SSH,
// Certificate Authority and TPM policies -- from dependencies the host
// supplies, through the same construction path xkmsd uses (pkg/compose).
// Each option below supplies one dependency; a feature whose dependency is
// absent stays off, logged with a typed reason and recorded in
// (*ServiceModule).HostStores().Disabled. Stores persist in the host's qrdb
// KV (WithServiceModuleQRDBClient) under ServiceModuleHostStoragePrefix.
// ---------------------------------------------------------------------------

// ServiceModuleHostStoragePrefix is the qrdb key namespace a self-built
// module persists its stores under in the host's KV.
const ServiceModuleHostStoragePrefix = apimodule.HostStoragePrefix

// ServiceModuleBarrierRegistryResolver returns the host's tenant barrier
// registry (an embedded qrdb node's BarrierRegistry), or nil when the host
// has none.
type ServiceModuleBarrierRegistryResolver = apimodule.BarrierRegistryResolver

// WithServiceModuleBarrierRegistry supplies the host's tenant barrier
// registry: it backs the "barrier" credential strategy and
// WithServiceModuleBarrierRoutes.
var WithServiceModuleBarrierRegistry = apimodule.WithBarrierRegistry

// ServiceModuleTenantStoresResolver returns the host's per-tenant store
// resolver (an embedded qrdb node's Services().StoreResolver), or nil when
// the host has none.
type ServiceModuleTenantStoresResolver = apimodule.TenantStoresResolver

// WithServiceModuleTenantStores supplies the host's per-tenant store
// resolver: each tenant's Password Manager entries live in that tenant's
// system database, behind that tenant's barrier.
var WithServiceModuleTenantStores = apimodule.WithTenantStores

// WithServiceModulePINBackend supplies the host's PIN backend, whose user
// PIN opens a tenant's Password Manager session. It also mounts the
// permission-gated, platform-scoped PIN management routes, /api/v1/pin/*
// (pin:read to verify a PIN or read the lockout, pin:write to set, change or
// reset).
var WithServiceModulePINBackend = apimodule.WithPINBackend

// WithServiceModulePlatformSealer enables the platform sealed-secret store,
// sealing its records through the given Sealer (which must seal with nil
// options, carrying its own key) under the named seal strategy.
var WithServiceModulePlatformSealer = apimodule.WithPlatformSealer

// WithServiceModuleCredentialStrategy selects the backend credential
// service's seal strategy: "manual" (default), "barrier" (needs
// WithServiceModuleBarrierRegistry) or a platform strategy (needs
// WithServiceModulePlatformSealer).
var WithServiceModuleCredentialStrategy = apimodule.WithCredentialStrategy

// WithServiceModuleCA enables the Certificate Authority from a
// TrustedCAMultiIdentityConfig; each CA key lives in the XKMSService
// backend named by its store type.
var WithServiceModuleCA = apimodule.WithCA

// WithServiceModuleVTPM makes vtpm mode available to the TPM policy service
// the module composes over its XKMSService's TPM2 backend (see
// TPMVTPMConfig).
var WithServiceModuleVTPM = apimodule.WithVTPM

// WithAttestedCallerGate builds go-xkms's attested-caller gate from the
// host's AttestedCallerPolicy. The module serves the gate's Challenge/Submit
// verbs and keeps its evidence in the host's datastore (requires
// WithServiceModuleQRDBClient); the host installs
// (*ServiceModule).PeerAttestationGate on its node with go-qrdb's
// node.WithPeerAttestationGate.
var WithAttestedCallerGate = apimodule.WithAttestedCallerGate

// AttestedCallerClientError reports WithAttestedCallerGate configured
// without WithServiceModuleQRDBClient.
type AttestedCallerClientError = apimodule.AttestedCallerClientError

// ServiceModuleHostStores is what a self-built module composed:
// (*ServiceModule).HostStores returns it after the module's first use.
type ServiceModuleHostStores = compose.Stores

// ServiceModuleFeature names a store-backed feature of the module.
type ServiceModuleFeature = compose.Feature

// The store-backed features a self-built module composes.
const (
	ServiceModuleFeaturePasswords       = compose.FeaturePasswords
	ServiceModuleFeatureTenantPasswords = compose.FeatureTenantPasswords
	ServiceModuleFeaturePIN             = compose.FeaturePIN
	ServiceModuleFeaturePlatformStore   = compose.FeaturePlatformStore
	ServiceModuleFeatureCredentials     = compose.FeatureCredentials
	ServiceModuleFeatureSSH             = compose.FeatureSSH
	ServiceModuleFeatureCA              = compose.FeatureCA
	ServiceModuleFeatureTPMPolicies     = compose.FeatureTPMPolicies
	ServiceModuleFeatureOIDCCredentials = compose.FeatureOIDCCredentials
)

// ServiceModuleFeatureDisabledError reports a feature left off because the
// host did not supply a dependency it needs.
type ServiceModuleFeatureDisabledError = compose.FeatureDisabledError

// ServiceModuleFeatureBuildError reports a feature whose construction
// failed with its dependencies present.
type ServiceModuleFeatureBuildError = compose.FeatureBuildError
