// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// This file is the construction path a HOST that merely embeds go-xkms's
// qrdb ServiceModule (pkg/apimodule) uses to get a working REST surface
// without reimplementing xkmsd's own wiring. xkmsd (pkg/server) composes
// the identical login plane -- token issuer, WebAuthn service, session
// authenticator -- from richer, config-file-driven inputs; the functions
// here are the shared primitives both xkmsd and NewHostServer build on, so
// a host's self-built surface mints and verifies session tokens exactly the
// way xkmsd does.
package rest

import (
	"context"
	stdcrypto "crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"log/slog"
	"reflect"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// DefaultJWTSigningKeyCN is the reserved backend key CN that signs session
// tokens when no operator override is configured. It matches xkmsd's own
// default (pkg/server jwt_signing.go) so a host and xkmsd provision the
// identical key when both point at the same backend.
const DefaultJWTSigningKeyCN = "xkms-jwt-signing"

// DefaultWebAuthnTenant is the qrdb tenant scope WebAuthn users and
// credentials persist under when a caller does not specify one.
const DefaultWebAuthnTenant = "system"

// ---------------------------------------------------------------------------
// Token issuer construction
// ---------------------------------------------------------------------------

// RetryFunc customizes how BuildTokenIssuer retries a transient signing-key
// provisioning failure (e.g. a raft-clustered backend still settling its
// leader election). Nil means "try once and return the error." xkmsd passes
// its own cluster-aware retry (pkg/server retryNotLeader); a host with a
// non-clustered backend has no need for one.
type RetryFunc func(ctx context.Context, logger *slog.Logger, what string, op func() error) error

// TokenIssuerParams configures BuildTokenIssuer.
type TokenIssuerParams struct {
	// Backend provisions and signs with the JWT signing key. Required.
	Backend xkms.Backend

	// BackendName identifies Backend for logging and key-attribute scoping.
	BackendName string

	// SigningKeyCN is the reserved key CN. Empty selects
	// DefaultJWTSigningKeyCN.
	SigningKeyCN string

	// IssuerName is the iss claim. Empty selects the token package default.
	IssuerName string

	// Audience is the aud claim. Empty selects the token package default.
	Audience []string

	// AccessTTL is the access token lifetime. Zero selects
	// token.DefaultAccessTTL.
	AccessTTL time.Duration

	// RefreshTTL is the refresh token lifetime. Zero selects
	// token.DefaultRefreshTTL.
	RefreshTTL time.Duration

	// QRDBClient persists refresh-token records on the qrdb identity plane
	// when set; nil falls back to an in-memory store (sessions then end on
	// restart).
	QRDBClient *qrdbsdk.Client

	// Logger receives provisioning diagnostics. Nil selects slog.Default().
	Logger *slog.Logger

	// Retry customizes transient-failure retry. Nil tries once.
	Retry RetryFunc
}

// TokenIssuerBackendError reports a signing-key backend failure (key
// provisioning or signer construction) from BuildTokenIssuer. Callers treat
// it as soft: the session/login surfaces stay unmounted rather than
// aborting startup, mirroring xkmsd's own lenient behavior when a backend
// cannot persist the signing key.
type TokenIssuerBackendError struct {
	Backend string
	Err     error
}

// Error implements the error interface.
func (e *TokenIssuerBackendError) Error() string {
	return "rest: token issuer signing-key backend \"" + e.Backend + "\" failed: " + e.Err.Error()
}

// Unwrap exposes the underlying backend error for errors.As/errors.Is.
func (e *TokenIssuerBackendError) Unwrap() error { return e.Err }

// TokenIssuerConfigError reports a refresh-store or issuer construction
// failure from BuildTokenIssuer -- a configuration or programming error
// distinct from a transient backend problem. Callers typically treat it as
// fatal.
type TokenIssuerConfigError struct {
	Err error
}

// Error implements the error interface.
func (e *TokenIssuerConfigError) Error() string {
	return "rest: token issuer construction failed: " + e.Err.Error()
}

// Unwrap exposes the underlying error for errors.As/errors.Is.
func (e *TokenIssuerConfigError) Unwrap() error { return e.Err }

// BuildTokenIssuer provisions the JWT signing key on p.Backend (generating
// it on first use, reusing it across restarts) and constructs the
// token.Issuer behind every login flow (WebAuthn passkey login, PIV/mTLS
// cert login, and the /api/v1/auth session endpoints). It is the
// construction path shared by xkmsd's own composition (pkg/server
// initializeTokenIssuer) and a host's self-built REST surface
// (NewHostServer), so a host mints and verifies session tokens exactly like
// xkmsd does.
func BuildTokenIssuer(ctx context.Context, p TokenIssuerParams) (*token.Issuer, error) {
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if p.Backend == nil {
		return nil, &TokenIssuerBackendError{Backend: p.BackendName, Err: ErrTokenIssuerBackendRequired}
	}

	cn := p.SigningKeyCN
	if cn == "" {
		cn = DefaultJWTSigningKeyCN
	}

	attrs := &types.KeyAttributes{
		CN:                 cn,
		Backend:            p.BackendName,
		StoreType:          p.Backend.Type(),
		KeyType:            types.KeyTypeSigning,
		KeyAlgorithm:       x509.ECDSA,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Hash:               stdcrypto.SHA256,
		ECCAttributes:      &types.ECCAttributes{Curve: elliptic.P256()},
	}

	// Reuse the key across restarts; generate it on first boot.
	provision := func() error {
		if _, err := p.Backend.GetKey(ctx, attrs); err != nil {
			if _, genErr := p.Backend.GenerateECDSA(ctx, attrs); genErr != nil {
				return genErr
			}
			logger.Info("JWT signing key provisioned", "cn", cn, "backend", p.BackendName)
		}
		return nil
	}
	var err error
	if p.Retry != nil {
		err = p.Retry(ctx, logger, "jwt signing key", provision)
	} else {
		err = provision()
	}
	if err != nil {
		return nil, &TokenIssuerBackendError{Backend: p.BackendName, Err: err}
	}

	signer, err := p.Backend.Signer(ctx, attrs)
	if err != nil {
		return nil, &TokenIssuerBackendError{Backend: p.BackendName, Err: err}
	}

	// Refresh-token records live on the qrdb identity plane when available,
	// falling back to process memory (sessions then end on restart, which
	// is the correct fail-closed behavior without a durable identity plane).
	var refreshStore token.RefreshStore
	if p.QRDBClient != nil {
		qs, storeErr := token.NewQRDBRefreshStore(p.QRDBClient.KV())
		if storeErr != nil {
			return nil, &TokenIssuerConfigError{Err: storeErr}
		}
		refreshStore = qs
	} else {
		refreshStore = token.NewMemoryRefreshStore()
	}

	accessTTL := p.AccessTTL
	if accessTTL <= 0 {
		accessTTL = token.DefaultAccessTTL
	}
	refreshTTL := p.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = token.DefaultRefreshTTL
	}

	issuer, err := token.NewIssuer(&token.Config{
		Signer:        signer,
		KeyAttributes: attrs,
		KeyID:         cn,
		Issuer:        p.IssuerName,
		Audience:      p.Audience,
		AccessTTL:     accessTTL,
		RefreshTTL:    refreshTTL,
		RefreshStore:  refreshStore,
	})
	if err != nil {
		return nil, &TokenIssuerConfigError{Err: err}
	}
	return issuer, nil
}

// ---------------------------------------------------------------------------
// WebAuthn service construction
// ---------------------------------------------------------------------------

// WebAuthnTokenAdapter bridges a token.Issuer into the WebAuthn service: it
// implements webauthn.JWTGenerator and webauthn.TokenPairGenerator, so
// ceremony completion mints real, verifiable access/refresh pairs instead of
// the library's base64 user-ID fallback. Shared by xkmsd's own composition
// (pkg/server) and a host's self-built WebAuthn service
// (BuildWebAuthnService).
type WebAuthnTokenAdapter struct {
	issuer   *token.Issuer
	tenantID string
}

// NewWebAuthnTokenAdapter builds the adapter around issuer, scoping minted
// identities to tenantID (DefaultWebAuthnTenant when empty).
func NewWebAuthnTokenAdapter(issuer *token.Issuer, tenantID string) *WebAuthnTokenAdapter {
	if tenantID == "" {
		tenantID = DefaultWebAuthnTenant
	}
	return &WebAuthnTokenAdapter{issuer: issuer, tenantID: tenantID}
}

// identityFor maps a WebAuthn user onto the auth identity carried in tokens.
// The subject is the base64url user ID -- the same binding the qrdb-backed
// WebAuthn store keys users by.
func (a *WebAuthnTokenAdapter) identityFor(user webauthn.User) *auth.Identity {
	id := &auth.Identity{
		Subject:  base64.RawURLEncoding.EncodeToString(user.WebAuthnID()),
		TenantID: a.tenantID,
		Metadata: map[string]string{
			"username":     user.WebAuthnName(),
			"display_name": user.WebAuthnDisplayName(),
		},
	}
	if email := user.Email(); email != "" {
		id.Metadata["email"] = email
	}
	if roleUser, ok := user.(interface{ GetRole() string }); ok {
		if role := roleUser.GetRole(); role != "" {
			id.Roles = []string{role}
		}
	}
	return id
}

// GenerateToken implements webauthn.JWTGenerator.
func (a *WebAuthnTokenAdapter) GenerateToken(ctx context.Context, user webauthn.User) (string, error) {
	pair, err := a.issuer.Mint(ctx, a.identityFor(user))
	if err != nil {
		return "", err
	}
	return pair.AccessToken, nil
}

// GenerateTokenPair implements webauthn.TokenPairGenerator.
func (a *WebAuthnTokenAdapter) GenerateTokenPair(ctx context.Context, user webauthn.User) (string, string, error) {
	pair, err := a.issuer.Mint(ctx, a.identityFor(user))
	if err != nil {
		return "", "", err
	}
	return pair.AccessToken, pair.RefreshToken, nil
}

// WebAuthnCredentialStoreDecorator wraps the qrdb-backed WebAuthn
// credential store BuildWebAuthnService constructs, so a composer can attach
// its own persistence side effects to the relying party xkms builds instead
// of standing up a second one over the same store.
//
// The motivating case is a composed node (go-quicbaas) whose unified login
// ceremony resolves a qrdb auth factor rather than the credential record:
// a credential enrolled through the xkms module's own registration routes
// has to create that factor too, or the two registration surfaces disagree
// about what a registered passkey is.
//
// Contract: the returned store MUST persist and read back credentials with
// the same semantics as the store it wraps, and MUST NOT be nil (a nil
// return fails construction with ErrWebAuthnCredentialStoreDecoratorNil).
// It is a persistence seam, not an authorization one: the relying party has
// already verified attestation, origin, RP ID, challenge, and user handle
// before it calls Save, and a decorator cannot reach or relax any of those
// checks.
type WebAuthnCredentialStoreDecorator func(webauthn.CredentialStore) webauthn.CredentialStore

// WebAuthnServiceParams configures BuildWebAuthnService.
type WebAuthnServiceParams struct {
	// Config is the relying-party configuration. Required.
	Config *webauthn.Config

	// QRDBClient persists WebAuthn users and credentials on the qrdb
	// identity plane -- the single source of identity for the stack.
	// Required: a host composes the module because it embeds qrdb, so the
	// datastore-backed fallback xkmsd uses for non-qrdb storage modes does
	// not apply here.
	QRDBClient *qrdbsdk.Client

	// TenantID scopes qrdb-backed WebAuthn user creation and lookup.
	// Defaults to DefaultWebAuthnTenant.
	TenantID string

	// TokenIssuer mints verifiable session tokens on ceremony completion.
	// Nil leaves ceremony completion unable to authenticate future requests
	// (logged, not fatal).
	TokenIssuer *token.Issuer

	// CredentialStoreDecorator optionally wraps the qrdb-backed credential
	// store this builder constructs. Nil leaves the qrdb store in place
	// unchanged -- the default composition is unaffected.
	CredentialStoreDecorator WebAuthnCredentialStoreDecorator

	// Logger receives construction diagnostics. Nil selects slog.Default().
	Logger *slog.Logger
}

// WebAuthnServiceBuildError reports a WebAuthn service construction failure
// from BuildWebAuthnService.
type WebAuthnServiceBuildError struct {
	Err error
}

// Error implements the error interface.
func (e *WebAuthnServiceBuildError) Error() string {
	return "rest: webauthn service construction failed: " + e.Err.Error()
}

// Unwrap exposes the underlying error for errors.As/errors.Is.
func (e *WebAuthnServiceBuildError) Unwrap() error { return e.Err }

// BuildWebAuthnService builds the WebAuthn relying-party service backed by
// the qrdb identity plane. It is the construction path shared by xkmsd's
// own composition (pkg/server initializeWebAuthnService's qrdb branch) and a
// host's self-built WebAuthn surface (NewHostServer): both persist WebAuthn
// users and credentials on the same qrdb node identity plane the rest of the
// stack uses, and both wire the token issuer so ceremony completion mints
// real, verifiable session tokens instead of the library's unsigned
// fallback.
func BuildWebAuthnService(p WebAuthnServiceParams) (*webauthn.Service, error) {
	if p.Config == nil {
		return nil, &WebAuthnServiceBuildError{Err: ErrWebAuthnConfigRequired}
	}
	if p.QRDBClient == nil {
		return nil, &WebAuthnServiceBuildError{Err: ErrWebAuthnQRDBClientRequired}
	}
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	tenantID := p.TenantID
	if tenantID == "" {
		tenantID = DefaultWebAuthnTenant
	}

	userStore, credStore, err := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
		Users:    p.QRDBClient.Users(),
		KV:       p.QRDBClient.KV(),
		TenantID: tenantID,
	})
	if err != nil {
		return nil, &WebAuthnServiceBuildError{Err: err}
	}

	credentialStore := credStore
	if p.CredentialStoreDecorator != nil {
		decorated := p.CredentialStoreDecorator(credentialStore)
		if isNilCredentialStore(decorated) {
			return nil, &WebAuthnServiceBuildError{Err: ErrWebAuthnCredentialStoreDecoratorNil}
		}
		credentialStore = decorated
		logger.Info("WebAuthn credential store decorated by the composing host")
	}

	params := webauthn.ServiceParams{
		Config:          p.Config,
		UserStore:       userStore,
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: credentialStore,
		Logger:          logger,
	}
	if p.TokenIssuer != nil {
		params.JWTGenerator = NewWebAuthnTokenAdapter(p.TokenIssuer, tenantID)
	} else {
		logger.Warn("WebAuthn service has no token issuer: ceremony tokens will not authenticate API requests")
	}

	svc, err := webauthn.NewService(params)
	if err != nil {
		return nil, &WebAuthnServiceBuildError{Err: err}
	}
	return svc, nil
}

// isNilCredentialStore reports whether cs carries no usable store. It
// catches both an untyped nil and a TYPED nil -- a (*T)(nil) a decorator
// returned by mistake compares != nil as an interface and would panic on the
// first Save, i.e. mid-ceremony, long after the wiring error was made.
func isNilCredentialStore(cs webauthn.CredentialStore) bool {
	if cs == nil {
		return true
	}
	v := reflect.ValueOf(cs)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
}

// WebAuthnConfigFromXKMS converts the operator-facing WebAuthn configuration
// (pkg/config WebAuthnConfig, xkmsd's own config-file section) into the
// pkg/webauthn Config the relying-party service consumes, applying the same
// defaults xkmsd's own composition does (pkg/server buildAuthenticator): the
// display name defaults to the RP identifier, and a single HTTPS origin is
// derived from the RP identifier when neither is configured. Shared by
// xkmsd's own composition and a host's self-built WebAuthn surface
// (NewHostServer / pkg/apimodule WithWebAuthnConfig), so both configure
// WebAuthn identically from the same YAML-shaped input. Returns nil for a
// nil input.
func WebAuthnConfigFromXKMS(cfg *config.WebAuthnConfig) *webauthn.Config {
	if cfg == nil {
		return nil
	}
	wc := &webauthn.Config{
		RPID:                    cfg.RPID,
		RPOrigins:               cfg.RPOrigins,
		RPDisplayName:           cfg.RPDisplayName,
		AttestationPreference:   cfg.AttestationPreference,
		AuthenticatorAttachment: cfg.AuthenticatorAttachment,
		ResidentKeyRequirement:  cfg.ResidentKey,
		UserVerification:        cfg.UserVerification,
		AllowPublicRegistration: cfg.AllowPublicRegistration,
	}
	if wc.RPDisplayName == "" {
		wc.RPDisplayName = wc.RPID
	}
	if len(wc.RPOrigins) == 0 && wc.RPID != "" {
		wc.RPOrigins = []string{"https://" + wc.RPID}
	}
	wc.SetDefaults()
	return wc
}

// ---------------------------------------------------------------------------
// Session authenticator construction
// ---------------------------------------------------------------------------

// AuthenticatorParams configures BuildAuthenticator.
type AuthenticatorParams struct {
	// TokenIssuer, when set, contributes a JWT authenticator verifying the
	// pairs it mints.
	TokenIssuer *token.Issuer

	// QRDBClient, when set, contributes an mTLS authenticator resolving
	// client certificates against the qrdb identity plane.
	QRDBClient *qrdbsdk.Client
}

// AuthenticatorBuildError reports a session authenticator construction
// failure from BuildAuthenticator.
type AuthenticatorBuildError struct {
	Err error
}

// Error implements the error interface.
func (e *AuthenticatorBuildError) Error() string {
	return "rest: session authenticator construction failed: " + e.Err.Error()
}

// Unwrap exposes the underlying error for errors.As/errors.Is.
func (e *AuthenticatorBuildError) Unwrap() error { return e.Err }

// BuildAuthenticator constructs the composite jwt+mtls session-vehicle
// authenticator a host's self-built REST surface authenticates callers
// with -- the JWT pairs BuildWebAuthnService's ceremonies (and the PIV/mTLS
// login exchange) mint, plus direct mTLS against the qrdb identity plane.
// It mirrors xkmsd's own derived composite chain (pkg/server
// deriveCompositeAuthenticator) without the operator-supplied
// public-key-file or no-qrdb certificate-field-extraction fallback
// branches, which are xkmsd config-file-only surfaces a host has no
// equivalent for. Fails when neither input yields a usable vehicle: a host
// providing nothing to authenticate callers with is a construction error,
// not a silent allow-all.
func BuildAuthenticator(p AuthenticatorParams) (auth.Authenticator, error) {
	var chain []auth.Authenticator

	if p.TokenIssuer != nil {
		jwtAuth, err := auth.NewJWTAuthenticator(&auth.JWTConfig{
			PublicKey:  p.TokenIssuer.PublicKey(),
			Issuer:     p.TokenIssuer.IssuerName(),
			Audience:   p.TokenIssuer.Audience(),
			HeaderName: "Authorization",
		})
		if err != nil {
			return nil, &AuthenticatorBuildError{Err: err}
		}
		chain = append(chain, jwtAuth)
	}
	if p.QRDBClient != nil {
		chain = append(chain, auth.NewMTLSAuthenticator(&auth.MTLSConfig{
			UserStore: auth.NewQRDBUserStore(p.QRDBClient.Users()),
		}))
	}

	switch len(chain) {
	case 0:
		return nil, &AuthenticatorBuildError{Err: ErrAuthenticatorChainEmpty}
	case 1:
		return chain[0], nil
	default:
		composite, err := auth.NewCompositeAuthenticator(chain...)
		if err != nil {
			return nil, &AuthenticatorBuildError{Err: err}
		}
		return composite, nil
	}
}

// ---------------------------------------------------------------------------
// Host server construction
// ---------------------------------------------------------------------------

// SessionOptions tunes the JWT signing key, token claims/TTLs, and login
// rate limiting behind a host's self-built session/login plane. The zero
// value uses the same defaults xkmsd itself derives.
type SessionOptions struct {
	// SigningKeyCN is the reserved backend key CN. Empty selects
	// DefaultJWTSigningKeyCN.
	SigningKeyCN string

	// Issuer is the iss claim. Empty selects the token package default.
	Issuer string

	// Audience is the aud claim. Empty selects the token package default.
	Audience []string

	// AccessTTL is the access token lifetime. Zero selects
	// token.DefaultAccessTTL.
	AccessTTL time.Duration

	// RefreshTTL is the refresh token lifetime. Zero selects
	// token.DefaultRefreshTTL.
	RefreshTTL time.Duration

	// LoginRatePerMin caps per-client login/refresh attempts per minute.
	// Zero uses the default (10), matching xkmsd.
	LoginRatePerMin int
}

// HostConfig configures NewHostServer: a self-sufficient, non-listening
// *Server a host that merely embeds go-xkms's qrdb ServiceModule
// (pkg/apimodule) can build from its resolved XKMSService and its own qrdb
// client, without any of the xkmsd-only wiring (barrier, custodian,
// ceremony, SSH, PKCS#11 remote state, CA). It is the host-composition path
// behind pkg/apimodule's self-built REST surface.
type HostConfig struct {
	// XKMSService is required; a nil service is a construction error.
	XKMSService *xkms.XKMSService

	// QRDBClient is the host's embedded/dialed qrdb node client. Optional:
	// nil disables the WebAuthn and mTLS-login identity plane (those route
	// families' Enabled predicates keep them off), and refresh tokens fall
	// back to an in-memory store.
	QRDBClient *qrdbsdk.Client

	// WebAuthn enables the WebAuthn ceremony routes when non-nil. Requires
	// QRDBClient; without one the routes stay unmounted.
	WebAuthn *webauthn.Config

	// WebAuthnTenantID scopes qrdb-backed WebAuthn user creation and
	// lookup. Empty selects DefaultWebAuthnTenant.
	WebAuthnTenantID string

	// WebAuthnCredentialStoreDecorator wraps the qrdb-backed credential
	// store the WebAuthn relying party persists passkeys through, letting
	// the composing host add its own side effects (an identity-plane auth
	// factor, an audit record) to registrations served by the module's own
	// ceremony routes. Nil leaves the qrdb store in place unchanged.
	WebAuthnCredentialStoreDecorator WebAuthnCredentialStoreDecorator

	// Session tunes the JWT signing key and token TTLs. Nil uses the zero
	// value (SessionOptions' own defaults).
	Session *SessionOptions

	// PIVLogin configures the TLS-client-certificate login exchange.
	PIVLogin *PIVLoginOptions

	// Logger receives construction and request diagnostics. Nil selects
	// slog.Default().
	Logger *slog.Logger

	// Version is the API version string reported by discovery endpoints.
	Version string

	// CORS is the cross-origin policy. Nil disables CORS.
	CORS *CORSOptions
}

// HostXKMSServiceRequiredError is returned by NewHostServer when hc is nil
// or carries no XKMSService.
type HostXKMSServiceRequiredError struct{}

// Error implements the error interface.
func (e *HostXKMSServiceRequiredError) Error() string {
	return "rest: NewHostServer requires a non-nil XKMSService"
}

// NewHostServer builds a non-listening *Server around the host's
// XKMSService and qrdb client: the crypto-operation surface (keys, certs,
// seal, ...) rides on whatever backends the XKMSService composed, and the
// token issuer, WebAuthn service, and session authenticator are wired
// exactly like xkmsd's own composition (pkg/server buildRESTConfig /
// initializeTokenIssuer / initializeWebAuthnService) via the shared
// Build* functions above. Barrier, custodian, ceremony, SSH, and CA
// surfaces are xkmsd-only and stay disabled -- their RouteEnabled
// predicates already gate on nil.
//
// A construction failure here means the host gave NewHostServer nothing it
// could authenticate callers with (no signing backend and no qrdb client) or
// the XKMSService itself has no crypto backend at all; the caller (the
// qrdb ServiceModule's self-build path) surfaces this loudly rather than
// serving a broken surface.
func NewHostServer(ctx context.Context, hc *HostConfig) (*Server, error) {
	if hc == nil || hc.XKMSService == nil {
		return nil, &HostXKMSServiceRequiredError{}
	}
	logger := hc.Logger
	if logger == nil {
		logger = slog.Default()
	}

	cfg := &Config{
		Version:     hc.Version,
		Logger:      logger,
		XKMSService: hc.XKMSService,
		CORS:        hc.CORS,
	}

	if names := hc.XKMSService.BackendNames(); len(names) > 0 {
		backends := make(map[string]xkms.Backend, len(names))
		for _, name := range names {
			if b, err := hc.XKMSService.LookupBackend(name); err == nil {
				backends[name] = b
			}
		}
		cfg.Backends = backends
		cfg.DefaultBackend = hc.XKMSService.DefaultBackendName()
	}

	session := hc.Session
	if session == nil {
		session = &SessionOptions{}
	}

	// Session/login plane: the token issuer needs a signing backend. A host
	// whose XKMSService has no default backend simply gets no session
	// plane -- its keys/certs/etc. routes still serve -- mirroring xkmsd's
	// own lenient "issuer stays nil" behavior.
	if backend, err := hc.XKMSService.LookupDefaultBackend(); err == nil {
		issuer, tiErr := BuildTokenIssuer(ctx, TokenIssuerParams{
			Backend:      backend,
			BackendName:  hc.XKMSService.DefaultBackendName(),
			SigningKeyCN: session.SigningKeyCN,
			IssuerName:   session.Issuer,
			Audience:     session.Audience,
			AccessTTL:    session.AccessTTL,
			RefreshTTL:   session.RefreshTTL,
			QRDBClient:   hc.QRDBClient,
			Logger:       logger,
		})
		if tiErr != nil {
			logger.Error("host REST surface: token issuer construction failed; "+
				"WebAuthn and PIV/mTLS logins will not work", "error", tiErr)
		} else {
			cfg.TokenIssuer = issuer

			loginRate := 10
			if session.LoginRatePerMin > 0 {
				loginRate = session.LoginRatePerMin
			}
			cfg.AuthRateLimiter = ratelimit.New(&ratelimit.Config{
				Enabled:           true,
				RequestsPerMinute: loginRate,
			})

			if hc.PIVLogin != nil {
				cfg.PIVLogin = hc.PIVLogin
			}
		}
	} else {
		logger.Info("host REST surface: no default signing backend; session/login routes stay unmounted", "error", err)
	}

	if hc.QRDBClient != nil {
		cfg.AuthUserStore = auth.NewQRDBUserStore(hc.QRDBClient.Users())

		if hc.WebAuthn != nil {
			tenantID := hc.WebAuthnTenantID
			if tenantID == "" {
				tenantID = DefaultWebAuthnTenant
			}
			svc, waErr := BuildWebAuthnService(WebAuthnServiceParams{
				Config:                   hc.WebAuthn,
				QRDBClient:               hc.QRDBClient,
				TenantID:                 tenantID,
				TokenIssuer:              cfg.TokenIssuer,
				CredentialStoreDecorator: hc.WebAuthnCredentialStoreDecorator,
				Logger:                   logger,
			})
			if waErr != nil {
				logger.Error("host REST surface: WebAuthn service construction failed; webauthn routes stay unmounted", "error", waErr)
			} else {
				cfg.WebAuthnConfig = hc.WebAuthn
				cfg.WebAuthnService = svc
				cfg.WebAuthnUsers = hc.QRDBClient.Users()
				cfg.WebAuthnKV = hc.QRDBClient.KV()
				cfg.WebAuthnTenantID = tenantID
				// Share the relying-party service into the XKMSService so
				// the SDK ceremony lane (/api/v1/webauthn/sdk/* ->
				// XKMSService.BeginRegistration et al.) resolves the SAME
				// instance as the browser handlers — the one-RP invariant
				// xkmsd establishes with the same SetWebAuthn call.
				// Without this the SDK lane fails ErrNotConfigured on a
				// host while the browser lane works.
				hc.XKMSService.SetWebAuthn(svc)
			}
		}
	}

	authenticator, authErr := BuildAuthenticator(AuthenticatorParams{
		TokenIssuer: cfg.TokenIssuer,
		QRDBClient:  hc.QRDBClient,
	})
	if authErr != nil {
		return nil, authErr
	}
	cfg.Authenticator = authenticator

	return NewServer(cfg)
}
