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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	dns01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01"
	http01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/http-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	acmenonce "github.com/jeremyhahn/go-xkms/pkg/acme/nonce"
	acmesdk "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	clustercasdk "github.com/jeremyhahn/go-xkms/sdk/go/clusterca"

	acmeserver "github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	acmemetrics "github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	nativeca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// ACME integration error types. These are returned from startACMEServer and
// embedded in start-up failures when the ACME subsystem cannot be brought up.
var (
	// ErrACMEBackendUnavailable is returned when the configured keystore
	// backend cannot be resolved from the xkmsd server.
	ErrACMEBackendUnavailable = errors.New("acme: keystore backend not available")

	// ErrACMEObjectStoreConfigure is returned when the object-store backend
	// used to persist ACME state cannot be configured.
	ErrACMEObjectStoreConfigure = errors.New("acme: failed to configure object store")

	// ErrACMECACreate is returned when the ACME certificate authority
	// cannot be created from the supplied configuration.
	ErrACMECACreate = errors.New("acme: failed to create certificate authority")

	// ErrACMEStorageFactory is returned when the ACME storage factory cannot
	// be created.
	ErrACMEStorageFactory = errors.New("acme: failed to create storage factory")

	// ErrACMERestService is returned when the ACME REST service cannot be
	// constructed from the supplied parameters.
	ErrACMERestService = errors.New("acme: failed to create REST service")

	// ErrACMETLSConfig is returned when the ACME TLS configuration cannot be
	// built (e.g. missing cert/key files).
	ErrACMETLSConfig = errors.New("acme: failed to build TLS configuration")

	// ErrACMEClientCALoad is returned when a client CA bundle cannot be
	// loaded from disk.
	ErrACMEClientCALoad = errors.New("acme: failed to load client CA bundle")

	// ErrACMENoClientCAPEM is returned when a client CA bundle file
	// contains no parseable PEM certificates.
	ErrACMENoClientCAPEM = errors.New("acme: no PEM certificates parsed")

	// ErrACMEListen is returned when the ACME listener cannot be bound.
	ErrACMEListen = errors.New("acme: failed to bind listener")

	// ErrACMEAuditLogger is returned when the audit trail cannot be opened.
	// The ACME CA does not start without it: a CA that issues and revokes
	// certificates it cannot record is not a CA any compliance regime accepts.
	ErrACMEAuditLogger = errors.New("acme: failed to open audit trail")

	// ErrACMECAAValidator is returned when the CAA validator cannot be
	// constructed from the supplied configuration.
	ErrACMECAAValidator = errors.New("acme: failed to create CAA validator")
)

// acmeServer holds the runtime state of the embedded ACME HTTPS server so it
// can be gracefully shut down alongside the primary xkmsd server.
type acmeServer struct {
	httpServer *http.Server
	listener   net.Listener
	logger     *slog.Logger

	// auditLog is the ACME audit trail. It is flushed and closed during
	// Shutdown so no recorded event is lost on a clean stop.
	auditLog audit.AuditLogger

	// tcgCA and storageFactory are the same TCG-capable CA and ACME storage
	// factory the ACME protocol listener issues from and persists to.
	// Exposed via accessors so the admin surface (admin.go) administers the
	// identical CA and storage state instead of standing up a second copy.
	tcgCA          nativeca.TCGCA
	storageFactory storage.Factory

	// routerLimiters holds the tenant-aware and per-category rate limiters
	// mounted on the router. Several of these own a background cleanup
	// goroutine (server.TenantRateLimiter) that Shutdown stops.
	routerLimiters *acmeRouterLimiters

	// doneCh is closed when the server goroutine exits.
	doneCh chan struct{}

	// err records any terminal error from the server goroutine.
	mu  sync.Mutex
	err error
}

// startACMEServer brings up the ACME server on the ACME HTTPS listener when
// cfg.ACME is non-nil and enabled. On success the returned *acmeServer must
// be closed via Shutdown before the process exits to ensure clean release of
// filesystem handles and pending requests. When cfg.ACME is nil or disabled
// the function returns (nil, nil) and the caller can proceed without ACME.
func startACMEServer(srv *server.Server, cfg *config.Config, logger *slog.Logger) (*acmeServer, error) {
	if cfg.ACME == nil || !cfg.ACME.Enabled {
		return nil, nil
	}

	acmeCfg := cfg.ACME
	logger = logger.With("component", "acme")
	logger.Info("Starting ACME server",
		slog.String("https_addr", acmeCfg.HTTPSAddr),
		slog.String("external_url", acmeCfg.ExternalURL),
		slog.String("keystore_backend", acmeCfg.KeystoreBackend))

	// Resolve data directory for ACME state. Defaults to "<storage.path>/acme".
	dataDir := acmeCfg.DataDir
	if dataDir == "" {
		if cfg.Storage.Path == "" {
			dataDir = "acme"
		} else {
			dataDir = filepath.Join(cfg.Storage.Path, "acme")
		}
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, &acmeInitError{Stage: "create data dir", Err: err}
	}

	// Open the audit trail before anything else that can issue a certificate.
	// A disabled trail yields the no-op logger; an enabled trail whose log file
	// cannot be created fails the start-up rather than running a CA that
	// silently keeps no record of what it signs.
	auditCfg := acmeCfg.Audit.AuditConfig(dataDir)
	auditLogger, err := audit.NewFileAuditLogger(auditCfg)
	if err != nil {
		return nil, &acmeInitError{Stage: "open audit trail", Sentinel: ErrACMEAuditLogger, Err: err}
	}
	// Every failure below this point must release the audit writer goroutine.
	started := false
	defer func() {
		if !started {
			if cerr := auditLogger.Close(); cerr != nil {
				logger.Warn("acme: failed to close the audit trail after a failed start-up", "error", cerr)
			}
		}
	}()
	if auditLogger.Enabled() {
		logger.Info("ACME audit trail enabled", slog.String("log_path", auditCfg.LogPath))
	} else {
		logger.Warn("ACME audit trail disabled: certificate issuance and revocation will not be recorded")
	}

	// Resolve the keystore backend from the xkmsd server. The ACME CA reuses
	// the same keystore as the primary xkmsd CA when configured identically,
	// so the same physical keys back both subsystems.
	backend := srv.Backend(acmeCfg.KeystoreBackend)
	if backend == nil {
		return nil, &acmeBackendError{
			Backend: acmeCfg.KeystoreBackend,
			Err:     ErrACMEBackendUnavailable,
		}
	}

	// Resolve the primary xkmsd CA. ACME issues certificates through the
	// same TrustedCA that backs the xkmsd REST/gRPC/QUIC surfaces so that
	// both issuance paths share serial counters, revocation state, TCG
	// enrollment artefacts, and trust-chain material. This removes the
	// previous dual-CA wiring where ACME maintained an independent CA
	// instance against a parallel keystore / certstore / object store.
	primaryCA := srv.CA()
	if primaryCA == nil {
		return nil, &acmeInitError{Stage: "resolve primary CA", Err: ErrACMECACreate}
	}
	tcgCA, ok := primaryCA.(nativeca.TCGCA)
	if !ok {
		return nil, &acmeInitError{Stage: "assert TCG CA", Err: ErrACMECACreate}
	}

	// Create the storage factory for ACME accounts/orders/authorizations.
	// ACME state persists through the server's configured datastore (the same
	// durable engine — pebble/file/qrdb — as the rest of xkmsd), wrapped as a
	// go-qrdb KVStore. This replaces the previous separate local object store.
	stateBackend, err := srv.CreateStorage("acme-state")
	if err != nil {
		return nil, &acmeInitError{Stage: "create state store", Err: err}
	}
	stateKV, err := kvadapter.New(stateBackend)
	if err != nil {
		return nil, &acmeInitError{Stage: "wrap state store", Err: err}
	}
	storageFactory, err := acmeobjstore.NewFactoryFromKVStore(stateKV)
	if err != nil {
		return nil, &acmeInitError{Stage: "create storage factory", Err: err}
	}

	// The shared circuit breaker manager backs every wrapped ACME outbound
	// dependency: the challenge verifiers wrapped below, and the storage
	// breaker RestService creates for its own CA-bundle access. Threading one
	// Manager through both means HealthHandler reports every breaker from a
	// single registry.
	breakers := circuitbreaker.NewManager()

	// Build the challenge verifier map based on configured challenge types.
	challengeMap := buildChallengeMap(acmeCfg.Challenges, acmeCfg.Resilience, breakers)

	// When cluster ACME enrollment is active, register the pre-sign hook that
	// stamps the SPIFFE node identity (spiffe://<trust-domain>/node/<raft-addr>)
	// as a URI SAN on enrolling nodes' transport certificates, keyed off the
	// TCG permanent-identifier the joiner presents. The hook is a no-op for
	// ordinary ACME orders (no permanent identifier), so registering it never
	// affects non-cluster issuance.
	preSignHooks := buildClusterPreSignHooks(cfg)

	// Normalize directory path. The ACME routes are mounted under this prefix.
	directoryPath := acmeCfg.DirectoryPath
	if directoryPath == "" {
		directoryPath = "/acme"
	}
	directoryPath = "/" + strings.Trim(directoryPath, "/")

	// Build the CAA (RFC 8659) validator that order finalize consults before
	// signing (pkg/acme/server/handlers/order_finalize.go), per the RFC 8555
	// Section 8.1 requirement to check CAA before issuance. This is the one
	// construction path for a CAA validator; pkg/acme/client/trustedca.go's
	// standalone TrustedCA composition builds its own from the same
	// server.NewCAAValidator constructor. pkg/config/acme.go's Validate
	// requires CAAIdentities whenever ACME is enabled, so acmeCfg.CAAIdentities
	// is never empty here in a validated configuration.
	caaValidator, err := acmeserver.NewCAAValidator(&acmeserver.CAAValidatorParams{
		CAAIdentities: acmeCfg.CAAIdentities,
		Logger:        logger,
		Resolver:      acmeCfg.CAADNSServer,
	})
	if err != nil {
		return nil, &acmeInitError{Stage: "create CAA validator", Sentinel: ErrACMECAAValidator, Err: err}
	}

	// Build the per-client admission-control middleware. acmeserver.
	// NewClientRateLimiterMiddleware is the single construction path shared
	// with the standalone TrustedCA (pkg/acme/client/trustedca.go) so
	// neither composition hand-rolls its own limiter wiring. Disabling it is
	// an explicit, logged act: Config.ComplianceGaps reports it and xkmsd
	// refuses to start, so there is no silent way to run the ACME listener
	// unthrottled.
	var rateLimitMiddleware mux.MiddlewareFunc
	if acmeCfg.RateLimit.IsEnabled() {
		rateLimitMiddleware = acmeserver.NewClientRateLimiterMiddleware(
			acmeCfg.RateLimit.ResolveMaxRequests(),
			acmeCfg.RateLimit.ResolveInterval(),
			auditLogger,
		)
		logger.Info("ACME rate limiting enabled",
			slog.Int("max_requests", acmeCfg.RateLimit.ResolveMaxRequests()),
			slog.Duration("interval", acmeCfg.RateLimit.ResolveInterval()))
	} else {
		logger.Warn("ACME rate limiting disabled: the ACME endpoint accepts unlimited " +
			"new-account, new-order, and challenge requests")
	}

	// Build the tenant-aware admission control: the per-tenant overall quota
	// and the RFC 8555 Section 6.6 per-category limiters (new-account,
	// new-order, certificate, failed-validation). Every one of these keys on
	// the tenant handlers.RestService.TenantAuthMiddleware resolves from a
	// fully verified JWS "kid" — never on X-Tenant-ID, the host, or the
	// path — so a client cannot spoof its way into another tenant's bucket
	// or escape its own.
	routerLimiters := buildACMERouterLimiters(&acmeCfg.RateLimit, logger)

	// Construct the REST service that implements all ACME HTTP handlers.
	// tcgCA is the primary xkmsd TrustedCA asserted to TCGCA above; the
	// ACME handlers rely on the TCG extensions (IssueEKCertificate,
	// SignTCGCSRIDevID, ...) exposed by *pkg/ca.CA.
	service, err := handlers.NewRestService(&handlers.Params{
		AllowLoopbackIdentifier:     acmeCfg.Enrollment.AllowLoopbackIdentifier,
		AuditLogger:                 auditLogger,
		BaseRESTURI:                 acmeCfg.ExternalURL,
		CA:                          tcgCA,
		CAAIdentities:               acmeCfg.CAAIdentities,
		CAAValidator:                caaValidator,
		ChallengeMap:                challengeMap,
		ClusterCACN:                 clusterACMEIssuerCN(cfg),
		EndorseEABRequired:          acmeCfg.EndorseEABRequired,
		EndorseDeviceIDMetaKey:      acmeCfg.EndorseDeviceIDMetaKey,
		ExternalAccountRequired:     acmeCfg.ExternalAccountRequired,
		FailedValidationRateLimiter: routerLimiters.failedValidation,
		Logger:                      logger,
		NoncePrefix:                 clusterNoncePrefix(cfg),
		NonceLifetime:               acmeCfg.Nonce.ResolveLifetime(),
		NonceMaxUsed:                acmeCfg.Nonce.ResolveMaxUsed(),
		OrderPreSignHooks:           preSignHooks,
		Policy:                      acmeCfg.Policy.PolicyConfig(),
		StorageFactory:              storageFactory,
		TermsOfService:              acmeCfg.TermsOfService,
		Breakers:                    breakers,
		StorageBreaker:              acmeCfg.Resilience.Storage.CircuitBreakerConfig("storage"),
		KMSBreaker:                  acmeCfg.Resilience.KMS.CircuitBreakerConfig("kms"),
		DegradationCacheTTL:         acmeCfg.Resilience.Degradation.ResolveCacheTTL(),
		DegradationStaleTTL:         acmeCfg.Resilience.Degradation.ResolveStaleTTL(),
		DegradationMaxCacheSize:     acmeCfg.Resilience.Degradation.ResolveMaxCacheSize(),
	})
	if err != nil {
		return nil, &acmeInitError{Stage: "create REST service", Sentinel: ErrACMERestService, Err: err}
	}

	// Build the HTTP router and mount the ACME routes.
	router := buildACMERouter(service, directoryPath, rateLimitMiddleware, routerLimiters)

	// Make the ACME metrics registry part of the same /metrics response
	// xkmsd already serves (pkg/server/server.go startMetrics), rather than
	// standing up a second scrape endpoint.
	srv.RegisterMetricsGatherer(acmemetrics.Registry)

	// When the cluster CA key strategy delivers post-enrollment material (the
	// tpm-kek cluster seed), mount its secret-delivery endpoint on the same
	// HTTPS server the joiner already reaches for enrollment. A no-op for
	// barrier/hsm (which deliver nothing).
	if delivery := srv.ClusterSecretDeliveryService(); delivery != nil {
		if muxRouter, ok := router.(*mux.Router); ok {
			muxRouter.HandleFunc(clustercasdk.SecretDeliveryPath, delivery.Handler()).Methods(http.MethodPost)
			logger.Info("Cluster CA secret-delivery endpoint mounted", slog.String("path", clustercasdk.SecretDeliveryPath))
		}
	}

	// Build the TLS configuration for the dedicated ACME listener.
	tlsCfg, err := buildACMETLSConfig(acmeCfg)
	if err != nil {
		return nil, &acmeInitError{Stage: "build TLS config", Sentinel: ErrACMETLSConfig, Err: err}
	}

	// Bind the listener before starting the goroutine so that configuration
	// errors are surfaced synchronously.
	ln, err := tls.Listen("tcp", acmeCfg.HTTPSAddr, tlsCfg)
	if err != nil {
		return nil, &acmeInitError{Stage: "listen on " + acmeCfg.HTTPSAddr, Sentinel: ErrACMEListen, Err: err}
	}

	httpSrv := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         tlsCfg,
	}

	as := &acmeServer{
		httpServer:     httpSrv,
		listener:       ln,
		logger:         logger,
		auditLog:       auditLogger,
		tcgCA:          tcgCA,
		storageFactory: storageFactory,
		routerLimiters: routerLimiters,
		doneCh:         make(chan struct{}),
	}
	started = true

	go func() {
		defer close(as.doneCh)
		logger.Info("ACME HTTPS server listening", slog.String("addr", acmeCfg.HTTPSAddr))
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			as.mu.Lock()
			as.err = err
			as.mu.Unlock()
			logger.Error("ACME server terminated with error", slog.Any("error", err))
		}
	}()

	return as, nil
}

// CA returns the TCG-capable certificate authority the ACME server issues
// from, or nil for a nil *acmeServer (ACME disabled). The admin surface
// (admin.go) administers this same CA rather than standing up a second one.
func (a *acmeServer) CA() nativeca.TCGCA {
	if a == nil {
		return nil
	}
	return a.tcgCA
}

// StorageFactory returns the ACME storage factory the ACME server persists
// accounts, orders, and authorizations through, or nil for a nil
// *acmeServer (ACME disabled). The admin surface (admin.go) reads and writes
// the same storage rather than a second copy.
func (a *acmeServer) StorageFactory() storage.Factory {
	if a == nil {
		return nil
	}
	return a.storageFactory
}

// Shutdown gracefully terminates the ACME HTTPS server and releases
// associated filesystem handles. It is safe to call Shutdown on a nil
// *acmeServer; this makes the caller side of shutdown cleaner when ACME is
// disabled.
func (a *acmeServer) Shutdown(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.logger.Info("Shutting down ACME server")
	shutdownErr := a.httpServer.Shutdown(ctx)
	select {
	case <-a.doneCh:
	case <-ctx.Done():
		// Shutdown context expired; the goroutine may still be running but we
		// proceed to release remaining resources. httpServer.Shutdown will
		// have already returned ctx.Err() in this case.
	}
	// Stop every tenant rate limiter's background cleanup goroutine before
	// the audit trail closes, so nothing can still be recording through it.
	for _, limiter := range a.routerLimiters.stoppableLimiters() {
		limiter.Stop()
	}

	// Close the audit trail last so any event recorded by an in-flight request
	// is flushed to disk before the process exits.
	if a.auditLog != nil {
		if err := a.auditLog.Close(); err != nil {
			a.logger.Error("Failed to close ACME audit trail", slog.Any("error", err))
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	return shutdownErr
}

// buildChallengeMap builds the map of challenge type -> verifier function
// based on the supplied configuration. At least one challenge type must be
// enabled; this is enforced by config.ACMEConfig.Validate.
//
// The http-01 and dns-01 verifiers are wrapped with a breaker from breakers,
// configured from resilience, so a target that stops responding trips its
// own breaker instead of holding up every challenge validation sharing the
// same worker. acmeserver.WrapChallengeVerifiers does the wrapping; it is
// the one construction path shared with the standalone TrustedCA
// (pkg/acme/client/trustedca.go), so neither composition hand-rolls its own
// wrapping. A nil breakers leaves both verifiers unwrapped.
func buildChallengeMap(
	cfg config.ACMEChallengesConfig,
	resilience config.ACMEResilienceConfig,
	breakers *circuitbreaker.Manager,
) map[string]common.ChallengeVerifierFunc {
	m := make(map[string]common.ChallengeVerifierFunc, 2)
	if cfg.HTTP01 {
		m[common.ChallengeTypeHTTP01] = common.ChallengeVerifierFunc(func(
			resolver *net.Resolver,
			_ common.CertificateAuthority,
			authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
			return http01.Verify(resolver, authzValue, challengePort, challengeToken, expectedKeyAuth)
		})
	}
	if cfg.DNS01 {
		m[common.ChallengeTypeDNS01] = common.ChallengeVerifierFunc(func(
			resolver *net.Resolver,
			_ common.CertificateAuthority,
			authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
			return dns01.Verify(resolver, authzValue, challengePort, challengeToken, expectedKeyAuth)
		})
	}
	// The TPM attestation challenges (enroll-01/endorse-01) use the shared SDK
	// wiring so every ACME server in the stack (xkmsd, quicbaas) enables them
	// identically. The verifiers encapsulate the CA type-assertion + Verify.
	for challengeType, verifier := range acmesdk.ACMEAttestationVerifiers(cfg.Enroll01, cfg.Endorse01) {
		m[challengeType] = verifier
	}
	return acmeserver.WrapChallengeVerifiers(m, resilience, breakers)
}

// buildClusterPreSignHooks returns the pre-sign hook registry for the ACME
// server. When cluster ACME enrollment is enabled it registers the SPIFFE
// node-identity URI-SAN hook so enrolling nodes' transport certificates carry
// spiffe://<trust-domain>/node/<raft-address>, derived from the TCG permanent
// identifier the joiner presents (the canonical clusterenroll.NodeURI is the
// single source of truth for the format). It returns nil when cluster ACME
// enrollment is off, leaving ordinary ACME issuance untouched.
func buildClusterPreSignHooks(cfg *config.Config) *handlers.OrderPreSignHookRegistry {
	if !cfg.Cluster.Enabled || !cfg.Cluster.RaftEnrollment.ACME.Enabled {
		return nil
	}
	trustDomain := cfg.Cluster.RaftEnrollment.TrustDomain
	if trustDomain == "" {
		trustDomain = defaultClusterTrustDomain
	}
	registry := handlers.NewOrderPreSignHookRegistry()
	registry.Register(handlers.NewPermanentIdentifierURISANHook(func(permanentID string) string {
		return clusterenroll.NodeURI(trustDomain, permanentID)
	}))
	return registry
}

// clusterACMEIssuerCN returns the dedicated cluster intermediate CN that
// enroll-01 (TCG-CSR-IDEVID) issuance should chain to, or "" to keep default
// issuance. It is only active when cluster ACME enrollment is enabled and the
// operator configured a cluster_ca_cn.
func clusterACMEIssuerCN(cfg *config.Config) string {
	if !cfg.Cluster.Enabled || !cfg.Cluster.RaftEnrollment.ACME.Enabled {
		return ""
	}
	return cfg.Cluster.RaftEnrollment.ClusterCACN
}

// noncePrefixSalt is the HMAC key nonce.DerivePrefix uses to turn a node ID
// into an 8-character ACME nonce prefix. The prefix is a public routing tag
// embedded in every issued nonce (pkg/acme/nonce.MultiService routes
// redemption by it), not a value that needs to stay secret, so a fixed salt
// shared by every deployment is sufficient — it only needs to be stable so
// the same node ID always derives the same prefix.
var noncePrefixSalt = []byte("go-xkms/acme/nonce-prefix-v1")

// clusterNoncePrefix derives this node's ACME nonce-service prefix from its
// Raft NodeID, so pkg/acme/nonce.MultiService can distinguish nonces minted
// by different nodes in a load-balanced deployment. A standalone node (Raft
// clustering off) has no peer to disambiguate from and mints unprefixed
// nonces.
//
// The prefix alone does not make nonces portable across nodes: that also
// requires every node to encrypt with the same key (handlers.Params.NonceKey),
// which is not wired here — see docs/acme-issuance/engineering.md.
func clusterNoncePrefix(cfg *config.Config) string {
	if !cfg.Cluster.Enabled {
		return ""
	}
	return acmenonce.DerivePrefix(strconv.FormatUint(cfg.Cluster.NodeID, 10), noncePrefixSalt)
}

// defaultClusterTrustDomain mirrors pkg/server's defaultRaftTrustDomain so the
// ACME server stamps the same SPIFFE trust domain the node provisioner uses
// when the operator leaves cluster.raft_enrollment.trust_domain unset.
const defaultClusterTrustDomain = "xkms.cluster"

// buildACMERouter mounts the ACME REST handlers on a gorilla/mux router
// under the given directory path prefix. The route layout follows
// RFC 8555 Section 7.1.
//
// rateLimitMiddleware, when non-nil, is applied to every route on the
// returned router (including any handler a caller mounts on it afterward,
// e.g. the cluster secret-delivery endpoint in startACMEServer) via
// mux.Router.Use, which every ACME server composition in the stack builds
// through acmeserver.NewClientRateLimiterMiddleware. A nil value mounts the
// router unthrottled — callers pass nil only when acme.rate_limit.enabled
// is false, which Config.ComplianceGaps reports.
//
// routerLimiters mounts the tenant-aware admission control (#886) alongside
// rateLimitMiddleware: TenantAuthMiddleware runs first so every tenant-keyed
// limiter after it (the overall quota, and the per-route new-order and
// certificate category limiters) reads an already-resolved, already-verified
// tenant from the request context. The new-account category limiter is
// mounted directly on its route since the tenant is never known at that
// point (no account exists yet).
func buildACMERouter(svc handlers.RestServicer, directoryPath string, rateLimitMiddleware mux.MiddlewareFunc, routerLimiters *acmeRouterLimiters) http.Handler {
	r := mux.NewRouter()

	// acmemetrics.Mount initializes the ACME Prometheus registry (base and
	// production metric sets) and attaches the request-instrumentation
	// middleware, the same shared entry point pkg/acme/client/trustedca.go
	// uses for the standalone TrustedCA, so both ACME server compositions
	// expose identical metrics. Mounted before the rate limiter so a
	// rate-limited (429) request is still recorded.
	acmemetrics.Mount(r)

	if rateLimitMiddleware != nil {
		r.Use(rateLimitMiddleware)
	}
	r.Use(svc.TenantAuthMiddleware)
	if routerLimiters != nil && routerLimiters.tenant != nil {
		r.Use(routerLimiters.tenant.Middleware())
	}
	r.HandleFunc(directoryPath+"/directory", svc.DirectoryHandler).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc(directoryPath+"/new-nonce", svc.NewNonceHandler).Methods(http.MethodGet, http.MethodHead)
	r.Handle(directoryPath+"/new-account", routerLimiters.wrapNewAccount(http.HandlerFunc(svc.NewAccountHandler))).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/account/{id:[0-9]+}", svc.AccountHandler).Methods(http.MethodPost)
	r.Handle(directoryPath+"/new-order", routerLimiters.wrapNewOrder(http.HandlerFunc(svc.NewOrderHandler))).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/order/{id:[0-9]+}", svc.OrderHandler).Methods(http.MethodPost)
	r.Handle(directoryPath+"/order/{id:[0-9]+}/finalize", routerLimiters.wrapCertificate(http.HandlerFunc(svc.OrderFinalizeHandler))).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/orders/{id:[0-9]+}", svc.OrdersListHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/authz/{id:[0-9]+}", svc.AuthorizationHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/challenge/{id:[0-9]+}", svc.ChallengeHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/cert/{id:[0-9]+}", svc.CertificateHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/revoke-cert", svc.RevokeCertHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/key-change", svc.KeyChangeHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/ca-bundle", svc.CABundleHandler).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc(directoryPath+"/health", svc.HealthHandler).Methods(http.MethodGet)
	return r
}

// acmeRouterLimiters bundles the tenant-aware overall quota and the RFC 8555
// Section 6.6 per-category limiters buildACMERouter mounts alongside the
// per-client blanket limiter (#885). A nil field mounts its route(s)
// unthrottled for that one control — callers leave a field nil only when the
// corresponding acme.rate_limit.* sub-section is disabled, which
// Config.ComplianceGaps reports.
type acmeRouterLimiters struct {
	// tenant is the per-tenant overall admission-control quota, shared
	// across every account belonging to the same tenant (tenantSharedClientKey).
	tenant *acmeserver.TenantRateLimiter

	// newAccount is the RFC 8555 Section 6.6 new-account category, keyed by
	// client IP: the tenant is never known before an account exists.
	newAccount mux.MiddlewareFunc

	// newOrder and certificate are the RFC 8555 Section 6.6 new-order and
	// certificate-issuance categories, keyed by account within the account's
	// tenant (or the shared "" bucket for a non-tenant account).
	newOrder    *acmeserver.TenantRateLimiter
	certificate *acmeserver.TenantRateLimiter

	// failedValidation is the RFC 8555 Section 6.6 failed-validation
	// category. It cannot be mounted as route middleware — it must count
	// only actual validation failures — so it is handed to
	// handlers.Params.FailedValidationRateLimiter instead, and
	// handlers.RestService.ChallengeHandler consults it directly.
	failedValidation *acmeserver.TenantRateLimiter
}

// wrapNewAccount applies the new-account category limiter to next, or
// returns next unwrapped when the category is disabled.
func (l *acmeRouterLimiters) wrapNewAccount(next http.Handler) http.Handler {
	if l == nil || l.newAccount == nil {
		return next
	}
	return l.newAccount(next)
}

// wrapNewOrder applies the new-order category limiter to next, or returns
// next unwrapped when the category is disabled.
func (l *acmeRouterLimiters) wrapNewOrder(next http.Handler) http.Handler {
	if l == nil || l.newOrder == nil {
		return next
	}
	return l.newOrder.Middleware()(next)
}

// wrapCertificate applies the certificate category limiter to next, or
// returns next unwrapped when the category is disabled.
func (l *acmeRouterLimiters) wrapCertificate(next http.Handler) http.Handler {
	if l == nil || l.certificate == nil {
		return next
	}
	return l.certificate.Middleware()(next)
}

// stoppableLimiters returns every TenantRateLimiter that owns a background
// cleanup goroutine, for Shutdown to Stop.
func (l *acmeRouterLimiters) stoppableLimiters() []*acmeserver.TenantRateLimiter {
	if l == nil {
		return nil
	}
	var limiters []*acmeserver.TenantRateLimiter
	for _, limiter := range []*acmeserver.TenantRateLimiter{l.tenant, l.newOrder, l.certificate, l.failedValidation} {
		if limiter != nil {
			limiters = append(limiters, limiter)
		}
	}
	return limiters
}

// tenantSharedClientKey is the TenantRateLimiter client-key function the
// per-tenant overall quota uses: a constant, so every account belonging to
// the same tenant draws from one shared bucket rather than being
// sub-divided per account or client IP within the tenant. This is what
// makes the quota a genuinely per-tenant control (RFC 8555 Section 6.6 does
// not define multi-tenancy, so go-xkms extends "per account" to "per
// tenant, shared across its accounts" here).
func tenantSharedClientKey(*http.Request) string { return "" }

// buildACMERouterLimiters constructs the tenant-aware overall quota and the
// four RFC 8555 Section 6.6 per-category limiters from cfg, logging each
// enabled/disabled decision. Every limiter keys on
// acmeserver.TenantRateLimiterFromRequestContext, the tenant
// handlers.RestService.TenantAuthMiddleware resolves and publishes from a
// verified JWS "kid" — the same mechanism, never a client-asserted header,
// host, or path.
func buildACMERouterLimiters(cfg *config.ACMERateLimitConfig, logger *slog.Logger) *acmeRouterLimiters {
	limiters := &acmeRouterLimiters{}

	if cfg.TenantIsEnabled() {
		limiters.tenant = acmeserver.NewTenantRateLimiter(
			&acmeserver.TenantRateLimiterConfig{
				DefaultConfig: &acmeserver.RateLimitConfig{
					OverallRequestRate: &acmeserver.RateLimit{
						MaxRequests: cfg.TenantResolveMaxRequests(),
						Interval:    cfg.TenantResolveInterval(),
					},
				},
			},
			acmeserver.TenantRateLimiterFromRequestContext(),
			tenantSharedClientKey,
			"overall",
		)
		logger.Info("ACME tenant rate limiting enabled",
			slog.Int("max_requests", cfg.TenantResolveMaxRequests()),
			slog.Duration("interval", cfg.TenantResolveInterval()))
	} else {
		logger.Warn("ACME tenant rate limiting disabled: a multi-tenant deployment's accounts share no per-tenant quota")
	}

	if cfg.NewAccountIsEnabled() {
		limiters.newAccount = acmeserver.NewAccountRateLimiter(&acmeserver.RateLimit{
			MaxRequests: cfg.NewAccountResolveMaxRequests(),
			Interval:    cfg.NewAccountResolveInterval(),
		})
	} else {
		logger.Warn("ACME new-account rate limiting disabled (acme.rate_limit.new_account.enabled=false)")
	}

	if cfg.NewOrderIsEnabled() {
		limiters.newOrder = acmeserver.NewTenantOrderRateLimiter(&acmeserver.TenantRateLimiterConfig{
			DefaultConfig: &acmeserver.RateLimitConfig{
				NewOrderRate: &acmeserver.RateLimit{
					MaxRequests: cfg.NewOrderResolveMaxRequests(),
					Interval:    cfg.NewOrderResolveInterval(),
				},
			},
		}, acmeserver.TenantRateLimiterFromRequestContext())
	} else {
		logger.Warn("ACME new-order rate limiting disabled (acme.rate_limit.new_order.enabled=false)")
	}

	if cfg.CertificateIsEnabled() {
		limiters.certificate = acmeserver.NewTenantCertificateRateLimiter(&acmeserver.TenantRateLimiterConfig{
			DefaultConfig: &acmeserver.RateLimitConfig{
				CertificateRate: &acmeserver.RateLimit{
					MaxRequests: cfg.CertificateResolveMaxRequests(),
					Interval:    cfg.CertificateResolveInterval(),
				},
			},
		}, acmeserver.TenantRateLimiterFromRequestContext())
	} else {
		logger.Warn("ACME certificate rate limiting disabled (acme.rate_limit.certificate.enabled=false)")
	}

	if cfg.FailedValidationIsEnabled() {
		limiters.failedValidation = acmeserver.NewTenantFailedValidationRateLimiter(&acmeserver.TenantRateLimiterConfig{
			DefaultConfig: &acmeserver.RateLimitConfig{
				FailedValidationRate: &acmeserver.RateLimit{
					MaxRequests: cfg.FailedValidationResolveMaxRequests(),
					Interval:    cfg.FailedValidationResolveInterval(),
				},
			},
		}, acmeserver.TenantRateLimiterFromRequestContext())
	} else {
		logger.Warn("ACME failed-validation rate limiting disabled (acme.rate_limit.failed_validation.enabled=false)")
	}

	return limiters
}

// buildACMETLSConfig loads the TLS material for the ACME listener.
//
// The ACME listener always uses its own dedicated TLS certificate rather
// than the primary xkmsd TLS config: the xkmsd TLS stack is authenticated
// against the xkmsd REST/gRPC server CN and would generally not match an
// ACME client's expected hostname. Operators provision a dedicated TLS
// cert/key pair for the ACME endpoint via acme.tls.cert_file and
// acme.tls.key_file.
func buildACMETLSConfig(cfg *config.ACMEConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if cfg.TLS.MinVersion != "" {
		if v := parseACMETLSVersion(cfg.TLS.MinVersion); v > 0 {
			tlsCfg.MinVersion = v
		}
	}
	if cfg.TLS.MaxVersion != "" {
		if v := parseACMETLSVersion(cfg.TLS.MaxVersion); v > 0 {
			tlsCfg.MaxVersion = v
		}
	}
	switch cfg.TLS.ClientAuth {
	case "request":
		tlsCfg.ClientAuth = tls.RequestClientCert
	case "require":
		tlsCfg.ClientAuth = tls.RequireAnyClientCert
	case "verify":
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	case "require_and_verify":
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	case "", "none":
		tlsCfg.ClientAuth = tls.NoClientCert
	}
	if len(cfg.TLS.ClientCAs) > 0 {
		pool := x509.NewCertPool()
		for _, path := range cfg.TLS.ClientCAs {
			data, err := os.ReadFile(path) // #nosec G304 - path from trusted config
			if err != nil {
				return nil, &acmeInitError{Stage: "read client CA " + path, Sentinel: ErrACMEClientCALoad, Err: err}
			}
			if !pool.AppendCertsFromPEM(data) {
				return nil, &acmeInitError{Stage: "parse client CA " + path, Sentinel: ErrACMEClientCALoad, Err: ErrACMENoClientCAPEM}
			}
		}
		tlsCfg.ClientCAs = pool
	}
	return tlsCfg, nil
}

// parseACMETLSVersion converts a TLS version string to the corresponding
// crypto/tls constant, returning 0 when the value is not recognized.
func parseACMETLSVersion(version string) uint16 {
	switch version {
	case "TLS1.2", "tls1.2", "1.2":
		return tls.VersionTLS12
	case "TLS1.3", "tls1.3", "1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

// acmeBackendError wraps ErrACMEBackendUnavailable with the offending
// backend name for diagnostic messages.
type acmeBackendError struct {
	Backend string
	Err     error
}

func (e *acmeBackendError) Error() string {
	return "acme: keystore backend \"" + e.Backend + "\" not available"
}

func (e *acmeBackendError) Unwrap() error { return e.Err }

// acmeInitError is the standard error type for ACME initialization failures.
// It captures the initialization stage, an optional sentinel for Is/As
// matching, and the underlying cause.
type acmeInitError struct {
	Stage    string
	Sentinel error
	Err      error
}

func (e *acmeInitError) Error() string {
	if e.Err == nil {
		return "acme: " + e.Stage
	}
	return "acme: " + e.Stage + ": " + e.Err.Error()
}

// Unwrap returns both the classifying sentinel and the underlying cause, so
// errors.Is matches either: callers typically match Sentinel, but the cause
// (e.g. a typed error stored in Err) must also be reachable.
func (e *acmeInitError) Unwrap() []error {
	if e.Sentinel != nil && e.Err != nil {
		return []error{e.Sentinel, e.Err}
	}
	if e.Sentinel != nil {
		return []error{e.Sentinel}
	}
	return []error{e.Err}
}
