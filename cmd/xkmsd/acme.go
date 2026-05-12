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
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	objstorelocal "github.com/jeremyhahn/go-objstore/pkg/local"

	dns01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01"
	http01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/http-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	nativeca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
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

	// ErrACMEListen is returned when the ACME listener cannot be bound.
	ErrACMEListen = errors.New("acme: failed to bind listener")
)

// acmeServer holds the runtime state of the embedded ACME HTTPS server so it
// can be gracefully shut down alongside the primary xkmsd server.
type acmeServer struct {
	httpServer *http.Server
	listener   net.Listener
	logger     *slog.Logger

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
	// All ACME persistence routes through this factory via the handlers.
	stateStore := objstorelocal.New()
	if err := stateStore.Configure(map[string]string{
		"path": filepath.Join(dataDir, "state"),
	}); err != nil {
		return nil, &acmeInitError{Stage: "configure state store", Err: err}
	}
	storageFactory, err := acmeobjstore.NewFactory(stateStore)
	if err != nil {
		return nil, &acmeInitError{Stage: "create storage factory", Err: err}
	}

	// Build the challenge verifier map based on configured challenge types.
	challengeMap := buildChallengeMap(acmeCfg.Challenges)

	// Normalize directory path. The ACME routes are mounted under this prefix.
	directoryPath := acmeCfg.DirectoryPath
	if directoryPath == "" {
		directoryPath = "/acme"
	}
	directoryPath = "/" + strings.Trim(directoryPath, "/")

	// Construct the REST service that implements all ACME HTTP handlers.
	// tcgCA is the primary xkmsd TrustedCA asserted to TCGCA above; the
	// ACME handlers rely on the TCG extensions (IssueEKCertificate,
	// SignTCGCSRIDevID, ...) exposed by *pkg/ca.CA.
	service, err := handlers.NewRestService(&handlers.Params{
		BaseRESTURI:             acmeCfg.ExternalURL,
		CA:                      tcgCA,
		CAAIdentities:           acmeCfg.CAAIdentities,
		ChallengeMap:            challengeMap,
		EndorseEABRequired:      acmeCfg.EndorseEABRequired,
		EndorseDeviceIDMetaKey:  acmeCfg.EndorseDeviceIDMetaKey,
		ExternalAccountRequired: acmeCfg.ExternalAccountRequired,
		Logger:                  logger,
		StorageFactory:          storageFactory,
		TermsOfService:          acmeCfg.TermsOfService,
	})
	if err != nil {
		return nil, &acmeInitError{Stage: "create REST service", Sentinel: ErrACMERestService, Err: err}
	}

	// Build the HTTP router and mount the ACME routes.
	router := buildACMERouter(service, directoryPath)

	// Build the TLS configuration. Currently only dedicated TLS material is
	// supported; reusing the xkmsd TLS config is deferred to a follow-up.
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
		httpServer: httpSrv,
		listener:   ln,
		logger:     logger,
		doneCh:     make(chan struct{}),
	}

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
func buildChallengeMap(cfg config.ACMEChallengesConfig) map[string]common.ChallengeVerifierFunc {
	m := make(map[string]common.ChallengeVerifierFunc, 2)
	if cfg.HTTP01 {
		m[common.ChallengeTypeHTTP01] = func(
			resolver *net.Resolver,
			_ common.CertificateAuthority,
			authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
			return http01.Verify(resolver, nil, authzValue, challengePort, challengeToken, expectedKeyAuth)
		}
	}
	if cfg.DNS01 {
		m[common.ChallengeTypeDNS01] = func(
			resolver *net.Resolver,
			_ common.CertificateAuthority,
			authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
			return dns01.Verify(resolver, nil, authzValue, challengePort, challengeToken, expectedKeyAuth)
		}
	}
	return m
}

// buildACMERouter mounts the ACME REST handlers on a gorilla/mux router
// under the given directory path prefix. The route layout follows
// RFC 8555 Section 7.1.
func buildACMERouter(svc handlers.RestServicer, directoryPath string) http.Handler {
	r := mux.NewRouter()
	r.HandleFunc(directoryPath+"/directory", svc.DirectoryHandler).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc(directoryPath+"/new-nonce", svc.NewNonceHandler).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc(directoryPath+"/new-account", svc.NewAccountHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/account/{id:[0-9]+}", svc.AccountHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/new-order", svc.NewOrderHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/order/{id:[0-9]+}", svc.OrderHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/order/{id:[0-9]+}/finalize", svc.OrderFinalizeHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/orders/{id:[0-9]+}", svc.OrdersListHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/authz/{id:[0-9]+}", svc.AuthorizationHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/challenge/{id:[0-9]+}", svc.ChallengeHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/cert/{id:[0-9]+}", svc.CertificateHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/revoke-cert", svc.RevokeCertHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/key-change", svc.KeyChangeHandler).Methods(http.MethodPost)
	r.HandleFunc(directoryPath+"/ca-bundle", svc.CABundleHandler).Methods(http.MethodGet, http.MethodHead)
	return r
}

// buildACMETLSConfig loads the TLS material for the ACME listener.
//
// Reuse of the primary xkmsd TLS config (acme.reuse_tls: true) is a
// follow-up item: the xkmsd TLS stack is authenticated against the xkmsd
// REST/gRPC server CN and would generally not match an ACME client's
// expected hostname. Operators should provision a dedicated TLS cert for
// the ACME endpoint until that support lands.
func buildACMETLSConfig(cfg *config.ACMEConfig) (*tls.Config, error) {
	if cfg.ReuseTLS {
		return nil, errors.New("acme: reuse_tls is not yet supported; set acme.tls.cert_file and acme.tls.key_file")
	}
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
				return nil, &acmeInitError{Stage: "parse client CA " + path, Sentinel: ErrACMEClientCALoad, Err: errors.New("no PEM certificates parsed")}
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

func (e *acmeInitError) Unwrap() error {
	if e.Sentinel != nil {
		return e.Sentinel
	}
	return e.Err
}
