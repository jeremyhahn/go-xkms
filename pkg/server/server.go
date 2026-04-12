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

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	flynn_noise "github.com/flynn/noise"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	noiseproto "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
	grpcinternal "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/quic"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/unix"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/authz"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/bootstrap"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
	"github.com/jeremyhahn/go-xkms/pkg/health"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/rbac"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/user"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Server represents the unified xkms server that runs all protocols
type Server struct {
	config       *config.Config
	mu           sync.RWMutex
	backends     map[string]xkms.Backend
	keyProviders map[string]types.KeyProvider
	logger       *slog.Logger

	// Protocol servers
	unixGRPCServer       *unix.GRPCServer
	restServer           *rest.Server
	grpcServer           *grpc.Server
	quicServer           *quic.Server
	mcpServer            *mcp.Server
	noiseBootstrapServer *noiseboot.Server

	// User management
	userStore user.Store

	// Authentication
	authenticator  auth.Authenticator
	webauthnConfig *webauthn.Config

	// Authorization
	authorizer authz.Authorizer

	// Audit logging
	auditLogger audit.Logger

	// Barrier (seal/unseal)
	barrier *seal.Barrier

	// Barrier registry (multi-tenant)
	barrierRegistry *seal.BarrierRegistry

	// Bootstrap service (server initialization)
	bootstrapService *bootstrap.Service

	// PIN backend
	pinManager pin.PINBackend

	// Password store
	passwordStore *staticpw.BackendStore

	// Platform store
	platformStore seal.PlatformStore

	// Policy manager
	policyManager *policy.Manager

	// Custodian group management
	custodianService *custodian.Service

	// Share store for Shamir share management
	shareStore sharestore.ShareStore

	// Health checker
	healthChecker *health.Checker

	// Metrics
	metricsCollector *metrics.ResourceCollector

	// CA for certificate authority operations
	ca ca.XKMSCA

	// Credential service for managing backend credentials
	credentialService *credentialspkg.Service

	// Ceremony service for init ceremony
	ceremonyService *initialize.CeremonyService

	// Lifecycle
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	shutdownCh chan struct{}
}

// New creates a new unified server instance
func New(cfg *config.Config) (*Server, error) {
	// Setup logging
	logger := setupLogger(cfg.Logging)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:       cfg,
		keyProviders: make(map[string]types.KeyProvider),
		backends:     make(map[string]xkms.Backend),
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		shutdownCh:   make(chan struct{}),
	}

	// Initialize backends
	if err := s.initializeBackends(); err != nil {
		cancel()
		return nil, &ErrServiceInit{Service: "backends", Err: err}
	}

	// Initialize keystore with default backend
	if err := s.initializeKeyStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "keystore", Err: err}
	}

	// Initialize user store
	if err := s.initializeUserStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "user store", Err: err}
	}

	// Initialize authentication
	if err := s.initializeAuthentication(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "authentication", Err: err}
	}

	// Initialize authorization
	if err := s.initializeAuthorization(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "authorization", Err: err}
	}

	// Initialize audit logger
	if err := s.initializeAuditLogger(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "audit logger", Err: err}
	}

	// Initialize barrier (seal/unseal)
	if err := s.initializeBarrier(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "barrier", Err: err}
	}

	// Initialize barrier registry
	if err := s.initializeBarrierRegistry(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "barrier registry", Err: err}
	}

	// Initialize custodian group service
	if err := s.initializeCustodianService(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "custodian service", Err: err}
	}

	// Initialize share store
	if err := s.initializeShareStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "share store", Err: err}
	}

	// Initialize bootstrap service
	if err := s.initializeBootstrapService(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "bootstrap service", Err: err}
	}

	// Initialize PIN manager
	if err := s.initializePINManager(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "PIN manager", Err: err}
	}

	// Initialize password store
	if err := s.initializePasswordStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "password store", Err: err}
	}

	// Initialize platform store
	if err := s.initializePlatformStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "platform store", Err: err}
	}

	// Initialize credential service
	if err := s.initializeCredentialService(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "credential service", Err: err}
	}

	// Initialize policy manager
	if err := s.initializePolicyManager(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "policy manager", Err: err}
	}

	// Initialize health checker
	if err := s.initializeHealth(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "health checker", Err: err}
	}

	// Initialize CA from config (optional)
	if err := s.initializeCA(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "CA", Err: err}
	}

	// Wire all subsystems into the XKMSService singleton so it implements
	// the full embedded.XKMSServicer interface for in-process SDK access.
	if svc, err := xkms.Get(); err == nil {
		if s.barrier != nil {
			svc.SetBarrier(s.barrier)
		}
		if s.pinManager != nil {
			svc.SetPINManager(s.pinManager)
		}
		if s.userStore != nil {
			svc.SetUserStore(s.userStore)
		}
		if s.passwordStore != nil {
			svc.SetPasswordStore(s.passwordStore)
			// Wire tenant password store manager if barrier registry is available
			if s.barrierRegistry != nil {
				pwManager, pwErr := staticpw.NewTenantPasswordStoreManager(s.barrierRegistry, s.passwordStore)
				if pwErr != nil {
					s.logger.Warn("Failed to create tenant password store manager", "error", pwErr)
				} else {
					svc.SetPasswordStoreManager(pwManager)
					s.logger.Info("Tenant password store manager wired into service")
				}
			}
		}
		if s.platformStore != nil {
			svc.SetPlatformStore(s.platformStore)
		}
		if s.policyManager != nil {
			svc.SetPolicyManager(s.policyManager)
		}
		if s.custodianService != nil {
			svc.SetCustodianService(s.custodianService)
		}
		if s.shareStore != nil {
			svc.SetShareStore(s.shareStore)
		}
		if s.barrierRegistry != nil {
			svc.SetBarrierRegistry(s.barrierRegistry)
		}
		if s.credentialService != nil {
			svc.SetCredentialService(s.credentialService)
		}
		if s.ceremonyService != nil {
			svc.SetCeremonyService(initialize.NewCeremonyAdapter(s.ceremonyService))
		}
		if s.ca != nil {
			// s.ca is ca.XKMSCA which doesn't include the *Raw adapter methods.
			// The concrete *ca.CA struct satisfies provider.CA via its Raw methods
			// in service_adapter.go. Type-assert to wire the typed interface.
			if caProvider, ok := s.ca.(provider.CA); ok {
				svc.SetCA(caProvider)
			}
		}
	}

	return s, nil
}

// setupLogger configures the logger based on config
func setupLogger(cfg config.LoggingConfig) *slog.Logger {
	// Parse log level
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Create handler options
	opts := &slog.HandlerOptions{
		Level: level,
	}

	// Create handler based on format
	var handler slog.Handler
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	case "text", "console":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

// getBuildVersion retrieves the version from build information
func getBuildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	// Try to get version from VCS (git tag)
	for _, setting := range info.Settings {
		if setting.Key == "vcs.version" {
			if setting.Value != "" && setting.Value != "devel" {
				return setting.Value
			}
		}
		if setting.Key == "vcs.revision" {
			// Get short commit hash (first 7 chars)
			if len(setting.Value) >= 7 {
				return setting.Value[:7]
			}
			return setting.Value
		}
	}

	// Try module version
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return "dev"
}

// initializeBackends creates and initializes all enabled backends
func (s *Server) initializeBackends() error {
	s.logger.Info("Initializing backends...")

	// Initialize Software backend (unified asymmetric + symmetric with import/export support)
	if s.config.Backends.Software != nil && s.config.Backends.Software.Enabled {
		keyStorage, err := s.createStorageAt(s.config.Backends.Software.Path)
		if err != nil {
			return &ErrStorageCreate{Resource: "software key storage", Err: err}
		}

		softwareBackend, err := software.NewBackend(&software.Config{
			KeyStorage: keyStorage,
		})
		if err != nil {
			return &ErrBackendCreate{Backend: "software", Err: err}
		}

		s.keyProviders["software"] = softwareBackend
		s.logger.Info("Software backend initialized", "backend", "software", "path", s.config.Backends.Software.Path)
	}

	// Initialize PKCS8 backend (software keys)
	if s.config.Backends.PKCS8 != nil && s.config.Backends.PKCS8.Enabled {
		keyStorage, err := s.createStorageAt(s.config.Backends.PKCS8.Path)
		if err != nil {
			return &ErrStorageCreate{Resource: "PKCS8 key storage", Err: err}
		}

		pkcs8Backend, err := pkcs8.NewBackend(&pkcs8.Config{
			KeyStorage: keyStorage,
		})
		if err != nil {
			return &ErrBackendCreate{Backend: "PKCS8", Err: err}
		}

		s.keyProviders["pkcs8"] = pkcs8Backend
		s.logger.Info("PKCS8 backend initialized", "backend", "pkcs8", "path", s.config.Backends.PKCS8.Path)
	}

	// Initialize other backends based on build tags
	// Each backend has separate files with build tags that automatically
	// compile the real implementation or a stub based on build flags

	if err := s.initTPM2Backend(); err != nil {
		return &ErrBackendInit{Backend: "TPM2", Err: err}
	}

	if err := s.initPKCS11Backend(); err != nil {
		return &ErrBackendInit{Backend: "PKCS#11", Err: err}
	}

	if err := s.initAWSKMSBackend(); err != nil {
		return &ErrBackendInit{Backend: "AWS KMS", Err: err}
	}

	if err := s.initGCPKMSBackend(); err != nil {
		return &ErrBackendInit{Backend: "GCP KMS", Err: err}
	}

	if err := s.initAzureKVBackend(); err != nil {
		return &ErrBackendInit{Backend: "Azure Key Vault", Err: err}
	}

	if err := s.initVaultBackend(); err != nil {
		return &ErrBackendInit{Backend: "Vault", Err: err}
	}

	if err := s.initPhoneBackend(); err != nil {
		return &ErrBackendInit{Backend: "phone", Err: err}
	}

	if len(s.keyProviders) == 0 {
		return ErrNoBackendsInitialized
	}

	return nil
}

// initializeKeyStore creates keystores for all backends
func (s *Server) initializeKeyStore() error {
	// Create certificate storage (shared across all keystores)
	certStorage, err := s.createStorage("certs")
	if err != nil {
		return &ErrStorageCreate{Resource: "certificate storage", Err: err}
	}

	// Create a keystore for each backend
	for name, backend := range s.keyProviders {
		keystore, err := xkms.New(&xkms.BackendConfig{
			Backend:     backend,
			CertStorage: certStorage,
		})
		if err != nil {
			return &ErrKeystoreCreate{Backend: name, Err: err}
		}

		s.backends[name] = keystore
		s.logger.Info("KeyStore initialized", "backend", name)
	}

	if len(s.backends) == 0 {
		return ErrNoKeystoresInitialized
	}

	// Determine default backend
	defaultBackend := string(s.config.Default)
	if _, ok := s.backends[defaultBackend]; !ok {
		// Fall back to first available backend
		for name := range s.backends {
			defaultBackend = name
			break
		}
	}

	// Initialize the global xkms service with the keystores
	// This allows REST handlers to access backends via xkms.Backends()
	serviceConfig := &xkms.ServiceConfig{
		Backends:       s.backends,
		DefaultBackend: defaultBackend,
	}
	if err := xkms.Initialize(serviceConfig); err != nil {
		return &ErrServiceInit{Service: "xkms service", Err: err}
	}

	s.logger.Info("xKMS service initialized",
		"default_backend", defaultBackend,
		"backends", len(s.backends))

	return nil
}

// initializeUserStore creates the user store.
func (s *Server) initializeUserStore() error {
	s.logger.Info("Initializing user store...")

	// Storage path for logging
	userStoragePath := s.config.Storage.Path + "/users"
	userStorage, err := s.createStorage("users")
	if err != nil {
		return &ErrStorageCreate{Resource: "user storage", Err: err}
	}

	// Create user store
	userStore, err := user.NewFileStore(userStorage)
	if err != nil {
		return &ErrServiceInit{Service: "user store", Err: err}
	}

	s.userStore = userStore
	s.logger.Info("User store initialized", "path", userStoragePath)

	// Check if bootstrap is required
	hasUsers, err := userStore.HasAnyUsers(s.ctx)
	if err != nil {
		s.logger.Warn("Failed to check user status", slog.Any("error", err))
	} else if !hasUsers {
		s.logger.Info("No users configured - first user registration required")
	}

	return nil
}

// initializeAuthentication sets up the authentication subsystem.
// It configures adaptive authentication that automatically switches between:
// - NoOp mode (when no users exist) - allows all requests for bootstrap
// - Required auth mode (when users exist) - requires JWT or mTLS authentication
func (s *Server) initializeAuthentication() error {
	s.logger.Info("Initializing authentication...")

	// Build WebAuthn config if enabled (do this first as WebAuthn can work independently
	// of the general auth system - it IS a form of authentication)
	if s.config.WebAuthn != nil && s.config.WebAuthn.Enabled {
		s.webauthnConfig = &webauthn.Config{
			RPID:                    s.config.WebAuthn.RPID,
			RPOrigins:               s.config.WebAuthn.RPOrigins,
			RPDisplayName:           s.config.WebAuthn.RPDisplayName,
			AttestationPreference:   s.config.WebAuthn.AttestationPreference,
			AuthenticatorAttachment: s.config.WebAuthn.AuthenticatorAttachment,
			ResidentKeyRequirement:  s.config.WebAuthn.ResidentKey,
			UserVerification:        s.config.WebAuthn.UserVerification,
		}

		// Set defaults for any unset values
		s.webauthnConfig.SetDefaults()

		s.logger.Info("WebAuthn configured",
			"rp_id", s.config.WebAuthn.RPID,
			"rp_display_name", s.config.WebAuthn.RPDisplayName)
	}

	// If auth is disabled, use NoOp authenticator
	if !s.config.Auth.Enabled {
		s.authenticator = auth.NewNoOpAuthenticator()
		s.logger.Info("Authentication disabled, using NoOp authenticator")
		return nil
	}

	// Determine the required authenticator based on config type
	var requiredAuth auth.Authenticator
	switch s.config.Auth.Type {
	case "jwt":
		// JWT authenticator requires a public key
		if s.config.Auth.JWT == nil || s.config.Auth.JWT.PublicKeyFile == "" {
			return ErrJWTPublicKeyRequired
		}
		jwtAuth, err := s.createJWTAuthenticator()
		if err != nil {
			return &ErrServiceInit{Service: "JWT authenticator", Err: err}
		}
		requiredAuth = jwtAuth
		s.logger.Info("JWT authentication configured",
			"issuer", s.config.Auth.JWT.Issuer)

	case "mtls":
		// mTLS authentication uses client certificates
		if !s.config.TLS.Enabled {
			return ErrMTLSRequiresTLS
		}
		mtlsConfig := &auth.MTLSConfig{}
		if s.userStore != nil {
			mtlsConfig.UserStore = user.NewMTLSUserStoreAdapter(s.userStore)
		}
		mtlsAuth := auth.NewMTLSAuthenticator(mtlsConfig)
		requiredAuth = mtlsAuth
		s.logger.Info("mTLS authentication configured")

	case "composite":
		compositeAuth, err := s.createCompositeAuthenticator()
		if err != nil {
			return err
		}
		requiredAuth = compositeAuth

	case "adaptive":
		// Adaptive mode will be configured below
		s.logger.Info("Adaptive authentication mode enabled")

	default:
		// Default to NoOp if type is not recognized
		s.authenticator = auth.NewNoOpAuthenticator()
		s.logger.Warn("Unknown auth type, using NoOp authenticator", "type", s.config.Auth.Type)
		return nil
	}

	// If adaptive mode is enabled or explicitly configured, wrap the authenticator
	if s.config.Auth.Adaptive || s.config.Auth.Type == "adaptive" {
		// For adaptive mode, we need a required authenticator
		// If none was configured, default to JWT (for WebAuthn flow)
		if requiredAuth == nil {
			// Try to create JWT authenticator if WebAuthn is configured
			if s.config.WebAuthn != nil && s.config.WebAuthn.Enabled {
				if s.config.Auth.JWT != nil && s.config.Auth.JWT.PublicKeyFile != "" {
					jwtAuth, err := s.createJWTAuthenticator()
					if err != nil {
						s.logger.Warn("Failed to create JWT authenticator for adaptive mode, falling back to NoOp",
							slog.Any("error", err))
						requiredAuth = auth.NewNoOpAuthenticator()
					} else {
						requiredAuth = jwtAuth
					}
				} else {
					// No JWT config, use NoOp for now
					s.logger.Warn("Adaptive mode enabled but no JWT config, using NoOp for required auth")
					requiredAuth = auth.NewNoOpAuthenticator()
				}
			} else {
				requiredAuth = auth.NewNoOpAuthenticator()
			}
		}

		adaptiveAuth, err := auth.NewAdaptiveAuthenticator(&auth.AdaptiveConfig{
			UserChecker:           s.userStore,
			RequiredAuthenticator: requiredAuth,
			CacheExpiry:           30 * time.Second,
			Logger:                s.logger.With("component", "auth"),
		})
		if err != nil {
			return &ErrServiceInit{Service: "adaptive authenticator", Err: err}
		}

		s.authenticator = adaptiveAuth
		s.logger.Info("Adaptive authentication initialized",
			"required_auth", requiredAuth.Name())
	} else if requiredAuth != nil {
		s.authenticator = requiredAuth
	} else {
		s.authenticator = auth.NewNoOpAuthenticator()
	}

	return nil
}

// createCompositeAuthenticator builds a CompositeAuthenticator from the
// configured composite authentication methods.
func (s *Server) createCompositeAuthenticator() (*auth.CompositeAuthenticator, error) {
	if s.config.Auth.Composite == nil || len(s.config.Auth.Composite.Methods) == 0 {
		return nil, ErrCompositeMethodsRequired
	}

	authenticators := make([]auth.Authenticator, 0, len(s.config.Auth.Composite.Methods))

	// compositeMethodFactory maps method names to factory functions for O(1) dispatch.
	type methodFactory func() (auth.Authenticator, error)
	compositeMethodFactory := map[string]methodFactory{
		"jwt": func() (auth.Authenticator, error) {
			if s.config.Auth.JWT == nil || s.config.Auth.JWT.PublicKeyFile == "" {
				return nil, ErrCompositeJWTRequired
			}
			return s.createJWTAuthenticator()
		},
		"mtls": func() (auth.Authenticator, error) {
			if !s.config.TLS.Enabled {
				return nil, ErrCompositeMTLSRequiresTLS
			}
			mtlsConfig := &auth.MTLSConfig{}
			if s.userStore != nil {
				mtlsConfig.UserStore = user.NewMTLSUserStoreAdapter(s.userStore)
			}
			return auth.NewMTLSAuthenticator(mtlsConfig), nil
		},
	}

	for _, method := range s.config.Auth.Composite.Methods {
		factory, ok := compositeMethodFactory[method]
		if !ok {
			return nil, &ErrCompositeMethodCreate{Method: method, Err: ErrUnknownCompositeMethod}
		}
		authenticator, err := factory()
		if err != nil {
			return nil, &ErrCompositeMethodCreate{Method: method, Err: err}
		}
		authenticators = append(authenticators, authenticator)
	}

	compositeAuth, err := auth.NewCompositeAuthenticator(authenticators...)
	if err != nil {
		return nil, &ErrServiceInit{Service: "composite authenticator", Err: err}
	}

	s.logger.Info("Composite authentication configured", "methods", s.config.Auth.Composite.Methods)
	return compositeAuth, nil
}

// initializeAuthorization sets up the authorization subsystem.
// When RBAC is enabled, it creates an RBACAuthorizer backed by a MemoryRBACAdapter.
// Otherwise, it uses a NoOpAuthorizer that permits all requests.
func (s *Server) initializeAuthorization() error {
	s.logger.Info("Initializing authorization...")

	if s.config.Auth.EnableRBAC {
		adapter := rbac.NewMemoryRBACAdapter(true)
		s.authorizer = authz.NewRBACAuthorizer(adapter)
		s.logger.Info("RBAC authorization enabled")
	} else {
		s.authorizer = &authz.NoOpAuthorizer{}
		s.logger.Info("Authorization disabled, using NoOp authorizer")
	}

	return nil
}

// initializeAuditLogger sets up the audit logging subsystem.
// When audit logging is enabled, it creates a FileLogger at the configured path.
// Otherwise, it uses a NoOpLogger that discards all events.
func (s *Server) initializeAuditLogger() error {
	s.logger.Info("Initializing audit logger...")

	if s.config.Auth.Audit != nil && s.config.Auth.Audit.Enabled {
		if s.config.Auth.Audit.Path == "" {
			return ErrAuditPathRequired
		}
		fileLogger, err := audit.NewFileLogger(&audit.FileLoggerConfig{
			Path: s.config.Auth.Audit.Path,
		})
		if err != nil {
			return &ErrServiceInit{Service: "audit file logger", Err: err}
		}
		s.auditLogger = fileLogger
		s.logger.Info("Audit logging enabled", "path", s.config.Auth.Audit.Path)
	} else {
		s.auditLogger = &audit.NoOpLogger{}
		s.logger.Info("Audit logging disabled, using NoOp logger")
	}

	return nil
}

// initializeBarrier creates and configures the barrier (seal/unseal) subsystem.
// The barrier wraps storage with transparent AES-256-GCM encryption.
func (s *Server) initializeBarrier() error {
	if !s.config.Barrier.Enabled {
		s.logger.Info("Barrier disabled")
		return nil
	}

	s.logger.Info("Initializing barrier...")

	// Create barrier storage backend
	barrierStorage, err := s.createStorage("barrier")
	if err != nil {
		return &ErrStorageCreate{Resource: "barrier storage", Err: err}
	}

	// Build sealing strategies
	strategies := []seal.SealingStrategy{
		seal.NewSoftwareStrategy(),
	}

	// Determine root key path
	rootKeyPath := s.config.Barrier.RootKeyPath
	if rootKeyPath == "" {
		rootKeyPath = "barrier/root-key"
	}

	// Build preference order
	var prefOrder []seal.StrategyID
	for _, id := range s.config.Barrier.PreferenceOrder {
		prefOrder = append(prefOrder, seal.StrategyID(id))
	}

	barrierConfig := seal.BarrierConfig{
		RootKeyPath:     rootKeyPath,
		PreferenceOrder: prefOrder,
		AuditLogger:     s.auditLogger,
	}

	barrier, err := seal.NewBarrier(s.logger, barrierStorage, barrierConfig, strategies...)
	if err != nil {
		return &ErrServiceInit{Service: "barrier", Err: err}
	}

	s.barrier = barrier
	s.logger.Info("Barrier initialized", "root_key_path", rootKeyPath)

	return nil
}

// initializeBarrierRegistry creates the barrier registry for multi-tenant isolation.
func (s *Server) initializeBarrierRegistry() error {
	if s.barrier == nil {
		s.logger.Info("Barrier registry skipped (no barrier)")
		return nil
	}

	registry, err := seal.NewBarrierRegistry(s.barrier)
	if err != nil {
		return &ErrServiceInit{Service: "barrier registry", Err: err}
	}

	s.barrierRegistry = registry
	s.logger.Info("Barrier registry initialized")

	return nil
}

// initializeCustodianService creates the custodian group management service.
func (s *Server) initializeCustodianService() error {
	store := custodian.NewMemoryStore()
	svc, err := custodian.NewService(store)
	if err != nil {
		return &ErrServiceInit{Service: "custodian service", Err: err}
	}
	s.custodianService = svc
	s.logger.Info("Custodian group service initialized")
	return nil
}

// initializeShareStore creates the Shamir share store.
func (s *Server) initializeShareStore() error {
	s.shareStore = sharestore.NewMemoryShareStore()
	s.logger.Info("Share store initialized")
	return nil
}

// initializeBootstrapService creates the bootstrap service for server initialization.
func (s *Server) initializeBootstrapService() error {
	if !s.config.InitBootstrap.Enabled {
		s.logger.Info("Bootstrap service disabled")
		return nil
	}

	if s.userStore == nil {
		return ErrBootstrapRequiresUserStore
	}

	bsCfg := bootstrap.Config{
		TokenTTL:       s.config.InitBootstrap.TokenTTL,
		ThresholdMode:  s.config.InitBootstrap.ThresholdMode,
		AdminThreshold: s.config.InitBootstrap.AdminThreshold,
		AdminTotal:     s.config.InitBootstrap.AdminTotal,
	}

	svc, err := bootstrap.NewService(bsCfg, s.userStore, s.logger)
	if err != nil {
		return &ErrServiceInit{Service: "bootstrap service", Err: err}
	}

	s.bootstrapService = svc
	s.logger.Info("Bootstrap service initialized",
		"threshold_mode", bsCfg.ThresholdMode)

	return nil
}

// initializePINManager creates and configures the PIN management subsystem.
func (s *Server) initializePINManager() error {
	if !s.config.PIN.Enabled {
		s.logger.Info("PIN management disabled")
		return nil
	}

	s.logger.Info("Initializing PIN manager...")

	// Create the PIN manager based on strategy
	strategy := s.config.PIN.Strategy
	if strategy == "" {
		strategy = "software"
	}

	pinDir := s.config.Storage.Path + "/pin"

	switch strategy {
	case "software":
		fileStore, err := filestorage.New(pinDir)
		if err != nil {
			return &ErrStorageCreate{Resource: "PIN state directory", Err: err}
		}
		hashConfig := pin.AutoDetectHashConfig()
		backend, err := pin.NewSoftwareBackend(fileStore, hashConfig)
		if err != nil {
			return &ErrServiceInit{Service: "software PIN manager", Err: err}
		}
		s.pinManager = backend
	default:
		return &ErrUnknownPINStrategy{Strategy: strategy}
	}

	s.logger.Info("PIN manager initialized",
		slog.String("strategy", strategy))

	return nil
}

// initializePasswordStore initializes the static password store.
func (s *Server) initializePasswordStore() error {
	passwordStoragePath := s.config.Storage.Path + "/passwords"

	backend, err := s.createStorage("passwords")
	if err != nil {
		return &ErrStorageCreate{Resource: "password storage", Err: err}
	}

	s.passwordStore = staticpw.NewStore(backend)
	s.logger.Info("Password store initialized", "path", passwordStoragePath)
	return nil
}

// initializePlatformStore initializes the platform sealed credential store.
func (s *Server) initializePlatformStore() error {
	// Platform store requires barrier to be initialized for sealing
	if s.barrier == nil {
		s.logger.Info("Platform store skipped: barrier not configured")
		return nil
	}

	s.logger.Info("Platform store initialized")
	return nil
}

// initializeCredentialService initializes the credential management service
// for sealing/unsealing backend credentials (PKCS#11 User PIN, TPM2 auth, etc.)
func (s *Server) initializeCredentialService() error {
	strategy := s.config.Credentials.SealStrategy
	if strategy == "" {
		strategy = "manual"
	}

	cfg := &credentialspkg.Config{
		Strategy: strategy,
	}

	svc, err := credentialspkg.New(cfg, s.platformStore, s.barrier, s.logger)
	if err != nil {
		return &ErrServiceInit{Service: "credential service", Err: err, Sentinel: ErrCredentialServiceFailed}
	}

	s.credentialService = svc
	s.logger.Info("Credential service initialized", "strategy", strategy)
	return nil
}

// initializePolicyManager initializes the PCR policy manager.
func (s *Server) initializePolicyManager() error {
	// Policy manager is optional, only for TPM-equipped servers
	s.logger.Info("Policy manager initialization deferred (requires TPM PCR reader)")
	return nil
}

// Barrier returns the barrier instance.
func (s *Server) Barrier() *seal.Barrier {
	return s.barrier
}

// BarrierRegistry returns the barrier registry instance.
func (s *Server) BarrierRegistry() *seal.BarrierRegistry {
	return s.barrierRegistry
}

// BootstrapService returns the bootstrap service instance.
func (s *Server) BootstrapService() *bootstrap.Service {
	return s.bootstrapService
}

// PINBackend returns the PIN backend instance.
func (s *Server) PINBackend() pin.PINBackend {
	return s.pinManager
}

// PasswordStore returns the password store instance.
func (s *Server) PasswordStore() *staticpw.BackendStore {
	return s.passwordStore
}

// PlatformStore returns the platform store instance.
func (s *Server) PlatformStore() seal.PlatformStore {
	return s.platformStore
}

// PolicyManager returns the policy manager instance.
func (s *Server) PolicyManager() *policy.Manager {
	return s.policyManager
}

// SetCA sets the Certificate Authority for CA-backed TLS and certificate operations.
func (s *Server) SetCA(basicCA ca.XKMSCA) {
	s.ca = basicCA
}

// SetCeremonyService sets the init ceremony service.
func (s *Server) SetCeremonyService(svc *initialize.CeremonyService) {
	s.ceremonyService = svc
}

// SetCredentialService sets the credential management service.
func (s *Server) SetCredentialService(svc *credentialspkg.Service) {
	s.credentialService = svc
}

// CredentialService returns the credential management service.
func (s *Server) CredentialService() *credentialspkg.Service {
	return s.credentialService
}

// createJWTAuthenticator creates a JWT authenticator from configuration.
func (s *Server) createJWTAuthenticator() (*auth.JWTAuthenticator, error) {
	if s.config.Auth.JWT == nil {
		return nil, ErrJWTConfigRequired
	}

	// Load public key from file
	pubKeyData, err := os.ReadFile(s.config.Auth.JWT.PublicKeyFile)
	if err != nil {
		return nil, &ErrFileRead{Path: "public key file", Err: err}
	}

	// Parse the public key (supports PEM-encoded ECDSA or RSA keys)
	pubKey, err := parsePublicKey(pubKeyData)
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "parse public key", Err: err}
	}

	return auth.NewJWTAuthenticator(&auth.JWTConfig{
		PublicKey:  pubKey,
		Issuer:     s.config.Auth.JWT.Issuer,
		Audience:   s.config.Auth.JWT.Audience,
		HeaderName: "Authorization",
	})
}

// parsePublicKey parses a PEM-encoded public key.
func parsePublicKey(data []byte) (interface{}, error) {
	// Try parsing as PEM first
	block, _ := pemDecode(data)
	if block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			return key, nil
		}
		// Try parsing as certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return cert.PublicKey, nil
		}
	}

	// Try parsing as raw DER
	key, err := x509.ParsePKIXPublicKey(data)
	if err == nil {
		return key, nil
	}

	return nil, ErrParsePublicKey
}

// pemDecode decodes a PEM block.
func pemDecode(data []byte) (*pemBlock, []byte) {
	// Simple PEM decoder
	const pemHeader = "-----BEGIN "
	const pemFooter = "-----END "

	start := bytes.Index(data, []byte(pemHeader))
	if start < 0 {
		return nil, data
	}

	rest := data[start+len(pemHeader):]
	endOfType := bytes.IndexByte(rest, '-')
	if endOfType < 0 {
		return nil, data
	}

	blockType := string(rest[:endOfType])
	rest = rest[endOfType:]

	// Find end of header line
	headerEnd := bytes.IndexByte(rest, '\n')
	if headerEnd < 0 {
		return nil, data
	}
	rest = rest[headerEnd+1:]

	// Find footer
	footer := []byte(pemFooter + blockType)
	footerStart := bytes.Index(rest, footer)
	if footerStart < 0 {
		return nil, data
	}

	base64Data := rest[:footerStart]
	// Remove newlines and decode base64
	base64Data = bytes.ReplaceAll(base64Data, []byte("\n"), nil)
	base64Data = bytes.ReplaceAll(base64Data, []byte("\r"), nil)

	decoded := make([]byte, base64Encoding.DecodedLen(len(base64Data)))
	n, err := base64Encoding.Decode(decoded, base64Data)
	if err != nil {
		return nil, data
	}

	// Find end of footer line
	rest = rest[footerStart+len(footer):]
	if len(rest) > 0 && rest[0] == '\n' {
		rest = rest[1:]
	}

	return &pemBlock{
		Type:  blockType,
		Bytes: decoded[:n],
	}, rest
}

type pemBlock struct {
	Type  string
	Bytes []byte
}

// base64Encoding is the standard base64 encoding for PEM data
var base64Encoding = base64.StdEncoding

// initializeHealth creates and configures the health checker.
func (s *Server) initializeHealth() error {
	s.logger.Info("Initializing health checker...")

	s.healthChecker = health.NewChecker()

	// Register backend health checks
	for name, keystore := range s.backends {
		backendName := name // Capture for closure
		ks := keystore      // Capture for closure

		s.healthChecker.RegisterCheck(fmt.Sprintf("backend-%s", backendName), func(ctx context.Context) health.CheckResult {
			start := time.Now()

			// Check if backend is responsive by listing keys with a timeout
			checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			// Run the check in a goroutine to respect the timeout
			done := make(chan error, 1)
			go func() {
				_, err := ks.ListKeys()
				done <- err
			}()

			select {
			case err := <-done:
				latency := time.Since(start)
				if err != nil {
					return health.CheckResult{
						Name:    fmt.Sprintf("backend-%s", backendName),
						Status:  health.StatusUnhealthy,
						Message: fmt.Sprintf("Backend %s is not responding", backendName),
						Error:   err.Error(),
						Latency: latency,
					}
				}
				return health.CheckResult{
					Name:    fmt.Sprintf("backend-%s", backendName),
					Status:  health.StatusHealthy,
					Message: fmt.Sprintf("Backend %s is responding", backendName),
					Latency: latency,
				}
			case <-checkCtx.Done():
				return health.CheckResult{
					Name:    fmt.Sprintf("backend-%s", backendName),
					Status:  health.StatusUnhealthy,
					Message: fmt.Sprintf("Backend %s check timed out", backendName),
					Error:   "timeout",
					Latency: time.Since(start),
				}
			}
		})
	}

	s.logger.Info("Health checker initialized", "checks", len(s.healthChecker.GetAllChecks()))
	return nil
}

// initializeCA creates and initializes a Certificate Authority from config.
// If config.CA is nil, the CA is not configured and initialization is skipped.
// On first startup (no existing CA data), Init() creates new root/intermediate certificates.
// On subsequent startups, Load() restores the CA from stored certificates and keys.
func (s *Server) initializeCA() error {
	if s.config.CA == nil {
		return nil
	}

	s.logger.Info("Initializing CA...")

	// Validate the CA configuration
	if err := s.config.CA.Validate(); err != nil {
		return &ErrCAInit{Operation: "validate CA configuration", Err: err}
	}

	// Resolve the keystore backend for the CA's root identity
	if len(s.config.CA.Identity) == 0 {
		return ErrCANoIdentities
	}
	keystoreType := s.config.CA.Identity[0].GetStoreType()
	backend, ok := s.backends[string(keystoreType)]
	if !ok {
		return &ErrBackendNotAvailable{Backend: string(keystoreType), Purpose: "CA keystore"}
	}

	// Create certificate storage for the CA
	caStorage, err := s.createStorage("ca")
	if err != nil {
		return &ErrStorageCreate{Resource: "CA storage directory", Err: err}
	}
	certAdapter := storage.NewCertAdapter(caStorage)
	caCertStore, err := certstore.New(&certstore.Config{
		CertStorage: certAdapter,
	})
	if err != nil {
		return &ErrServiceInit{Service: "CA certificate store", Err: err}
	}

	// Create the CA instance
	basicCA, err := ca.NewFromMultiIdentityConfig(&ca.MultiIdentityParams{
		Config:    s.config.CA,
		KeyStore:  backend,
		CertStore: caCertStore,
	})
	if err != nil {
		return &ErrCAInit{Operation: "create CA", Err: err}
	}

	// Try to load existing CA state (certificates and keys from a previous run).
	// If loading fails, the CA has not been initialized yet, so create it.
	if err := basicCA.Load(); err != nil {
		s.logger.Info("No existing CA found, initializing new CA", "reason", err.Error())
		if initErr := basicCA.Init(); initErr != nil {
			return &ErrCAInit{Operation: "initialize new CA", Err: initErr}
		}
	}

	s.ca = basicCA

	cn := s.config.CA.Identity[0].Subject.CommonName
	s.logger.Info("CA initialized", "identity", cn)

	// If TLS is enabled with a server_cn, auto-issue a TLS server certificate
	// so that buildTLSConfig() can retrieve it for HTTPS/gRPC/QUIC.
	if s.config.TLS.Enabled && s.config.TLS.ServerCN != "" {
		if err := s.ensureTLSServerCert(basicCA, keystoreType); err != nil {
			return &ErrTLSCertOp{Operation: "ensure TLS server certificate", Err: err}
		}
	}

	return nil
}

// ensureTLSServerCert checks if a TLS server certificate exists for the configured
// server CN and issues one from the CA if it doesn't. This enables CA-backed TLS
// without requiring pre-generated cert/key files.
func (s *Server) ensureTLSServerCert(xkmsCA ca.XKMSCA, keystoreType types.StoreType) error {
	serverCN := s.config.TLS.ServerCN

	// Build key attributes for the TLS server cert using the CA identity's store type
	identity := s.config.CA.Identity[s.config.CA.SelectedCA]
	attrs := &types.KeyAttributes{
		CN:        serverCN,
		StoreType: keystoreType,
		KeyType:   types.KeyTypeTLS,
	}

	// Check if the cert already exists by trying to retrieve it
	if _, err := xkmsCA.TLSCertificate(attrs); err == nil {
		s.logger.Info("TLS server certificate already exists", "cn", serverCN)
		return nil
	}

	s.logger.Info("Issuing TLS server certificate from CA", "cn", serverCN)

	// Build SANs: include server CN, localhost, and common container names
	sans := &ca.SubjectAlternativeNames{
		DNS: []string{serverCN, "localhost"},
		IPs: []string{"127.0.0.1", "::1", "0.0.0.0"},
	}

	// Issue the TLS server certificate
	issued, err := xkmsCA.IssueCertificateWithProfile(&ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   serverCN,
			Organization: identity.Subject.Organization,
			Country:      identity.Subject.Country,
		},
		SANS:     sans,
		Valid:    s.config.CA.DefaultValidityDays,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}, "server")
	if err != nil {
		// Handle stale state: the CA's certStore has the cert (from a previous run)
		// but the backend's certStorage doesn't (volumes were partially cleaned).
		// Retrieve the existing cert from the CA and sync it to the backend.
		if errors.Is(err, ca.ErrCertificateAlreadyExists) {
			return s.syncExistingTLSCert(xkmsCA, serverCN, keystoreType)
		}
		return &ErrTLSCertOp{Operation: "issue TLS server certificate", Err: err}
	}

	// Store the issued cert in the backend's cert storage so that
	// ca.TLSCertificate() → keyStore.GetTLSCertificate() can find it.
	// The CA stores certs in its own certStore, but GetTLSCertificate
	// looks in the compositeBackend's certStorage (separate storage).
	if err := s.storeTLSCertInBackend(xkmsCA, serverCN, keystoreType, issued.Certificate); err != nil {
		return err
	}

	s.logger.Info("TLS server certificate issued", "cn", serverCN)
	return nil
}

// syncExistingTLSCert handles the case where the CA's certStore already has a TLS
// certificate (from a previous run) but the backend's certStorage doesn't. This
// happens when Docker volumes are partially cleaned between runs. The function
// retrieves the existing cert from the CA's certStore and stores it in the backend.
func (s *Server) syncExistingTLSCert(xkmsCA ca.XKMSCA, serverCN string, keystoreType types.StoreType) error {
	s.logger.Info("TLS cert exists in CA but not in backend, syncing", "cn", serverCN)

	cert, err := xkmsCA.CertStore().GetCertificate(serverCN)
	if err != nil {
		return &ErrTLSCertOp{Operation: "retrieve existing TLS cert from CA certStore", Err: err}
	}

	if err := s.storeTLSCertInBackend(xkmsCA, serverCN, keystoreType, cert); err != nil {
		return err
	}

	s.logger.Info("TLS server certificate synced from CA to backend", "cn", serverCN)
	return nil
}

// storeTLSCertInBackend stores a TLS certificate and its chain in the backend's
// cert storage so that ca.TLSCertificate() → keyStore.GetTLSCertificate() can
// find it. The CA stores certs in its own certStore, but GetTLSCertificate looks
// in the compositeBackend's certStorage (separate storage).
func (s *Server) storeTLSCertInBackend(xkmsCA ca.XKMSCA, serverCN string, keystoreType types.StoreType, cert *x509.Certificate) error {
	backend, ok := s.backends[string(keystoreType)]
	if !ok {
		return &ErrBackendNotAvailable{Backend: string(keystoreType), Purpose: "TLS cert storage"}
	}
	if err := backend.SaveCert(serverCN, cert); err != nil {
		return &ErrTLSCertOp{Operation: "store TLS cert in backend", Err: err}
	}

	// Also store the certificate chain (leaf + CA) for proper TLS handshakes
	caCert, caErr := xkmsCA.CACertificate()
	if caErr == nil && caCert != nil {
		chain := []*x509.Certificate{cert, caCert}
		if chainErr := backend.SaveCertChain(serverCN, chain); chainErr != nil {
			s.logger.Warn("Failed to store TLS cert chain in backend", "error", chainErr)
		}
	}

	return nil
}

// Start starts all enabled protocol servers
func (s *Server) Start() error {
	s.logger.Info("Starting xkms server...")

	// Initialize CA bundler from TLS configuration so REST, gRPC, and Noise
	// subsystems can serve the CA certificate bundle for trust bootstrap.
	if s.config.TLS.Enabled && s.config.TLS.CAFile != "" {
		bundler, err := newTLSCABundler(s.config.TLS.CAFile)
		if err != nil {
			s.logger.Warn("Failed to initialize CA bundler", slog.Any("error", err))
		} else {
			rest.SetCABundler(bundler)
			grpcinternal.SetCABundler(bundler)
			s.logger.Info("CA bundler initialized from TLS CA file", "ca_file", s.config.TLS.CAFile)
		}
	} else if s.config.TLS.Enabled && s.ca != nil && s.ca.IsInitialized() {
		// When using CA-backed TLS (no CAFile), create bundler from the CA instance
		bundler, err := newCAInstanceBundler(s.ca)
		if err != nil {
			s.logger.Warn("Failed to initialize CA bundler from CA instance", slog.Any("error", err))
		} else {
			rest.SetCABundler(bundler)
			grpcinternal.SetCABundler(bundler)
			s.logger.Info("CA bundler initialized from CA instance")
		}
	}

	// Initialize metrics if enabled
	if s.config.Metrics.Enabled {
		if err := s.initializeMetrics(); err != nil {
			s.logger.Error("Failed to initialize metrics", slog.Any("error", err))
			return &ErrServiceInit{Service: "metrics", Err: err}
		}
	}

	// Start Unix socket server if enabled (default: true)
	if s.config.Protocols.Unix {
		s.wg.Add(1)
		go s.startUnix()
	}

	// Start REST API if enabled
	if s.config.Protocols.REST {
		s.wg.Add(1)
		go s.startREST()
	}

	// Start gRPC if enabled
	if s.config.Protocols.GRPC {
		s.wg.Add(1)
		go s.startGRPC()
	}

	// Start QUIC if enabled
	if s.config.Protocols.QUIC {
		s.wg.Add(1)
		go s.startQUIC()
	}

	// Start MCP if enabled
	if s.config.Protocols.MCP {
		s.wg.Add(1)
		go s.startMCP()
	}

	// Start Noise bootstrap server if enabled
	if s.config.Protocols.Noise {
		s.wg.Add(1)
		go s.startNoiseBootstrap()
	}

	// Start metrics server if enabled
	if s.config.Metrics.Enabled {
		s.wg.Add(1)
		go s.startMetrics()
	}

	// Mark service as fully started for startup probes
	if s.healthChecker != nil {
		s.healthChecker.MarkStarted()
		s.logger.Info("Health checker marked as started")
	}

	s.logger.Info("All servers started successfully")

	return nil
}

// startUnix starts the Unix domain socket server (IPC, HTTP or gRPC based on configuration)
func (s *Server) startUnix() {
	defer s.wg.Done()

	// Determine socket path
	socketPath := s.config.Unix.SocketPath
	if socketPath == "" {
		socketPath = unix.DefaultSocketPath
	}

	// Determine protocol (default to gRPC)
	protocol := s.config.Unix.Protocol
	if protocol == "" {
		protocol = "grpc"
	}

	// Start server based on protocol configuration
	switch protocol {
	case "grpc":
		s.logger.Info("Starting Unix socket with gRPC protocol", "socket", socketPath)

		// Create Unix gRPC server configuration
		// Note: Logger is nil - the unix package will use its internal noOpLogger
		grpcConfig := &unix.GRPCConfig{
			SocketPath: socketPath,
			Logger:     nil,
		}

		grpcServer, err := unix.NewGRPCServer(grpcConfig)
		if err != nil {
			s.logger.Error("Failed to create Unix gRPC server", slog.Any("error", err))
			return
		}

		// Store server with lock
		s.mu.Lock()
		s.unixGRPCServer = grpcServer
		s.mu.Unlock()

		if err := grpcServer.Start(); err != nil {
			s.logger.Error("Unix gRPC server error", slog.Any("error", err))
		}

	default:
		s.logger.Error("Unknown Unix socket protocol", "protocol", protocol)
	}
}

// startREST starts the REST API server
func (s *Server) startREST() {
	defer s.wg.Done()

	// Create REST server configuration
	restConfig := &rest.Config{
		Port:              s.config.Server.RESTPort,
		Backends:          s.backends,
		Version:           getBuildVersion(),
		UserStore:         s.userStore,
		Authenticator:     s.authenticator,
		EnableRBAC:        s.config.Auth.EnableRBAC,
		Authorizer:        s.authorizer,
		AuditLogger:       s.auditLogger,
		Barrier:           s.barrier,
		PINManager:        s.pinManager,
		PasswordStore:     s.passwordStore,
		PlatformStore:     s.platformStore,
		PolicyManager:     s.policyManager,
		BootstrapService:  s.bootstrapService,
		BarrierRegistry:   s.barrierRegistry,
		CustodianService:  s.custodianService,
		ShareStore:        s.shareStore,
		CeremonyService:   s.ceremonyService,
		CredentialService: s.credentialService,
	}

	// Pass the XKMSService as CA servicer. The XKMSService wraps the raw CA
	// with transport-level methods (GetCABundle, IssueCertificate, etc.) that
	// match the caServicer interface expected by the REST handlers.
	if s.ca != nil {
		if svc, err := xkms.Get(); err == nil {
			restConfig.CA = svc
		}
	}

	// Add WebAuthn config if enabled
	if s.webauthnConfig != nil {
		restConfig.WebAuthnConfig = s.webauthnConfig
		s.logger.Info("WebAuthn enabled for REST server",
			"rp_id", s.webauthnConfig.RPID)
	}

	// Add TLS config if enabled
	if s.config.TLS.Enabled {
		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			s.logger.Error("Failed to build TLS config for REST server", slog.Any("error", err))
			return
		}
		restConfig.TLSConfig = tlsConfig
	}

	// Create REST server
	restSrv, err := rest.NewServer(restConfig)
	if err != nil {
		s.logger.Error("Failed to create REST server", slog.Any("error", err))
		return
	}

	// Store server with lock
	s.mu.Lock()
	s.restServer = restSrv
	s.mu.Unlock()

	// Configure health checker for REST API
	if s.healthChecker != nil {
		restSrv.SetHealthChecker(s.healthChecker)
		s.logger.Info("Health checker configured for REST server")
	}

	s.logger.Info("Starting REST server",
		"port", s.config.Server.RESTPort,
		"auth", s.authenticator.Name(),
		"rbac", s.config.Auth.EnableRBAC)

	if err := restSrv.Start(); err != nil {
		s.logger.Error("REST server error", slog.Any("error", err))
	}
}

// startGRPC starts the gRPC server
func (s *Server) startGRPC() {
	defer s.wg.Done()

	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.GRPCPort)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error("Failed to listen for gRPC", slog.Any("error", err), "address", addr)
		return
	}

	// Build gRPC server options
	var opts []grpc.ServerOption

	// Add TLS credentials if TLS is enabled
	if s.config.TLS.Enabled {
		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			s.logger.Error("Failed to build TLS config for gRPC", slog.Any("error", err))
			return
		}
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.Creds(creds))
		s.logger.Info("gRPC server TLS enabled")
	}

	grpcSrv := grpc.NewServer(opts...)

	// Store server with lock
	s.mu.Lock()
	s.grpcServer = grpcSrv
	s.mu.Unlock()

	// Create and register gRPC service (uses xkms service)
	service := grpcinternal.NewService(s.authorizer, s.auditLogger)

	// Wire barrier and PIN manager into gRPC service
	if s.barrier != nil {
		grpcinternal.SetBarrier(s.barrier)
	}
	if s.pinManager != nil {
		grpcinternal.SetPINManager(s.pinManager)
	}

	// Wire custodian, share, and tenant services into gRPC
	if s.custodianService != nil {
		grpcinternal.SetCustodianService(s.custodianService)
	}
	if s.shareStore != nil {
		grpcinternal.SetShareStore(s.shareStore)
	}
	if s.barrierRegistry != nil {
		grpcinternal.SetBarrierRegistry(s.barrierRegistry)
	}

	// Wire init ceremony and credential services into gRPC
	if s.ceremonyService != nil {
		grpcinternal.SetCeremonyService(initialize.NewCeremonyAdapter(s.ceremonyService))
	}
	if s.credentialService != nil {
		grpcinternal.SetCredentialService(s.credentialService)
	}

	// Wire CA into gRPC
	if s.ca != nil {
		grpcinternal.SetCA(s.ca)
	}

	pb.RegisterKeystoreServiceServer(grpcSrv, service)

	s.logger.Info("gRPC services registered", "backends", len(s.backends))
	s.logger.Info("Starting gRPC server", "address", addr)

	if err := grpcSrv.Serve(lis); err != nil {
		s.logger.Error("gRPC server error", slog.Any("error", err))
	}
}

// initializeMetrics initializes the metrics subsystem
func (s *Server) initializeMetrics() error {
	s.logger.Info("Initializing metrics...")

	// Enable metrics collection
	metrics.Enable()

	// Start resource collector with 30-second interval
	s.metricsCollector = metrics.StartResourceCollector(s.ctx, 30*time.Second)

	// Initialize backend health metrics
	for name := range s.keyProviders {
		metrics.SetBackendHealth(name, true)
	}

	s.logger.Info("Metrics initialized successfully")
	return nil
}

// startMetrics starts the Prometheus metrics server
func (s *Server) startMetrics() {
	defer s.wg.Done()

	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Metrics.Port)

	mux := http.NewServeMux()
	mux.Handle(s.config.Metrics.Path, promhttp.Handler())

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
	}

	s.logger.Info("Starting metrics server", "address", addr, "path", s.config.Metrics.Path)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.logger.Error("Metrics server error", slog.Any("error", err))
	}
}

// startMCP starts the MCP JSON-RPC server
func (s *Server) startMCP() {
	defer s.wg.Done()

	// Get default keystore for MCP (use first available if no default specified)
	var defaultKS xkms.Backend
	if s.config.Default != "" {
		defaultKS = s.backends[string(s.config.Default)]
	}
	if defaultKS == nil {
		for _, ks := range s.backends {
			defaultKS = ks
			break
		}
	}

	if defaultKS == nil {
		s.logger.Error("No keystore available for MCP server")
		return
	}

	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.MCPPort)

	mcpConfig := &mcp.Config{
		Addr:   addr,
		Logger: s.logger.With("component", "mcp"),
	}

	mcpSrv, err := mcp.NewServer(mcpConfig)
	if err != nil {
		s.logger.Error("Failed to create MCP server", slog.Any("error", err))
		return
	}

	// Store server with lock
	s.mu.Lock()
	s.mcpServer = mcpSrv
	s.mu.Unlock()

	s.logger.Info("Starting MCP server", "address", addr)

	if err := mcpSrv.Start(); err != nil {
		s.logger.Error("MCP server error", slog.Any("error", err))
	}
}

// startNoiseBootstrap starts the Noise_NK bootstrap server for secure CA bundle distribution.
func (s *Server) startNoiseBootstrap() {
	defer s.wg.Done()

	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.NoisePort)

	// Get CA bundler
	bundler := grpcinternal.GetCABundler()
	if bundler == nil {
		s.logger.Error("Noise bootstrap requires a CA bundler to be configured")
		return
	}

	noiseCfg := s.config.Bootstrap.Noise

	// Parse timeouts
	readTimeout := 10 * time.Second
	writeTimeout := 10 * time.Second
	if noiseCfg.ReadTimeout != "" {
		if d, err := time.ParseDuration(noiseCfg.ReadTimeout); err == nil {
			readTimeout = d
		}
	}
	if noiseCfg.WriteTimeout != "" {
		if d, err := time.ParseDuration(noiseCfg.WriteTimeout); err == nil {
			writeTimeout = d
		}
	}

	maxConns := noiseCfg.MaxConnections
	if maxConns <= 0 {
		maxConns = 100
	}

	// Load static key from file or hex config
	staticKey, err := s.loadNoiseStaticKey()
	if err != nil {
		s.logger.Error("Failed to load Noise static key", slog.Any("error", err))
		return
	}

	serverCfg := &noiseboot.ServerConfig{
		ListenAddr:     addr,
		StaticKey:      staticKey,
		CABundler:      bundler,
		MaxConnections: maxConns,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		Logger:         s.logger.With("component", "noise_bootstrap"),
	}

	server, err := noiseboot.NewServer(serverCfg)
	if err != nil {
		s.logger.Error("Failed to create Noise bootstrap server", slog.Any("error", err))
		return
	}

	s.mu.Lock()
	s.noiseBootstrapServer = server
	s.mu.Unlock()

	s.logger.Info("Starting Noise bootstrap server", "address", addr)

	if err := server.Start(); err != nil {
		s.logger.Error("Noise bootstrap server error", slog.Any("error", err))
	}
}

// loadNoiseStaticKey loads the Noise static key from config.
func (s *Server) loadNoiseStaticKey() (*flynn_noise.DHKey, error) {
	noiseCfg := s.config.Bootstrap.Noise

	// Try hex key first (inline config)
	if noiseCfg.StaticKeyHex != "" {
		return noiseproto.DecodeStaticKey(noiseCfg.StaticKeyHex)
	}

	// Try key file
	if noiseCfg.StaticKeyFile != "" {
		// #nosec G304 - Key file path from trusted config
		data, err := os.ReadFile(noiseCfg.StaticKeyFile)
		if err != nil {
			return nil, &ErrFileRead{Path: "noise key file", Err: err}
		}
		hexKey := strings.TrimSpace(string(data))
		return noiseproto.DecodeStaticKey(hexKey)
	}

	// Generate a new key (first-time setup)
	s.logger.Warn("No Noise static key configured, generating ephemeral key. This is NOT recommended for production.")
	return noiseproto.GenerateStaticKey()
}

// buildTLSConfig builds a crypto/tls.Config from the server configuration
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if !s.config.TLS.Enabled {
		return nil, ErrTLSNotEnabled
	}

	// Load server certificate -- prefer CA-backed (hardware crypto.Signer) over file-based
	var cert tls.Certificate
	var certLoaded bool
	if s.ca != nil && s.ca.IsInitialized() {
		// CA-backed TLS: the CA provides a tls.Certificate with crypto.Signer
		// from the configured backend. Private key management is handled by the CA.
		identity := s.config.CA.Identity[s.config.CA.SelectedCA]
		keystoreType := identity.GetStoreType()
		attrs, tlsErr := types.KeyAttributesFromConfig(identity.Keys[0])
		if tlsErr == nil {
			attrs.CN = s.config.TLS.ServerCN
			attrs.StoreType = keystoreType
			attrs.KeyType = types.KeyTypeTLS
			var err error
			cert, err = s.ca.TLSCertificate(attrs)
			if err != nil {
				if s.config.TLS.CertFile == "" && s.config.TLS.KeyFile == "" {
					return nil, &ErrTLSCertOp{Operation: "load CA-backed TLS certificate", Err: err, Sentinel: ErrCATLSCertFailed}
				}
				s.logger.Warn("CA-backed TLS unavailable, falling back to file-based TLS",
					"error", err)
			} else {
				s.logger.Info("Using CA-backed TLS certificate", "cn", s.config.TLS.ServerCN)
				certLoaded = true
			}
		} else {
			if s.config.TLS.CertFile == "" && s.config.TLS.KeyFile == "" {
				return nil, &ErrTLSCertOp{Operation: "build TLS key attributes from CA config", Err: tlsErr, Sentinel: ErrCATLSCertFailed}
			}
			s.logger.Warn("Failed to build TLS key attributes from CA config, falling back to file-based TLS",
				"error", tlsErr)
		}
	}
	if !certLoaded && s.config.TLS.CertFile != "" && s.config.TLS.KeyFile != "" {
		// File-based TLS: backward compatible with existing deployments
		var err error
		cert, err = tls.LoadX509KeyPair(s.config.TLS.CertFile, s.config.TLS.KeyFile)
		if err != nil {
			return nil, &ErrTLSCertOp{Operation: "load server certificate", Err: err}
		}
		certLoaded = true
		s.logger.Info("Using file-based TLS certificate")
	}
	if !certLoaded {
		return nil, ErrNoTLSCertAvailable
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Default to TLS 1.2
	}

	// Set TLS version based on configuration
	if s.config.TLS.MinVersion != "" {
		minVersion := parseTLSVersion(s.config.TLS.MinVersion)
		if minVersion > 0 {
			tlsConfig.MinVersion = minVersion
		}
	}

	if s.config.TLS.MaxVersion != "" {
		maxVersion := parseTLSVersion(s.config.TLS.MaxVersion)
		if maxVersion > 0 {
			tlsConfig.MaxVersion = maxVersion
		}
	}

	// Load CA certificate pool if configured
	if s.config.TLS.CAFile != "" {
		caCert, err := os.ReadFile(s.config.TLS.CAFile)
		if err != nil {
			return nil, &ErrFileRead{Path: "CA certificate", Err: err}
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, ErrCAParseCert
		}

		tlsConfig.ClientCAs = caCertPool
	}

	// Load additional client CAs if configured
	if len(s.config.TLS.ClientCAs) > 0 {
		if tlsConfig.ClientCAs == nil {
			tlsConfig.ClientCAs = x509.NewCertPool()
		}

		for _, caPath := range s.config.TLS.ClientCAs {
			// #nosec G304 - CA certificate path from trusted config file
			caCert, err := os.ReadFile(caPath)
			if err != nil {
				return nil, &ErrFileRead{Path: "additional client CA certificate at " + caPath, Err: err}
			}

			if !tlsConfig.ClientCAs.AppendCertsFromPEM(caCert) {
				return nil, &ErrCertParse{Path: caPath}
			}
		}
	}

	// Configure client authentication (mTLS) if specified
	switch s.config.TLS.ClientAuth {
	case "require", "require_and_verify":
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	case "verify":
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	case "request":
		tlsConfig.ClientAuth = tls.RequestClientCert
	default:
		tlsConfig.ClientAuth = tls.NoClientCert
	}

	// Set cipher suites if specified
	if len(s.config.TLS.CipherSuites) > 0 {
		tlsConfig.CipherSuites = parseCipherSuites(s.config.TLS.CipherSuites)
	}

	// Configure server cipher preference

	return tlsConfig, nil
}

// parseTLSVersion converts a version string to a tls.uint16 version constant
func parseTLSVersion(version string) uint16 {
	switch version {
	case "TLS1.2", "tls1.2", "1.2":
		return tls.VersionTLS12
	case "TLS1.3", "tls1.3", "1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

// parseCipherSuites converts cipher suite names to their corresponding constants
func parseCipherSuites(names []string) []uint16 {
	cipherMap := map[string]uint16{
		"TLS_AES_128_GCM_SHA256":                  tls.TLS_AES_128_GCM_SHA256,
		"TLS_AES_256_GCM_SHA384":                  tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256":            tls.TLS_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	var result []uint16
	for _, name := range names {
		if cipher, ok := cipherMap[name]; ok {
			result = append(result, cipher)
		}
	}
	return result
}

// startQUIC starts the QUIC/HTTP3 server
func (s *Server) startQUIC() {
	defer s.wg.Done()

	// Get default keystore for QUIC (use first available if no default specified)
	var defaultKS xkms.Backend
	if s.config.Default != "" {
		defaultKS = s.backends[string(s.config.Default)]
	}
	if defaultKS == nil {
		for _, ks := range s.backends {
			defaultKS = ks
			break
		}
	}

	if defaultKS == nil {
		s.logger.Error("No keystore available for QUIC server")
		return
	}

	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.QUICPort)

	// Load TLS configuration
	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		s.logger.Error("Failed to load TLS configuration for QUIC", slog.Any("error", err))
		return
	}

	quicConfig := &quic.Config{
		Addr:          addr,
		Version:       getBuildVersion(),
		TLSConfig:     tlsConfig,
		Logger:        s.logger.With("component", "quic"),
		Authenticator: s.authenticator,
		Authorizer:    s.authorizer,
		AuditLogger:   s.auditLogger,
	}

	quicSrv, err := quic.NewServer(quicConfig)
	if err != nil {
		s.logger.Error("Failed to create QUIC server", slog.Any("error", err))
		return
	}

	// Store server with lock
	s.mu.Lock()
	s.quicServer = quicSrv
	s.mu.Unlock()

	s.logger.Info("Starting QUIC server", "address", addr)

	if err := quicSrv.Start(); err != nil {
		s.logger.Error("QUIC server error", slog.Any("error", err))
	}
}

// handleHealth handles health check requests

// Shutdown gracefully shuts down all servers
func (s *Server) Shutdown() error {
	s.logger.Info("Shutting down server...")

	// Stop metrics collector if running
	if s.metricsCollector != nil {
		s.logger.Info("Stopping metrics collector...")
		s.metricsCollector.Stop()
	}

	// Cancel context to signal all goroutines
	s.cancel()

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Copy server references under lock to avoid races with startup goroutines
	// We copy first, then release the lock before calling shutdown operations
	// which could take a long time
	s.mu.RLock()
	unixGRPC := s.unixGRPCServer
	restSrv := s.restServer
	grpcSrv := s.grpcServer
	noiseSrv := s.noiseBootstrapServer
	s.mu.RUnlock()

	// Shutdown Unix gRPC socket server
	if unixGRPC != nil {
		s.logger.Info("Shutting down Unix gRPC socket server...")
		if err := unixGRPC.Stop(shutdownCtx); err != nil {
			s.logger.Error("Error shutting down Unix gRPC socket server", slog.Any("error", err))
		}
	}

	// Shutdown REST server
	if restSrv != nil {
		s.logger.Info("Shutting down REST server...")
		if err := restSrv.Stop(shutdownCtx); err != nil {
			s.logger.Error("Error shutting down REST server", slog.Any("error", err))
		}
	}

	// Shutdown gRPC server
	if grpcSrv != nil {
		s.logger.Info("Shutting down gRPC server...")
		grpcSrv.GracefulStop()
	}

	// Shutdown Noise bootstrap server
	if noiseSrv != nil {
		s.logger.Info("Shutting down Noise bootstrap server...")
		if err := noiseSrv.Stop(shutdownCtx); err != nil {
			s.logger.Error("Error shutting down Noise bootstrap server", slog.Any("error", err))
		}
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("All servers stopped")
	case <-shutdownCtx.Done():
		s.logger.Warn("Shutdown timeout exceeded, forcing stop")
	}

	// Close audit logger
	if s.auditLogger != nil {
		if err := s.auditLogger.Close(); err != nil {
			s.logger.Error("Failed to close audit logger", slog.Any("error", err))
		}
	}

	// Close all backends
	for name, ks := range s.backends {
		s.logger.Info("Closing backend...", "backend", name)
		if err := ks.Close(); err != nil {
			s.logger.Error("Error closing backend", slog.Any("error", err), "backend", name)
		}
	}

	// Close all key providers
	s.closeBackends()

	close(s.shutdownCh)
	s.logger.Info("Server shutdown complete")

	return nil
}

// closeBackends closes all key provider connections
func (s *Server) closeBackends() {
	for name, backend := range s.keyProviders {
		s.logger.Info("Closing key provider...", "key_provider", name)
		if err := backend.Close(); err != nil {
			s.logger.Error("Error closing backend", slog.Any("error", err), "backend", name)
		}
	}
}

// WaitForShutdown blocks until the server is shut down
func (s *Server) WaitForShutdown() {
	<-s.shutdownCh
}

// SetupSignalHandler sets up signal handling for graceful shutdown
func SetupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- cancel is called in the goroutine below

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalCh
		slog.Info("Received shutdown signal")
		cancel()
	}()

	return ctx
}

// RESTServer returns the REST server instance
func (s *Server) RESTServer() *rest.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.restServer
}

// GRPCServer returns the gRPC server instance
func (s *Server) GRPCServer() *grpc.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.grpcServer
}

// QUICServer returns the QUIC server instance
func (s *Server) QUICServer() *quic.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.quicServer
}

// MCPServer returns the MCP server instance
func (s *Server) MCPServer() *mcp.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mcpServer
}

// NoiseBootstrapServer returns the Noise bootstrap server instance
func (s *Server) NoiseBootstrapServer() *noiseboot.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.noiseBootstrapServer
}

// UnixGRPCServer returns the Unix gRPC socket server instance
func (s *Server) UnixGRPCServer() *unix.GRPCServer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unixGRPCServer
}
