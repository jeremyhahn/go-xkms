// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/internal/config"
	grpcinternal "github.com/jeremyhahn/go-keychain/internal/grpc"
	"github.com/jeremyhahn/go-keychain/internal/mcp"
	"github.com/jeremyhahn/go-keychain/internal/quic"
	"github.com/jeremyhahn/go-keychain/internal/rest"
	"github.com/jeremyhahn/go-keychain/internal/unix"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/health"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/metrics"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/jeremyhahn/go-keychain/pkg/user"
)

// Server represents the unified keychain server that runs all protocols
type Server struct {
	config    *config.Config
	mu        sync.RWMutex
	keystores map[string]keychain.KeyStore
	backends  map[string]types.Backend
	logger    *slog.Logger

	// Protocol servers
	unixServer     *unix.Server
	unixGRPCServer *unix.GRPCServer
	restServer     *rest.Server
	grpcServer     *grpc.Server
	quicServer     *quic.Server
	mcpServer      *mcp.Server

	// User management
	userStore user.Store

	// Health checker
	healthChecker *health.Checker

	// Metrics
	metricsCollector *metrics.ResourceCollector

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
		config:     cfg,
		backends:   make(map[string]types.Backend),
		keystores:  make(map[string]keychain.KeyStore),
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
		shutdownCh: make(chan struct{}),
	}

	// Initialize backends
	if err := s.initializeBackends(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize backends: %w", err)
	}

	// Initialize keystore with default backend
	if err := s.initializeKeyStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, fmt.Errorf("failed to initialize keystore: %w", err)
	}

	// Initialize user store
	if err := s.initializeUserStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, fmt.Errorf("failed to initialize user store: %w", err)
	}

	// Initialize health checker
	if err := s.initializeHealth(); err != nil {
		cancel()
		s.closeBackends()
		return nil, fmt.Errorf("failed to initialize health checker: %w", err)
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

	// Initialize Software backend (uses PKCS#8 internally)
	if s.config.Backends.Software != nil && s.config.Backends.Software.Enabled {
		keyStorage, err := file.New(s.config.Backends.Software.Path)
		if err != nil {
			return fmt.Errorf("failed to create software key storage: %w", err)
		}

		softwareBackend, err := pkcs8.NewBackend(&pkcs8.Config{
			KeyStorage: keyStorage,
		})
		if err != nil {
			return fmt.Errorf("failed to create software backend: %w", err)
		}

		s.backends["software"] = softwareBackend
		s.logger.Info("Software backend initialized", "backend", "software", "path", s.config.Backends.Software.Path)
	}

	// Initialize PKCS8 backend (software keys)
	if s.config.Backends.PKCS8 != nil && s.config.Backends.PKCS8.Enabled {
		keyStorage, err := file.New(s.config.Backends.PKCS8.Path)
		if err != nil {
			return fmt.Errorf("failed to create PKCS8 key storage: %w", err)
		}

		pkcs8Backend, err := pkcs8.NewBackend(&pkcs8.Config{
			KeyStorage: keyStorage,
		})
		if err != nil {
			return fmt.Errorf("failed to create PKCS8 backend: %w", err)
		}

		s.backends["pkcs8"] = pkcs8Backend
		s.logger.Info("PKCS8 backend initialized", "backend", "pkcs8", "path", s.config.Backends.PKCS8.Path)
	}

	// Initialize other backends based on build tags
	// Each backend has separate files with build tags that automatically
	// compile the real implementation or a stub based on build flags

	if err := s.initTPM2Backend(); err != nil {
		return fmt.Errorf("failed to initialize TPM2 backend: %w", err)
	}

	if err := s.initPKCS11Backend(); err != nil {
		return fmt.Errorf("failed to initialize PKCS#11 backend: %w", err)
	}

	if err := s.initAWSKMSBackend(); err != nil {
		return fmt.Errorf("failed to initialize AWS KMS backend: %w", err)
	}

	if err := s.initGCPKMSBackend(); err != nil {
		return fmt.Errorf("failed to initialize GCP KMS backend: %w", err)
	}

	if err := s.initAzureKVBackend(); err != nil {
		return fmt.Errorf("failed to initialize Azure Key Vault backend: %w", err)
	}

	if err := s.initVaultBackend(); err != nil {
		return fmt.Errorf("failed to initialize Vault backend: %w", err)
	}

	if len(s.backends) == 0 {
		return fmt.Errorf("no backends initialized")
	}

	return nil
}

// initializeKeyStore creates keystores for all backends
func (s *Server) initializeKeyStore() error {
	// Create certificate storage (shared across all keystores)
	certPath := s.config.Storage.Path + "/certs"
	certStorage, err := file.New(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate storage: %w", err)
	}

	// Create a keystore for each backend
	for name, backend := range s.backends {
		keystore, err := keychain.New(&keychain.Config{
			Backend:     backend,
			CertStorage: certStorage,
		})
		if err != nil {
			return fmt.Errorf("failed to create keystore for backend '%s': %w", name, err)
		}

		s.keystores[name] = keystore
		s.logger.Info("KeyStore initialized", "backend", name)
	}

	if len(s.keystores) == 0 {
		return fmt.Errorf("no keystores initialized")
	}

	// Determine default backend
	defaultBackend := string(s.config.Default)
	if _, ok := s.keystores[defaultBackend]; !ok {
		// Fall back to first available backend
		for name := range s.keystores {
			defaultBackend = name
			break
		}
	}

	// Initialize the global keychain service with the keystores
	// This allows REST handlers to access backends via keychain.Backends()
	serviceConfig := &keychain.ServiceConfig{
		Backends:       s.keystores,
		DefaultBackend: defaultBackend,
	}
	if err := keychain.Initialize(serviceConfig); err != nil {
		return fmt.Errorf("failed to initialize keychain service: %w", err)
	}

	s.logger.Info("Keychain service initialized",
		"default_backend", defaultBackend,
		"backends", len(s.keystores))

	return nil
}

// initializeUserStore creates the user store.
func (s *Server) initializeUserStore() error {
	s.logger.Info("Initializing user store...")

	// Create user storage directory
	userStoragePath := s.config.Storage.Path + "/users"
	userStorage, err := file.New(userStoragePath)
	if err != nil {
		return fmt.Errorf("failed to create user storage: %w", err)
	}

	// Create user store
	userStore, err := user.NewFileStore(userStorage)
	if err != nil {
		return fmt.Errorf("failed to create user store: %w", err)
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

// initializeHealth creates and configures the health checker.
func (s *Server) initializeHealth() error {
	s.logger.Info("Initializing health checker...")

	s.healthChecker = health.NewChecker()

	// Register backend health checks
	for name, keystore := range s.keystores {
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

// Start starts all enabled protocol servers
func (s *Server) Start() error {
	s.logger.Info("Starting keychain server...")

	// Initialize metrics if enabled
	if s.config.Metrics.Enabled {
		if err := s.initializeMetrics(); err != nil {
			s.logger.Error("Failed to initialize metrics", slog.Any("error", err))
			return fmt.Errorf("failed to initialize metrics: %w", err)
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

// startUnix starts the Unix domain socket server (HTTP or gRPC based on configuration)
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

	// Create logger adapter for Unix server
	unixLogger := logger.NewSlogAdapter(&logger.SlogConfig{
		Logger: s.logger.With("component", "unix"),
	})

	// Start either HTTP or gRPC server based on configuration
	if protocol == "grpc" {
		s.logger.Info("Starting Unix socket with gRPC protocol", "socket", socketPath)

		// Create Unix gRPC server configuration
		grpcConfig := &unix.GRPCConfig{
			SocketPath: socketPath,
			Logger:     unixLogger,
		}

		var err error
		s.unixGRPCServer, err = unix.NewGRPCServer(grpcConfig)
		if err != nil {
			s.logger.Error("Failed to create Unix gRPC server", slog.Any("error", err))
			return
		}

		if err := s.unixGRPCServer.Start(); err != nil {
			s.logger.Error("Unix gRPC server error", slog.Any("error", err))
		}
	} else {
		s.logger.Info("Starting Unix socket with HTTP protocol", "socket", socketPath)

		// Create Unix HTTP server configuration
		unixConfig := &unix.Config{
			SocketPath:     socketPath,
			Backends:       s.keystores,
			DefaultBackend: string(s.config.Default),
			Version:        getBuildVersion(),
			Logger:         unixLogger,
			UserStore:      s.userStore,
		}

		var err error
		s.unixServer, err = unix.NewServer(unixConfig)
		if err != nil {
			s.logger.Error("Failed to create Unix HTTP server", slog.Any("error", err))
			return
		}

		// Configure health checker for Unix HTTP server
		if s.healthChecker != nil {
			s.unixServer.SetHealthChecker(s.healthChecker)
			s.logger.Info("Health checker configured for Unix HTTP server")
		}

		if err := s.unixServer.Start(); err != nil {
			s.logger.Error("Unix HTTP server error", slog.Any("error", err))
		}
	}
}

// startREST starts the REST API server
func (s *Server) startREST() {
	defer s.wg.Done()

	// Create REST server configuration
	restConfig := &rest.Config{
		Port:      s.config.Server.RESTPort,
		Backends:  s.keystores,
		Version:   getBuildVersion(),
		UserStore: s.userStore,
	}

	// Create REST server
	var err error
	s.restServer, err = rest.NewServer(restConfig)
	if err != nil {
		s.logger.Error("Failed to create REST server", slog.Any("error", err))
		return
	}

	// Configure health checker for REST API
	if s.healthChecker != nil {
		s.restServer.SetHealthChecker(s.healthChecker)
		s.logger.Info("Health checker configured for REST server")
	}

	s.logger.Info("Starting REST server", "port", s.config.Server.RESTPort)

	if err := s.restServer.Start(); err != nil {
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

	s.grpcServer = grpc.NewServer()

	// Create and register gRPC service (uses keychain service)
	service := grpcinternal.NewService()
	pb.RegisterKeystoreServiceServer(s.grpcServer, service)

	s.logger.Info("gRPC services registered", "keystores", len(s.keystores))
	s.logger.Info("Starting gRPC server", "address", addr)

	if err := s.grpcServer.Serve(lis); err != nil {
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
	for name := range s.backends {
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
	var defaultKS keychain.KeyStore
	if s.config.Default != "" {
		defaultKS = s.keystores[string(s.config.Default)]
	}
	if defaultKS == nil {
		for _, ks := range s.keystores {
			defaultKS = ks
			break
		}
	}

	if defaultKS == nil {
		s.logger.Error("No keystore available for MCP server")
		return
	}

	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.MCPPort)

	// Create logger adapter for MCP server
	mcpLogger := logger.NewSlogAdapter(&logger.SlogConfig{
		Logger: s.logger.With("component", "mcp"),
	})

	mcpConfig := &mcp.Config{
		Addr:   addr,
		Logger: mcpLogger,
	}

	var err error
	s.mcpServer, err = mcp.NewServer(mcpConfig)
	if err != nil {
		s.logger.Error("Failed to create MCP server", slog.Any("error", err))
		return
	}

	s.logger.Info("Starting MCP server", "address", addr)

	if err := s.mcpServer.Start(); err != nil {
		s.logger.Error("MCP server error", slog.Any("error", err))
	}
}

// buildTLSConfig builds a crypto/tls.Config from the server configuration
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if !s.config.TLS.Enabled {
		return nil, fmt.Errorf("TLS is not enabled in configuration")
	}

	// Load server certificate and private key
	cert, err := tls.LoadX509KeyPair(s.config.TLS.CertFile, s.config.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
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
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
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
				return nil, fmt.Errorf("failed to read additional client CA certificate at %s: %w", caPath, err)
			}

			if !tlsConfig.ClientCAs.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse additional client CA certificate at %s", caPath)
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
	var defaultKS keychain.KeyStore
	if s.config.Default != "" {
		defaultKS = s.keystores[string(s.config.Default)]
	}
	if defaultKS == nil {
		for _, ks := range s.keystores {
			defaultKS = ks
			break
		}
	}

	if defaultKS == nil {
		s.logger.Error("No keystore available for QUIC server")
		return
	}

	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.QUICPort)

	// Create logger adapter for QUIC server
	quicLogger := logger.NewSlogAdapter(&logger.SlogConfig{
		Logger: s.logger.With("component", "quic"),
	})

	// Load TLS configuration
	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		s.logger.Error("Failed to load TLS configuration for QUIC", slog.Any("error", err))
		return
	}

	quicConfig := &quic.Config{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Logger:    quicLogger,
	}

	s.quicServer, err = quic.NewServer(quicConfig)
	if err != nil {
		s.logger.Error("Failed to create QUIC server", slog.Any("error", err))
		return
	}

	s.logger.Info("Starting QUIC server", "address", addr)

	if err := s.quicServer.Start(); err != nil {
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

	// Shutdown Unix socket server
	if s.unixServer != nil {
		s.logger.Info("Shutting down Unix socket server...")
		if err := s.unixServer.Stop(shutdownCtx); err != nil {
			s.logger.Error("Error shutting down Unix socket server", slog.Any("error", err))
		}
	}

	// Shutdown Unix gRPC socket server
	if s.unixGRPCServer != nil {
		s.logger.Info("Shutting down Unix gRPC socket server...")
		if err := s.unixGRPCServer.Stop(shutdownCtx); err != nil {
			s.logger.Error("Error shutting down Unix gRPC socket server", slog.Any("error", err))
		}
	}

	// Shutdown REST server
	if s.restServer != nil {
		s.logger.Info("Shutting down REST server...")
		if err := s.restServer.Stop(shutdownCtx); err != nil {
			s.logger.Error("Error shutting down REST server", slog.Any("error", err))
		}
	}

	// Shutdown gRPC server
	if s.grpcServer != nil {
		s.logger.Info("Shutting down gRPC server...")
		s.grpcServer.GracefulStop()
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

	// Close all keystores
	for name, ks := range s.keystores {
		s.logger.Info("Closing keystore...", "backend", name)
		if err := ks.Close(); err != nil {
			s.logger.Error("Error closing keystore", slog.Any("error", err), "backend", name)
		}
	}

	// Close all backends
	s.closeBackends()

	close(s.shutdownCh)
	s.logger.Info("Server shutdown complete")

	return nil
}

// closeBackends closes all backend connections
func (s *Server) closeBackends() {
	for name, backend := range s.backends {
		s.logger.Info("Closing backend...", "backend", name)
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
	ctx, cancel := context.WithCancel(context.Background())

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
	return s.restServer
}

// GRPCServer returns the gRPC server instance
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpcServer
}

// QUICServer returns the QUIC server instance
func (s *Server) QUICServer() *quic.Server {
	return s.quicServer
}

// MCPServer returns the MCP server instance
func (s *Server) MCPServer() *mcp.Server {
	return s.mcpServer
}

// UnixServer returns the Unix socket server instance
func (s *Server) UnixServer() *unix.Server {
	return s.unixServer
}

// UnixGRPCServer returns the Unix gRPC socket server instance
func (s *Server) UnixGRPCServer() *unix.GRPCServer {
	return s.unixGRPCServer
}
