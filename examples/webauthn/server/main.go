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

// WebAuthn Server Example
//
// This example demonstrates a complete WebAuthn server implementation
// for passwordless authentication using go-xkms.
//
// Usage:
//
//	go run main.go
//
// Then open https://localhost:8443 in your browser.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
)

//go:embed static/*
var staticFiles embed.FS

func main() {
	fmt.Println("=== WebAuthn Server Example ===")
	fmt.Println()

	// Get configuration from environment
	rpID := getEnv("WEBAUTHN_RP_ID", "localhost")
	rpName := getEnv("WEBAUTHN_RP_NAME", "go-xkms Example")
	port := getEnv("PORT", "8443")

	// TLS is on by default. Set TLS_ENABLED=false to serve plain HTTP, which
	// is what mobile testing over `adb reverse` needs: http://localhost is a
	// WebAuthn secure context, so no certificate has to be trusted on the
	// device.
	tlsEnabled := getEnv("TLS_ENABLED", "true") != "false"
	scheme := "https"
	if !tlsEnabled {
		scheme = "http"
	}

	rpOriginsStr := getEnv("WEBAUTHN_RP_ORIGINS", fmt.Sprintf("%s://localhost:%s", scheme, port))
	rpOrigins := strings.Split(rpOriginsStr, ",")

	fmt.Printf("Configuration:\n")
	fmt.Printf("  RP ID:      %s\n", rpID)
	fmt.Printf("  RP Name:    %s\n", rpName)
	fmt.Printf("  RP Origins: %v\n", rpOrigins)
	fmt.Printf("  Port:       %s\n", port)
	fmt.Printf("  TLS:        %t\n", tlsEnabled)
	fmt.Println()

	// Boot an in-memory qrdb node. Users are qrdb user records and passkey
	// credentials are DAO entities on the node's datastore, exactly as in
	// xkmsd; only the storage backend differs.
	fmt.Println("1. Initializing WebAuthn stores...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node, dataDir, err := startQRDBNode(ctx)
	if err != nil {
		log.Fatalf("Failed to start qrdb node: %v", err)
	}
	defer func() {
		if err := node.Close(); err != nil {
			log.Printf("Failed to stop qrdb node: %v", err)
		}
		if err := os.RemoveAll(dataDir); err != nil {
			log.Printf("Failed to remove qrdb data directory: %v", err)
		}
	}()
	users, credentials, err := newStores(node)
	if err != nil {
		log.Fatalf("Failed to build WebAuthn stores: %v", err)
	}
	sessions := webauthn.NewMemorySessionStoreWithTTL(5 * time.Minute)
	fmt.Println("   ✓ In-memory qrdb node and stores initialized")

	// Sweep expired ceremony sessions until shutdown
	go webauthn.SweepSessions(ctx, sessions, time.Minute)
	fmt.Println("   ✓ Session cleanup routine started")

	// Create WebAuthn configuration
	fmt.Println()
	fmt.Println("2. Configuring WebAuthn service...")
	cfg := &webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpName,
		RPOrigins:     rpOrigins,
		Debug:         true,
	}

	// Create WebAuthn service
	svc, err := webauthn.NewService(webauthn.ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    sessions,
		CredentialStore: credentials,
	})
	if err != nil {
		log.Fatalf("Failed to create WebAuthn service: %v", err)
	}
	fmt.Println("   ✓ WebAuthn service created")

	// Create HTTP handlers. The handler logs the underlying cause of a
	// verification failure at debug level, which is the only way to tell an
	// authenticator interop bug from a genuinely forged credential, so the
	// example runs its logger at debug level to match cfg.Debug.
	fmt.Println()
	fmt.Println("3. Setting up HTTP handlers...")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handlers := webauthnhttp.NewHandler(svc).WithLogger(logger)

	// Create router
	mux := http.NewServeMux()

	// Mount WebAuthn handlers
	mux.HandleFunc("/api/v1/webauthn/registration/begin", handlers.BeginRegistration)
	mux.HandleFunc("/api/v1/webauthn/registration/finish", handlers.FinishRegistration)
	mux.HandleFunc("/api/v1/webauthn/login/begin", handlers.BeginLogin)
	mux.HandleFunc("/api/v1/webauthn/login/finish", handlers.FinishLogin)
	fmt.Println("   ✓ WebAuthn API mounted at /api/v1/webauthn")

	// Serve static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to get static files: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	fmt.Println("   ✓ Static files mounted at /")

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})
	fmt.Println("   ✓ Health endpoint at /health")

	// Debug/diagnostic endpoint
	mux.HandleFunc("/api/v1/webauthn/debug", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		// Call BeginRegistration with a dummy user to capture the exact
		// CredentialCreation options that would be sent to the browser.
		options, _, err := svc.BeginRegistration(r.Context(), "debug@test.com", "Debug User")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("failed to generate registration options: %v", err),
			})
			return
		}

		svcCfg := svc.Config()

		response := map[string]interface{}{
			"registration_options": options,
			"config": map[string]interface{}{
				"rp_id":             svcCfg.RPID,
				"rp_display_name":   svcCfg.RPDisplayName,
				"rp_origins":        svcCfg.RPOrigins,
				"user_verification": svcCfg.UserVerification,
				"resident_key":      svcCfg.ResidentKeyRequirement,
				"attestation":       svcCfg.AttestationPreference,
			},
			"go_webauthn_version": "v0.15.0",
		}

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(response)
	})
	fmt.Println("   ✓ Debug endpoint at /api/v1/webauthn/debug")

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	if tlsEnabled {
		fmt.Println()
		fmt.Println("4. Generating TLS certificate...")
		tlsConfig, err := generateTLSConfig()
		if err != nil {
			log.Fatalf("Failed to generate TLS config: %v", err)
		}
		server.TLSConfig = tlsConfig
		fmt.Println("   ✓ Self-signed certificate generated")
	} else {
		fmt.Println()
		fmt.Println("4. TLS disabled (TLS_ENABLED=false); serving plain HTTP")
	}

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println()
		fmt.Println("Shutting down server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	// Start server
	fmt.Println()
	fmt.Println("=== Server Ready ===")
	fmt.Printf("Server listening on: %s://localhost:%s\n", scheme, port)
	fmt.Println()
	fmt.Println("Available endpoints:")
	fmt.Printf("  - %s://localhost:%s/              (Web UI)\n", scheme, port)
	fmt.Printf("  - %s://localhost:%s/health        (Health check)\n", scheme, port)
	fmt.Printf("  - %s://localhost:%s/api/v1/webauthn/*\n", scheme, port)
	fmt.Println()
	fmt.Println("WebAuthn API:")
	fmt.Println("  POST /api/v1/webauthn/registration/begin   - Start registration")
	fmt.Println("  POST /api/v1/webauthn/registration/finish  - Complete registration")
	fmt.Println("  POST /api/v1/webauthn/login/begin          - Start login")
	fmt.Println("  POST /api/v1/webauthn/login/finish         - Complete login")
	fmt.Println("  GET  /api/v1/webauthn/debug                - Debug/diagnostic info")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop the server")
	fmt.Println()

	// With TLS enabled the certificates already live in server.TLSConfig, so
	// ListenAndServeTLS is called with empty cert/key paths.
	var serveErr error
	if tlsEnabled {
		serveErr = server.ListenAndServeTLS("", "")
	} else {
		serveErr = server.ListenAndServe()
	}
	if !errors.Is(serveErr, http.ErrServerClosed) {
		log.Fatalf("Server error: %v", serveErr)
	}

	fmt.Println("Server stopped")
}

// startQRDBNode boots a standalone qrdb node with an in-memory database and
// no network listeners. Its raft metadata lives in a temporary directory the
// caller removes.
func startQRDBNode(ctx context.Context) (*qrdbnode.Node, string, error) {
	dataDir, err := os.MkdirTemp("", "webauthn-example-")
	if err != nil {
		return nil, "", err
	}
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = dataDir
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false
	node, err := qrdbnode.NewStandaloneNode(ctx, cfg, nil, serviceprincipal.Option())
	if err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, "", err
	}
	return node, dataDir, nil
}

// newStores builds the WebAuthn user and credential stores on the node's
// system tenant: users are qrdb user records and credentials are DAO
// entities on the node's datastore. The ceremony endpoints are public, so
// every qrdb call runs as the node's service principal, as in xkmsd, and the
// pending-enrolment claims live in the node's KV store.
func newStores(node *qrdbnode.Node) (webauthn.UserStore, webauthn.CredentialStore, error) {
	ds, err := datastore.New(node.Client(), config.DatastoreConfig{}, datastore.WithCallContext(node.ServiceContext))
	if err != nil {
		return nil, nil, err
	}
	return webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
		Users:       node.Client().Users(),
		DAOFactory:  ds.DAOFactory(),
		TenantID:    "system",
		CallContext: node.ServiceContext,
		KV:          node.Client().KV(),
	})
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func generateTLSConfig() (*tls.Config, error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate private key", Err: err}
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate serial number", Err: err}
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"go-xkms Example"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create certificate", Err: err}
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal private key", Err: err}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	// Load certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to load key pair", Err: err}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}
