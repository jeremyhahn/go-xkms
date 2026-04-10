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
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
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
	rpOriginsStr := getEnv("WEBAUTHN_RP_ORIGINS", "https://localhost:8443")
	port := getEnv("PORT", "8443")

	rpOrigins := strings.Split(rpOriginsStr, ",")

	fmt.Printf("Configuration:\n")
	fmt.Printf("  RP ID:      %s\n", rpID)
	fmt.Printf("  RP Name:    %s\n", rpName)
	fmt.Printf("  RP Origins: %v\n", rpOrigins)
	fmt.Printf("  Port:       %s\n", port)
	fmt.Println()

	// Create WebAuthn stores (use database stores for production)
	fmt.Println("1. Initializing WebAuthn stores...")
	stores := rest.NewWebAuthnStores(&rest.WebAuthnStoresConfig{
		SessionTTL: 5 * time.Minute,
	})
	fmt.Println("   ✓ Memory stores initialized")

	// Start session cleanup routine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanupCancel := stores.StartCleanupRoutine(ctx, time.Minute)
	defer cleanupCancel()
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
		UserStore:       stores.UserStore(),
		SessionStore:    stores.SessionStore(),
		CredentialStore: stores.CredentialStore(),
	})
	if err != nil {
		log.Fatalf("Failed to create WebAuthn service: %v", err)
	}
	fmt.Println("   ✓ WebAuthn service created")

	// Create HTTP handlers
	fmt.Println()
	fmt.Println("3. Setting up HTTP handlers...")
	handlers := webauthnhttp.NewHandler(svc)

	// Create router
	mux := http.NewServeMux()

	// Mount WebAuthn handlers
	mux.HandleFunc("/api/v1/webauthn/registration/begin", handlers.BeginRegistration)
	mux.HandleFunc("/api/v1/webauthn/registration/finish", handlers.FinishRegistration)
	mux.HandleFunc("/api/v1/webauthn/registration/status", handlers.RegistrationStatus)
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

	// Generate self-signed certificate for HTTPS
	fmt.Println()
	fmt.Println("4. Generating TLS certificate...")
	tlsConfig, err := generateTLSConfig()
	if err != nil {
		log.Fatalf("Failed to generate TLS config: %v", err)
	}
	fmt.Println("   ✓ Self-signed certificate generated")

	// Create HTTPS server
	server := &http.Server{
		Addr:      ":" + port,
		Handler:   mux,
		TLSConfig: tlsConfig,
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
	fmt.Printf("Server listening on: https://localhost:%s\n", port)
	fmt.Println()
	fmt.Println("Available endpoints:")
	fmt.Printf("  - https://localhost:%s/              (Web UI)\n", port)
	fmt.Printf("  - https://localhost:%s/health        (Health check)\n", port)
	fmt.Printf("  - https://localhost:%s/api/v1/webauthn/*\n", port)
	fmt.Println()
	fmt.Println("WebAuthn API:")
	fmt.Println("  POST /api/v1/webauthn/registration/begin   - Start registration")
	fmt.Println("  POST /api/v1/webauthn/registration/finish  - Complete registration")
	fmt.Println("  GET  /api/v1/webauthn/registration/status  - Check registration status")
	fmt.Println("  POST /api/v1/webauthn/login/begin          - Start login")
	fmt.Println("  POST /api/v1/webauthn/login/finish         - Complete login")
	fmt.Println("  GET  /api/v1/webauthn/debug                - Debug/diagnostic info")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop the server")
	fmt.Println()

	// The server uses ListenAndServeTLS with empty cert/key paths
	// because we've already configured the TLS certificates in tlsConfig
	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	fmt.Println("Server stopped")
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
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
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
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	// Load certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
