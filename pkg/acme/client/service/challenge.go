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

package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	dns01providers "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

const (
	wellKnownChallenge  = "/.well-known/acme-challenge/"
	acmeChallengePrefix = "_acme-challenge."

	// maxHTTP01TokenLength bounds the RFC 8555 Section 8.3 challenge token
	// length. The bundled ACME server encodes a 16-byte (128-bit) random
	// value to a 22-character base64url token; this cap leaves generous
	// headroom for other ACME servers while still rejecting pathological
	// input before it reaches the filesystem.
	maxHTTP01TokenLength = 256
)

// http01TokenPattern matches RFC 8555 Section 8.3 challenge tokens:
// unpadded base64url characters only.
var http01TokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// validateHTTP01Token rejects challenge tokens that do not conform to RFC
// 8555 Section 8.3 before they are joined into a filesystem path. The token
// is supplied by the ACME server and is otherwise unvalidated input; without
// this check a malicious or compromised server could smuggle path traversal
// sequences (e.g. "../../etc/passwd") into WriteHTTP01TokenFile or
// CleanupHTTP01TokenFile.
func validateHTTP01Token(token string) error {
	if token == "" {
		return ErrInvalidHTTP01Token{Token: token, Reason: "token is empty"}
	}
	if len(token) > maxHTTP01TokenLength {
		return ErrInvalidHTTP01Token{Token: token, Reason: fmt.Sprintf("token exceeds maximum length of %d characters", maxHTTP01TokenLength)}
	}
	if !http01TokenPattern.MatchString(token) {
		return ErrInvalidHTTP01Token{Token: token, Reason: "token contains characters outside the base64url alphabet"}
	}
	return nil
}

// ChallengeServer manages an HTTP server for responding to ACME HTTP-01 challenges.
type ChallengeServer struct {
	server       *http.Server
	listener     net.Listener
	keyAuth      string
	token        string
	host         string
	port         string
	shutdownOnce sync.Once
	mu           sync.Mutex
	logger       *slog.Logger
}

// NewChallengeServer creates a new HTTP-01 challenge server bound to host and
// port. An empty host, the defaults-layer value, binds every interface.
func NewChallengeServer(host, port, token, keyAuth string, logger *slog.Logger) *ChallengeServer {
	return &ChallengeServer{
		token:   token,
		keyAuth: keyAuth,
		host:    host,
		port:    port,
		logger:  logger,
	}
}

// Start begins serving HTTP-01 challenge responses.
func (cs *ChallengeServer) Start() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownChallenge, cs.handleChallenge)

	addr := net.JoinHostPort(cs.host, cs.port)
	cs.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return caerrors.ConnectionFailureError("failed to listen on %s: %v", addr, err)
	}
	cs.listener = listener

	go func() {
		cs.logger.Info("HTTP-01 challenge server started", slog.String("addr", listener.Addr().String()))
		if err := cs.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			cs.logger.Error("HTTP server error", slog.String("error", err.Error()))
		}
	}()

	return nil
}

// Addr returns the address the challenge server is listening on. It is nil
// until Start has bound a listener. Callers that start the server with port
// "0" use Addr to discover the port the kernel actually assigned, rather
// than pre-allocating a port and racing another process to rebind it.
func (cs *ChallengeServer) Addr() net.Addr {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.listener == nil {
		return nil
	}
	return cs.listener.Addr()
}

// handleChallenge serves the key authorization for HTTP-01 challenges.
func (cs *ChallengeServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	requestedToken := strings.TrimPrefix(r.URL.Path, wellKnownChallenge)

	if requestedToken != cs.token {
		cs.logger.Debug("token mismatch",
			slog.String("requested", requestedToken),
			slog.String("expected", cs.token))
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(cs.keyAuth)); err != nil {
		cs.logger.Error("failed to write challenge response", slog.String("error", err.Error()))
	}

	cs.logger.Debug("served HTTP-01 challenge",
		slog.String("token", cs.token),
		slog.String("remote_addr", r.RemoteAddr))
}

// Shutdown gracefully stops the challenge server.
func (cs *ChallengeServer) Shutdown() {
	cs.shutdownOnce.Do(func() {
		cs.mu.Lock()
		defer cs.mu.Unlock()

		if cs.server == nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := cs.server.Shutdown(ctx); err != nil {
			cs.logger.Error("failed to shutdown challenge server", slog.String("error", err.Error()))
		} else {
			cs.logger.Info("HTTP-01 challenge server stopped")
		}
	})
}

// SetupHTTP01Challenge sets up an HTTP-01 challenge by starting an HTTP server
// that responds to ACME server validation requests, or by writing a token file
// to a webroot directory.
func SetupHTTP01Challenge(config *Config, logger *slog.Logger, token, keyAuth string) (*ChallengeServer, error) {
	port := config.Challenge.HTTP01.Port
	if port == "" {
		port = "80"
	}

	// If webroot is configured, write the token file instead of starting a server
	if config.Challenge.HTTP01.WebRoot != "" {
		return nil, WriteHTTP01TokenFile(config.Challenge.HTTP01.WebRoot, token, keyAuth, logger)
	}

	// Start HTTP server to serve challenge
	server := NewChallengeServer(config.Challenge.HTTP01.Host, port, token, keyAuth, logger)
	if err := server.Start(); err != nil {
		return nil, ErrChallengeSetupFailed{
			ChallengeType: "http-01",
			Reason:        err.Error(),
		}
	}

	return server, nil
}

// WriteHTTP01TokenFile writes the key authorization to a webroot directory
// for HTTP-01 challenge validation when using an existing web server.
func WriteHTTP01TokenFile(webroot, token, keyAuth string, logger *slog.Logger) error {
	if err := validateHTTP01Token(token); err != nil {
		return err
	}

	challengeDir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengeDir, 0750); err != nil { // #nosec G301 - directory needs group read for web server
		return caerrors.StorageFailureError("failed to create challenge directory: %v", err)
	}

	tokenPath := filepath.Join(challengeDir, token)
	// #nosec G306 - HTTP-01 challenge token needs to be readable by web server (group permissions)
	if err := os.WriteFile(tokenPath, []byte(keyAuth), 0640); err != nil {
		return caerrors.StorageFailureError("failed to write token file: %v", err)
	}

	logger.Info("HTTP-01 challenge token file written",
		slog.String("path", tokenPath))

	return nil
}

// CleanupHTTP01TokenFile removes the challenge token file from webroot.
func CleanupHTTP01TokenFile(webroot, token string, logger *slog.Logger) {
	if webroot == "" {
		return
	}

	if err := validateHTTP01Token(token); err != nil {
		logger.Warn("refusing to clean up invalid http-01 challenge token", slog.String("error", err.Error()))
		return
	}

	tokenPath := filepath.Join(webroot, ".well-known", "acme-challenge", token)
	if err := os.Remove(tokenPath); err != nil && !os.IsNotExist(err) {
		logger.Warn("failed to remove token file", slog.String("path", tokenPath), slog.String("error", err.Error()))
	} else {
		logger.Debug("HTTP-01 challenge token file removed", slog.String("path", tokenPath))
	}
}

// ComputeDNS01Response computes the DNS-01 challenge response value.
// Per RFC 8555 Section 8.4, the value is the base64url encoding of the
// SHA-256 hash of the key authorization.
func ComputeDNS01Response(keyAuth string) string {
	hash := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// SetupDNS01Challenge provisions the DNS TXT record required for DNS-01
// challenge validation.
//
// When config.Challenge.DNS01.Provider names a supported provider (route53,
// cloudflare, azure, or clouddns), the record is created automatically
// through that provider and the returned DNS01Challenge must be cleaned up
// by calling Cleanup once ACME validation completes. When Provider is empty,
// the record must be created manually (or by an external DNS API) and the
// details are printed for the operator; the returned DNS01Challenge is nil
// since there is nothing for this process to clean up. An unrecognized
// Provider fails fast with ErrUnsupportedDNSProvider rather than printing
// manual instructions and proceeding to a validation that can never succeed.
func SetupDNS01Challenge(ctx context.Context, config *Config, logger *slog.Logger, domain, token, keyAuth string) (*DNS01Challenge, error) {
	dnsResponse := ComputeDNS01Response(keyAuth)
	recordName := fmt.Sprintf("%s%s", acmeChallengePrefix, domain)

	if config.Challenge.DNS01.Provider == "" {
		logger.Info("DNS-01 challenge setup required",
			slog.String("action", "Create the following DNS TXT record"))

		fmt.Println()
		fmt.Println("=== DNS-01 Challenge Setup ===")
		fmt.Println()
		fmt.Printf("Create a DNS TXT record with the following details:\n\n")
		fmt.Printf("  Record Name:  %s\n", recordName)
		fmt.Printf("  Record Type:  TXT\n")
		fmt.Printf("  Record Value: %s\n", dnsResponse)
		fmt.Printf("  TTL:          %d seconds\n", config.Challenge.DNS01.TTL)
		fmt.Println()
		fmt.Println("Example DNS zone entry:")
		fmt.Printf("  %s. %d IN TXT \"%s\"\n", recordName, config.Challenge.DNS01.TTL, dnsResponse)
		fmt.Println()
		fmt.Println("Wait for DNS propagation before continuing.")
		fmt.Println("You can verify with: dig TXT " + recordName)
		fmt.Println()

		return nil, nil
	}

	provider, err := buildDNS01Provider(ctx, config.Challenge.DNS01)
	if err != nil {
		return nil, err
	}

	fqdn := dns01providers.ToFQDN(recordName)

	logger.Info("DNS-01 challenge provisioning record",
		slog.String("provider", config.Challenge.DNS01.Provider),
		slog.String("record", fqdn))

	return newDNS01Challenge(ctx, provider, domain, fqdn, dnsResponse, logger)
}
