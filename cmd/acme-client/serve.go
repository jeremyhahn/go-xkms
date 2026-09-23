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

//go:build gui

package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	clientapi "github.com/jeremyhahn/go-xkms/pkg/acme/gui/client/api"
	"github.com/jeremyhahn/go-xkms/pkg/acme/gui/webui"
)

// ErrServeStart indicates the serve command failed to start the HTTP server.
type ErrServeStart struct {
	Detail string
}

// Error returns the error message.
func (e *ErrServeStart) Error() string {
	return "serve: server start failed: " + e.Detail
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the ACME client as a self-hosted web service",
	Long: `Start the ACME client web UI and REST API as a self-hosted service.
This makes the client accessible via browser from any machine on the network.

Examples:
  # Start with default TLS on :8443
  trusted-acme-client serve --tls-cert cert.pem --tls-key key.pem

  # Start without TLS for development
  trusted-acme-client serve --no-tls --addr :8080

  # Custom bind address; the browser UI is told to reach the API at localhost
  trusted-acme-client serve --addr 0.0.0.0:9443 --tls-cert cert.pem --tls-key key.pem

  # Bind every interface but advertise the name clients use to reach the API
  trusted-acme-client serve --addr 0.0.0.0:9443 --api-base-url https://acme.example.com:9443 \
    --tls-cert cert.pem --tls-key key.pem`,
	RunE: runServe,
}

func init() {
	registerServeFlags(serveCmd.Flags())
	bindServeFlags(serveCmd.Flags())

	rootCmd.AddCommand(serveCmd)
}

// runServe starts the ACME client as a self-hosted web service with the REST
// API and SPA frontend accessible via browser.
func runServe(cmd *cobra.Command, args []string) error {
	addr := viper.GetString("serve.addr")
	tlsCert := viper.GetString("serve.tls_cert")
	tlsKey := viper.GetString("serve.tls_key")
	noTLS := viper.GetBool("serve.no_tls")

	if !noTLS && (tlsCert == "" || tlsKey == "") {
		return &ErrServeConfig{
			Detail: "TLS certificate and key are required (use --tls-cert and --tls-key, or --no-tls to disable)",
		}
	}

	cfg := buildServiceConfig()
	logger := service.InitLogger(cfg.Logging)

	svc, err := service.NewService(cfg, logger)
	if err != nil {
		return err
	}

	router := clientapi.NewRouter(nil, svc, logger)

	// The API base URL the frontend dials is configuration; derived from the
	// listen address only when the operator left it unset.
	apiBaseURL, urlErr := advertisedAPIBaseURL(viper.GetString("serve.api_base_url"), noTLS, addr)
	if urlErr != nil {
		return urlErr
	}

	// Mount client SPA at /ui/client/ using the embedded frontend assets.
	if err := webui.RegisterSPA(router, webui.ClientAssets, "/ui/client/", logger, webui.WithAPIBaseURL(apiBaseURL)); err != nil {
		return &ErrServeStart{Detail: "mounting client SPA: " + err.Error()}
	}

	// Redirect root to client UI for convenience.
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/client/", http.StatusTemporaryRedirect)
	}).Methods(http.MethodGet)

	server := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if !noTLS {
		tlsConfig, tlsErr := buildTLSConfig(tlsCert, tlsKey)
		if tlsErr != nil {
			return tlsErr
		}
		server.TLSConfig = tlsConfig
	}

	// Set up signal-based context for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer stop()

	// Start server in background goroutine.
	errCh := make(chan error, 1)
	go func() {
		logger.Info("serving ACME client",
			slog.String("addr", addr),
			slog.String("api_base_url", apiBaseURL),
			slog.Bool("tls", !noTLS),
		)
		if noTLS {
			errCh <- server.ListenAndServe()
		} else {
			errCh <- server.ListenAndServeTLS(tlsCert, tlsKey)
		}
	}()

	// Wait for shutdown signal or server error.
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return &ErrServeStart{Detail: err.Error()}
		}
		return nil
	}

	// Graceful shutdown with 30 second deadline.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown error", slog.String("error", err.Error()))
		return &ErrServeStart{Detail: "shutdown: " + err.Error()}
	}

	logger.Info("server stopped gracefully")
	return nil
}

// buildTLSConfig creates a tls.Config from the provided certificate and key paths.
func buildTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, &ErrServeConfig{Detail: "loading TLS keypair: " + err.Error()}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}
