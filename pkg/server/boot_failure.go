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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// bootFailureShutdownTimeout bounds the failed-boot listener's drain.
const bootFailureShutdownTimeout = 15 * time.Second

// bootFailureStatus is the body every request to the failed-boot listener
// gets: the node did not complete its boot after unseal; Sealed reports
// whether qrdb re-sealed the barrier on that failure.
type bootFailureStatus struct {
	Sealed     bool   `json:"sealed"`
	BootFailed bool   `json:"boot_failed"`
	Stage      string `json:"stage"`
	Error      string `json:"error"`
}

// ServeBootFailure keeps the daemon reachable after a boot-completion
// failure following unseal (#2290): exiting would make the supervisor
// restart re-seal the barrier, a crash loop that needs an unseal per boot.
// It serves HTTPS on Server.Host:RESTPort under the sealed window's bind
// rule with the unified listener's TLS policy (TLS 1.3, tls.client_auth and
// the configured client CAs, from buildUnifiedTLSConfig), and answers every
// request, GET /v1/barrier/status included, with 503 and the failed stage
// and cause. It blocks until ctx is done and returns
// nil, or an error when the listener cannot be set up.
func ServeBootFailure(ctx context.Context, cfg *config.Config, bootErr *QRDBNodeError, logger *slog.Logger) error {
	if cfg == nil || bootErr == nil {
		return errors.New("server: ServeBootFailure needs a config and a boot error")
	}
	if logger == nil {
		logger = slog.Default()
	}
	host := cfg.Server.Host
	if !isLoopbackHost(host) && !cfg.Barrier.SealedWindowAllowRemote {
		return &SealedWindowBindError{Host: host}
	}

	// The same policy the unified listener serves: TLS 1.3, tls.client_auth
	// and the configured client CAs, so a boot failure exposes its cause to
	// no caller that policy would reject.
	tlsConfig, err := (&Server{config: cfg, logger: logger}).buildUnifiedTLSConfig()
	if err != nil {
		return fmt.Errorf("server: failed-boot listener TLS: %w", err)
	}

	cause := ""
	if bootErr.Err != nil {
		cause = bootErr.Err.Error()
	}
	body, err := json.Marshal(bootFailureStatus{Sealed: bootErr.Resealed, BootFailed: true, Stage: bootErr.Stage, Error: cause})
	if err != nil {
		return fmt.Errorf("server: failed-boot status body: %w", err)
	}
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/barrier/status", handler)
	mux.HandleFunc("/", handler)

	addr := net.JoinHostPort(host, strconv.Itoa(cfg.Server.RESTPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("server: failed-boot listener on %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeTLS(ln, "", "") }()
	logger.Warn("serving the boot failure on the REST listener until shutdown",
		"addr", ln.Addr().String(), "stage", bootErr.Stage)

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server: failed-boot listener: %w", err)
		}
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), bootFailureShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("failed-boot listener shutdown", "error", err)
	}
	return nil
}
