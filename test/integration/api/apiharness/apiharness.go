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

// Package apiharness brings the API suite's compose server past its sealed
// window. Every test package under test/integration/api calls Main from its
// TestMain, so a package run on its own (one protocol's make target) finds the
// server unsealed and ready exactly as the full suite does.
package apiharness

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/test/integration/xkmsdtest"
)

// BarrierPassphrase is the passphrase Main unseals the server's barrier with.
// docker-compose.yml hands the same value to `xkmsd init` as XKMS_SO_PIN,
// which init makes the barrier passphrase; the two must match.
const BarrierPassphrase = "xkms-api-harness-barrier-passphrase"

// BarrierTimeout bounds bringing the server past its sealed window.
const BarrierTimeout = 120 * time.Second

// restURLEnv names the server's REST base URL; compose sets it for the
// integration-tests service.
const restURLEnv = "KEYSTORE_REST_URL"

// caFileEnv names the suite CA that anchors the sealed window's certificate.
const caFileEnv = "KEYSTORE_TLS_CA"

// defaultCAFile is the suite CA's path inside the integration-tests service.
const defaultCAFile = "/etc/xkms/certs/ca.crt"

// readyPollInterval spaces the /health/ready probes.
const readyPollInterval = 500 * time.Millisecond

// Main brings the server past its sealed window, then runs the package's
// tests and exits with their status. The compose stack bootstraps a fresh
// volume with `xkmsd init --admin-factor mtls`, which also initializes the
// passphrase barrier, so xkmsd boots sealed and answers nothing but the
// barrier routes until it is unsealed -- exactly as the cluster harness's
// TestMain does for its nodes. The integration-tests service therefore waits
// for the server to start, not to turn healthy. Unsealing leaves an unsealed
// server alone, so packages run one after another each call it safely.
// Outside compose (a bare compile or vet run) KEYSTORE_REST_URL is unset and
// there is no server to open.
func Main(m *testing.M) {
	if baseURL := os.Getenv(restURLEnv); baseURL != "" {
		if err := Open(baseURL); err != nil {
			fmt.Fprintf(os.Stderr, "api harness barrier unseal failed: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// Open unseals the barrier of the server at baseURL through its sealed window
// and waits until the full server is ready. The window serves the configured
// certificate (tls.cert_file), so the suite's CA is the anchor; once unsealed
// the server presents the certificate its serving CA issued and persisted
// under the unified-TLS data dir (XKMS_UNIFIED_CA). The client re-reads both
// on every dial (TrustedHTTPClient), so AwaitReady verifies the switched
// certificate.
func Open(baseURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), BarrierTimeout)
	defer cancel()
	// The suite CA may not be on disk yet when the server is still starting.
	for {
		_, err := TrustPool()
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(readyPollInterval):
		}
	}
	client := TrustedHTTPClient(15 * time.Second)
	return openReady(ctx, client, baseURL, []byte(BarrierPassphrase))
}

// openReady opens the barrier of the server at baseURL and waits until it is
// ready. go test runs the test binaries under test/integration/api at once,
// and each one's TestMain opens the same server: every binary may see the
// barrier sealed and post an unseal, and the server answers each one that
// loses with the already-unsealed refusal, HTTP 409 Conflict. That answer
// means another binary opened the barrier, so the loser waits for readiness
// within the same deadline like the winner; any other unseal error fails.
func openReady(ctx context.Context, client *http.Client, baseURL string, passphrase []byte) error {
	if err := xkmsdtest.OpenBarrier(ctx, client, baseURL, passphrase); err != nil && !lostUnsealRace(err) {
		return err
	}
	return AwaitReady(ctx, client, baseURL)
}

// lostUnsealRace reports whether err is the server's already-unsealed answer
// to an unseal post, recognised by its HTTP status.
func lostUnsealRace(err error) bool {
	var status *xkmsdtest.StatusError
	if !errors.As(err, &status) {
		return false
	}
	switch status.Code {
	case http.StatusConflict:
		return true
	case http.StatusServiceUnavailable:
		// Another package's TestMain unsealed between this caller's status
		// read and its unseal post: the sealed-window listener has closed
		// and answers 503 with code SEALED_WINDOW_CLOSED (barrier unsealed).
		return strings.Contains(status.Body, sealedWindowClosedCode)
	default:
		return false
	}
}

// sealedWindowClosedCode is the error code the sealed-window listener sends
// once the barrier is unsealed and the listener is shutting down.
const sealedWindowClosedCode = `"SEALED_WINDOW_CLOSED"`

// AwaitReady polls baseURL's /health/ready, the probe the cluster stack waits
// on, over client (anchored on the suite's CA, so only the verified server
// answers) until it returns 200 or ctx ends. The unseal answering 204 means
// the barrier opened, not that the full server has replaced the sealed window
// and serves requests.
func AwaitReady(ctx context.Context, client *http.Client, baseURL string) error {
	route := baseURL + "/health/ready"
	var last error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, route, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close() // only the status is read; a close failure cannot change it
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("GET %s: status %d", route, resp.StatusCode)
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("server not ready after unseal: %w (last: %v)", ctx.Err(), last)
		case <-time.After(readyPollInterval):
		}
	}
}
