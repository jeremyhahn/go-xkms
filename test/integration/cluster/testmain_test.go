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

//go:build integration

package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// TestMain bootstraps TLS trust for the whole suite. Every node mints its
// serving certificate from its own embedded CA at boot, so the harness obtains
// each root the way any first-contact client does — through the trust bootstrap
// pkg/trust owns, in TOFU mode over GET /api/v1/ca/bundle — and installs the
// union as the httpClient's RootCAs. No InsecureSkipVerify anywhere: after the
// first-contact fetch, every request in the suite verifies against the fetched
// roots exactly as a production client would.
//
// TOFU (trust-on-first-use) is the correct mode for this harness: the compose
// stack starts from clean volumes, so first contact IS the trust ceremony, and
// the in-memory pin store scopes the captured pins to this process. When the
// CLUSTER_NODE* environment is absent (e.g. a bare compile or lint run) the
// bootstrap is skipped so the binary still builds and runs outside compose.
func TestMain(m *testing.M) {
	urls := trustBootstrapURLs()
	if len(urls) > 0 {
		pool := x509.NewCertPool()
		if err := fetchClusterRoots(urls, pool); err != nil {
			fmt.Fprintf(os.Stderr, "cluster harness trust bootstrap failed: %v\n", err)
			os.Exit(1)
		}
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS13,
			},
		}
	}
	os.Exit(m.Run())
}

// trustBootstrapURLs returns the node base URLs the suite will dial, from the
// same environment variables the tests read. Absent variables are skipped.
func trustBootstrapURLs() []string {
	var urls []string
	for _, key := range []string{envNode1URL, envNode2URL, envNode3URL, "CLUSTER_STANDALONE_URL"} {
		if v := os.Getenv(key); v != "" {
			urls = append(urls, v)
		}
	}
	return urls
}

// fetchClusterRoots performs a TOFU bootstrap against each node URL and adds
// every fetched CA bundle to pool. Nodes may still be settling when the runner
// starts, so each fetch polls with a bounded deadline.
func fetchClusterRoots(urls []string, pool *x509.CertPool) error {
	pins := truststrap.NewMemoryPinStore()
	deadline := time.Now().Add(90 * time.Second)

	for _, u := range urls {
		var lastErr error
		for {
			ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
			bundle, err := bootstrap.Fetch(ctx, bootstrap.Config{
				Mode:       bootstrap.ModeTOFU,
				ServerURL:  u,
				BundlePath: "/api/v1/ca/bundle",
				TOFU: &bootstrap.TOFUConfig{
					PinStore: pins,
					// First contact against a freshly provisioned throwaway
					// cluster: accept the captured pin. This is the TOFU
					// ceremony, not a verification bypass — every subsequent
					// request verifies against the fetched root.
					ConfirmFunc: func(_ context.Context, _ *truststrap.Pin) error {
						return nil
					},
				},
			})
			cancel()
			if err == nil {
				if !pool.AppendCertsFromPEM(bundle.PEM) {
					return fmt.Errorf("node %s served a CA bundle with no parseable certificates", u)
				}
				break
			}
			lastErr = err
			if time.Now().After(deadline) {
				return fmt.Errorf("node %s: %w", u, lastErr)
			}
			time.Sleep(2 * time.Second)
		}
	}
	return nil
}
