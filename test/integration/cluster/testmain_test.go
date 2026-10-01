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
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// TestMain bootstraps TLS trust for the whole suite. Every node mints its
// serving certificate from its own embedded CA at boot, so the harness obtains
// each root the way any first-contact client does — through the trust bootstrap
// pkg/trust owns, in TOFU mode over GET /v1/ca/bootstrap — and installs the
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
		if err := openBarriers(); err != nil {
			fmt.Fprintf(os.Stderr, "cluster harness barrier unseal failed: %v\n", err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if err := fetchClusterRoots(urls, pool); err != nil {
			fmt.Fprintf(os.Stderr, "cluster harness trust bootstrap failed: %v\n", err)
			os.Exit(1)
		}
		if err := installAdminClients(pool); err != nil {
			fmt.Fprintf(os.Stderr, "cluster harness admin credential setup failed: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// adminCredentialGroups maps candidate first-boot data directories to the node
// base URLs whose requests authenticate with that group's admin credential.
// First boot (qrdb pkg/firstboot, run at xkmsd startup) provisions the system
// administrator once per deployment and writes the generate-and-distribute
// admin certificate and key into the data directory of whichever node executed
// it; the compose file mounts every data volume into the test container so the
// suite can authenticate the way a freshly enrolled operator does — admin
// mTLS, no invite tokens, no pre-seeded passwords.
func adminCredentialGroups() map[string][]string {
	groups := map[string][]string{}
	clusterURLs := []string{}
	for _, key := range []string{envNode1URL, envNode2URL, envNode3URL} {
		if v := os.Getenv(key); v != "" {
			clusterURLs = append(clusterURLs, v)
		}
	}
	if len(clusterURLs) > 0 {
		groups["/node1-data,/node2-data,/node3-data"] = clusterURLs
	}
	if v := os.Getenv("CLUSTER_STANDALONE_URL"); v != "" {
		groups["/standalone-data"] = []string{v}
	}
	return groups
}

// loadAdminCredential polls the candidate directories until one of them holds
// a loadable first-boot admin certificate and key.
func loadAdminCredential(dirs []string) (tls.Certificate, error) {
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for {
		for _, dir := range dirs {
			cert, err := tls.LoadX509KeyPair(datastore(dir)+"/admin-cert.pem", datastore(dir)+"/admin-key.pem")
			if err == nil {
				return cert, nil
			}
			lastErr = err
		}
		if time.Now().After(deadline) {
			return tls.Certificate{}, fmt.Errorf("admin credential in %v: %w", dirs, lastErr)
		}
		time.Sleep(2 * time.Second)
	}
}

// installAdminClients waits for each deployment's first-boot admin credential
// and installs a per-base-URL HTTP client that presents it. The cluster shares
// one admin (first boot runs once, replicated), so a single credential
// authenticates against all three nodes; the standalone server has its own CA
// and its own admin.
func installAdminClients(pool *x509.CertPool) error {
	for dirList, urls := range adminCredentialGroups() {
		cert, err := loadAdminCredential(strings.Split(dirList, ","))
		if err != nil {
			return err
		}
		client := &http.Client{
			Timeout: 2 * requestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      pool,
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS13,
				},
			},
		}
		for _, u := range urls {
			clientsByBase[u] = client
		}
	}
	// The default client (trust-verified, unauthenticated) covers public
	// endpoints and any URL without an admin credential mapping.
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		},
	}
	return nil
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
				BundlePath: "/v1/ca/bootstrap",
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
