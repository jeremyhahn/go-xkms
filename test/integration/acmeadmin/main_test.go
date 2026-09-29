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

package acmeadmin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// TestMain establishes trust in the compose stack's xkmsd before any test
// runs, the same way test/integration/cluster's TestMain does: xkmsd mints
// its serving certificate from its own embedded CA at boot
// (pkg/server/unified_tls.go's buildUnifiedTLSConfig — there is no
// operator-supplied cert_file/key_file/ca_file in xkmsd.yaml on purpose), so
// the harness fetches that root the way any first-contact client does,
// through pkg/trust/bootstrap in TOFU mode over the public
// GET /v1/ca/bootstrap route, and presents the qrdb first-boot
// administrator's mTLS credential (pkg/server/firstboot.go — written to
// storage.path/admin-cert.pem and admin-key.pem, mounted read-only from the
// xkmsd-data volume) for every xkmsctl invocation this suite makes.
//
// When XKMSCTL_ACME_SERVER is unset (a bare compile/vet/lint run, or `go
// test` outside compose) trust bootstrap is skipped entirely so the package
// still builds and the tests still fail informatively (missing TLS material)
// rather than hanging on a server that was never going to be there.
func TestMain(m *testing.M) {
	serverURL := os.Getenv("XKMSCTL_ACME_SERVER")
	if serverURL == "" {
		os.Exit(m.Run())
	}

	if err := bootstrapTrust(serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "acmeadmin harness trust bootstrap failed: %v\n", err)
		os.Exit(1)
	}

	if err := waitForAdminCredential(); err != nil {
		fmt.Fprintf(os.Stderr, "acmeadmin harness admin credential wait failed: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// bootstrapTrust fetches xkmsd's CA bundle over TOFU and writes it to a file,
// then points XKMSCTL_TLS_CA at it (unless the caller already set one) so
// every xkmsctl invocation harness.go builds verifies the server against
// this suite's own captured root — no InsecureSkipVerify anywhere.
//
// TOFU (trust-on-first-use) is correct here for the same reason it is in the
// cluster harness: the compose stack starts from a clean volume, so first
// contact IS the trust ceremony, and the pin store is scoped to this
// process.
func bootstrapTrust(serverURL string) error {
	if os.Getenv("XKMSCTL_TLS_CA") != "" {
		return nil
	}

	pins := truststrap.NewMemoryPinStore()
	deadline := time.Now().Add(90 * time.Second)

	var (
		bundle  *bootstrap.CABundle
		lastErr error
	)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		b, err := bootstrap.Fetch(ctx, bootstrap.Config{
			Mode:      bootstrap.ModeTOFU,
			ServerURL: serverURL,
			Logger:    slog.Default(),
			TOFU: &bootstrap.TOFUConfig{
				PinStore: pins,
				ConfirmFunc: func(context.Context, *truststrap.Pin) error {
					return nil
				},
			},
		})
		cancel()
		if err == nil {
			bundle = b
			break
		}
		lastErr = err
		if time.Now().After(deadline) {
			return fmt.Errorf("fetch CA bundle from %s: %w", serverURL, lastErr)
		}
		time.Sleep(2 * time.Second)
	}

	path := filepath.Join(os.TempDir(), "acmeadmin-ca-bundle.pem")
	if err := os.WriteFile(path, bundle.PEM, 0o644); err != nil {
		return fmt.Errorf("write CA bundle to %s: %w", path, err)
	}

	return os.Setenv("XKMSCTL_TLS_CA", path)
}

// waitForAdminCredential polls until the qrdb first-boot administrator's
// mTLS certificate and key exist on the mounted xkmsd-data volume, then
// points XKMSCTL_TLS_CERT/XKMSCTL_TLS_KEY at them (unless the caller already
// set them). XKMSCTL_ADMIN_CRED_DIR names the directory; it defaults to
// /data/storage to match where xkmsd.yaml's storage.path writes them and
// where the compose file mounts the shared xkmsd-data volume in the test
// container.
func waitForAdminCredential() error {
	if os.Getenv("XKMSCTL_TLS_CERT") != "" && os.Getenv("XKMSCTL_TLS_KEY") != "" {
		return nil
	}

	dir := getEnvOrDefault("XKMSCTL_ADMIN_CRED_DIR", "/data/storage")
	certPath := filepath.Join(dir, "admin-cert.pem")
	keyPath := filepath.Join(dir, "admin-key.pem")

	deadline := time.Now().Add(90 * time.Second)
	for {
		_, certErr := os.Stat(certPath)
		_, keyErr := os.Stat(keyPath)
		if certErr == nil && keyErr == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("admin credential not found in %s within deadline (cert: %v, key: %v)", dir, certErr, keyErr)
		}
		time.Sleep(2 * time.Second)
	}

	if err := os.Setenv("XKMSCTL_TLS_CERT", certPath); err != nil {
		return err
	}
	return os.Setenv("XKMSCTL_TLS_KEY", keyPath)
}
