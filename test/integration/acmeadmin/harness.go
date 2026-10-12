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

// Package acmeadmin drives the real xkmsctl binary against a running xkmsd
// to exercise the ACME admin plane end to end: "xkmsctl acme ..." for
// status/stats/cert/account/eab, and "xkmsctl tenant ..." for tenant
// lifecycle (a separate command group — see tenant.go's doc comment for
// why one process needs both).
//
// This package replaces test/integration/cactl (go-xkms#949): go-trusted-ca's
// cactl binary no longer exists in this repository, and the ACME admin
// plane it drove is served exclusively over REST by xkmsd today (see
// docs/acme-issuance/api.md, "Transport adapters"). Every case here therefore runs a single
// transport, REST, via "--acme-transport rest"; the former transport-matrix
// coverage (gRPC/QUIC/MCP/Unix) is dropped, not adapted, because xkmsd does
// not serve those transports (go-xkms#743 tracks wiring them).
//
// PRODUCTION BUG FOUND AND FIXED WHILE BUILDING THIS SUITE (see
// cli_test.go's testCLITenantLifecycle doc comment for the full trace):
// "xkmsctl tenant create"/"list" requested the tenant collection root as
// "/api/v1/tenants", without the trailing slash xkmsd's own route table
// registers it under ("/api/v1/tenants/", pkg/api/rest/routes.go — the
// same convention every other collection-root route in that file uses).
// That gap was silently bridged by a slash redirect as long as nothing
// else claimed the exact, no-slash path — until the ACME admin plane
// (required for this whole suite) registered precisely that literal path
// for its own, differently-shaped tenant surface
// (pkg/apimodule/admin_module.go, cmd/xkmsd/admin.go's adminAPIPrefixes),
// which then answered first with no error and no redirect, just an
// all-zero-value response body. Fixed in
// pkg/api/transport/rest/transport.go's CreateTenant/ListTenants; see that
// file's doc comments and transport_tenant_test.go's
// TestCreateTenant_CollectionRootRequiresTrailingSlash /
// TestListTenants_CollectionRootRequiresTrailingSlash for the regression
// coverage.
//
// Environment variables:
//   - XKMSCTL_BINARY: path to the xkmsctl binary (default: xkmsctl, resolved from PATH)
//   - XKMSCTL_ACME_SERVER: ACME admin REST base URL (default: https://localhost:8443)
//   - XKMSCTL_SERVER: xkmsd's own control-plane address, for "tenant" commands (default: https://localhost:8443)
//   - XKMSCTL_TRANSPORT: transport for "tenant" commands (default: rest)
//   - XKMSCTL_TLS_CERT / XKMSCTL_TLS_KEY / XKMSCTL_TLS_CA: mTLS client material.
//     Normally left unset: main_test.go's TestMain derives all three itself
//     (TOFU CA fetch + the qrdb first-boot admin credential — see its doc
//     comment) and only fills in what the caller did not already set.
//   - XKMSCTL_ADMIN_CRED_DIR: directory holding the qrdb first-boot
//     administrator's admin-cert.pem/admin-key.pem (default: /data/storage),
//     consumed by main_test.go, not this file.
package acmeadmin

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// defaultTimeout bounds every xkmsctl invocation this package makes.
const defaultTimeout = 30 * time.Second

// testTenantPrefix marks tenants this suite creates, for identification in
// server-side logs; cleanup is unconditional (each test deletes what it
// creates), not name-pattern-based.
const testTenantPrefix = "integration-test-"

// xkmsctlConfig holds the connection material for both xkmsctl command
// groups this suite drives.
type xkmsctlConfig struct {
	Binary string

	// ACME admin plane ("xkmsctl acme ...").
	ACMEServer    string
	ACMETransport string

	// xkmsd's own control plane ("xkmsctl tenant ...").
	Server    string
	Transport string

	// mTLS client material, shared by both command groups.
	TLSCert   string
	TLSKey    string
	TLSCACert string

	Timeout time.Duration
}

// newXkmsctlConfig builds the configuration from environment variables.
func newXkmsctlConfig() *xkmsctlConfig {
	return &xkmsctlConfig{
		Binary:        getEnvOrDefault("XKMSCTL_BINARY", "xkmsctl"),
		ACMEServer:    getEnvOrDefault("XKMSCTL_ACME_SERVER", "https://localhost:8443"),
		ACMETransport: getEnvOrDefault("XKMSCTL_ACME_TRANSPORT", "rest"),
		Server:        getEnvOrDefault("XKMSCTL_SERVER", "https://localhost:8443"),
		Transport:     getEnvOrDefault("XKMSCTL_TRANSPORT", "rest"),
		TLSCert:       os.Getenv("XKMSCTL_TLS_CERT"),
		TLSKey:        os.Getenv("XKMSCTL_TLS_KEY"),
		TLSCACert:     os.Getenv("XKMSCTL_TLS_CA"),
		Timeout:       defaultTimeout,
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// tlsArgs returns the shared --tls-cert/--tls-key/--tls-ca flags, common to
// every xkmsctl command group.
func tlsArgs(cfg *xkmsctlConfig) []string {
	var args []string
	if cfg.TLSCert != "" {
		args = append(args, "--tls-cert", cfg.TLSCert)
	}
	if cfg.TLSKey != "" {
		args = append(args, "--tls-key", cfg.TLSKey)
	}
	if cfg.TLSCACert != "" {
		args = append(args, "--tls-ca", cfg.TLSCACert)
	}
	return args
}

// xkmsctlError reports a failed xkmsctl invocation with its captured output.
type xkmsctlError struct {
	Err    error
	Stdout string
	Stderr string
	Args   []string
}

func (e *xkmsctlError) Error() string {
	return fmt.Sprintf("xkmsctl command failed: %v\nargs: %v\nstdout: %s\nstderr: %s",
		e.Err, e.Args, e.Stdout, e.Stderr)
}

func (e *xkmsctlError) Unwrap() error { return e.Err }

// run executes xkmsctl with the given full argument list and returns stdout.
func run(cfg *xkmsctlConfig, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cfg.Binary, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", &xkmsctlError{Err: err, Stdout: stdout.String(), Stderr: stderr.String(), Args: args}
	}
	return stdout.String(), nil
}

// runAcme runs "xkmsctl [tls flags] --acme-server ... --acme-transport rest
// acme <args...>".
func runAcme(cfg *xkmsctlConfig, args ...string) (string, error) {
	full := append([]string{}, tlsArgs(cfg)...)
	full = append(full, "--acme-server", cfg.ACMEServer, "--acme-transport", cfg.ACMETransport, "acme")
	full = append(full, args...)
	return run(cfg, full...)
}

// runTenant runs "xkmsctl [tls flags] --server ... --transport rest tenant
// <args...>". Tenant lifecycle has no verb under "xkmsctl acme" (there is
// no ACME-admin-scoped tenant command group); it is xkmsd's own
// control-plane command, backed by the same embedded qrdb node the ACME
// admin plane delegates tenant identity to (pkg/acme/admin/tenant_service.go,
// SetTenantService), so a tenant created here is visible to "acme eab ...".
func runTenant(cfg *xkmsctlConfig, args ...string) (string, error) {
	full := append([]string{}, tlsArgs(cfg)...)
	full = append(full, "--server", cfg.Server, "--transport", cfg.Transport, "tenant")
	full = append(full, args...)
	return run(cfg, full...)
}

// requireSuccess runs xkmsctl and fails the test if it does not succeed.
func requireSuccess(t testingT, cfg *xkmsctlConfig, group string, args ...string) string {
	t.Helper()
	var (
		out string
		err error
	)
	switch group {
	case "acme":
		out, err = runAcme(cfg, args...)
	case "tenant":
		out, err = runTenant(cfg, args...)
	default:
		t.Fatalf("unknown command group %q", group)
	}
	if err != nil {
		t.Fatalf("xkmsctl %s %v should succeed: %v", group, args, err)
	}
	return out
}

// requireFail runs xkmsctl and fails the test if it succeeds.
func requireFail(t testingT, cfg *xkmsctlConfig, group string, args ...string) *xkmsctlError {
	t.Helper()
	var err error
	switch group {
	case "acme":
		_, err = runAcme(cfg, args...)
	case "tenant":
		_, err = runTenant(cfg, args...)
	default:
		t.Fatalf("unknown command group %q", group)
	}
	if err == nil {
		t.Fatalf("xkmsctl %s %v should fail", group, args)
	}
	xerr, ok := err.(*xkmsctlError)
	if !ok {
		t.Fatalf("error should be *xkmsctlError, got %T", err)
	}
	return xerr
}

// testingT is the subset of *testing.T this harness needs, so requireSuccess/
// requireFail can be shared by top-level tests and t.Run subtests alike.
type testingT interface {
	Helper()
	Fatalf(format string, args ...interface{})
}

// findXkmsctlBinary resolves cfg.Binary to a runnable path, trying the
// configured value, PATH resolution, and a couple of common build output
// locations, in that order. Returns a typed not-found error rather than
// panicking so callers can report it through the normal test-failure path.
func findXkmsctlBinary(cfg *xkmsctlConfig) error {
	candidates := []string{
		cfg.Binary,
		"xkmsctl",
		"./xkmsctl",
		"../../../cmd/xkmsctl/xkmsctl",
		"/usr/local/bin/xkmsctl",
	}

	for _, candidate := range candidates {
		resolved, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		cfg.Binary = resolved
		return nil
	}

	return caerrors.NotFoundError("xkmsctl binary not found")
}
