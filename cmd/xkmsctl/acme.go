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

// acme.go implements the "xkmsctl acme" command tree: administration of
// the ACME (RFC 8555) certificate authority go-xkms hosts on its own
// dedicated HTTPS listener (pkg/acme, cfg.ACME.HTTPSAddr). This is a
// distinct service from xkmsd's own keystore/control-plane surface, so it
// is reached through the ACME admin SDK (sdk/go/acme, sdk/go/acme/client/admin)
// over its own --acme-server/--acme-transport connection rather than the
// xkms client.Client used by every other command group.
//
// The verb set brings xkmsctl to parity with go-trusted-ca's cactl for
// account, certificate, EAB and CA status/stats administration.
package main

import (
	"context"

	"github.com/spf13/cobra"

	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	acmeadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
	acmeerrors "github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// acmeCmd is the top-level command for ACME certificate authority
// administration.
var acmeCmd = &cobra.Command{
	Use:   "acme",
	Short: "Administer the ACME (RFC 8555) certificate authority",
	Long: `Administer the ACME certificate authority go-xkms hosts on its own
HTTPS listener: accounts, issued certificates, external account bindings
(EAB), and CA status/statistics.

The ACME admin API is served on a separate address from xkmsd's own
keystore/control-plane surface, so these commands connect independently
via --acme-server (and, when the address carries no scheme, --acme-transport).

Examples:
  xkmsctl acme --acme-server https://ca.example.com:8443 account list
  xkmsctl acme --acme-server grpc://ca.example.com:9443 cert get 01:02:03
  xkmsctl acme --acme-server https://ca.example.com:8443 status`,
}

// Connection flags, scoped to the acme command tree.
var (
	// acmeServerFlag is the address of the ACME admin API (e.g.
	// "https://host:8443", "grpc://host:9443", "quic://host:9444",
	// "mcp://host:9444"). Required: the ACME admin plane has no default
	// address to fall back to, unlike xkmsd's own Unix socket.
	acmeServerFlag string

	// acmeTransportFlag selects the SDK transport when acmeServerFlag
	// carries no scheme (rest, grpc, quic, mcp). Defaults to the SDK's
	// own default (gRPC) when empty.
	acmeTransportFlag string
)

func init() {
	acmeCmd.PersistentFlags().StringVar(&acmeServerFlag, "acme-server", "",
		"address of the ACME admin API (e.g. https://host:8443, grpc://host:9443); required")
	acmeCmd.PersistentFlags().StringVar(&acmeTransportFlag, "acme-transport", "",
		"ACME admin transport when --acme-server carries no scheme: rest, grpc, quic, mcp (default grpc)")

	acmeCmd.AddCommand(acmeAccountCmd)
	acmeCmd.AddCommand(acmeCertCmd)
	acmeCmd.AddCommand(acmeEABCmd)
	acmeCmd.AddCommand(acmeStatusCmd)
	acmeCmd.AddCommand(acmeStatsCmd)

	rootCmd.AddCommand(acmeCmd)
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

// ACMEAdminAddressRequiredError is returned when an "acme" subcommand runs
// without --acme-server. The ACME admin plane is a distinct service from
// xkmsd's own address, so there is no --server fallback to reuse.
type ACMEAdminAddressRequiredError struct{}

// Error returns a human-readable description.
func (e *ACMEAdminAddressRequiredError) Error() string {
	return "acme: --acme-server is required to reach the ACME admin API " +
		"(e.g. https://host:8443, grpc://host:9443, quic://host:9444, mcp://host:9444)"
}

// ACMEAdminUnsupportedTransportError is returned when --acme-transport (or
// a URL scheme in --acme-server) names a transport the ACME admin plane
// does not serve.
type ACMEAdminUnsupportedTransportError struct {
	Transport string
}

// Error returns a human-readable description.
func (e *ACMEAdminUnsupportedTransportError) Error() string {
	return "acme: unsupported --acme-transport " + e.Transport +
		" (the ACME admin API is served over rest, grpc, quic, or mcp; there is no unix adapter)"
}

// ACMEAdminConnectError wraps a failure to construct or connect the ACME
// admin SDK client.
type ACMEAdminConnectError struct {
	Cause error
}

// Error returns a human-readable description.
func (e *ACMEAdminConnectError) Error() string {
	return "acme: failed to connect to the ACME admin API: " + e.Cause.Error()
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *ACMEAdminConnectError) Unwrap() error { return e.Cause }

// ACMEAdminClientMissingError is returned when no admin client factory is
// wired (e.g. a test cleared it without installing a fake).
type ACMEAdminClientMissingError struct{}

// Error returns a human-readable description.
func (e *ACMEAdminClientMissingError) Error() string {
	return "acme: ACME admin client is not configured"
}

// ACMEAdminForbiddenError reports that the ACME admin API denied an
// operation on permission grounds (pkg/acme/admin's PermissionGate). It is
// distinguished from ACMEAdminOperationError so operators (and scripts
// checking errors.As) can tell "you may not do this" apart from every
// other failure mode.
type ACMEAdminForbiddenError struct {
	// Op names the operation that was denied (e.g. "list accounts").
	Op string
	// Err is the underlying SDK error.
	Err error
}

// Error returns a human-readable description.
func (e *ACMEAdminForbiddenError) Error() string {
	return "acme: permission denied: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *ACMEAdminForbiddenError) Unwrap() error { return e.Err }

// ACMEAdminNotFoundError reports that the ACME admin API found no such
// resource (account, certificate, or EAB).
type ACMEAdminNotFoundError struct {
	// Op names the operation that failed (e.g. "get account 12345").
	Op string
	// Err is the underlying SDK error.
	Err error
}

// Error returns a human-readable description.
func (e *ACMEAdminNotFoundError) Error() string {
	return "acme: not found: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *ACMEAdminNotFoundError) Unwrap() error { return e.Err }

// classifyACMEAdminError maps an ACME admin SDK error to a specific typed
// xkmsctl error when the SDK classified it as forbidden or not-found, so a
// permission denial or a missing resource reads distinctly from every other
// failure instead of being flattened into the same "operation failed"
// sentinel. Any other error falls back to the package's usual
// sentinel+cause WrappedError.
func classifyACMEAdminError(op string, sentinel error, err error) error {
	switch {
	case acmeerrors.IsForbidden(err):
		return &ACMEAdminForbiddenError{Op: op, Err: err}
	case acmeerrors.IsNotFound(err):
		return &ACMEAdminNotFoundError{Op: op, Err: err}
	default:
		return &WrappedError{Sentinel: sentinel, Err: err}
	}
}

// ---------------------------------------------------------------------------
// SDK client wiring (factory seam, mirrors QRDBControlClientFactory)
// ---------------------------------------------------------------------------

// ACMEAdminClientFactory builds an admin.Client plus a close function the
// caller must invoke before returning. The default factory dials the
// configured --acme-server; tests override it via SetACMEAdminClientFactory.
type ACMEAdminClientFactory func(ctx context.Context) (acmeadmin.Client, func() error, error)

// acmeAdminClientFactory is the active factory used by every acme
// command group.
var acmeAdminClientFactory ACMEAdminClientFactory = defaultACMEAdminClientFactory

// SetACMEAdminClientFactory replaces the active factory and returns a
// restore closure. Intended for tests; production code should not call it.
func SetACMEAdminClientFactory(f ACMEAdminClientFactory) func() {
	prev := acmeAdminClientFactory
	acmeAdminClientFactory = f
	return func() { acmeAdminClientFactory = prev }
}

// acmeAdminClient resolves the active factory and opens a client.
func acmeAdminClient(ctx context.Context) (acmeadmin.Client, func() error, error) {
	if acmeAdminClientFactory == nil {
		return nil, nil, &ACMEAdminClientMissingError{}
	}
	return acmeAdminClientFactory(ctx)
}

// defaultACMEAdminClientFactory derives the ACME SDK transport from
// --acme-server/--acme-transport (plus the CLI's usual --tls-cert/--tls-key/
// --tls-ca material) and connects.
func defaultACMEAdminClientFactory(ctx context.Context) (acmeadmin.Client, func() error, error) {
	address, opts, err := acmeClientOptions(getConfig())
	if err != nil {
		return nil, nil, err
	}

	cl, err := trustedca.NewClient(address, opts...)
	if err != nil {
		return nil, nil, &ACMEAdminConnectError{Cause: err}
	}

	return cl.Admin(), cl.Close, nil
}

// acmeClientOptions maps --acme-server/--acme-transport (and the CLI's TLS
// material flags) onto a trustedca SDK address + option set.
//
//   - https://host:port or http://host:port: REST.
//   - grpc://host:port: gRPC, plaintext unless TLS flags are set.
//   - grpcs://host:port: gRPC with TLS.
//   - quic://host:port: QUIC (always TLS).
//   - mcp://host:port or mcps://host:port: MCP.
//   - a bare host:port: routed by --acme-transport (default gRPC).
//
// The ACME admin plane has no Unix adapter (docs/acme-issuance/api.md), so
// unix:// addresses and --acme-transport unix are rejected up front.
func acmeClientOptions(cfg *Config) (string, []trustedca.Option, error) {
	if acmeServerFlag == "" {
		return "", nil, &ACMEAdminAddressRequiredError{}
	}

	address := acmeServerFlag
	var opts []trustedca.Option
	forceTLS := false

	switch {
	case hasPrefix(address, "https://"):
		opts = append(opts, trustedca.WithREST())
	case hasPrefix(address, "http://"):
		opts = append(opts, trustedca.WithREST())
	case hasPrefix(address, "grpc://"):
		address = trimPrefix(address, "grpc://")
	case hasPrefix(address, "grpcs://"):
		address = trimPrefix(address, "grpcs://")
		forceTLS = true
	case hasPrefix(address, "quic://"):
		address = trimPrefix(address, "quic://")
		opts = append(opts, trustedca.WithQUIC())
		forceTLS = true
	case hasPrefix(address, "mcp://"):
		address = trimPrefix(address, "mcp://")
		opts = append(opts, trustedca.WithMCP())
	case hasPrefix(address, "mcps://"):
		address = trimPrefix(address, "mcps://")
		opts = append(opts, trustedca.WithMCP())
		forceTLS = true
	case hasPrefix(address, "unix://"):
		return "", nil, &ACMEAdminUnsupportedTransportError{Transport: "unix"}
	case !hasScheme(address):
		switch acmeTransportFlag {
		case "", "grpc":
			// SDK default; address stays bare.
		case "rest":
			opts = append(opts, trustedca.WithREST())
		case "quic":
			opts = append(opts, trustedca.WithQUIC())
			forceTLS = true
		case "mcp":
			opts = append(opts, trustedca.WithMCP())
		case "unix":
			return "", nil, &ACMEAdminUnsupportedTransportError{Transport: "unix"}
		default:
			return "", nil, &ACMEAdminUnsupportedTransportError{Transport: acmeTransportFlag}
		}
	default:
		return "", nil, &ACMEAdminUnsupportedTransportError{Transport: address}
	}

	if forceTLS || cfg.TLSCert != "" || cfg.TLSKey != "" || cfg.TLSCACert != "" {
		opts = append(opts, trustedca.WithTLS(trustedca.TLSConfig{
			CertFile: cfg.TLSCert,
			KeyFile:  cfg.TLSKey,
			CAFile:   cfg.TLSCACert,
		}))
	}

	return address, opts, nil
}
