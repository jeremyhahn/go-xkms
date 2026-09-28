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

// This file carries what remains of test/integration/cactl's
// cactl_transport_matrix_test.go after go-xkms#949's port to xkmsctl.
//
// That file iterated every case (status, stats, tenant/EAB lifecycle,
// certificate/account listing, output formats, error handling) across five
// transports: REST, gRPC, QUIC, MCP, and Unix. xkmsd serves none of the
// latter four for the ACME admin plane (docs/acme/protocols/grpc.md,
// quic.md, mcp.md, unix-socket.md); wiring them is tracked in go-xkms#743,
// at which point a real transport matrix belongs back here. Until then a
// "matrix" of one transport is just the REST suite, so this file keeps only
// the assertions cli_test.go does not already cover — the filtered-list and
// validation cases — rather than a one-entry loop that adds nothing over a
// second call to the same helpers.
package acmeadmin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestXkmsctlCertListFiltered tests "xkmsctl acme cert list --status".
func TestXkmsctlCertListFiltered(t *testing.T) {
	cfg := newXkmsctlConfig()
	if err := findXkmsctlBinary(cfg); err != nil {
		t.Fatalf("xkmsctl binary not found: %v", err)
	}

	for _, status := range []string{"valid", "revoked"} {
		t.Run(status, func(t *testing.T) {
			output, err := runAcme(cfg, "cert", "list", "--status", status, "-o", "json")
			require.NoError(t, err, "cert list --status %s should succeed", status)
			assert.NotEmpty(t, output, "cert list --status %s should return output", status)
		})
	}
}

// TestXkmsctlTenantCreateMissingName tests that "xkmsctl tenant create"
// without --name fails (cmd/xkmsctl/tenant.go: ErrTenantNameRequired).
func TestXkmsctlTenantCreateMissingName(t *testing.T) {
	cfg := newXkmsctlConfig()
	if err := findXkmsctlBinary(cfg); err != nil {
		t.Fatalf("xkmsctl binary not found: %v", err)
	}

	xerr := requireFail(t, cfg, "tenant", "create", "--id", "missing-name-test")
	assert.True(t, len(xerr.Stderr) > 0 || len(xerr.Stdout) > 0,
		"should have error output for missing tenant name")
}
