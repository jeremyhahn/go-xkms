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

// acme_status_run_test.go exercises "xkmsctl acme status" and "xkmsctl
// acme stats" against the real sdk/go/acme embedded transport, per
// acme_testutil_test.go.
package main

import (
	"net/http"
	"testing"
)

func TestACMEStatusCmd_Success(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("StatusHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{
			"identity": "ca.example.com", "initialized": true, "version": "1.0.0",
			"started_at": "2026-01-01T00:00:00Z", "key_algorithm": "ECDSA-P256",
			"signature_algorithm": "ECDSA-SHA256", "root_ca": "CN=Example Root CA",
		})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "table"})

	captureStdout(t, func() {
		acmeStatusCmd.Run(acmeStatusCmd, nil)
	})
}

func TestACMEStatusCmd_Forbidden(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("StatusHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusForbidden, problemForbidden, "status requires the viewer role")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	code := captureExit(t, func() {
		acmeStatusCmd.Run(acmeStatusCmd, nil)
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMEStatsCmd_Success(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("StatsHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{
			"total_certificates": 10, "valid_certificates": 8, "revoked_certificates": 1, "expired_certificates": 1,
			"total_accounts": 5, "active_accounts": 4,
			"total_orders": 20, "pending_orders": 2, "completed_orders": 18,
		})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "table"})

	captureStdout(t, func() {
		acmeStatsCmd.Run(acmeStatsCmd, nil)
	})
}

func TestACMEStatsCmd_ServerError(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("StatsHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusInternalServerError, "about:blank", "boom")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	code := captureExit(t, func() {
		acmeStatsCmd.Run(acmeStatsCmd, nil)
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}
