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

// acme_eab_run_test.go exercises "xkmsctl acme eab" (create, get, delete,
// list) against the real sdk/go/acme embedded transport, per
// acme_testutil_test.go.
package main

import (
	"net/http"
	"testing"
)

// resetACMEEABFlags clears the package-level EAB flag state so tests do
// not leak values into each other.
func resetACMEEABFlags(t *testing.T) {
	t.Helper()
	acmeEABTenant = ""
	acmeEABPurpose = ""
	acmeEABExternalAccountID = ""
	acmeEABContact = nil
	acmeEABExpiresInDays = 0
	acmeEABListStatus = ""
	acmeEABListPurpose = ""
	t.Cleanup(func() {
		acmeEABTenant = ""
		acmeEABPurpose = ""
		acmeEABExternalAccountID = ""
		acmeEABContact = nil
		acmeEABExpiresInDays = 0
		acmeEABListStatus = ""
		acmeEABListPurpose = ""
	})
}

func TestACMEEABCreateCmd_MissingTenant(t *testing.T) {
	resetACMEEABFlags(t)
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	code := captureExit(t, func() {
		acmeEABCreateCmd.Run(acmeEABCreateCmd, nil)
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMEEABCreateCmd_Success(t *testing.T) {
	resetACMEEABFlags(t)
	acmeEABTenant = "acme-tenant"
	acmeEABPurpose = "device-enrollment"

	var gotTenant, gotPurpose string
	fake := newACMEFakeAdminServicer().on("CreateEABHandler", func(w http.ResponseWriter, r *http.Request) {
		body := acmeDecodeBody(t, r)
		gotTenant, _ = body["tenantId"].(string)
		gotPurpose, _ = body["purpose"].(string)
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{
			"id": "kid-1", "mac_key": "c2VjcmV0", "algorithm": "HS256",
		})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "table"})

	captureStdout(t, func() {
		acmeEABCreateCmd.Run(acmeEABCreateCmd, nil)
	})
	if gotTenant != "acme-tenant" || gotPurpose != "device-enrollment" {
		t.Errorf("expected tenantId=acme-tenant purpose=device-enrollment, got tenantId=%q purpose=%q", gotTenant, gotPurpose)
	}
}

func TestACMEEABCreateCmd_Forbidden(t *testing.T) {
	resetACMEEABFlags(t)
	acmeEABTenant = "acme-tenant"

	fake := newACMEFakeAdminServicer().on("CreateEABHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusForbidden, problemForbidden, "create EAB requires the admin role")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	code := captureExit(t, func() {
		acmeEABCreateCmd.Run(acmeEABCreateCmd, nil)
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMEEABGetCmd_MissingTenant(t *testing.T) {
	resetACMEEABFlags(t)
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	code := captureExit(t, func() {
		acmeEABGetCmd.Run(acmeEABGetCmd, []string{"kid-1"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMEEABGetCmd_Success(t *testing.T) {
	resetACMEEABFlags(t)
	acmeEABTenant = "acme-tenant"

	fake := newACMEFakeAdminServicer().on("GetEABHandler", func(w http.ResponseWriter, r *http.Request) {
		body := acmeDecodeBody(t, r)
		if body["tenantId"] != "acme-tenant" || body["kid"] != "kid-1" {
			t.Errorf("expected tenantId=acme-tenant kid=kid-1, got %v", body)
		}
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{
			"id": "kid-1", "status": "unused", "purpose": "device-enrollment",
			"created_at": "2026-01-01T00:00:00Z",
		})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "table"})

	captureStdout(t, func() {
		acmeEABGetCmd.Run(acmeEABGetCmd, []string{"kid-1"})
	})
}

func TestACMEEABGetCmd_NotFound(t *testing.T) {
	resetACMEEABFlags(t)
	acmeEABTenant = "acme-tenant"

	fake := newACMEFakeAdminServicer().on("GetEABHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusNotFound, problemNotFound, "no such EAB")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	code := captureExit(t, func() {
		acmeEABGetCmd.Run(acmeEABGetCmd, []string{"missing-kid"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMEEABDeleteCmd_Success(t *testing.T) {
	resetACMEEABFlags(t)
	acmeEABTenant = "acme-tenant"

	fake := newACMEFakeAdminServicer().on("DeleteEABHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	captureStdout(t, func() {
		acmeEABDeleteCmd.Run(acmeEABDeleteCmd, []string{"kid-1"})
	})
}

func TestACMEEABDeleteCmd_Forbidden(t *testing.T) {
	resetACMEEABFlags(t)
	acmeEABTenant = "acme-tenant"

	fake := newACMEFakeAdminServicer().on("DeleteEABHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusForbidden, problemForbidden, "delete EAB requires the admin role")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	code := captureExit(t, func() {
		acmeEABDeleteCmd.Run(acmeEABDeleteCmd, []string{"kid-1"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMEEABListCmd_MissingTenant(t *testing.T) {
	resetACMEEABFlags(t)
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	code := captureExit(t, func() {
		acmeEABListCmd.Run(acmeEABListCmd, nil)
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMEEABListCmd_Success(t *testing.T) {
	resetACMEEABFlags(t)
	acmeEABTenant = "acme-tenant"

	fake := newACMEFakeAdminServicer().on("ListEABHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{
			"eabs": []map[string]interface{}{
				{"id": "kid-1", "status": "unused", "purpose": "device-enrollment", "created_at": "2026-01-01T00:00:00Z"},
			},
			"pagination": map[string]interface{}{"page": 1, "per_page": 20, "total": 1},
		})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "table"})

	captureStdout(t, func() {
		acmeEABListCmd.Run(acmeEABListCmd, nil)
	})
}

func TestACMEEABListCmd_ServerError(t *testing.T) {
	resetACMEEABFlags(t)
	acmeEABTenant = "acme-tenant"

	fake := newACMEFakeAdminServicer().on("ListEABHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusInternalServerError, "about:blank", "boom")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	code := captureExit(t, func() {
		acmeEABListCmd.Run(acmeEABListCmd, nil)
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}
