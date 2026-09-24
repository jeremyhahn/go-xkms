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

// acme_cert_run_test.go exercises "xkmsctl acme cert" (list, get, revoke)
// against the real sdk/go/acme embedded transport, per
// acme_testutil_test.go.
package main

import (
	"net/http"
	"testing"
)

func TestACMECertListCmd_Success(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("ListCertificatesHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{
			"certificates": []map[string]interface{}{
				{
					"id": 1, "serial_number": "01:02:03", "subject": "CN=host.example.com",
					"issuer": "CN=Example CA", "status": "valid",
					"not_before": "2026-01-01T00:00:00Z", "not_after": "2026-04-01T00:00:00Z",
					"issued_at": "2026-01-01T00:00:00Z",
				},
			},
			"pagination": map[string]interface{}{"page": 1, "per_page": 20, "total": 1},
		})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "table"})

	captureStdout(t, func() {
		acmeCertListCmd.Run(acmeCertListCmd, nil)
	})
}

func TestACMECertListCmd_ServerError(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("ListCertificatesHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusInternalServerError, "about:blank", "boom")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	code := captureExit(t, func() {
		acmeCertListCmd.Run(acmeCertListCmd, nil)
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMECertGetCmd_Success(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("GetCertificateHandler", func(w http.ResponseWriter, r *http.Request) {
		body := acmeDecodeBody(t, r)
		if body["serial"] != "01:02:03:04" {
			t.Errorf("expected serial 01:02:03:04 in request body, got %v", body["serial"])
		}
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{
			"id": 1, "serial_number": "01:02:03:04", "subject": "CN=host.example.com",
			"issuer": "CN=Example CA", "status": "valid",
			"not_before": "2026-01-01T00:00:00Z", "not_after": "2026-04-01T00:00:00Z",
			"issued_at": "2026-01-01T00:00:00Z",
		})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "table"})

	captureStdout(t, func() {
		acmeCertGetCmd.Run(acmeCertGetCmd, []string{"01:02:03:04"})
	})
}

func TestACMECertGetCmd_NotFound(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("GetCertificateHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusNotFound, problemNotFound, "no such certificate")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	code := captureExit(t, func() {
		acmeCertGetCmd.Run(acmeCertGetCmd, []string{"missing-serial"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMECertRevokeCmd_Success(t *testing.T) {
	var gotSerial, gotReason string
	fake := newACMEFakeAdminServicer().on("RevokeCertificateHandler", func(w http.ResponseWriter, r *http.Request) {
		body := acmeDecodeBody(t, r)
		gotSerial, _ = body["serial"].(string)
		gotReason, _ = body["reason"].(string)
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "text"})
	acmeCertRevokeRsn = "keyCompromise"
	t.Cleanup(func() { acmeCertRevokeRsn = "unspecified" })

	captureStdout(t, func() {
		acmeCertRevokeCmd.Run(acmeCertRevokeCmd, []string{"01:02:03:04"})
	})
	if gotSerial != "01:02:03:04" || gotReason != "keyCompromise" {
		t.Errorf("expected serial=01:02:03:04 reason=keyCompromise, got serial=%q reason=%q", gotSerial, gotReason)
	}
}

func TestACMECertRevokeCmd_Forbidden(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("RevokeCertificateHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusForbidden, problemForbidden, "revoke requires the operator role")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	code := captureExit(t, func() {
		acmeCertRevokeCmd.Run(acmeCertRevokeCmd, []string{"01:02:03:04"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMECertGetCmd_EmptySerial(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	code := captureExit(t, func() {
		acmeCertGetCmd.Run(acmeCertGetCmd, []string{""})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}
