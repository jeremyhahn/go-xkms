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

// acme_account_run_test.go exercises "xkmsctl acme account" (list, get,
// disable) against the real sdk/go/acme embedded transport, per
// acme_testutil_test.go.
package main

import (
	"errors"
	"net/http"
	"testing"
)

func TestACMEAccountListCmd_Success(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("ListAccountsHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{
			"accounts": []map[string]interface{}{
				{"id": 1, "status": "valid", "order_count": 2, "created_at": "2026-01-01T00:00:00Z"},
			},
			"pagination": map[string]interface{}{"page": 1, "per_page": 20, "total": 1},
		})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	captureStdout(t, func() {
		acmeAccountListCmd.Run(acmeAccountListCmd, nil)
	})
}

func TestACMEAccountListCmd_Forbidden(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("ListAccountsHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusForbidden, problemForbidden, "list accounts requires the operator role")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	code := captureExit(t, func() {
		acmeAccountListCmd.Run(acmeAccountListCmd, nil)
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMEAccountGetCmd_Success(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("GetAccountHandler", func(w http.ResponseWriter, r *http.Request) {
		body := acmeDecodeBody(t, r)
		if got, ok := body["accountId"].(float64); !ok || uint64(got) != 12345 {
			t.Errorf("expected accountId 12345 in request body, got %v", body["accountId"])
		}
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{
			"id": 12345, "status": "valid", "order_count": 3, "created_at": "2026-01-01T00:00:00Z",
		})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "table"})

	captureStdout(t, func() {
		acmeAccountGetCmd.Run(acmeAccountGetCmd, []string{"12345"})
	})
}

func TestACMEAccountGetCmd_NotFound(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("GetAccountHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusNotFound, problemNotFound, "account 999 does not exist")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	code := captureExit(t, func() {
		acmeAccountGetCmd.Run(acmeAccountGetCmd, []string{"999"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMEAccountGetCmd_InvalidID(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	code := captureExit(t, func() {
		acmeAccountGetCmd.Run(acmeAccountGetCmd, []string{"not-a-number"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestACMEAccountDisableCmd_Success(t *testing.T) {
	var gotID float64
	fake := newACMEFakeAdminServicer().on("DisableAccountHandler", func(w http.ResponseWriter, r *http.Request) {
		body := acmeDecodeBody(t, r)
		gotID, _ = body["accountId"].(float64)
		acmeWriteJSON(w, http.StatusOK, map[string]interface{}{})
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	captureStdout(t, func() {
		acmeAccountDisableCmd.Run(acmeAccountDisableCmd, []string{"777"})
	})
	if uint64(gotID) != 777 {
		t.Errorf("expected DisableAccount called with 777, got %v", gotID)
	}
}

func TestACMEAccountDisableCmd_Forbidden(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("DisableAccountHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusForbidden, problemForbidden, "disable account requires the admin role")
	})
	withACMEAdminClient(t, newACMEAdminTestClient(t, fake))
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	code := captureExit(t, func() {
		acmeAccountDisableCmd.Run(acmeAccountDisableCmd, []string{"777"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestClassifyACMEAdminError_Forbidden(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("GetAccountHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusForbidden, problemForbidden, "nope")
	})
	client := newACMEAdminTestClient(t, fake)

	_, err := client.Account().Get(t.Context(), 1)
	if err == nil {
		t.Fatal("expected an error")
	}
	classified := classifyACMEAdminError("get account 1", ErrGetACMEAccountFailed, err)
	var forbidden *ACMEAdminForbiddenError
	if !errors.As(classified, &forbidden) {
		t.Fatalf("expected *ACMEAdminForbiddenError, got %T: %v", classified, classified)
	}
}

func TestClassifyACMEAdminError_NotFound(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("GetAccountHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusNotFound, problemNotFound, "nope")
	})
	client := newACMEAdminTestClient(t, fake)

	_, err := client.Account().Get(t.Context(), 1)
	if err == nil {
		t.Fatal("expected an error")
	}
	classified := classifyACMEAdminError("get account 1", ErrGetACMEAccountFailed, err)
	var notFound *ACMEAdminNotFoundError
	if !errors.As(classified, &notFound) {
		t.Fatalf("expected *ACMEAdminNotFoundError, got %T: %v", classified, classified)
	}
}

func TestClassifyACMEAdminError_Fallback(t *testing.T) {
	fake := newACMEFakeAdminServicer().on("GetAccountHandler", func(w http.ResponseWriter, r *http.Request) {
		acmeWriteProblem(w, http.StatusInternalServerError, "about:blank", "boom")
	})
	client := newACMEAdminTestClient(t, fake)

	_, err := client.Account().Get(t.Context(), 1)
	if err == nil {
		t.Fatal("expected an error")
	}
	classified := classifyACMEAdminError("get account 1", ErrGetACMEAccountFailed, err)
	var wrapped *WrappedError
	if !errors.As(classified, &wrapped) {
		t.Fatalf("expected *WrappedError, got %T: %v", classified, classified)
	}
	if wrapped.Sentinel != ErrGetACMEAccountFailed {
		t.Errorf("expected sentinel ErrGetACMEAccountFailed, got %v", wrapped.Sentinel)
	}
}
