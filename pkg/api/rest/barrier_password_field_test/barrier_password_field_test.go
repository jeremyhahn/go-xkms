// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package barrier_password_field_test isolates coverage for the
// PasswordField-aware Barrier handlers into an external test package
// so it is independent of any unrelated test-binary build failures in
// the sibling internal rest test suite. This mirrors the
// ssh_handlers_test package layout already in use.
package barrier_password_field_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// newTestBarrierHandler wires a HandlerContext backed by a fresh
// in-memory barrier using the software sealing strategy.
func newTestBarrierHandler(t *testing.T) (*rest.HandlerContext, *seal.Barrier) {
	t.Helper()

	store := storage.NewMemory()
	sealStrategy := seal.NewSoftwareStrategy()

	barrier, err := seal.NewBarrier(
		slog.Default(),
		store,
		seal.BarrierConfig{RootKeyPath: "test-root-key"},
		sealStrategy,
	)
	if err != nil {
		t.Fatalf("NewBarrier: %v", err)
	}

	h := rest.NewHandlerContext("test")
	h.SetBarrier(barrier)
	return h, barrier
}

// TestBarrierInitializeHandler_PasswordBase64_Success verifies that a
// client supplying password_b64 instead of secret is accepted and
// initializes the barrier correctly.
func TestBarrierInitializeHandler_PasswordBase64_Success(t *testing.T) {
	h, _ := newTestBarrierHandler(t)

	encoded := base64.StdEncoding.EncodeToString([]byte("enclaved-passphrase-1"))
	body := `{"password_b64":"` + encoded + `"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/initialize", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.BarrierInitializeHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Success {
		t.Fatalf("Success=false: %+v", resp)
	}
}

// TestBarrierUnsealHandler_PasswordBase64_RoundTrip initializes the
// barrier with a legacy `secret` string, seals, then unseals via the
// enclaved `password_b64` field — proving the two field forms are
// interchangeable at the wire level.
func TestBarrierUnsealHandler_PasswordBase64_RoundTrip(t *testing.T) {
	h, barrier := newTestBarrierHandler(t)

	creds := seal.Credentials{Secret: []byte("roundtrip-secret")}
	if err := barrier.Initialize(context.Background(), creds); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if err := barrier.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte("roundtrip-secret"))
	body := `{"password_b64":"` + encoded + `"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/unseal", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.BarrierUnsealHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// TestBarrierUnsealHandler_BothFieldsPresent_PrefersEnclaved verifies
// that when both secret and password_b64 are present, the enclaved
// form wins. The legacy fallback must not override the secure path.
func TestBarrierUnsealHandler_BothFieldsPresent_PrefersEnclaved(t *testing.T) {
	h, barrier := newTestBarrierHandler(t)

	creds := seal.Credentials{Secret: []byte("the-enclaved-secret")}
	if err := barrier.Initialize(context.Background(), creds); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if err := barrier.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte("the-enclaved-secret"))
	// Legacy secret is intentionally wrong — enclaved must prevail.
	body := `{"secret":"wrong-legacy","password_b64":"` + encoded + `"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/unseal", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.BarrierUnsealHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// TestBarrierInitializeHandler_LegacySecretStillWorks guards against
// regression — existing clients on the `secret` string path must
// keep working after the Phase 1d migration.
func TestBarrierInitializeHandler_LegacySecretStillWorks(t *testing.T) {
	h, _ := newTestBarrierHandler(t)

	body := `{"secret":"legacy-path-ok"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/initialize", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.BarrierInitializeHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// TestBarrierUnsealHandler_MissingBothFields maps to the
// ErrMissingSecret error path for both request types.
func TestBarrierUnsealHandler_MissingBothFields(t *testing.T) {
	h, _ := newTestBarrierHandler(t)
	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/unseal", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.BarrierUnsealHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// TestBarrierInitializeHandler_EmptyBothFields also yields a 400.
func TestBarrierInitializeHandler_EmptyBothFields(t *testing.T) {
	h, _ := newTestBarrierHandler(t)
	body := `{"secret":"","password_b64":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/initialize", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.BarrierInitializeHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
