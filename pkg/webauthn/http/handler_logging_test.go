// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package http

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
	pkgwebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// failingLookupHandler builds a handler whose user lookup fails with cause,
// logging through a logger at Info level into the returned buffer, the
// level a production server logs at.
func failingLookupHandler(t *testing.T, cause error) (*Handler, *bytes.Buffer) {
	t.Helper()
	stores := webauthntest.NewStores(t)
	svc, err := pkgwebauthn.NewService(pkgwebauthn.ServiceParams{
		Config: &pkgwebauthn.Config{
			RPID:          "example.com",
			RPDisplayName: "Example",
			RPOrigins:     []string{"https://example.com"},
		},
		UserStore:       &errorUserStore{UserStore: stores.Users, getByEmailErr: cause},
		SessionStore:    pkgwebauthn.NewMemorySessionStore(),
		CredentialStore: stores.Credentials,
	})
	require.NoError(t, err)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return NewHandler(svc).WithLogger(logger), &buf
}

// TestHandler_InternalError_LogsCauseAtError is ruling 973 (4): a 500's
// cause was logged only at Debug, so a server at Info level showed nothing
// for "qrdb/auth: unauthenticated". The cause is logged at Error; the log
// carries no challenge.
func TestHandler_InternalError_LogsCauseAtError(t *testing.T) {
	h, logs := failingLookupHandler(t, errors.New("qrdb user lookup: qrdb/auth: unauthenticated"))

	req := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"error@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.BeginRegistration(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	out := logs.String()
	require.Contains(t, out, "level=ERROR", "a 500's cause is logged at Error: %q", out)
	require.Contains(t, out, "qrdb/auth: unauthenticated", "the log carries the cause: %q", out)
	require.NotContains(t, strings.ToLower(out), "challenge", "the log carries no challenge: %q", out)
	require.NotContains(t, rec.Body.String(), "unauthenticated", "the client sees only the generic message")
}

// TestHandler_ClientError_NotLoggedAtError: a refused or malformed request is
// the client's error, not the server's, and stays below Error.
func TestHandler_ClientError_NotLoggedAtError(t *testing.T) {
	h, logs := failingLookupHandler(t, pkgwebauthn.ErrRegistrationRefused)

	req := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"refused@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.BeginRegistration(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.NotContains(t, logs.String(), "level=ERROR")
}
