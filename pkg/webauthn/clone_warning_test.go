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

package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
)

// recordingAuditLogger captures audit events, or fails every write with err.
type recordingAuditLogger struct {
	mu     sync.Mutex
	events []*audit.Event
	err    error
}

func (r *recordingAuditLogger) Log(_ context.Context, event *audit.Event) error {
	if r.err != nil {
		return r.err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *recordingAuditLogger) Close() error { return nil }

func (r *recordingAuditLogger) recorded() []*audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*audit.Event(nil), r.events...)
}

// cloneFixture is a registered credential on a service whose log output and
// audit events the test can inspect.
type cloneFixture struct {
	svc           *Service
	logs          *bytes.Buffer
	rp            virtualwebauthn.RelyingParty
	authenticator virtualwebauthn.Authenticator
	credential    virtualwebauthn.Credential
	user          User
}

func newCloneFixture(t *testing.T, auditLogger audit.Logger) *cloneFixture {
	t.Helper()
	ctx := context.Background()

	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
	}
	logs := &bytes.Buffer{}
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       NewMemoryUserStore(),
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: NewMemoryCredentialStore(),
		Logger:          slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})),
		AuditLogger:     auditLogger,
	})
	require.NoError(t, err)

	f := &cloneFixture{
		svc:           svc,
		logs:          logs,
		rp:            virtualwebauthn.RelyingParty{Name: cfg.RPDisplayName, ID: cfg.RPID, Origin: cfg.RPOrigins[0]},
		authenticator: virtualwebauthn.NewAuthenticator(),
		credential:    newEC2Credential(t),
	}

	regOptions, regSessionID, err := svc.BeginRegistration(ctx, "clone@example.com", "Clone User")
	require.NoError(t, err)
	regOptionsJSON, err := json.Marshal(regOptions.Response)
	require.NoError(t, err)
	parsedRegOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)
	attestation := virtualwebauthn.CreateAttestationResponse(f.rp, f.authenticator, f.credential, *parsedRegOptions)
	parsedAttestation, err := parseAttestationResponse(attestation)
	require.NoError(t, err)
	_, f.user, err = svc.FinishRegistration(ctx, regSessionID, parsedAttestation)
	require.NoError(t, err)
	f.authenticator.AddCredential(f.credential)
	return f
}

// login runs one login ceremony presenting signature counter counter.
func (f *cloneFixture) login(t *testing.T, counter uint32) error {
	t.Helper()
	ctx := context.Background()

	f.credential.Counter = counter
	loginOptions, sessionID, err := f.svc.BeginLogin(ctx, f.user.WebAuthnID())
	require.NoError(t, err)
	loginOptionsJSON, err := json.Marshal(loginOptions.Response)
	require.NoError(t, err)
	parsedLoginOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)
	assertion := virtualwebauthn.CreateAssertionResponse(f.rp, f.authenticator, f.credential, *parsedLoginOptions)
	parsedAssertion, err := parseAssertionResponse(assertion)
	require.NoError(t, err)

	_, _, err = f.svc.FinishLogin(ctx, sessionID, f.user.WebAuthnID(), parsedAssertion)
	return err
}

func TestFinishLogin_CloneWarningIsLoggedAndAudited(t *testing.T) {
	recorder := &recordingAuditLogger{}
	f := newCloneFixture(t, recorder)

	require.NoError(t, f.login(t, 5))
	assert.Empty(t, recorder.recorded(), "an advancing counter raises no clone warning")
	assert.Empty(t, f.logs.String())

	// A counter that goes backwards is go-webauthn's CloneWarning. Refusing
	// the login is RP policy the service does not impose, so it still succeeds.
	require.NoError(t, f.login(t, 3), "the clone warning must not change the login outcome")

	events := recorder.recorded()
	require.Len(t, events, 1)
	event := events[0]
	assert.Equal(t, CloneWarningAuditAction, event.Action)
	assert.Equal(t, "webauthn_credential", event.Resource)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(f.credential.ID), event.ResourceID)
	assert.Equal(t, "clone@example.com", event.Subject)
	assert.Equal(t, audit.OutcomeAllow, event.Outcome)
	assert.Equal(t, "5", event.Details["stored_sign_count"])
	assert.Equal(t, "3", event.Details["presented_sign_count"])
	assert.Equal(t, "true", event.Details["first_detection"])
	assert.Equal(t, "example.com", event.Details["rp_id"])

	var logged map[string]any
	require.NoError(t, json.Unmarshal(f.logs.Bytes(), &logged))
	assert.Equal(t, "WARN", logged["level"])
	assert.Contains(t, logged["msg"], "may be cloned")
	assert.Equal(t, event.ResourceID, logged["credential_id"])

	// The flag is sticky on the stored credential: the next login with it is
	// reported again, no longer as the first detection.
	require.NoError(t, f.login(t, 6))
	events = recorder.recorded()
	require.Len(t, events, 2)
	assert.Equal(t, "false", events[1].Details["first_detection"])
}

func TestFinishLogin_CloneWarningAuditFailureFailsLogin(t *testing.T) {
	writeErr := errors.New("audit sink unavailable")
	f := newCloneFixture(t, &recordingAuditLogger{err: writeErr})

	require.NoError(t, f.login(t, 5), "no audit event is written without a clone warning")

	err := f.login(t, 5)
	var auditErr *audit.ErrAuditWriteFailed
	require.ErrorAs(t, err, &auditErr, "a security event that cannot be audited must fail the login")
	assert.ErrorIs(t, err, writeErr)
}

func TestFinishLogin_CloneWarningWithoutAuditLoggerIsLogged(t *testing.T) {
	f := newCloneFixture(t, nil)

	require.NoError(t, f.login(t, 5))
	require.NoError(t, f.login(t, 5))
	assert.Contains(t, f.logs.String(), "may be cloned")
}
