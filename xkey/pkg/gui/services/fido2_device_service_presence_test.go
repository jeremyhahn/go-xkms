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

//go:build linux

package services

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/stretchr/testify/require"
)

// presenceTestTimeout keeps the user-presence wait short so a test that expects
// a request to go unanswered does not sit through the production 30s timeout.
const presenceTestTimeout = 100 * time.Millisecond

// signallingNotifier reports every touch prompt on a channel so a test can
// answer the prompt without polling or sleeping.
type signallingNotifier struct {
	prompts chan *notify.TouchRequest
}

func newSignallingNotifier() *signallingNotifier {
	return &signallingNotifier{prompts: make(chan *notify.TouchRequest, 4)}
}

func (n *signallingNotifier) NotifyTouchRequired(req *notify.TouchRequest) error {
	n.prompts <- req
	return nil
}

func (n *signallingNotifier) Close() error { return nil }

// countingPresenceHandler records how it was asked and always denies, standing
// in for a presence channel that is not the GUI prompt.
type countingPresenceHandler struct {
	calls chan struct{}
}

func newCountingPresenceHandler() *countingPresenceHandler {
	return &countingPresenceHandler{calls: make(chan struct{}, 8)}
}

func (h *countingPresenceHandler) RequestUserPresence(
	ctx context.Context, req *authenticator.UserPresenceRequest,
) (*authenticator.UserPresenceResult, error) {
	h.calls <- struct{}{}
	return nil, authenticator.ErrUserPresenceDenied
}

func (h *countingPresenceHandler) RequestUserVerification(
	ctx context.Context, req *authenticator.UserVerificationRequest,
) (*authenticator.UserVerificationResult, error) {
	return nil, authenticator.ErrUserVerificationDenied
}

// newSharedAuthenticator builds the authenticator the way pkg/gui/app.go
// initializeAuthenticator does — notably with no UserPresenceHandler of its
// own, which is what makes the library's auto-grant default the thing under
// test here.
func newSharedAuthenticator(t *testing.T, timeout time.Duration) *authenticator.Authenticator {
	t.Helper()

	config := authenticator.DefaultConfig()
	config.UserPresenceHandler = authenticator.NewAutoGrantHandler()
	config.Storage = authenticator.NewMemoryStorage()
	config.EnablePIN = false
	config.UserPresenceTimeout = timeout

	auth, err := authenticator.NewAuthenticator(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

// startedService returns a service wired to auth and holding the bridge state
// Start would have set, so Stop can run without a UHID device.
func startedService(t *testing.T, auth *authenticator.Authenticator, notifier notify.Notifier) *FIDO2DeviceService {
	t.Helper()

	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetAuthenticator(auth)

	handler := svc.ensurePresenceHandler(notifier)
	svc.priorUPHandler = auth.SetUserPresenceHandler(handler)
	svc.running.Store(true)
	svc.stopCh = make(chan struct{})
	return svc
}

// registerCredential drives the shared authenticator the way the browser
// extension path does, so whichever presence handler is in force decides the
// outcome.
func registerCredential(t *testing.T, auth *authenticator.Authenticator, label string) error {
	t.Helper()

	clientDataHash := sha256.Sum256([]byte(label))
	_, err := auth.MakeCredential(
		clientDataHash[:],
		authenticator.RelyingParty{ID: "example.com", Name: "Example Corp"},
		authenticator.User{ID: []byte("user-1"), Name: "user@example.com", DisplayName: "User"},
		[]authenticator.PublicKeyCredentialParam{{Type: "public-key", Alg: authenticator.COSEAlgES256}},
		&authenticator.MakeCredentialOptions{Options: map[string]bool{"rk": true}},
	)
	return err
}

// TestFIDO2DeviceService_AttachedPromptSurvivesStop proves the fix for the
// remaining half of the shared-handler defect. Restoring the handler Start
// displaced is only as good as what was there before, and the GUI configures
// none — so the restored handler was the library's auto-grant default and the
// browser-extension path went back to approving user presence with no user
// involved. With the prompt attached for the session, Stop restores the prompt.
func TestFIDO2DeviceService_AttachedPromptSurvivesStop(t *testing.T) {
	auth := newSharedAuthenticator(t, presenceTestTimeout)

	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetAuthenticator(auth)
	svc.AttachPresenceHandler(newSignallingNotifier()) // what app.go now does

	// What Start does once UHID is available.
	svc.priorUPHandler = auth.SetUserPresenceHandler(svc.presenceHandler())
	svc.running.Store(true)
	svc.stopCh = make(chan struct{})

	require.NoError(t, svc.Stop())

	_, autoGranting := auth.UserPresenceHandler().(*authenticator.AutoGrantHandler)
	require.False(t, autoGranting,
		"after Stop the shared authenticator auto-grants user presence")
	require.Same(t, svc.presenceHandler(), auth.UserPresenceHandler())

	// Nobody answers the prompt, so the request must fail rather than be
	// granted on the user's behalf.
	require.Error(t, registerCredential(t, auth, "after-stop"),
		"presence was granted with no user involved after the device was stopped")
}

// TestFIDO2DeviceService_PresenceStillPromptsAfterStop proves the other half:
// stopping the virtual device must not break the legitimate flow either. The
// GUI prompt does not depend on the UHID bridge, so an approved touch still
// produces a credential.
func TestFIDO2DeviceService_PresenceStillPromptsAfterStop(t *testing.T) {
	auth := newSharedAuthenticator(t, 5*time.Second)

	notifier := newSignallingNotifier()
	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetAuthenticator(auth)
	svc.AttachPresenceHandler(notifier)

	svc.priorUPHandler = auth.SetUserPresenceHandler(svc.presenceHandler())
	svc.running.Store(true)
	svc.stopCh = make(chan struct{})
	require.NoError(t, svc.Stop())

	done := make(chan error, 1)
	go func() {
		done <- registerCredential(t, auth, "approved-after-stop")
	}()

	select {
	case req := <-notifier.prompts:
		require.Equal(t, "register", req.Operation)
		require.True(t, svc.ApproveTouchRequest(), "the pending prompt should be approvable")
	case <-time.After(5 * time.Second):
		t.Fatal("no touch prompt was raised after Stop")
	}

	require.NoError(t, <-done)
}

// TestFIDO2DeviceService_StopRestoresPriorHandlerWhenNotAttached keeps the
// existing contract for an embedder that never attaches a session prompt: Stop
// puts back exactly the handler Start displaced, and does not invent one.
func TestFIDO2DeviceService_StopRestoresPriorHandlerWhenNotAttached(t *testing.T) {
	prior := newCountingPresenceHandler()

	config := authenticator.DefaultConfig()
	config.UserPresenceHandler = authenticator.NewAutoGrantHandler()
	config.Storage = authenticator.NewMemoryStorage()
	config.EnablePIN = false
	config.UserPresenceTimeout = presenceTestTimeout
	config.UserPresenceHandler = prior

	auth, err := authenticator.NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	svc := startedService(t, auth, newSignallingNotifier())
	require.NoError(t, svc.Stop())

	require.Same(t, authenticator.UserPresenceHandler(prior), auth.UserPresenceHandler())

	require.Error(t, registerCredential(t, auth, "prior-handler"))
	select {
	case <-prior.calls:
	default:
		t.Fatal("the restored handler was never asked for user presence")
	}
}

// TestFIDO2DeviceService_AttachPresenceHandlerIsIdempotent proves repeated
// attachment keeps the same handler instance, so ApproveTouchRequest always
// addresses the request that is actually pending.
func TestFIDO2DeviceService_AttachPresenceHandlerIsIdempotent(t *testing.T) {
	auth := newSharedAuthenticator(t, presenceTestTimeout)

	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetAuthenticator(auth)
	svc.AttachPresenceHandler(newSignallingNotifier())

	first := auth.UserPresenceHandler()
	require.Same(t, svc.presenceHandler(), first)

	svc.AttachPresenceHandler(newSignallingNotifier())
	require.Same(t, first, auth.UserPresenceHandler())
	require.Same(t, svc.presenceHandler(), auth.UserPresenceHandler())
}

// TestFIDO2DeviceService_AttachPresenceHandlerWithoutAuthenticator covers the
// case where no shared authenticator has been wired yet: the prompt is created
// for later use and nothing panics.
func TestFIDO2DeviceService_AttachPresenceHandlerWithoutAuthenticator(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.AttachPresenceHandler(nil)

	require.NotNil(t, svc.presenceHandler())
	require.False(t, svc.HasPendingTouch())
	require.False(t, svc.ApproveTouchRequest())
	require.False(t, svc.DenyTouchRequest())
}
