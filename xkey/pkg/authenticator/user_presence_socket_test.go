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

package authenticator

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

// mockNotifier records calls to NotifyTouchRequired for test assertions.
type mockNotifier struct {
	calls   atomic.Int32
	lastReq atomic.Pointer[notify.TouchRequest]
	err     error
	closed  atomic.Bool
}

func (m *mockNotifier) NotifyTouchRequired(req *notify.TouchRequest) error {
	m.calls.Add(1)
	m.lastReq.Store(req)
	return m.err
}

func (m *mockNotifier) Close() error {
	m.closed.Store(true)
	return nil
}

// newTestLogger returns a no-op logger suitable for unit tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestSocketHandler_NewSocketHandler verifies the constructor creates a valid
// handler with no pending request.
func TestSocketHandler_NewSocketHandler(t *testing.T) {
	t.Parallel()

	n := &mockNotifier{}
	logger := newTestLogger()

	h := NewSocketHandler(n, logger)

	if h == nil {
		t.Fatal("NewSocketHandler returned nil")
	}
	if h.notifier != n {
		t.Error("notifier not set correctly")
	}
	if h.logger != logger {
		t.Error("logger not set correctly")
	}
	if h.HasPending() {
		t.Error("new handler should have no pending request")
	}
}

// TestSocketHandler_NewSocketHandler_NilNotifier verifies the constructor
// accepts a nil notifier without panicking.
func TestSocketHandler_NewSocketHandler_NilNotifier(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(nil, newTestLogger())

	if h == nil {
		t.Fatal("NewSocketHandler returned nil with nil notifier")
	}
}

// TestSocketHandler_RequestUserPresence_Approved verifies that calling Approve
// unblocks RequestUserPresence with an approved result.
func TestSocketHandler_RequestUserPresence_Approved(t *testing.T) {
	t.Parallel()

	n := &mockNotifier{}
	h := NewSocketHandler(n, newTestLogger())

	req := &UserPresenceRequest{
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  "alice",
		Operation: "register",
		Timeout:   5 * time.Second,
	}

	type presenceResult struct {
		result *UserPresenceResult
		err    error
	}
	done := make(chan presenceResult, 1)

	go func() {
		r, err := h.RequestUserPresence(context.Background(), req)
		done <- presenceResult{result: r, err: err}
	}()

	// Wait until the pending request is visible.
	waitForPending(t, h, true)

	if !h.Approve() {
		t.Fatal("Approve returned false, expected true")
	}

	select {
	case pr := <-done:
		if pr.err != nil {
			t.Fatalf("unexpected error: %v", pr.err)
		}
		if pr.result == nil || !pr.result.Approved {
			t.Fatalf("expected approved result, got %+v", pr.result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RequestUserPresence did not return after Approve")
	}
}

// TestSocketHandler_RequestUserPresence_Timeout verifies that
// RequestUserPresence returns ErrUserPresenceTimeout when the timeout elapses.
func TestSocketHandler_RequestUserPresence_Timeout(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	req := &UserPresenceRequest{
		RPID:    "timeout.example.com",
		Timeout: 50 * time.Millisecond,
	}

	result, err := h.RequestUserPresence(context.Background(), req)

	if !errors.Is(err, ErrUserPresenceTimeout) {
		t.Fatalf("expected ErrUserPresenceTimeout, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
	if h.HasPending() {
		t.Error("pending request should be cleared after timeout")
	}
}

// TestSocketHandler_RequestUserPresence_ContextCancellation verifies that
// a cancelled parent context propagates correctly.
func TestSocketHandler_RequestUserPresence_ContextCancellation(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	ctx, cancel := context.WithCancel(context.Background())

	req := &UserPresenceRequest{
		RPID:    "cancel.example.com",
		Timeout: 5 * time.Second,
	}

	type presenceResult struct {
		result *UserPresenceResult
		err    error
	}
	done := make(chan presenceResult, 1)

	go func() {
		r, err := h.RequestUserPresence(ctx, req)
		done <- presenceResult{result: r, err: err}
	}()

	waitForPending(t, h, true)
	cancel()

	select {
	case pr := <-done:
		if !errors.Is(pr.err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", pr.err)
		}
		if pr.result != nil {
			t.Fatalf("expected nil result, got %+v", pr.result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RequestUserPresence did not return after context cancel")
	}

	if h.HasPending() {
		t.Error("pending request should be cleared after cancellation")
	}
}

// TestSocketHandler_RequestUserPresence_DefaultTimeout verifies that a zero
// Timeout field uses DefaultUserPresenceTimeout. We test indirectly by
// confirming the request blocks and can be approved before the default fires.
func TestSocketHandler_RequestUserPresence_DefaultTimeout(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	req := &UserPresenceRequest{
		RPID:    "default-timeout.example.com",
		Timeout: 0, // should use DefaultUserPresenceTimeout
	}

	type presenceResult struct {
		result *UserPresenceResult
		err    error
	}
	done := make(chan presenceResult, 1)

	go func() {
		r, err := h.RequestUserPresence(context.Background(), req)
		done <- presenceResult{result: r, err: err}
	}()

	waitForPending(t, h, true)

	if !h.Approve() {
		t.Fatal("Approve returned false")
	}

	select {
	case pr := <-done:
		if pr.err != nil {
			t.Fatalf("unexpected error: %v", pr.err)
		}
		if pr.result == nil || !pr.result.Approved {
			t.Fatal("expected approved result")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RequestUserPresence did not return")
	}
}

// TestSocketHandler_RequestUserPresence_NotificationFired verifies that
// the Notifier receives the correct TouchRequest when UP is requested.
func TestSocketHandler_RequestUserPresence_NotificationFired(t *testing.T) {
	t.Parallel()

	n := &mockNotifier{}
	h := NewSocketHandler(n, newTestLogger())

	req := &UserPresenceRequest{
		RPID:      "notify.example.com",
		RPName:    "Notify Corp",
		UserName:  "bob",
		Operation: "authenticate",
		Timeout:   5 * time.Second,
	}

	go func() {
		waitForPending(t, h, true)
		h.Approve()
	}()

	result, err := h.RequestUserPresence(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Approved {
		t.Fatal("expected approved")
	}

	if n.calls.Load() != 1 {
		t.Fatalf("expected 1 notification call, got %d", n.calls.Load())
	}

	touchReq := n.lastReq.Load()
	if touchReq == nil {
		t.Fatal("notification touch request is nil")
	}
	if touchReq.RPID != "notify.example.com" {
		t.Errorf("RPID = %q, want %q", touchReq.RPID, "notify.example.com")
	}
	if touchReq.RPName != "Notify Corp" {
		t.Errorf("RPName = %q, want %q", touchReq.RPName, "Notify Corp")
	}
	if touchReq.UserName != "bob" {
		t.Errorf("UserName = %q, want %q", touchReq.UserName, "bob")
	}
	if touchReq.Operation != "authenticate" {
		t.Errorf("Operation = %q, want %q", touchReq.Operation, "authenticate")
	}
}

// TestSocketHandler_RequestUserPresence_NotificationError verifies that a
// notification failure is logged but does not prevent the UP request from
// completing.
func TestSocketHandler_RequestUserPresence_NotificationError(t *testing.T) {
	t.Parallel()

	n := &mockNotifier{err: errors.New("dbus unavailable")}
	h := NewSocketHandler(n, newTestLogger())

	req := &UserPresenceRequest{
		RPID:    "notify-err.example.com",
		Timeout: 5 * time.Second,
	}

	go func() {
		waitForPending(t, h, true)
		h.Approve()
	}()

	result, err := h.RequestUserPresence(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Approved {
		t.Fatal("expected approved despite notification error")
	}

	if n.calls.Load() != 1 {
		t.Fatalf("expected 1 notification call, got %d", n.calls.Load())
	}
}

// TestSocketHandler_HasPending_NoPending verifies HasPending returns false
// when no request is pending.
func TestSocketHandler_HasPending_NoPending(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	if h.HasPending() {
		t.Error("expected HasPending to return false on new handler")
	}
}

// TestSocketHandler_HasPending_WithPending verifies HasPending returns true
// while a request is blocking on approval.
func TestSocketHandler_HasPending_WithPending(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	req := &UserPresenceRequest{
		RPID:    "has-pending.example.com",
		Timeout: 5 * time.Second,
	}

	go func() {
		h.RequestUserPresence(context.Background(), req)
	}()

	waitForPending(t, h, true)

	if !h.HasPending() {
		t.Error("expected HasPending to return true during pending request")
	}

	h.Approve()
}

// TestSocketHandler_Approve_NoPending verifies Approve returns false when
// there is no pending request.
func TestSocketHandler_Approve_NoPending(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	if h.Approve() {
		t.Error("Approve should return false when no request is pending")
	}
}

// TestSocketHandler_Approve_WithPending verifies Approve claims the pending
// request, unblocks RequestUserPresence, and returns true.
func TestSocketHandler_Approve_WithPending(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	req := &UserPresenceRequest{
		RPID:    "approve.example.com",
		Timeout: 5 * time.Second,
	}

	type presenceResult struct {
		result *UserPresenceResult
		err    error
	}
	done := make(chan presenceResult, 1)

	go func() {
		r, err := h.RequestUserPresence(context.Background(), req)
		done <- presenceResult{result: r, err: err}
	}()

	waitForPending(t, h, true)

	if !h.Approve() {
		t.Fatal("Approve returned false")
	}

	if h.HasPending() {
		t.Error("pending should be cleared after Approve")
	}

	select {
	case pr := <-done:
		if pr.err != nil {
			t.Fatalf("unexpected error: %v", pr.err)
		}
		if pr.result == nil || !pr.result.Approved {
			t.Fatal("expected approved result")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RequestUserPresence did not return after Approve")
	}
}

// TestSocketHandler_Deny_NoPending verifies Deny returns false when there
// is no pending request.
func TestSocketHandler_Deny_NoPending(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	if h.Deny() {
		t.Error("Deny should return false when no request is pending")
	}
}

// TestSocketHandler_Deny_WithPending verifies Deny closes the result channel,
// causing RequestUserPresence to return ErrUserPresenceDenied.
func TestSocketHandler_Deny_WithPending(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	req := &UserPresenceRequest{
		RPID:    "deny.example.com",
		Timeout: 5 * time.Second,
	}

	type presenceResult struct {
		result *UserPresenceResult
		err    error
	}
	done := make(chan presenceResult, 1)

	go func() {
		r, err := h.RequestUserPresence(context.Background(), req)
		done <- presenceResult{result: r, err: err}
	}()

	waitForPending(t, h, true)

	if !h.Deny() {
		t.Fatal("Deny returned false")
	}

	select {
	case pr := <-done:
		if !errors.Is(pr.err, ErrUserPresenceDenied) {
			t.Fatalf("expected ErrUserPresenceDenied, got %v", pr.err)
		}
		if pr.result != nil {
			t.Fatalf("expected nil result, got %+v", pr.result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RequestUserPresence did not return after Deny")
	}

	if h.HasPending() {
		t.Error("pending should be cleared after Deny")
	}
}

// TestSocketHandler_RequestUserVerification_ReturnsTerminalUnavailable
// verifies that user verification returns ErrTerminalUnavailable since
// PIN entry over IPC is not supported.
func TestSocketHandler_RequestUserVerification_ReturnsTerminalUnavailable(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	req := &UserVerificationRequest{
		RPID:        "example.com",
		PINRequired: true,
		Timeout:     5 * time.Second,
	}

	result, err := h.RequestUserVerification(context.Background(), req)

	if !errors.Is(err, ErrTerminalUnavailable) {
		t.Fatalf("expected ErrTerminalUnavailable, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
}

// TestSocketHandler_RequestUserVerification_NoPIN verifies that user
// verification without PIN still returns ErrTerminalUnavailable.
func TestSocketHandler_RequestUserVerification_NoPIN(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	req := &UserVerificationRequest{
		RPID:        "example.com",
		PINRequired: false,
	}

	result, err := h.RequestUserVerification(context.Background(), req)

	if !errors.Is(err, ErrTerminalUnavailable) {
		t.Fatalf("expected ErrTerminalUnavailable, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
}

// TestSocketHandler_ImplementsInterface is a compile-time check that
// SocketHandler satisfies the UserPresenceHandler interface.
func TestSocketHandler_ImplementsInterface(t *testing.T) {
	t.Parallel()

	var _ UserPresenceHandler = (*SocketHandler)(nil)
	var _ UserPresenceHandler = NewSocketHandler(&mockNotifier{}, newTestLogger())
}

// TestSocketHandler_ConcurrentAccess verifies that multiple goroutines
// calling HasPending and Approve concurrently do not race.
func TestSocketHandler_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	req := &UserPresenceRequest{
		RPID:    "concurrent.example.com",
		Timeout: 5 * time.Second,
	}

	go func() {
		h.RequestUserPresence(context.Background(), req)
	}()

	waitForPending(t, h, true)

	var wg sync.WaitGroup
	const workers = 50

	approvedCount := atomic.Int32{}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.HasPending()
			if h.Approve() {
				approvedCount.Add(1)
			}
		}()
	}

	wg.Wait()

	if count := approvedCount.Load(); count != 1 {
		t.Fatalf("expected exactly 1 successful Approve, got %d", count)
	}
}

// TestSocketHandler_SequentialRequests verifies that two user presence
// requests can be handled one after the other without interference.
func TestSocketHandler_SequentialRequests(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())

	for i := 0; i < 3; i++ {
		req := &UserPresenceRequest{
			RPID:    "sequential.example.com",
			Timeout: 5 * time.Second,
		}

		type presenceResult struct {
			result *UserPresenceResult
			err    error
		}
		done := make(chan presenceResult, 1)

		go func() {
			r, err := h.RequestUserPresence(context.Background(), req)
			done <- presenceResult{result: r, err: err}
		}()

		waitForPending(t, h, true)

		if !h.Approve() {
			t.Fatalf("iteration %d: Approve returned false", i)
		}

		select {
		case pr := <-done:
			if pr.err != nil {
				t.Fatalf("iteration %d: unexpected error: %v", i, pr.err)
			}
			if pr.result == nil || !pr.result.Approved {
				t.Fatalf("iteration %d: expected approved", i)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("iteration %d: timed out waiting for result", i)
		}

		if h.HasPending() {
			t.Fatalf("iteration %d: pending should be cleared", i)
		}
	}
}

// TestSocketHandler_ApproveRacesTimeout verifies that when Approve and a
// timeout fire concurrently, exactly one outcome wins cleanly without panics
// or data races.
func TestSocketHandler_ApproveRacesTimeout(t *testing.T) {
	t.Parallel()

	for attempt := 0; attempt < 20; attempt++ {
		h := NewSocketHandler(&mockNotifier{}, newTestLogger())

		req := &UserPresenceRequest{
			RPID:    "race.example.com",
			Timeout: 1 * time.Millisecond,
		}

		type presenceResult struct {
			result *UserPresenceResult
			err    error
		}
		done := make(chan presenceResult, 1)

		go func() {
			r, err := h.RequestUserPresence(context.Background(), req)
			done <- presenceResult{result: r, err: err}
		}()

		// Try to approve at roughly the same time the timeout fires.
		time.Sleep(500 * time.Microsecond)
		h.Approve()

		select {
		case pr := <-done:
			// Either outcome is acceptable: approved or timed out.
			if pr.err != nil && !errors.Is(pr.err, ErrUserPresenceTimeout) {
				t.Fatalf("attempt %d: unexpected error: %v", attempt, pr.err)
			}
			if pr.err == nil && (pr.result == nil || !pr.result.Approved) {
				t.Fatalf("attempt %d: nil error but not approved", attempt)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("attempt %d: timed out waiting for result", attempt)
		}

		if h.HasPending() {
			t.Fatalf("attempt %d: pending should be cleared", attempt)
		}
	}
}

// TestSocketHandler_NilNotifier verifies that RequestUserPresence works
// correctly when no notifier is configured.
func TestSocketHandler_NilNotifier(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(nil, newTestLogger())

	req := &UserPresenceRequest{
		RPID:    "nil-notifier.example.com",
		Timeout: 5 * time.Second,
	}

	go func() {
		waitForPending(t, h, true)
		h.Approve()
	}()

	result, err := h.RequestUserPresence(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Approved {
		t.Fatal("expected approved")
	}
}

// TestSocketHandler_OnResolved_Approved verifies that the onResolved callback
// fires with approved=true when the request is approved.
func TestSocketHandler_OnResolved_Approved(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())
	var called atomic.Bool
	var gotApproved atomic.Bool
	h.SetOnResolved(func(approved bool) {
		gotApproved.Store(approved)
		called.Store(true)
	})

	req := &UserPresenceRequest{
		RPID:    "resolved-approved.example.com",
		Timeout: 5 * time.Second,
	}

	go func() {
		waitForPending(t, h, true)
		h.Approve()
	}()

	result, err := h.RequestUserPresence(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Approved {
		t.Fatal("expected approved")
	}
	if !called.Load() {
		t.Fatal("onResolved callback was not called")
	}
	if !gotApproved.Load() {
		t.Fatal("onResolved should have been called with approved=true")
	}
}

// TestSocketHandler_OnResolved_Timeout verifies that the onResolved callback
// fires with approved=false when the request times out.
func TestSocketHandler_OnResolved_Timeout(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())
	var called atomic.Bool
	var gotApproved atomic.Bool
	gotApproved.Store(true) // set true so we can verify it changes to false
	h.SetOnResolved(func(approved bool) {
		gotApproved.Store(approved)
		called.Store(true)
	})

	req := &UserPresenceRequest{
		RPID:    "resolved-timeout.example.com",
		Timeout: 50 * time.Millisecond,
	}

	_, err := h.RequestUserPresence(context.Background(), req)
	if !errors.Is(err, ErrUserPresenceTimeout) {
		t.Fatalf("expected timeout error, got: %v", err)
	}
	if !called.Load() {
		t.Fatal("onResolved callback was not called on timeout")
	}
	if gotApproved.Load() {
		t.Fatal("onResolved should have been called with approved=false on timeout")
	}
}

// TestSocketHandler_OnResolved_Denied verifies that the onResolved callback
// fires with approved=false when the request is denied.
func TestSocketHandler_OnResolved_Denied(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())
	var called atomic.Bool
	var gotApproved atomic.Bool
	gotApproved.Store(true) // set true so we can verify it changes to false
	h.SetOnResolved(func(approved bool) {
		gotApproved.Store(approved)
		called.Store(true)
	})

	req := &UserPresenceRequest{
		RPID:    "resolved-denied.example.com",
		Timeout: 5 * time.Second,
	}

	go func() {
		waitForPending(t, h, true)
		h.Deny()
	}()

	_, err := h.RequestUserPresence(context.Background(), req)
	if !errors.Is(err, ErrUserPresenceDenied) {
		t.Fatalf("expected denied error, got: %v", err)
	}
	if !called.Load() {
		t.Fatal("onResolved callback was not called on denial")
	}
	if gotApproved.Load() {
		t.Fatal("onResolved should have been called with approved=false on denial")
	}
}

// TestSocketHandler_OnResolved_Nil verifies that a nil onResolved callback
// does not cause a panic.
func TestSocketHandler_OnResolved_Nil(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(&mockNotifier{}, newTestLogger())
	// Do NOT set onResolved — verify no panic.

	req := &UserPresenceRequest{
		RPID:    "resolved-nil.example.com",
		Timeout: 50 * time.Millisecond,
	}

	_, err := h.RequestUserPresence(context.Background(), req)
	if !errors.Is(err, ErrUserPresenceTimeout) {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

// waitForPending polls HasPending until the desired state is observed
// or a reasonable deadline is exceeded.
func waitForPending(t *testing.T, h *SocketHandler, want bool) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if h.HasPending() == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for HasPending() == %v", want)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}
