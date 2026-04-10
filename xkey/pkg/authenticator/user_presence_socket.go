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
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

// pendingPresenceRequest wraps a user presence request with a buffered result
// channel. The channel capacity of 1 prevents goroutine leaks when a timeout
// fires before Approve or Deny is called.
type pendingPresenceRequest struct {
	request  *UserPresenceRequest
	resultCh chan *UserPresenceResult
}

// SocketHandler implements UserPresenceHandler for daemon mode. Instead of
// interactive terminal prompts, it receives user presence approvals via IPC
// (e.g. from a CLI touch command or desktop agent).
//
// The handler uses lock-free atomic operations for pending request management.
// All methods are safe for concurrent use.
type SocketHandler struct {
	pendingReq atomic.Pointer[pendingPresenceRequest]
	notifier   notify.Notifier
	logger     *slog.Logger
	auditLog   atomic.Pointer[audit.Logger]
	onResolved func(approved bool) // optional callback fired when a request resolves
}

// NewSocketHandler creates a SocketHandler that dispatches touch notifications
// through the provided Notifier and logs diagnostic messages to logger.
func NewSocketHandler(notifier notify.Notifier, logger *slog.Logger) *SocketHandler {
	return &SocketHandler{
		notifier: notifier,
		logger:   logger,
	}
}

// SetAuditLogger sets the audit logger for security event logging.
func (h *SocketHandler) SetAuditLogger(logger audit.Logger) {
	h.auditLog.Store(&logger)
}

// logUserPresence logs a user presence event to the audit log.
func (h *SocketHandler) logUserPresence(op audit.OperationType, source string, success bool, details map[string]any) {
	ptr := h.auditLog.Load()
	if ptr == nil {
		return
	}
	(*ptr).LogUserPresenceEvent(op, source, success, details)
}

// SetOnResolved registers a callback that is invoked whenever a user presence
// request resolves — by approval, denial, or timeout. The approved parameter
// is true only when the user explicitly approved. This allows the GUI layer
// to clear pending UI state on timeout without polling.
func (h *SocketHandler) SetOnResolved(fn func(approved bool)) {
	h.onResolved = fn
}

// RequestUserPresence blocks until the pending request is approved, denied,
// timed out, or the context is cancelled. The Notifier is informed that touch
// is required so external agents can prompt the user.
func (h *SocketHandler) RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultUserPresenceTimeout
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pending := &pendingPresenceRequest{
		request:  req,
		resultCh: make(chan *UserPresenceResult, 1),
	}
	h.pendingReq.Store(pending)

	// Log user presence request.
	h.logUserPresence(audit.OpUserPresenceRequested, "fido2", true, map[string]any{
		"operation": req.Operation,
		"rpid":      req.RPID,
		"rp_name":   req.RPName,
		"user_name": req.UserName,
	})

	// Fire notification; failures are logged but do not abort the UP request.
	if h.notifier != nil {
		touchReq := &notify.TouchRequest{
			Operation: req.Operation,
			RPID:      req.RPID,
			RPName:    req.RPName,
			UserName:  req.UserName,
		}
		if err := h.notifier.NotifyTouchRequired(touchReq); err != nil {
			h.logger.Warn("failed to send touch notification",
				slog.String("error", err.Error()),
				slog.String("rpid", req.RPID))
		}
	}

	select {
	case result := <-pending.resultCh:
		// Approved or denied by external caller. Clear pending if it is
		// still ours (Approve/Deny already swapped it in the fast path).
		h.pendingReq.CompareAndSwap(pending, nil)
		if result == nil || !result.Approved {
			if h.onResolved != nil {
				h.onResolved(false)
			}
			h.logUserPresence(audit.OpUserPresenceCancelled, "fido2", false, map[string]any{
				"operation": req.Operation,
				"rpid":      req.RPID,
			})
			return nil, ErrUserPresenceDenied
		}
		if h.onResolved != nil {
			h.onResolved(true)
		}
		h.logUserPresence(audit.OpUserPresenceConfirmed, "fido2", true, map[string]any{
			"operation": req.Operation,
			"rpid":      req.RPID,
		})
		return result, nil

	case <-timeoutCtx.Done():
		// Clear pending so a late Approve harmlessly writes into the
		// buffered channel of an orphaned request.
		h.pendingReq.CompareAndSwap(pending, nil)
		if h.onResolved != nil {
			h.onResolved(false)
		}
		h.logUserPresence(audit.OpUserPresenceTimedOut, "fido2", false, map[string]any{
			"operation": req.Operation,
			"rpid":      req.RPID,
		})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUserPresenceTimeout
	}
}

// RequestUserVerification returns ErrTerminalUnavailable because PIN entry
// over IPC is not supported in Phase 2. Callers that need user verification
// should compose this handler with an InteractiveHandler fallback.
func (h *SocketHandler) RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error) {
	return nil, ErrTerminalUnavailable
}

// HasPending reports whether a user presence request is currently awaiting
// approval or denial.
func (h *SocketHandler) HasPending() bool {
	return h.pendingReq.Load() != nil
}

// Approve fulfills the pending user presence request with an approval. It
// returns true if a pending request was successfully claimed and approved,
// or false if there was no pending request.
func (h *SocketHandler) Approve() bool {
	pending := h.pendingReq.Load()
	if pending == nil {
		return false
	}
	if !h.pendingReq.CompareAndSwap(pending, nil) {
		return false
	}
	pending.resultCh <- &UserPresenceResult{Approved: true}
	return true
}

// Deny fulfills the pending user presence request with a denial. It returns
// true if a pending request was successfully claimed and denied, or false
// if there was no pending request.
func (h *SocketHandler) Deny() bool {
	pending := h.pendingReq.Load()
	if pending == nil {
		return false
	}
	if !h.pendingReq.CompareAndSwap(pending, nil) {
		return false
	}
	close(pending.resultCh)
	return true
}

// Ensure SocketHandler implements UserPresenceHandler at compile time.
var _ UserPresenceHandler = (*SocketHandler)(nil)
