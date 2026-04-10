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

package pairing

import (
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

// BiometricPendingHandler processes local.biometricPending notifications.
// This handler is responsible for showing desktop notifications when the
// phone is waiting for biometric approval.
type BiometricPendingHandler struct {
	notifier notify.Notifier
	logger   *slog.Logger
}

// NewBiometricPendingHandler creates a handler for biometric pending notifications.
func NewBiometricPendingHandler(notifier notify.Notifier, logger *slog.Logger) *BiometricPendingHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &BiometricPendingHandler{
		notifier: notifier,
		logger:   logger.With("component", "biometric_handler"),
	}
}

// HandleBiometricPending processes a biometric pending notification.
// This shows a desktop notification to alert the user that the phone
// is waiting for biometric approval.
func (h *BiometricPendingHandler) HandleBiometricPending(params *LocalBiometricPendingParams) {
	if h.notifier == nil {
		h.logger.Debug("no notifier configured, skipping biometric notification")
		return
	}

	h.logger.Info("phone waiting for biometric approval",
		"operation", params.Operation,
		"rpName", params.RPName,
		"timeoutSecs", params.TimeoutSecs)

	req := &notify.TouchRequest{
		Operation: fmt.Sprintf("phone:%s", params.Operation),
		RPName:    params.RPName,
	}

	if params.RPName == "" {
		req.RPName = "Phone authentication required"
	}

	if err := h.notifier.NotifyTouchRequired(req); err != nil {
		h.logger.Warn("failed to show biometric pending notification", "error", err)
	}
}
