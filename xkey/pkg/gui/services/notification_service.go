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

package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

// Notification service errors.
var (
	// ErrNotificationDisabled is returned when notifications are toggled off.
	ErrNotificationDisabled = errors.New("notification_service: notifications are disabled")

	// ErrNotificationUnavailable is returned when no notifier has been set.
	ErrNotificationUnavailable = errors.New("notification_service: notifier not available")

	// ErrNotificationSendFailed is returned when the underlying notifier fails.
	ErrNotificationSendFailed = errors.New("notification_service: failed to send notification")
)

// NotificationRequest is the frontend-facing notification request.
type NotificationRequest struct {
	Title   string `json:"title"`
	Message string `json:"message"`
}

// NotificationService manages desktop notification delivery for the xKey
// GUI. It wraps the notify.Notifier interface and is bound to the Wails
// runtime so every exported method is callable from the frontend.
type NotificationService struct {
	ctx      context.Context
	log      *slog.Logger
	notifier notify.Notifier
	enabled  atomic.Bool
}

// NewNotificationService creates a new NotificationService with logging
// and notifications enabled by default.
func NewNotificationService() *NotificationService {
	svc := &NotificationService{
		log: slog.Default(),
	}
	svc.enabled.Store(true)
	return svc
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *NotificationService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetNotifier injects the underlying notifier implementation.
func (s *NotificationService) SetNotifier(n notify.Notifier) {
	s.notifier = n
}

// SetEnabled toggles notification delivery on or off.
func (s *NotificationService) SetEnabled(enabled bool) {
	s.enabled.Store(enabled)
}

// IsEnabled returns whether notification delivery is enabled.
func (s *NotificationService) IsEnabled() bool {
	return s.enabled.Load()
}

// IsAvailable returns true if a notifier backend has been configured.
func (s *NotificationService) IsAvailable() bool {
	return s.notifier != nil
}

// SendNotification sends a generic notification from the frontend. The
// request Title is mapped to the TouchRequest Operation field and the
// Message is mapped to the RPName field.
func (s *NotificationService) SendNotification(req NotificationRequest) error {
	if !s.enabled.Load() {
		return ErrNotificationDisabled
	}
	if s.notifier == nil {
		return ErrNotificationUnavailable
	}

	touchReq := &notify.TouchRequest{
		Operation: req.Title,
		RPName:    req.Message,
	}

	if err := s.notifier.NotifyTouchRequired(touchReq); err != nil {
		s.log.Error("Failed to send notification",
			slog.String("title", req.Title),
			slog.String("error", err.Error()),
		)
		return fmt.Errorf("%w: %w", ErrNotificationSendFailed, err)
	}

	return nil
}

// NotifyTouchRequired sends a FIDO2 touch-required notification to the
// user. The operation describes the WebAuthn ceremony type (e.g.
// "register" or "authenticate") and rpID identifies the relying party.
func (s *NotificationService) NotifyTouchRequired(operation, rpID string) error {
	if !s.enabled.Load() {
		return ErrNotificationDisabled
	}
	if s.notifier == nil {
		return ErrNotificationUnavailable
	}

	touchReq := &notify.TouchRequest{
		Operation: operation,
		RPID:      rpID,
	}

	if err := s.notifier.NotifyTouchRequired(touchReq); err != nil {
		s.log.Error("Failed to send touch notification",
			slog.String("operation", operation),
			slog.String("rp_id", rpID),
			slog.String("error", err.Error()),
		)
		return fmt.Errorf("%w: %w", ErrNotificationSendFailed, err)
	}

	return nil
}

// Close releases resources held by the underlying notifier. If no
// notifier has been set, Close is a no-op.
func (s *NotificationService) Close() error {
	if s.notifier == nil {
		return nil
	}
	return s.notifier.Close()
}
