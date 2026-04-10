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
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockNotifier struct {
	lastReq *notify.TouchRequest
	err     error
	closed  bool
}

func (m *mockNotifier) NotifyTouchRequired(req *notify.TouchRequest) error {
	if m.closed {
		return notify.ErrNotifierClosed
	}
	m.lastReq = req
	return m.err
}

func (m *mockNotifier) Close() error {
	m.closed = true
	return nil
}

func TestNewNotificationService(t *testing.T) {
	svc := NewNotificationService()
	require.NotNil(t, svc)
	assert.True(t, svc.IsEnabled())
}

func TestNotificationService_SetContext(t *testing.T) {
	svc := NewNotificationService()
	ctx := context.Background()
	svc.SetContext(ctx)
	// No panic means success; context is internal.
}

func TestNotificationService_IsAvailable_NoNotifier(t *testing.T) {
	svc := NewNotificationService()
	assert.False(t, svc.IsAvailable())
}

func TestNotificationService_IsAvailable_WithNotifier(t *testing.T) {
	svc := NewNotificationService()
	svc.SetNotifier(&mockNotifier{})
	assert.True(t, svc.IsAvailable())
}

func TestNotificationService_SendNotification_Success(t *testing.T) {
	mock := &mockNotifier{}
	svc := NewNotificationService()
	svc.SetNotifier(mock)

	req := NotificationRequest{
		Title:   "Touch Required",
		Message: "Example Corp",
	}
	err := svc.SendNotification(req)
	assert.NoError(t, err)

	require.NotNil(t, mock.lastReq)
	assert.Equal(t, "Touch Required", mock.lastReq.Operation)
	assert.Equal(t, "Example Corp", mock.lastReq.RPName)
}

func TestNotificationService_SendNotification_Disabled(t *testing.T) {
	svc := NewNotificationService()
	svc.SetNotifier(&mockNotifier{})
	svc.SetEnabled(false)

	err := svc.SendNotification(NotificationRequest{Title: "test", Message: "test"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotificationDisabled))
}

func TestNotificationService_SendNotification_NoNotifier(t *testing.T) {
	svc := NewNotificationService()

	err := svc.SendNotification(NotificationRequest{Title: "test", Message: "test"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotificationUnavailable))
}

func TestNotificationService_SendNotification_Error(t *testing.T) {
	mock := &mockNotifier{
		err: notify.ErrNotificationFailed,
	}
	svc := NewNotificationService()
	svc.SetNotifier(mock)

	err := svc.SendNotification(NotificationRequest{Title: "test", Message: "test"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotificationSendFailed))
}

func TestNotificationService_NotifyTouchRequired_Success(t *testing.T) {
	mock := &mockNotifier{}
	svc := NewNotificationService()
	svc.SetNotifier(mock)

	err := svc.NotifyTouchRequired("register", "example.com")
	assert.NoError(t, err)

	require.NotNil(t, mock.lastReq)
	assert.Equal(t, "register", mock.lastReq.Operation)
	assert.Equal(t, "example.com", mock.lastReq.RPID)
}

func TestNotificationService_NotifyTouchRequired_Disabled(t *testing.T) {
	svc := NewNotificationService()
	svc.SetNotifier(&mockNotifier{})
	svc.SetEnabled(false)

	err := svc.NotifyTouchRequired("register", "example.com")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotificationDisabled))
}

func TestNotificationService_NotifyTouchRequired_NoNotifier(t *testing.T) {
	svc := NewNotificationService()

	err := svc.NotifyTouchRequired("register", "example.com")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotificationUnavailable))
}

func TestNotificationService_NotifyTouchRequired_Error(t *testing.T) {
	mock := &mockNotifier{
		err: notify.ErrNotificationFailed,
	}
	svc := NewNotificationService()
	svc.SetNotifier(mock)

	err := svc.NotifyTouchRequired("authenticate", "example.com")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotificationSendFailed))
}

func TestNotificationService_SetEnabled(t *testing.T) {
	svc := NewNotificationService()
	assert.True(t, svc.IsEnabled())

	svc.SetEnabled(false)
	assert.False(t, svc.IsEnabled())

	svc.SetEnabled(true)
	assert.True(t, svc.IsEnabled())
}

func TestNotificationService_Close_NoNotifier(t *testing.T) {
	svc := NewNotificationService()
	err := svc.Close()
	assert.NoError(t, err)
}

func TestNotificationService_Close_WithNotifier(t *testing.T) {
	mock := &mockNotifier{}
	svc := NewNotificationService()
	svc.SetNotifier(mock)

	err := svc.Close()
	assert.NoError(t, err)
	assert.True(t, mock.closed)
}
