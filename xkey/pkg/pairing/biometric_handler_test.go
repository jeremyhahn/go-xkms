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
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/stretchr/testify/assert"
)

// mockNotifier is a test double for notify.Notifier.
type mockNotifier struct {
	calls  []notify.TouchRequest
	err    error
	closed bool
}

func (m *mockNotifier) NotifyTouchRequired(req *notify.TouchRequest) error {
	m.calls = append(m.calls, *req)
	return m.err
}

func (m *mockNotifier) Close() error {
	m.closed = true
	return nil
}

func TestNewBiometricPendingHandler_NilLogger(t *testing.T) {
	t.Parallel()

	notifier := &mockNotifier{}
	handler := NewBiometricPendingHandler(notifier, nil)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.logger)
}

func TestNewBiometricPendingHandler_Success(t *testing.T) {
	t.Parallel()

	notifier := &mockNotifier{}
	logger := slog.Default()
	handler := NewBiometricPendingHandler(notifier, logger)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.notifier)
	assert.NotNil(t, handler.logger)
}

func TestHandleBiometricPending_NilNotifier(t *testing.T) {
	t.Parallel()

	handler := NewBiometricPendingHandler(nil, nil)

	// Should not panic with nil notifier.
	handler.HandleBiometricPending(&LocalBiometricPendingParams{
		Operation:   "sign",
		RPName:      "Example Corp",
		TimeoutSecs: 30,
	})
}

func TestHandleBiometricPending_Success(t *testing.T) {
	t.Parallel()

	notifier := &mockNotifier{}
	handler := NewBiometricPendingHandler(notifier, nil)

	params := &LocalBiometricPendingParams{
		Operation:   "sign",
		RPName:      "Example Corp",
		TimeoutSecs: 30,
	}

	handler.HandleBiometricPending(params)

	assert.Len(t, notifier.calls, 1)
	assert.Equal(t, "phone:sign", notifier.calls[0].Operation)
	assert.Equal(t, "Example Corp", notifier.calls[0].RPName)
}

func TestHandleBiometricPending_EmptyRPName(t *testing.T) {
	t.Parallel()

	notifier := &mockNotifier{}
	handler := NewBiometricPendingHandler(notifier, nil)

	params := &LocalBiometricPendingParams{
		Operation:   "decrypt",
		RPName:      "",
		TimeoutSecs: 60,
	}

	handler.HandleBiometricPending(params)

	assert.Len(t, notifier.calls, 1)
	assert.Equal(t, "phone:decrypt", notifier.calls[0].Operation)
	assert.Equal(t, "Phone authentication required", notifier.calls[0].RPName)
}

func TestHandleBiometricPending_NotifyError(t *testing.T) {
	t.Parallel()

	notifier := &mockNotifier{err: errors.New("notification failed")}
	handler := NewBiometricPendingHandler(notifier, nil)

	params := &LocalBiometricPendingParams{
		Operation:   "attestKey",
		RPName:      "Test RP",
		TimeoutSecs: 45,
	}

	// Should not panic on notifier error.
	handler.HandleBiometricPending(params)

	assert.Len(t, notifier.calls, 1)
}

func TestLocalBiometricPendingParams_IsLocalMethod(t *testing.T) {
	t.Parallel()

	assert.True(t, IsLocalMethod(MethodLocalBiometricPending))
}

func TestMethodLocalBiometricPending_Constant(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "local.biometricPending", MethodLocalBiometricPending)
}
