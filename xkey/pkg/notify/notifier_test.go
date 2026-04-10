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

package notify

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNotifier is a test double that records calls and optionally returns errors.
type mockNotifier struct {
	notifyCalled atomic.Int32
	closeCalled  atomic.Int32
	notifyErr    error
	closeErr     error
	lastReq      atomic.Pointer[TouchRequest]
}

func (m *mockNotifier) NotifyTouchRequired(req *TouchRequest) error {
	m.notifyCalled.Add(1)
	m.lastReq.Store(req)
	return m.notifyErr
}

func (m *mockNotifier) Close() error {
	m.closeCalled.Add(1)
	return m.closeErr
}

func TestNotifier_InterfaceCompliance(t *testing.T) {
	var _ Notifier = (*MultiNotifier)(nil)
	var _ Notifier = (*LogNotifier)(nil)
	var _ Notifier = (*DBusNotifier)(nil)
	var _ Notifier = (*CommandNotifier)(nil)
	var _ Notifier = (*FocusNotifier)(nil)
}

func TestMultiNotifier_FiresAll(t *testing.T) {
	n1 := &mockNotifier{}
	n2 := &mockNotifier{}
	n3 := &mockNotifier{}
	multi := NewMultiNotifier(n1, n2, n3)

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
		RPName:    "Example",
		UserName:  "alice",
	}

	err := multi.NotifyTouchRequired(req)
	require.NoError(t, err)

	assert.Equal(t, int32(1), n1.notifyCalled.Load())
	assert.Equal(t, int32(1), n2.notifyCalled.Load())
	assert.Equal(t, int32(1), n3.notifyCalled.Load())

	// Verify request was passed through
	assert.Equal(t, "register", n1.lastReq.Load().Operation)
	assert.Equal(t, "example.com", n2.lastReq.Load().RPID)
	assert.Equal(t, "alice", n3.lastReq.Load().UserName)
}

func TestMultiNotifier_ContinuesOnFailure(t *testing.T) {
	failErr := errors.New("test: notifier failed")
	n1 := &mockNotifier{}
	n2 := &mockNotifier{notifyErr: failErr}
	n3 := &mockNotifier{}
	multi := NewMultiNotifier(n1, n2, n3)

	req := &TouchRequest{
		Operation: "authenticate",
		RPID:      "example.com",
	}

	err := multi.NotifyTouchRequired(req)
	require.Error(t, err)

	// All notifiers should have been called despite n2's failure.
	assert.Equal(t, int32(1), n1.notifyCalled.Load())
	assert.Equal(t, int32(1), n2.notifyCalled.Load())
	assert.Equal(t, int32(1), n3.notifyCalled.Load())
}

func TestMultiNotifier_CollectsErrors(t *testing.T) {
	err1 := errors.New("test: first failed")
	err2 := errors.New("test: second failed")
	n1 := &mockNotifier{notifyErr: err1}
	n2 := &mockNotifier{}
	n3 := &mockNotifier{notifyErr: err2}
	multi := NewMultiNotifier(n1, n2, n3)

	req := &TouchRequest{Operation: "register", RPID: "example.com"}
	err := multi.NotifyTouchRequired(req)
	require.Error(t, err)

	// Both errors should be present in the joined error.
	assert.ErrorIs(t, err, err1)
	assert.ErrorIs(t, err, err2)
}

func TestMultiNotifier_CloseAll(t *testing.T) {
	n1 := &mockNotifier{}
	n2 := &mockNotifier{}
	multi := NewMultiNotifier(n1, n2)

	err := multi.Close()
	require.NoError(t, err)

	assert.Equal(t, int32(1), n1.closeCalled.Load())
	assert.Equal(t, int32(1), n2.closeCalled.Load())
}

func TestMultiNotifier_CloseCollectsErrors(t *testing.T) {
	closeErr := errors.New("test: close failed")
	n1 := &mockNotifier{closeErr: closeErr}
	n2 := &mockNotifier{}
	multi := NewMultiNotifier(n1, n2)

	err := multi.Close()
	require.Error(t, err)
	assert.ErrorIs(t, err, closeErr)

	// Both should still have been closed.
	assert.Equal(t, int32(1), n1.closeCalled.Load())
	assert.Equal(t, int32(1), n2.closeCalled.Load())
}

func TestMultiNotifier_CloseIdempotent(t *testing.T) {
	n1 := &mockNotifier{}
	multi := NewMultiNotifier(n1)

	require.NoError(t, multi.Close())
	require.NoError(t, multi.Close()) // second close is a no-op

	// Close should only have been called on the child once.
	assert.Equal(t, int32(1), n1.closeCalled.Load())
}

func TestMultiNotifier_NotifyAfterClose(t *testing.T) {
	n1 := &mockNotifier{}
	multi := NewMultiNotifier(n1)

	require.NoError(t, multi.Close())

	req := &TouchRequest{Operation: "register", RPID: "example.com"}
	err := multi.NotifyTouchRequired(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotifierClosed)

	// The child notifier should not have been called.
	assert.Equal(t, int32(0), n1.notifyCalled.Load())
}

func TestMultiNotifier_Empty(t *testing.T) {
	multi := NewMultiNotifier()

	req := &TouchRequest{Operation: "register", RPID: "example.com"}
	err := multi.NotifyTouchRequired(req)
	require.NoError(t, err)

	err = multi.Close()
	require.NoError(t, err)
}
