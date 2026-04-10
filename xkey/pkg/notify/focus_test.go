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

func TestFocusNotifier_CallsFocusThenDelegates(t *testing.T) {
	var focusCalled atomic.Int32
	inner := &mockNotifier{}

	fn := NewFocusNotifier(inner, func() {
		focusCalled.Add(1)
	})

	req := &TouchRequest{
		Operation: "authenticate",
		RPID:      "example.com",
		RPName:    "Example",
		UserName:  "alice",
	}

	err := fn.NotifyTouchRequired(req)
	require.NoError(t, err)

	assert.Equal(t, int32(1), focusCalled.Load())
	assert.Equal(t, int32(1), inner.notifyCalled.Load())
	assert.Equal(t, "example.com", inner.lastReq.Load().RPID)
}

func TestFocusNotifier_PropagatesInnerError(t *testing.T) {
	innerErr := errors.New("test: inner failed")
	var focusCalled atomic.Int32
	inner := &mockNotifier{notifyErr: innerErr}

	fn := NewFocusNotifier(inner, func() {
		focusCalled.Add(1)
	})

	req := &TouchRequest{Operation: "register", RPID: "example.com"}
	err := fn.NotifyTouchRequired(req)

	require.Error(t, err)
	assert.ErrorIs(t, err, innerErr)
	// Focus should still have been called before the inner error.
	assert.Equal(t, int32(1), focusCalled.Load())
}

func TestFocusNotifier_NotifyAfterClose(t *testing.T) {
	var focusCalled atomic.Int32
	inner := &mockNotifier{}

	fn := NewFocusNotifier(inner, func() {
		focusCalled.Add(1)
	})

	require.NoError(t, fn.Close())

	req := &TouchRequest{Operation: "authenticate", RPID: "example.com"}
	err := fn.NotifyTouchRequired(req)

	assert.ErrorIs(t, err, ErrNotifierClosed)
	assert.Equal(t, int32(0), focusCalled.Load())
	assert.Equal(t, int32(0), inner.notifyCalled.Load())
}

func TestFocusNotifier_CloseIdempotent(t *testing.T) {
	inner := &mockNotifier{}
	fn := NewFocusNotifier(inner, func() {})

	require.NoError(t, fn.Close())
	require.NoError(t, fn.Close())

	// Inner Close should only be called once.
	assert.Equal(t, int32(1), inner.closeCalled.Load())
}

func TestFocusNotifier_ClosePropagatesToInner(t *testing.T) {
	closeErr := errors.New("test: close failed")
	inner := &mockNotifier{closeErr: closeErr}
	fn := NewFocusNotifier(inner, func() {})

	err := fn.Close()
	require.Error(t, err)
	assert.ErrorIs(t, err, closeErr)
	assert.Equal(t, int32(1), inner.closeCalled.Load())
}

func TestFocusNotifier_MultipleCalls(t *testing.T) {
	var focusCalled atomic.Int32
	inner := &mockNotifier{}

	fn := NewFocusNotifier(inner, func() {
		focusCalled.Add(1)
	})

	req := &TouchRequest{Operation: "register", RPID: "a.com"}
	require.NoError(t, fn.NotifyTouchRequired(req))

	req2 := &TouchRequest{Operation: "authenticate", RPID: "b.com"}
	require.NoError(t, fn.NotifyTouchRequired(req2))

	assert.Equal(t, int32(2), focusCalled.Load())
	assert.Equal(t, int32(2), inner.notifyCalled.Load())
	assert.Equal(t, "b.com", inner.lastReq.Load().RPID)
}
