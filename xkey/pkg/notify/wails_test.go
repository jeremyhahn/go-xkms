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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type emitCall struct {
	eventType string
	data      any
}

func newMockEmitFunc(calls *[]emitCall) func(string, any) {
	return func(eventType string, data any) {
		*calls = append(*calls, emitCall{eventType, data})
	}
}

func TestWailsNotifier_NotifyTouchRequired(t *testing.T) {
	var calls []emitCall
	emitFn := newMockEmitFunc(&calls)

	n := NewWailsNotifier(emitFn)
	err := n.NotifyTouchRequired(&TouchRequest{
		Operation: "register",
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  "alice",
	})

	require.NoError(t, err)
	require.Len(t, calls, 1)
	assert.Equal(t, "fido2:touch_required", calls[0].eventType)

	dataMap, ok := calls[0].data.(map[string]string)
	require.True(t, ok)
	assert.Equal(t, "register", dataMap["operation"])
	assert.Equal(t, "example.com", dataMap["rp_id"])
	assert.Equal(t, "Example Corp", dataMap["rp_name"])
	assert.Equal(t, "alice", dataMap["user_name"])
}

func TestWailsNotifier_NotifyTouchRequired_Closed(t *testing.T) {
	var calls []emitCall
	emitFn := newMockEmitFunc(&calls)

	n := NewWailsNotifier(emitFn)
	require.NoError(t, n.Close())

	err := n.NotifyTouchRequired(&TouchRequest{
		Operation: "authenticate",
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  "bob",
	})

	assert.ErrorIs(t, err, ErrNotifierClosed)
	assert.Empty(t, calls)
}

func TestWailsNotifier_Close(t *testing.T) {
	var calls []emitCall
	emitFn := newMockEmitFunc(&calls)

	n := NewWailsNotifier(emitFn)

	err := n.Close()
	require.NoError(t, err)

	// Second close also returns nil.
	err = n.Close()
	assert.NoError(t, err)
}

func TestWailsNotifier_Close_PreventsNotify(t *testing.T) {
	var calls []emitCall
	emitFn := newMockEmitFunc(&calls)

	n := NewWailsNotifier(emitFn)

	// Notify succeeds before close.
	err := n.NotifyTouchRequired(&TouchRequest{
		Operation: "register",
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  "carol",
	})
	require.NoError(t, err)
	require.Len(t, calls, 1)

	// Close the notifier.
	require.NoError(t, n.Close())

	// Notify after close returns ErrNotifierClosed.
	err = n.NotifyTouchRequired(&TouchRequest{
		Operation: "authenticate",
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  "carol",
	})
	assert.ErrorIs(t, err, ErrNotifierClosed)
	assert.Len(t, calls, 1)
}

func TestWailsNotifier_EmitFuncCalledCorrectly(t *testing.T) {
	var calls []emitCall
	emitFn := newMockEmitFunc(&calls)

	n := NewWailsNotifier(emitFn)

	req := &TouchRequest{
		Operation: "authenticate",
		RPID:      "login.corp.net",
		RPName:    "Corporate Login",
		UserName:  "dave@corp.net",
	}
	err := n.NotifyTouchRequired(req)
	require.NoError(t, err)

	require.Len(t, calls, 1)
	assert.Equal(t, "fido2:touch_required", calls[0].eventType)

	dataMap, ok := calls[0].data.(map[string]string)
	require.True(t, ok)

	// Verify every TouchRequest field is present in the emitted data map.
	assert.Equal(t, req.Operation, dataMap["operation"])
	assert.Equal(t, req.RPID, dataMap["rp_id"])
	assert.Equal(t, req.RPName, dataMap["rp_name"])
	assert.Equal(t, req.UserName, dataMap["user_name"])
	assert.Len(t, dataMap, 4, "data map should contain exactly 4 keys")
}
