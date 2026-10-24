// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package embedded

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/signingkeytest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestSigningKey_CallsTheService proves every signing-key method reaches the
// service: one with no Verifier answers each with ErrNotConfigured.
func TestSigningKey_CallsTheService(t *testing.T) {
	tr, err := New(&xkms.XKMSService{})
	require.NoError(t, err)
	for name, call := range signingkeytest.Calls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), xkms.ErrNotConfigured) })
	}
}

// TestSigningKey_NotConnected proves every signing-key method refuses once
// the transport is closed.
func TestSigningKey_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	for name, call := range signingkeytest.Calls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
