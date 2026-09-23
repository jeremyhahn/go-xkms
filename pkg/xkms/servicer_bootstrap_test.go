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

package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBootstrapListenerKeys_NotEnabled proves the typed "not enabled" error
// is returned before any key is ever published — the default, safe state.
func TestBootstrapListenerKeys_NotEnabled(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.BootstrapListenerKeys(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBootstrapListenerNotEnabled))
	assert.Nil(t, resp)
}

// TestBootstrapListenerKeys_PublishedRoundTrips proves a published response is
// reported back verbatim, and that the caller cannot mutate the servicer's
// copy through the returned pointer.
func TestBootstrapListenerKeys_PublishedRoundTrips(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	published := &transport.BootstrapListenerKeysResponse{
		NoisePublicKey: "aa",
		P256PublicKey:  "cc",
	}
	svc.SetBootstrapListenerKeys(published)

	resp, err := svc.BootstrapListenerKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, *published, *resp)

	// Mutating the caller's copy after publication must not reach the
	// servicer's state.
	resp.NoisePublicKey = "mutated"
	resp2, err := svc.BootstrapListenerKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "aa", resp2.NoisePublicKey)
}

// TestBootstrapListenerKeys_ClearReturnsToNotEnabled proves withdrawal (e.g.
// server shutdown claiming the listener) puts BootstrapListenerKeys back to
// the not-enabled state.
func TestBootstrapListenerKeys_ClearReturnsToNotEnabled(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	svc.SetBootstrapListenerKeys(&transport.BootstrapListenerKeysResponse{NoisePublicKey: "aa"})
	_, err = svc.BootstrapListenerKeys(context.Background())
	require.NoError(t, err)

	svc.ClearBootstrapListenerKeys()

	_, err = svc.BootstrapListenerKeys(context.Background())
	assert.True(t, errors.Is(err, ErrBootstrapListenerNotEnabled))
}

// TestSetBootstrapListenerKeys_NilIsNoOp proves publishing a nil response
// does not panic and leaves BootstrapListenerKeys reporting not-enabled.
func TestSetBootstrapListenerKeys_NilIsNoOp(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	svc.SetBootstrapListenerKeys(nil)

	_, err = svc.BootstrapListenerKeys(context.Background())
	assert.True(t, errors.Is(err, ErrBootstrapListenerNotEnabled))
}
