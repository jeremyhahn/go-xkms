// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package apimodule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestModuleHost_ForwardsServiceContext is PR #2296's Codex P1: a module
// host built WithServiceContext must hand its binder to the REST host, whose
// refresh store binds every KV call through it. Without it the refresh store
// is built with a nil binder and saving the refresh record on token minting
// answers qrdb/auth: unauthenticated on an auth-enforcing node.
func TestModuleHost_ForwardsServiceContext(t *testing.T) {
	type marker struct{}
	called := false
	bind := func(ctx context.Context) (context.Context, error) {
		called = true
		return context.WithValue(ctx, marker{}, true), nil
	}
	m, _, _ := nodeHostedModule(t, WithServiceContext(bind))

	x := m.resolve()
	require.NotNil(t, x)
	hc, err := m.hostConfig(x)
	require.NoError(t, err)
	require.NotNil(t, hc.ServiceCallContext, "the host's refresh store needs the module's service-context binder")

	bound, err := hc.ServiceCallContext(context.Background())
	require.NoError(t, err)
	require.True(t, called, "HostConfig.ServiceCallContext must be the module's binder")
	require.Equal(t, true, bound.Value(marker{}))
}
