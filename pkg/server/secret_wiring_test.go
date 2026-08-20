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

package server

import (
	"context"
	"testing"

	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildSecretRegistry_NilCredentialService verifies that buildSecretRegistry
// returns a non-nil registry even when the server has no credential service.
// The registry must not match any credential:// URI because no resolver is registered.
func TestBuildSecretRegistry_NilCredentialService(t *testing.T) {
	t.Parallel()

	s := &Server{credentialService: nil}
	reg := s.buildSecretRegistry()

	require.NotNil(t, reg, "registry must never be nil")
	assert.False(t, reg.IsSecretURI("credential://any-ref"),
		"no credential resolver registered — IsSecretURI must return false")
}

// TestBuildSecretRegistry_WithCredentialService verifies that buildSecretRegistry
// registers a credential:// resolver when the server has a credential service,
// and that the resolver correctly routes lookups through that service.
func TestBuildSecretRegistry_WithCredentialService(t *testing.T) {
	t.Parallel()

	// Use the "manual" strategy so New() needs no barrier or platform store.
	svc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: credentialspkg.StrategyManual},
		nil, // platformStore — not required for StrategyManual
		nil, // barrier      — not required for StrategyManual
		nil, // logger       — defaults to slog.Default()
	)
	require.NoError(t, err)

	// Pre-load a credential so RetrieveCredential can return it synchronously.
	const credName = "test-cred"
	const credValue = "hunter2"
	require.NoError(t, svc.StoreCredential(context.Background(), credName, []byte(credValue)))

	s := &Server{credentialService: svc}
	reg := s.buildSecretRegistry()

	require.NotNil(t, reg)
	assert.True(t, reg.IsSecretURI("credential://"+credName),
		"registry must recognise credential:// URIs after registration")

	// Full resolution round-trip.
	sv, err := reg.Resolve(context.Background(), "credential://"+credName)
	require.NoError(t, err)
	// nolint:staticcheck // go-xkms#41: this asserts the round trip the
	// production path still performs. It migrates WITH those sites, not before
	// them — asserting on String is only wrong once production stops using it.
	// Delete this directive when #41 lands.
	assert.Equal(t, credValue, sv.String())
	sv.Clear()
}
