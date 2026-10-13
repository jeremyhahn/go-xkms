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

//go:build !frost

package server

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestInitFrostBackend_NotCompiledIn verifies that a build without -tags
// frost fails closed with *ErrNotCompiledIn (unwrapping to
// ErrBackendNotCompiled) when backends.frost is configured and enabled,
// rather than silently starting with no FROST backend registered.
func TestInitFrostBackend_NotCompiledIn(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Backends: config.BackendsConfig{
			Frost: &config.FrostConfig{
				Enabled:       true,
				SecretBackend: "software",
			},
		},
	})
	s.keyProviders = map[string]types.KeyProvider{}

	err := s.initFrostBackend()
	require.Error(t, err)

	var notCompiledErr *ErrNotCompiledIn
	require.True(t, errors.As(err, &notCompiledErr), "error must unwrap to *ErrNotCompiledIn, got %v", err)
	assert.Equal(t, "FROST", notCompiledErr.Backend)
	assert.Equal(t, "frost", notCompiledErr.Tag)
	assert.True(t, errors.Is(err, ErrBackendNotCompiled))
}

// TestInitFrostBackend_StubDisabledIsNoop verifies that the !frost stub is a
// no-op when backends.frost is nil or not enabled.
func TestInitFrostBackend_StubDisabledIsNoop(t *testing.T) {
	tests := []struct {
		name  string
		frost *config.FrostConfig
	}{
		{name: "nil section", frost: nil},
		{name: "present but disabled", frost: &config.FrostConfig{Enabled: false}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newMinimalServer(t, &config.Config{
				Backends: config.BackendsConfig{Frost: tt.frost},
			})
			s.keyProviders = map[string]types.KeyProvider{}

			err := s.initFrostBackend()
			require.NoError(t, err)
			assert.Empty(t, s.keyProviders)
		})
	}
}
