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

package clouddns

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
	"github.com/stretchr/testify/require"
)

// The registered env factory surfaces a NewFromEnv error with a nil Provider
// interface, not one holding a nil pointer.
func TestEnvFactory_ErrorReturnsNilProvider(t *testing.T) {
	t.Setenv(envProject, "")
	t.Setenv(envProject+"_FILE", "")

	provider, err := providers.GetEnvFactory(providers.ProviderCloudDNS)(t.Context())
	require.Error(t, err)
	require.True(t, provider == nil, "the factory must return a nil Provider, got %#v", provider)
}

// The registered config factory surfaces a New error with a nil Provider
// interface, not one holding a nil pointer.
func TestFactory_ErrorReturnsNilProvider(t *testing.T) {
	provider, err := providers.Get(providers.ProviderCloudDNS)(t.Context(), Config{})
	require.Error(t, err)
	require.True(t, provider == nil, "the factory must return a nil Provider, got %#v", provider)
}
