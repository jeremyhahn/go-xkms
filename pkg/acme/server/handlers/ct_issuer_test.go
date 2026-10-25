//go:build codec_json

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

package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/acme/linter"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
)

// ctLogGroup returns a CT log with a real P-256 key; the log is never
// contacted.
func ctLogGroup(t *testing.T, url string, enabled bool) ct.LogGroup {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return ct.LogGroup{Name: "log", Operator: "op", URL: url, PublicKey: &key.PublicKey, Enabled: enabled}
}

// ctParams returns issuer Params with the given CT policy.
func ctParams(policy ct.PolicyConfig) *Params {
	return &Params{CA: &MockCA{}, Logger: slog.Default(), CT: policy}
}

// ctBreaker returns the registered ct_submitter breaker, or nil. Manager.Get
// would create one, so the registry is listed instead.
func ctBreaker(manager *circuitbreaker.Manager) *circuitbreaker.CircuitBreaker {
	for _, breaker := range manager.List() {
		if breaker.Name() == "ct_submitter" {
			return breaker
		}
	}
	return nil
}

// TestNewIssuerBuildsCTPolicy verifies an enabled log turns CT on and, with
// a breaker manager, guards submission with the ct_submitter breaker.
func TestNewIssuerBuildsCTPolicy(t *testing.T) {
	params := ctParams(ct.PolicyConfig{
		MinSCTs:      1,
		MinOperators: 1,
		LogGroups:    []ct.LogGroup{ctLogGroup(t, "https://ct.example.com", true)},
	})
	params.Breakers = circuitbreaker.NewManager()

	issuer, err := newIssuer(params, audit.NewNoOpLogger(), linter.Identifiers{})
	require.NoError(t, err)
	require.NotNil(t, issuer)
	require.NotNil(t, ctBreaker(params.Breakers), "CT submission is not guarded by a breaker")
}

// TestNewIssuerLeavesCTOffWithoutEnabledLogs verifies a configured but
// disabled log leaves CT off and builds no breaker.
func TestNewIssuerLeavesCTOffWithoutEnabledLogs(t *testing.T) {
	params := ctParams(ct.PolicyConfig{
		MinSCTs:      1,
		MinOperators: 1,
		LogGroups:    []ct.LogGroup{ctLogGroup(t, "https://ct.example.com", false)},
	})
	params.Breakers = circuitbreaker.NewManager()

	issuer, err := newIssuer(params, audit.NewNoOpLogger(), linter.Identifiers{})
	require.NoError(t, err)
	require.NotNil(t, issuer)
	require.Nil(t, ctBreaker(params.Breakers), "CT off built a CT breaker")
}

// TestNewIssuerRefusesInvalidCTPolicy verifies an enabled log the policy
// refuses fails issuer construction rather than turning CT off.
func TestNewIssuerRefusesInvalidCTPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy func(t *testing.T) ct.PolicyConfig
	}{
		{
			name: "log URL is not http(s)",
			policy: func(t *testing.T) ct.PolicyConfig {
				return ct.PolicyConfig{
					MinSCTs:      1,
					MinOperators: 1,
					LogGroups:    []ct.LogGroup{ctLogGroup(t, "ftp://ct.example.com", true)},
				}
			},
		},
		{
			name: "log has no public key",
			policy: func(*testing.T) ct.PolicyConfig {
				return ct.PolicyConfig{
					MinSCTs:      1,
					MinOperators: 1,
					LogGroups:    []ct.LogGroup{{Name: "log", URL: "https://ct.example.com", Enabled: true}},
				}
			},
		},
		{
			name: "minimum SCTs below one",
			policy: func(t *testing.T) ct.PolicyConfig {
				return ct.PolicyConfig{
					MinOperators: 1,
					LogGroups:    []ct.LogGroup{ctLogGroup(t, "https://ct.example.com", true)},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, err := newIssuer(ctParams(tt.policy(t)), audit.NewNoOpLogger(), linter.Identifiers{})
			require.ErrorContains(t, err, "certificate transparency")
			require.Nil(t, issuer)
		})
	}
}
