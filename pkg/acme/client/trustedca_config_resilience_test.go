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

package client

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTCAACMEConfig_Validate_ResilienceZeroValueSucceeds verifies that a
// TCAACMEConfig with no Resilience section configured is valid: every
// breaker and the degradation cache fall back to their package defaults
// (ACMECircuitBreakerConfig.CircuitBreakerConfig / ACMEDegradationConfig's
// Resolve* methods), so a zero value is never a configuration error.
func TestTCAACMEConfig_Validate_ResilienceZeroValueSucceeds(t *testing.T) {
	cfg := TCAACMEConfig{
		HTTPSAddr:     ":8443",
		ExternalURL:   "https://acme.example.com",
		CAIdentifiers: []string{"acme.example.com"},
	}
	assert.NoError(t, cfg.Validate())
}

// TestTCAACMEConfig_Validate_ResilienceNegativeValueFails verifies that
// TCAACMEConfig.Validate rejects a negative resilience setting by
// delegating to config.ACMEResilienceConfig.Validate, the same check
// pkg/config.ACMEConfig.Validate applies to xkmsd's embedded ACME listener,
// so both compositions reject the same malformed configuration.
func TestTCAACMEConfig_Validate_ResilienceNegativeValueFails(t *testing.T) {
	cfg := TCAACMEConfig{
		HTTPSAddr:     ":8443",
		ExternalURL:   "https://acme.example.com",
		CAIdentifiers: []string{"acme.example.com"},
		Resilience: config.ACMEResilienceConfig{
			Storage: config.ACMECircuitBreakerConfig{TimeoutSeconds: -1},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, config.ErrACMEResilienceNegativeValue)
}
