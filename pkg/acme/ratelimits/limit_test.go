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

package ratelimits

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNameString(t *testing.T) {
	tests := []struct {
		name     Name
		expected string
	}{
		{Unknown, "Unknown"},
		{NewRegistrationsPerIPAddress, "NewRegistrationsPerIPAddress"},
		{NewRegistrationsPerIPv6Range, "NewRegistrationsPerIPv6Range"},
		{NewOrdersPerAccount, "NewOrdersPerAccount"},
		{FailedAuthorizationsPerDomainPerAccount, "FailedAuthorizationsPerDomainPerAccount"},
		{CertificatesPerDomain, "CertificatesPerDomain"},
		{CertificatesPerDomainPerAccount, "CertificatesPerDomainPerAccount"},
		{CertificatesPerFQDNSet, "CertificatesPerFQDNSet"},
		{OverallRequestsPerIPAddress, "OverallRequestsPerIPAddress"},
		{Name(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.name.String())
		})
	}
}

func TestNameIsValid(t *testing.T) {
	t.Run("valid names return true", func(t *testing.T) {
		validNames := []Name{
			NewRegistrationsPerIPAddress,
			NewRegistrationsPerIPv6Range,
			NewOrdersPerAccount,
			FailedAuthorizationsPerDomainPerAccount,
			CertificatesPerDomain,
			CertificatesPerDomainPerAccount,
			CertificatesPerFQDNSet,
			OverallRequestsPerIPAddress,
		}

		for _, name := range validNames {
			assert.True(t, name.IsValid(), "expected %s to be valid", name)
		}
	})

	t.Run("invalid names return false", func(t *testing.T) {
		invalidNames := []Name{Unknown, Name(-1), Name(100)}
		for _, name := range invalidNames {
			assert.False(t, name.IsValid(), "expected %d to be invalid", name)
		}
	})
}

func TestNewLimit(t *testing.T) {
	t.Run("creates valid limit", func(t *testing.T) {
		limit, err := NewLimit(NewOrdersPerAccount, 10, 100, time.Hour)

		require.NoError(t, err)
		require.NotNil(t, limit)
		assert.Equal(t, NewOrdersPerAccount, limit.Name)
		assert.Equal(t, int64(10), limit.Burst)
		assert.Equal(t, int64(100), limit.Count)
		assert.Equal(t, time.Hour, limit.Period)
	})

	t.Run("calculates emission interval", func(t *testing.T) {
		limit, err := NewLimit(NewOrdersPerAccount, 10, 100, time.Hour)

		require.NoError(t, err)
		// 1 hour / 100 = 36 seconds per token
		expected := time.Duration(time.Hour.Nanoseconds() / 100)
		assert.Equal(t, expected, limit.EmissionInterval())
	})

	t.Run("calculates burst offset", func(t *testing.T) {
		limit, err := NewLimit(NewOrdersPerAccount, 10, 100, time.Hour)

		require.NoError(t, err)
		// 10 * (1 hour / 100) = 6 minutes
		emissionInterval := time.Hour.Nanoseconds() / 100
		expected := time.Duration(emissionInterval * 10)
		assert.Equal(t, expected, limit.BurstOffset())
	})

	t.Run("rejects zero burst", func(t *testing.T) {
		_, err := NewLimit(NewOrdersPerAccount, 0, 100, time.Hour)
		assert.ErrorIs(t, err, errors.ErrInvalidBurst)
	})

	t.Run("rejects negative burst", func(t *testing.T) {
		_, err := NewLimit(NewOrdersPerAccount, -1, 100, time.Hour)
		assert.ErrorIs(t, err, errors.ErrInvalidBurst)
	})

	t.Run("rejects zero count", func(t *testing.T) {
		_, err := NewLimit(NewOrdersPerAccount, 10, 0, time.Hour)
		assert.ErrorIs(t, err, errors.ErrInvalidCount)
	})

	t.Run("rejects negative count", func(t *testing.T) {
		_, err := NewLimit(NewOrdersPerAccount, 10, -1, time.Hour)
		assert.ErrorIs(t, err, errors.ErrInvalidCount)
	})

	t.Run("rejects zero period", func(t *testing.T) {
		_, err := NewLimit(NewOrdersPerAccount, 10, 100, 0)
		assert.ErrorIs(t, err, errors.ErrInvalidPeriod)
	})

	t.Run("rejects negative period", func(t *testing.T) {
		_, err := NewLimit(NewOrdersPerAccount, 10, 100, -time.Hour)
		assert.ErrorIs(t, err, errors.ErrInvalidPeriod)
	})
}

func TestLimitClone(t *testing.T) {
	t.Run("creates independent copy", func(t *testing.T) {
		original, err := NewLimit(NewOrdersPerAccount, 10, 100, time.Hour)
		require.NoError(t, err)

		clone := original.Clone()

		assert.Equal(t, original.Name, clone.Name)
		assert.Equal(t, original.Burst, clone.Burst)
		assert.Equal(t, original.Count, clone.Count)
		assert.Equal(t, original.Period, clone.Period)
		assert.Equal(t, original.emissionInterval, clone.emissionInterval)
		assert.Equal(t, original.burstOffset, clone.burstOffset)
		assert.Equal(t, original.isOverride, clone.isOverride)

		// Verify independence.
		clone.Burst = 999
		assert.NotEqual(t, original.Burst, clone.Burst)
	})
}

func TestLimitIsOverride(t *testing.T) {
	t.Run("returns isOverride field", func(t *testing.T) {
		limit, err := NewLimit(NewOrdersPerAccount, 10, 100, time.Hour)
		require.NoError(t, err)
		assert.False(t, limit.IsOverride())

		limit.isOverride = true
		assert.True(t, limit.IsOverride())
	})
}

func TestDefaultLimits(t *testing.T) {
	t.Run("returns all expected limits", func(t *testing.T) {
		defaults := DefaultLimits()

		expectedLimits := []Name{
			NewRegistrationsPerIPAddress,
			NewRegistrationsPerIPv6Range,
			NewOrdersPerAccount,
			FailedAuthorizationsPerDomainPerAccount,
			CertificatesPerDomain,
			CertificatesPerFQDNSet,
			OverallRequestsPerIPAddress,
		}

		for _, name := range expectedLimits {
			limit, ok := defaults[name]
			assert.True(t, ok, "expected default limit for %s", name)
			assert.NotNil(t, limit)
			assert.Equal(t, name, limit.Name)
		}
	})

	t.Run("all default limits are valid", func(t *testing.T) {
		defaults := DefaultLimits()

		for name, limit := range defaults {
			err := limit.Validate()
			assert.NoError(t, err, "limit %s failed validation", name)
		}
	})

	t.Run("all default limits have precomputed values", func(t *testing.T) {
		defaults := DefaultLimits()

		for name, limit := range defaults {
			assert.Greater(t, limit.emissionInterval, int64(0),
				"limit %s has zero emission interval", name)
			assert.Greater(t, limit.burstOffset, int64(0),
				"limit %s has zero burst offset", name)
		}
	})
}
