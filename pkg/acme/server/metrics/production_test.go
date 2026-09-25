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

package metrics

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitProduction(t *testing.T) {
	// InitProduction should be idempotent
	InitProduction()
	InitProduction()

	// Verify metrics are registered
	metricFamilies, err := Registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metricFamilies)
}

func TestTenantCertificateMetrics(t *testing.T) {
	InitProduction()

	t.Run("record tenant certificate issued", func(t *testing.T) {
		before := getCounterValueSingle(t, certificatesIssuedByTenant, "tenant-1")
		RecordTenantCertificateIssued("tenant-1")
		after := getCounterValueSingle(t, certificatesIssuedByTenant, "tenant-1")
		assert.Equal(t, before+1, after)
	})

	t.Run("record tenant certificate revoked", func(t *testing.T) {
		before := getCounterValueSingle(t, certificatesRevokedByTenant, "tenant-2")
		RecordTenantCertificateRevoked("tenant-2")
		after := getCounterValueSingle(t, certificatesRevokedByTenant, "tenant-2")
		assert.Equal(t, before+1, after)
	})
}

func TestTenantChallengeMetrics(t *testing.T) {
	InitProduction()

	before := getCounterValue(t, challengesByTenant, "tenant-1", "http-01", "valid")
	RecordTenantChallenge("tenant-1", "http-01", "valid")
	after := getCounterValue(t, challengesByTenant, "tenant-1", "http-01", "valid")
	assert.Equal(t, before+1, after)
}

func TestTenantGaugeMetrics(t *testing.T) {
	InitProduction()

	t.Run("increment and decrement tenant active accounts", func(t *testing.T) {
		before := getGaugeVecValue(t, activeAccountsByTenant, "tenant-1")
		IncTenantActiveAccounts("tenant-1")
		afterInc := getGaugeVecValue(t, activeAccountsByTenant, "tenant-1")
		assert.Equal(t, before+1, afterInc)

		DecTenantActiveAccounts("tenant-1")
		afterDec := getGaugeVecValue(t, activeAccountsByTenant, "tenant-1")
		assert.Equal(t, before, afterDec)
	})

	t.Run("increment and decrement tenant active orders", func(t *testing.T) {
		before := getGaugeVecValue(t, activeOrdersByTenant, "tenant-2")
		IncTenantActiveOrders("tenant-2")
		afterInc := getGaugeVecValue(t, activeOrdersByTenant, "tenant-2")
		assert.Equal(t, before+1, afterInc)

		DecTenantActiveOrders("tenant-2")
		afterDec := getGaugeVecValue(t, activeOrdersByTenant, "tenant-2")
		assert.Equal(t, before, afterDec)
	})
}

func TestCircuitBreakerMetrics(t *testing.T) {
	InitProduction()

	t.Run("set circuit breaker state", func(t *testing.T) {
		SetCircuitBreakerState("dns-provider", CircuitBreakerClosed)
		value := getGaugeVecValue(t, circuitBreakerState, "dns-provider")
		assert.Equal(t, 0.0, value)

		SetCircuitBreakerState("dns-provider", CircuitBreakerHalfOpen)
		value = getGaugeVecValue(t, circuitBreakerState, "dns-provider")
		assert.Equal(t, 1.0, value)

		SetCircuitBreakerState("dns-provider", CircuitBreakerOpen)
		value = getGaugeVecValue(t, circuitBreakerState, "dns-provider")
		assert.Equal(t, 2.0, value)
	})

	t.Run("record circuit breaker failure", func(t *testing.T) {
		before := getCounterValueSingle(t, circuitBreakerFailures, "dns-provider")
		RecordCircuitBreakerFailure("dns-provider")
		after := getCounterValueSingle(t, circuitBreakerFailures, "dns-provider")
		assert.Equal(t, before+1, after)
	})

	t.Run("record circuit breaker success", func(t *testing.T) {
		before := getCounterValueSingle(t, circuitBreakerSuccesses, "dns-provider")
		RecordCircuitBreakerSuccess("dns-provider")
		after := getCounterValueSingle(t, circuitBreakerSuccesses, "dns-provider")
		assert.Equal(t, before+1, after)
	})

	t.Run("record circuit breaker trip", func(t *testing.T) {
		before := getCounterValueSingle(t, circuitBreakerTrips, "dns-provider")
		RecordCircuitBreakerTrip("dns-provider")
		after := getCounterValueSingle(t, circuitBreakerTrips, "dns-provider")
		assert.Equal(t, before+1, after)
	})
}

func TestCacheMetrics(t *testing.T) {
	InitProduction()

	t.Run("record cache hit", func(t *testing.T) {
		before := getCounterValueSingle(t, cacheHits, "directory")
		RecordCacheHit("directory")
		after := getCounterValueSingle(t, cacheHits, "directory")
		assert.Equal(t, before+1, after)
	})

	t.Run("record cache miss", func(t *testing.T) {
		before := getCounterValueSingle(t, cacheMisses, "directory")
		RecordCacheMiss("directory")
		after := getCounterValueSingle(t, cacheMisses, "directory")
		assert.Equal(t, before+1, after)
	})

	t.Run("set cache size", func(t *testing.T) {
		SetCacheSize("directory", 1000)
		value := getGaugeVecValue(t, cacheSize, "directory")
		assert.Equal(t, 1000.0, value)
	})
}

func TestHealthIndicators(t *testing.T) {
	InitProduction()

	t.Run("set degradation active", func(t *testing.T) {
		SetDegradationActive(true)
		value := getGaugeValue(t, degradationActive)
		assert.Equal(t, 1.0, value)

		SetDegradationActive(false)
		value = getGaugeValue(t, degradationActive)
		assert.Equal(t, 0.0, value)
	})
}

func TestGetterFunctions(t *testing.T) {
	InitProduction()

	t.Run("tenant metrics getters", func(t *testing.T) {
		assert.NotNil(t, GetCertificatesIssuedByTenant())
		assert.NotNil(t, GetCertificatesRevokedByTenant())
		assert.NotNil(t, GetChallengesByTenant())
		assert.NotNil(t, GetActiveAccountsByTenant())
		assert.NotNil(t, GetActiveOrdersByTenant())
	})

	t.Run("circuit breaker metrics getters", func(t *testing.T) {
		assert.NotNil(t, GetCircuitBreakerState())
		assert.NotNil(t, GetCircuitBreakerFailures())
		assert.NotNil(t, GetCircuitBreakerSuccesses())
		assert.NotNil(t, GetCircuitBreakerTrips())
	})

	t.Run("cache metrics getters", func(t *testing.T) {
		assert.NotNil(t, GetCacheHits())
		assert.NotNil(t, GetCacheMisses())
		assert.NotNil(t, GetCacheSize())
	})

	t.Run("health indicator getters", func(t *testing.T) {
		assert.NotNil(t, GetDegradationActive())
	})
}

func TestMetricsCollector(t *testing.T) {
	InitProduction()
	Init()

	t.Run("record certificate issued with tenant", func(t *testing.T) {
		mc := NewMetricsCollector("cert-tenant")
		mc.RecordCertificateIssued()

		globalValue := getCounterValueSimple(t, certificatesIssuedTotal)
		assert.GreaterOrEqual(t, globalValue, float64(1))

		tenantValue := getCounterValueSingle(t, certificatesIssuedByTenant, "cert-tenant")
		assert.GreaterOrEqual(t, tenantValue, float64(1))
	})

	t.Run("record certificate issued without tenant", func(t *testing.T) {
		before := getCounterValueSimple(t, certificatesIssuedTotal)
		mc := NewMetricsCollector("")
		mc.RecordCertificateIssued()

		after := getCounterValueSimple(t, certificatesIssuedTotal)
		assert.Equal(t, before+1, after)
	})

	t.Run("record certificate revoked", func(t *testing.T) {
		mc := NewMetricsCollector("revoke-tenant")
		mc.RecordCertificateRevoked()

		globalValue := getCounterValueSimple(t, certificatesRevokedTotal)
		assert.GreaterOrEqual(t, globalValue, float64(1))

		tenantValue := getCounterValueSingle(t, certificatesRevokedByTenant, "revoke-tenant")
		assert.GreaterOrEqual(t, tenantValue, float64(1))
	})

	t.Run("record challenge", func(t *testing.T) {
		mc := NewMetricsCollector("challenge-tenant")
		mc.RecordChallenge("http-01", "valid")

		globalValue := getCounterValue(t, challengesCompletedTotal, "http-01", "valid")
		assert.GreaterOrEqual(t, globalValue, float64(1))

		tenantValue := getCounterValue(t, challengesByTenant, "challenge-tenant", "http-01", "valid")
		assert.GreaterOrEqual(t, tenantValue, float64(1))
	})
}

func TestConcurrentProductionMetrics(t *testing.T) {
	InitProduction()

	var wg sync.WaitGroup
	operations := 100

	t.Run("concurrent tenant metrics", func(t *testing.T) {
		for i := 0; i < operations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				IncTenantActiveOrders("concurrent-tenant")
				DecTenantActiveOrders("concurrent-tenant")
				RecordTenantChallenge("concurrent-tenant", "http-01", "valid")
			}()
		}
		wg.Wait()
	})

	t.Run("concurrent circuit breaker metrics", func(t *testing.T) {
		for i := 0; i < operations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				SetCircuitBreakerState("test-cb", CircuitBreakerClosed)
				RecordCircuitBreakerSuccess("test-cb")
				RecordCircuitBreakerFailure("test-cb")
			}()
		}
		wg.Wait()
	})
}

// Helper functions for testing with multiple labels

func getGaugeVecValue(t *testing.T, gaugeVec *prometheus.GaugeVec, labels ...string) float64 {
	metric := &dto.Metric{}
	g, err := gaugeVec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	err = g.Write(metric)
	require.NoError(t, err)
	return metric.Gauge.GetValue()
}
