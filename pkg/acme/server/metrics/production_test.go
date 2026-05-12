// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
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

func TestTenantRequestMetrics(t *testing.T) {
	InitProduction()

	t.Run("record tenant request", func(t *testing.T) {
		before := getCounterValue(t, requestsByTenant, "tenant-1", "new-account", "200")
		RecordTenantRequest("tenant-1", "new-account", "200")
		after := getCounterValue(t, requestsByTenant, "tenant-1", "new-account", "200")
		assert.Equal(t, before+1, after)
	})

	t.Run("record tenant request duration", func(t *testing.T) {
		before := getHistogramCount(t, requestDurationByTenant, "tenant-1", "new-order")
		RecordTenantRequestDuration("tenant-1", "new-order", 0.5)
		after := getHistogramCount(t, requestDurationByTenant, "tenant-1", "new-order")
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

	t.Run("set tenant active accounts", func(t *testing.T) {
		SetTenantActiveAccounts("tenant-1", 100)
		value := getGaugeVecValue(t, activeAccountsByTenant, "tenant-1")
		assert.Equal(t, 100.0, value)
	})

	t.Run("set tenant active orders", func(t *testing.T) {
		SetTenantActiveOrders("tenant-2", 50)
		value := getGaugeVecValue(t, activeOrdersByTenant, "tenant-2")
		assert.Equal(t, 50.0, value)
	})
}

func TestClusterMetrics(t *testing.T) {
	InitProduction()

	t.Run("set cluster healthy", func(t *testing.T) {
		SetClusterHealthy(true)
		value := getGaugeValue(t, clusterHealthy)
		assert.Equal(t, 1.0, value)

		SetClusterHealthy(false)
		value = getGaugeValue(t, clusterHealthy)
		assert.Equal(t, 0.0, value)
	})

	t.Run("set cluster leader", func(t *testing.T) {
		SetClusterLeader(true)
		value := getGaugeValue(t, clusterLeader)
		assert.Equal(t, 1.0, value)

		SetClusterLeader(false)
		value = getGaugeValue(t, clusterLeader)
		assert.Equal(t, 0.0, value)
	})

	t.Run("set cluster followers", func(t *testing.T) {
		SetClusterFollowers(3)
		value := getGaugeValue(t, clusterFollowers)
		assert.Equal(t, 3.0, value)
	})

	t.Run("record cluster election", func(t *testing.T) {
		before := getCounterValueSimple(t, clusterElectionCount)
		RecordClusterElection()
		after := getCounterValueSimple(t, clusterElectionCount)
		assert.Equal(t, before+1, after)
	})

	t.Run("record cluster kv operation", func(t *testing.T) {
		before := getCounterValue(t, clusterKVOperations, "get", "success")
		RecordClusterKVOperation("get", "success")
		after := getCounterValue(t, clusterKVOperations, "get", "success")
		assert.Equal(t, before+1, after)
	})

	t.Run("record cluster kv latency", func(t *testing.T) {
		before := getHistogramCount(t, clusterKVLatency, "put")
		RecordClusterKVLatency("put", 0.001)
		after := getHistogramCount(t, clusterKVLatency, "put")
		assert.Equal(t, before+1, after)
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

func TestRateLimitMetrics(t *testing.T) {
	InitProduction()

	t.Run("record tenant rate limit hit", func(t *testing.T) {
		before := getCounterValue(t, rateLimitHitsByTenant, "tenant-1", "new-order")
		RecordTenantRateLimitHit("tenant-1", "new-order")
		after := getCounterValue(t, rateLimitHitsByTenant, "tenant-1", "new-order")
		assert.Equal(t, before+1, after)
	})

	t.Run("set tenant rate limit tokens", func(t *testing.T) {
		SetTenantRateLimitTokens("tenant-1", 42.5)
		value := getGaugeVecValue(t, rateLimitTokensByTenant, "tenant-1")
		assert.Equal(t, 42.5, value)
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

func TestSLOMetrics(t *testing.T) {
	InitProduction()

	t.Run("record slo latency", func(t *testing.T) {
		before := getHistogramCount(t, sloLatencyBudget, "new-order", "tenant-1")
		RecordSLOLatency("new-order", "tenant-1", 0.05)
		after := getHistogramCount(t, sloLatencyBudget, "new-order", "tenant-1")
		assert.Equal(t, before+1, after)
	})

	t.Run("record slo success", func(t *testing.T) {
		before := getCounterValueSingle(t, sloAvailability, "success")
		RecordSLOSuccess()
		after := getCounterValueSingle(t, sloAvailability, "success")
		assert.Equal(t, before+1, after)
	})

	t.Run("record slo error", func(t *testing.T) {
		before := getCounterValueSingle(t, sloAvailability, "error")
		RecordSLOError()
		after := getCounterValueSingle(t, sloAvailability, "error")
		assert.Equal(t, before+1, after)
	})
}

func TestHealthIndicators(t *testing.T) {
	InitProduction()

	t.Run("set service health", func(t *testing.T) {
		SetServiceHealth("ca", true)
		value := getGaugeVecValue(t, serviceHealth, "ca")
		assert.Equal(t, 1.0, value)

		SetServiceHealth("ca", false)
		value = getGaugeVecValue(t, serviceHealth, "ca")
		assert.Equal(t, 0.0, value)
	})

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
		assert.NotNil(t, GetRequestsByTenant())
		assert.NotNil(t, GetRequestDurationByTenant())
		assert.NotNil(t, GetChallengesByTenant())
		assert.NotNil(t, GetActiveAccountsByTenant())
		assert.NotNil(t, GetActiveOrdersByTenant())
	})

	t.Run("cluster metrics getters", func(t *testing.T) {
		assert.NotNil(t, GetClusterHealthy())
		assert.NotNil(t, GetClusterLeader())
		assert.NotNil(t, GetClusterFollowers())
		assert.NotNil(t, GetClusterElectionCount())
		assert.NotNil(t, GetClusterKVOperations())
		assert.NotNil(t, GetClusterKVLatency())
	})

	t.Run("circuit breaker metrics getters", func(t *testing.T) {
		assert.NotNil(t, GetCircuitBreakerState())
		assert.NotNil(t, GetCircuitBreakerFailures())
		assert.NotNil(t, GetCircuitBreakerSuccesses())
		assert.NotNil(t, GetCircuitBreakerTrips())
	})

	t.Run("rate limit metrics getters", func(t *testing.T) {
		assert.NotNil(t, GetRateLimitHitsByTenant())
		assert.NotNil(t, GetRateLimitTokensByTenant())
	})

	t.Run("cache metrics getters", func(t *testing.T) {
		assert.NotNil(t, GetCacheHits())
		assert.NotNil(t, GetCacheMisses())
		assert.NotNil(t, GetCacheSize())
	})

	t.Run("slo metrics getters", func(t *testing.T) {
		assert.NotNil(t, GetSLOLatencyBudget())
		assert.NotNil(t, GetSLOAvailability())
	})

	t.Run("health indicator getters", func(t *testing.T) {
		assert.NotNil(t, GetServiceHealth())
		assert.NotNil(t, GetDegradationActive())
	})
}

func TestMetricsCollector(t *testing.T) {
	InitProduction()
	Init()

	t.Run("record request with tenant", func(t *testing.T) {
		mc := NewMetricsCollector("test-tenant", "new-account")
		mc.RecordRequest("200", 0.1)

		// Verify both global and tenant metrics were updated
		// Note: Values include previous test runs
		globalValue := getCounterValue(t, requestsTotal, "new-account", "200")
		assert.GreaterOrEqual(t, globalValue, float64(1))

		tenantValue := getCounterValue(t, requestsByTenant, "test-tenant", "new-account", "200")
		assert.GreaterOrEqual(t, tenantValue, float64(1))
	})

	t.Run("record request without tenant", func(t *testing.T) {
		mc := NewMetricsCollector("", "directory")
		mc.RecordRequest("200", 0.05)

		// Only global metrics should be updated
		globalValue := getCounterValue(t, requestsTotal, "directory", "200")
		assert.GreaterOrEqual(t, globalValue, float64(1))
	})

	t.Run("record certificate issued", func(t *testing.T) {
		mc := NewMetricsCollector("cert-tenant", "finalize")
		mc.RecordCertificateIssued()

		// Verify both metrics
		globalValue := getCounterValueSimple(t, certificatesIssuedTotal)
		assert.GreaterOrEqual(t, globalValue, float64(1))

		tenantValue := getCounterValueSingle(t, certificatesIssuedByTenant, "cert-tenant")
		assert.GreaterOrEqual(t, tenantValue, float64(1))
	})

	t.Run("record certificate revoked", func(t *testing.T) {
		mc := NewMetricsCollector("revoke-tenant", "revoke")
		mc.RecordCertificateRevoked()

		globalValue := getCounterValueSimple(t, certificatesRevokedTotal)
		assert.GreaterOrEqual(t, globalValue, float64(1))

		tenantValue := getCounterValueSingle(t, certificatesRevokedByTenant, "revoke-tenant")
		assert.GreaterOrEqual(t, tenantValue, float64(1))
	})

	t.Run("record challenge", func(t *testing.T) {
		mc := NewMetricsCollector("challenge-tenant", "challenge")
		mc.RecordChallenge("http-01", "valid")

		globalValue := getCounterValue(t, challengesCompletedTotal, "http-01", "valid")
		assert.GreaterOrEqual(t, globalValue, float64(1))

		tenantValue := getCounterValue(t, challengesByTenant, "challenge-tenant", "http-01", "valid")
		assert.GreaterOrEqual(t, tenantValue, float64(1))
	})
}

func TestClusterMetricsCollector(t *testing.T) {
	InitProduction()

	dmc := NewClusterMetricsCollector()

	t.Run("update cluster status", func(t *testing.T) {
		dmc.UpdateClusterStatus(true, true, 2)

		healthValue := getGaugeValue(t, clusterHealthy)
		assert.Equal(t, 1.0, healthValue)

		leaderValue := getGaugeValue(t, clusterLeader)
		assert.Equal(t, 1.0, leaderValue)

		followersValue := getGaugeValue(t, clusterFollowers)
		assert.Equal(t, 2.0, followersValue)
	})

	t.Run("record election", func(t *testing.T) {
		before := getCounterValueSimple(t, clusterElectionCount)
		dmc.RecordElection()
		after := getCounterValueSimple(t, clusterElectionCount)
		assert.Equal(t, before+1, after)
	})

	t.Run("record kv operation", func(t *testing.T) {
		before := getCounterValue(t, clusterKVOperations, "scan", "success")
		dmc.RecordKVOperation("scan", "success", 0.01)
		after := getCounterValue(t, clusterKVOperations, "scan", "success")
		assert.Equal(t, before+1, after)
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
				RecordTenantRequest("concurrent-tenant", "test", "200")
				RecordTenantRequestDuration("concurrent-tenant", "test", 0.1)
				RecordTenantChallenge("concurrent-tenant", "http-01", "valid")
			}()
		}
		wg.Wait()
	})

	t.Run("concurrent cluster metrics", func(t *testing.T) {
		for i := 0; i < operations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				SetClusterHealthy(true)
				SetClusterLeader(false)
				SetClusterFollowers(2)
				RecordClusterKVOperation("get", "success")
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
