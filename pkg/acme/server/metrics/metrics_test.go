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

func TestInit(t *testing.T) {
	// Init should be idempotent
	Init()
	Init()

	// Verify registry has metrics
	metricFamilies, err := Registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metricFamilies)
}

// TestInitExcludesRuntimeCollectors guards the fix for the duplicate-metric
// scrape failure this registry caused when merged into xkmsd's own /metrics:
// prometheus.DefaultGatherer already registers Go/process collectors for the
// host process, so Init must never add a second copy of them to Registry.
func TestInitExcludesRuntimeCollectors(t *testing.T) {
	useFreshRegistry(t)

	Init()

	families, err := Registry.Gather()
	require.NoError(t, err)
	assert.True(t, hasMetricFamily(families, "acme_active_orders"),
		"Init must register the ACME metrics into Registry")
	assert.False(t, hasMetricFamily(families, "go_goroutines"),
		"Init must not register the Go runtime collector into Registry")
}

// useFreshRegistry points Registry at an empty registry and re-arms Init for
// the rest of the test, so the test observes only what Init itself adds and
// not what earlier tests (or earlier -count iterations) left in the
// process-wide registry. The process-wide registry, fully initialised, is
// restored when the test ends.
func useFreshRegistry(t *testing.T) {
	t.Helper()
	Init()
	saved := Registry
	Registry = prometheus.NewRegistry()
	once = sync.Once{}
	t.Cleanup(func() {
		Registry = saved
		// saved already holds Init's metrics: Init must stay a no-op.
		once.Do(func() {})
	})
}

func TestRegisterRuntimeCollectors(t *testing.T) {
	Init()

	// Idempotent: calling it twice must not panic (MustRegister would panic
	// on a duplicate registration).
	RegisterRuntimeCollectors()
	RegisterRuntimeCollectors()

	families, err := Registry.Gather()
	require.NoError(t, err)
	assert.True(t, hasMetricFamily(families, "go_goroutines"),
		"RegisterRuntimeCollectors must register the Go runtime collector into Registry")
}

func hasMetricFamily(families []*dto.MetricFamily, name string) bool {
	for _, f := range families {
		if f.GetName() == name {
			return true
		}
	}
	return false
}

func TestRecordCertificateIssued(t *testing.T) {
	Init()

	before := getCounterValueSimple(t, certificatesIssuedTotal)
	RecordCertificateIssued()
	after := getCounterValueSimple(t, certificatesIssuedTotal)

	assert.Equal(t, before+1, after)
}

func TestRecordCertificateRevoked(t *testing.T) {
	Init()

	before := getCounterValueSimple(t, certificatesRevokedTotal)
	RecordCertificateRevoked()
	after := getCounterValueSimple(t, certificatesRevokedTotal)

	assert.Equal(t, before+1, after)
}

func TestRecordAccountCreated(t *testing.T) {
	Init()

	before := getCounterValueSimple(t, accountsCreatedTotal)
	RecordAccountCreated()
	after := getCounterValueSimple(t, accountsCreatedTotal)

	assert.Equal(t, before+1, after)
}

func TestRecordChallengeCompleted(t *testing.T) {
	Init()

	tests := []struct {
		name          string
		challengeType string
		status        string
	}{
		{
			name:          "http-01 valid",
			challengeType: "http-01",
			status:        "valid",
		},
		{
			name:          "dns-01 valid",
			challengeType: "dns-01",
			status:        "valid",
		},
		{
			name:          "http-01 invalid",
			challengeType: "http-01",
			status:        "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := getCounterValue(t, challengesCompletedTotal, tt.challengeType, tt.status)
			RecordChallengeCompleted(tt.challengeType, tt.status)
			after := getCounterValue(t, challengesCompletedTotal, tt.challengeType, tt.status)

			assert.Equal(t, before+1, after)
		})
	}
}

func TestRecordError(t *testing.T) {
	Init()

	tests := []struct {
		name      string
		errorType string
	}{
		{
			name:      "client error",
			errorType: "client_error",
		},
		{
			name:      "server error",
			errorType: "server_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := getCounterValueSingle(t, errorsTotal, tt.errorType)
			RecordError(tt.errorType)
			after := getCounterValueSingle(t, errorsTotal, tt.errorType)

			assert.Equal(t, before+1, after)
		})
	}
}

func TestActiveOrders(t *testing.T) {
	Init()

	t.Run("increment active orders", func(t *testing.T) {
		before := getGaugeValue(t, activeOrders)
		IncActiveOrders()
		after := getGaugeValue(t, activeOrders)
		assert.Equal(t, before+1, after)
	})

	t.Run("decrement active orders", func(t *testing.T) {
		before := getGaugeValue(t, activeOrders)
		DecActiveOrders()
		after := getGaugeValue(t, activeOrders)
		assert.Equal(t, before-1, after)
	})
}

func TestPendingChallenges(t *testing.T) {
	Init()

	t.Run("increment pending challenges", func(t *testing.T) {
		before := getGaugeValue(t, pendingChallenges)
		IncPendingChallenges()
		after := getGaugeValue(t, pendingChallenges)
		assert.Equal(t, before+1, after)
	})

	t.Run("decrement pending challenges", func(t *testing.T) {
		before := getGaugeValue(t, pendingChallenges)
		DecPendingChallenges()
		after := getGaugeValue(t, pendingChallenges)
		assert.Equal(t, before-1, after)
	})
}

func TestObserveCertificateIssuanceDuration(t *testing.T) {
	Init()

	beforeCount := getHistogramCountSimple(t, certificateIssuanceDuration)

	durations := []float64{0.5, 1.2, 3.5}
	for _, duration := range durations {
		ObserveCertificateIssuanceDuration(duration)
	}

	// Verify histogram was updated
	afterCount := getHistogramCountSimple(t, certificateIssuanceDuration)
	assert.Equal(t, beforeCount+uint64(len(durations)), afterCount)
}

func TestGetters(t *testing.T) {
	Init()

	t.Run("get requests total", func(t *testing.T) {
		counter := GetRequestsTotal()
		assert.NotNil(t, counter)
		assert.Equal(t, requestsTotal, counter)
	})

	t.Run("get certificates issued total", func(t *testing.T) {
		counter := GetCertificatesIssuedTotal()
		assert.NotNil(t, counter)
		assert.Equal(t, certificatesIssuedTotal, counter)
	})

	t.Run("get certificates revoked total", func(t *testing.T) {
		counter := GetCertificatesRevokedTotal()
		assert.NotNil(t, counter)
		assert.Equal(t, certificatesRevokedTotal, counter)
	})

	t.Run("get accounts created total", func(t *testing.T) {
		counter := GetAccountsCreatedTotal()
		assert.NotNil(t, counter)
		assert.Equal(t, accountsCreatedTotal, counter)
	})

	t.Run("get challenges completed total", func(t *testing.T) {
		counter := GetChallengesCompletedTotal()
		assert.NotNil(t, counter)
		assert.Equal(t, challengesCompletedTotal, counter)
	})

	t.Run("get errors total", func(t *testing.T) {
		counter := GetErrorsTotal()
		assert.NotNil(t, counter)
		assert.Equal(t, errorsTotal, counter)
	})

	t.Run("get active orders", func(t *testing.T) {
		gauge := GetActiveOrders()
		assert.NotNil(t, gauge)
		assert.Equal(t, activeOrders, gauge)
	})

	t.Run("get pending challenges", func(t *testing.T) {
		gauge := GetPendingChallenges()
		assert.NotNil(t, gauge)
		assert.Equal(t, pendingChallenges, gauge)
	})

	t.Run("get request duration", func(t *testing.T) {
		hist := GetRequestDuration()
		assert.NotNil(t, hist)
		assert.Equal(t, requestDuration, hist)
	})

	t.Run("get certificate issuance duration", func(t *testing.T) {
		hist := GetCertificateIssuanceDuration()
		assert.NotNil(t, hist)
		assert.Equal(t, certificateIssuanceDuration, hist)
	})
}

// TestMetricsConcurrentOperations tests all metric operations under concurrent load
func TestMetricsConcurrentOperations(t *testing.T) {
	Init()

	var wg sync.WaitGroup
	operations := 1000

	// Test counter operations
	t.Run("concurrent counter operations", func(t *testing.T) {
		for i := 0; i < operations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				RecordRequest("test", "200")
				RecordCertificateIssued()
				RecordCertificateRevoked()
				RecordChallengeCompleted("http-01", "valid")
				RecordError("test_error")
			}()
		}
		wg.Wait()

		// Verify all operations completed
		assert.GreaterOrEqual(t, getCounterValue(t, requestsTotal, "test", "200"), float64(operations))
	})

	// Test gauge operations
	t.Run("concurrent gauge operations", func(t *testing.T) {
		before := getGaugeValue(t, activeOrders)
		for i := 0; i < operations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				IncActiveOrders()
				DecActiveOrders()
				IncPendingChallenges()
				DecPendingChallenges()
			}()
		}
		wg.Wait()

		// Every increment is paired with a decrement, so the net effect is zero,
		// though concurrent inc/dec pairs may transiently disagree in order.
		value := getGaugeValue(t, activeOrders)
		assert.Equal(t, before, value)
	})

	// Test histogram operations
	t.Run("concurrent histogram operations", func(t *testing.T) {
		for i := 0; i < operations; i++ {
			wg.Add(1)
			go func(val int) {
				defer wg.Done()
				ObserveRequestDuration("test", float64(val)/1000.0)
				ObserveCertificateIssuanceDuration(float64(val) / 100.0)
			}(i)
		}
		wg.Wait()

		// Verify observations were recorded
		count := getHistogramCount(t, requestDuration, "test")
		assert.GreaterOrEqual(t, count, uint64(operations))
	})
}
