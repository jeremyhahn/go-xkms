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

func TestRecordRequest(t *testing.T) {
	Init()

	tests := []struct {
		name     string
		endpoint string
		status   string
	}{
		{
			name:     "new-account success",
			endpoint: "new-account",
			status:   "200",
		},
		{
			name:     "new-order success",
			endpoint: "new-order",
			status:   "201",
		},
		{
			name:     "challenge error",
			endpoint: "challenge",
			status:   "400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get initial value
			before := getCounterValue(t, requestsTotal, tt.endpoint, tt.status)

			// Record request
			RecordRequest(tt.endpoint, tt.status)

			// Verify increment
			after := getCounterValue(t, requestsTotal, tt.endpoint, tt.status)
			assert.Equal(t, before+1, after)
		})
	}
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

	t.Run("set active orders", func(t *testing.T) {
		SetActiveOrders(5)
		value := getGaugeValue(t, activeOrders)
		assert.Equal(t, 5.0, value)
	})

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

	t.Run("set pending challenges", func(t *testing.T) {
		SetPendingChallenges(10)
		value := getGaugeValue(t, pendingChallenges)
		assert.Equal(t, 10.0, value)
	})

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

func TestSetCertificatesExpiringSoon(t *testing.T) {
	Init()

	SetCertificatesExpiringSoon(3)
	value := getGaugeValue(t, certificatesExpiringSoon)
	assert.Equal(t, 3.0, value)
}

func TestObserveRequestDuration(t *testing.T) {
	Init()

	tests := []struct {
		name     string
		endpoint string
		duration float64
	}{
		{
			name:     "fast request",
			endpoint: "new-account",
			duration: 0.05,
		},
		{
			name:     "slow request",
			endpoint: "order-finalize",
			duration: 2.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get count before
			beforeCount := getHistogramCount(t, requestDuration, tt.endpoint)

			// Observe duration
			ObserveRequestDuration(tt.endpoint, tt.duration)

			// Verify observation was recorded
			afterCount := getHistogramCount(t, requestDuration, tt.endpoint)
			assert.Equal(t, beforeCount+1, afterCount)
		})
	}
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

	t.Run("get certificates expiring soon", func(t *testing.T) {
		gauge := GetCertificatesExpiringSoon()
		assert.NotNil(t, gauge)
		assert.Equal(t, certificatesExpiringSoon, gauge)
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

// TestInitIdempotency verifies Init can be called multiple times safely
func TestInitIdempotency(t *testing.T) {
	// Call Init multiple times
	for i := 0; i < 10; i++ {
		Init()
	}

	// Verify metrics are still accessible
	metricFamilies, err := Registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metricFamilies)
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
		for i := 0; i < operations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				IncActiveOrders()
				DecActiveOrders()
				IncPendingChallenges()
				DecPendingChallenges()
				SetCertificatesExpiringSoon(5)
			}()
		}
		wg.Wait()

		// Gauge values may vary due to concurrent inc/dec, but should be valid
		value := getGaugeValue(t, certificatesExpiringSoon)
		assert.GreaterOrEqual(t, value, float64(0))
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

// TestMetricsWithZeroValues tests edge cases with zero and negative values
func TestMetricsWithZeroValues(t *testing.T) {
	Init()

	t.Run("set gauge to zero", func(t *testing.T) {
		SetActiveOrders(0)
		value := getGaugeValue(t, activeOrders)
		assert.Equal(t, 0.0, value)
	})

	t.Run("set gauge to negative", func(t *testing.T) {
		SetPendingChallenges(-5)
		value := getGaugeValue(t, pendingChallenges)
		assert.Equal(t, -5.0, value)
	})

	t.Run("observe zero duration", func(t *testing.T) {
		before := getHistogramCount(t, requestDuration, "zero-test")
		ObserveRequestDuration("zero-test", 0.0)
		after := getHistogramCount(t, requestDuration, "zero-test")
		assert.Equal(t, before+1, after)
	})

	t.Run("observe negative duration", func(t *testing.T) {
		// Negative durations are technically valid for histograms
		before := getHistogramCountSimple(t, certificateIssuanceDuration)
		ObserveCertificateIssuanceDuration(-1.0)
		after := getHistogramCountSimple(t, certificateIssuanceDuration)
		assert.Equal(t, before+1, after)
	})
}

// TestMetricsWithLargeValues tests edge cases with very large values
func TestMetricsWithLargeValues(t *testing.T) {
	Init()

	t.Run("very large gauge value", func(t *testing.T) {
		largeValue := float64(1<<53 - 1) // Max safe integer in float64
		SetActiveOrders(largeValue)
		value := getGaugeValue(t, activeOrders)
		assert.Equal(t, largeValue, value)
	})

	t.Run("very large histogram observation", func(t *testing.T) {
		before := getHistogramCount(t, requestDuration, "large-test")
		ObserveRequestDuration("large-test", 1e10)
		after := getHistogramCount(t, requestDuration, "large-test")
		assert.Equal(t, before+1, after)
	})
}

// TestMetricsLabelVariations tests various label combinations
func TestMetricsLabelVariations(t *testing.T) {
	Init()

	labelSets := []struct {
		endpoint string
		status   string
	}{
		{"new-account", "200"},
		{"new-account", "201"},
		{"new-account", "400"},
		{"new-order", "200"},
		{"new-order", "201"},
		{"challenge", "200"},
		{"challenge", "400"},
		{"finalize", "200"},
		{"finalize", "500"},
	}

	for _, ls := range labelSets {
		t.Run(ls.endpoint+"_"+ls.status, func(t *testing.T) {
			before := getCounterValue(t, requestsTotal, ls.endpoint, ls.status)
			RecordRequest(ls.endpoint, ls.status)
			after := getCounterValue(t, requestsTotal, ls.endpoint, ls.status)
			assert.Equal(t, before+1, after)
		})
	}
}

// TestChallengeMetricsVariations tests various challenge type and status combinations
func TestChallengeMetricsVariations(t *testing.T) {
	Init()

	variations := []struct {
		challengeType string
		status        string
	}{
		{"http-01", "valid"},
		{"http-01", "invalid"},
		{"http-01", "pending"},
		{"dns-01", "valid"},
		{"dns-01", "invalid"},
		{"dns-01", "pending"},
		{"tls-alpn-01", "valid"},
		{"tls-alpn-01", "invalid"},
		{"device-attest-01", "valid"},
		{"device-attest-01", "invalid"},
	}

	for _, v := range variations {
		t.Run(v.challengeType+"_"+v.status, func(t *testing.T) {
			before := getCounterValue(t, challengesCompletedTotal, v.challengeType, v.status)
			RecordChallengeCompleted(v.challengeType, v.status)
			after := getCounterValue(t, challengesCompletedTotal, v.challengeType, v.status)
			assert.Equal(t, before+1, after)
		})
	}
}

// TestErrorMetricsVariations tests various error types
func TestErrorMetricsVariations(t *testing.T) {
	Init()

	errorTypes := []string{
		"client_error",
		"server_error",
		"validation_error",
		"timeout_error",
		"network_error",
		"database_error",
		"storage_error",
		"authentication_error",
		"authorization_error",
	}

	for _, errType := range errorTypes {
		t.Run(errType, func(t *testing.T) {
			before := getCounterValueSingle(t, errorsTotal, errType)
			RecordError(errType)
			after := getCounterValueSingle(t, errorsTotal, errType)
			assert.Equal(t, before+1, after)
		})
	}
}

// TestGaugeOperationsSequence tests sequences of gauge operations
func TestGaugeOperationsSequence(t *testing.T) {
	Init()

	t.Run("increment sequence", func(t *testing.T) {
		// Set a known starting point to avoid interference from other tests
		SetActiveOrders(1000)
		initial := getGaugeValue(t, activeOrders)
		for i := 0; i < 10; i++ {
			IncActiveOrders()
		}
		final := getGaugeValue(t, activeOrders)
		assert.Equal(t, initial+10, final)
	})

	t.Run("decrement sequence", func(t *testing.T) {
		initial := getGaugeValue(t, activeOrders)
		for i := 0; i < 5; i++ {
			DecActiveOrders()
		}
		final := getGaugeValue(t, activeOrders)
		assert.Equal(t, initial-5, final)
	})

	t.Run("mixed operations", func(t *testing.T) {
		SetActiveOrders(100)
		IncActiveOrders()
		IncActiveOrders()
		DecActiveOrders()
		value := getGaugeValue(t, activeOrders)
		assert.Equal(t, 101.0, value)
	})
}

// TestHistogramBucketDistribution tests histogram bucket distribution
func TestHistogramBucketDistribution(t *testing.T) {
	Init()

	// Observe various durations to hit different buckets
	durations := []float64{
		0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0,
	}

	for _, duration := range durations {
		ObserveCertificateIssuanceDuration(duration)
	}

	// Verify all observations were recorded
	count := getHistogramCountSimple(t, certificateIssuanceDuration)
	assert.GreaterOrEqual(t, count, uint64(len(durations)))
}

// TestGettersReturnCorrectTypes tests that all getter functions return the right types
func TestGettersReturnCorrectTypes(t *testing.T) {
	Init()

	t.Run("counter vec getters", func(t *testing.T) {
		assert.NotNil(t, GetRequestsTotal())
		assert.NotNil(t, GetChallengesCompletedTotal())
		assert.NotNil(t, GetErrorsTotal())
	})

	t.Run("simple counter getters", func(t *testing.T) {
		assert.NotNil(t, GetCertificatesIssuedTotal())
		assert.NotNil(t, GetCertificatesRevokedTotal())
	})

	t.Run("gauge getters", func(t *testing.T) {
		assert.NotNil(t, GetActiveOrders())
		assert.NotNil(t, GetPendingChallenges())
		assert.NotNil(t, GetCertificatesExpiringSoon())
	})

	t.Run("histogram getters", func(t *testing.T) {
		assert.NotNil(t, GetRequestDuration())
		assert.NotNil(t, GetCertificateIssuanceDuration())
	})
}

// TestRegistryNotNil verifies the global registry is initialized
func TestRegistryNotNil(t *testing.T) {
	assert.NotNil(t, Registry, "Registry should not be nil")
}
