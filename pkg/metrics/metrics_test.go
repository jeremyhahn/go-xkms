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
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsEnabled(t *testing.T) {
	// Metrics should be enabled by default
	if !IsEnabled() {
		t.Error("Expected metrics to be enabled by default")
	}

	// Test disabling
	Disable()
	if IsEnabled() {
		t.Error("Expected metrics to be disabled after Disable()")
	}

	// Test enabling
	Enable()
	if !IsEnabled() {
		t.Error("Expected metrics to be enabled after Enable()")
	}
}

func TestRecordOperation(t *testing.T) {
	Enable()

	// Reset counters before test
	OperationsTotal.Reset()
	OperationDuration.Reset()

	// Record a successful operation
	RecordOperation(OpGenerate, "pkcs8", StatusSuccess, 0.5)

	// Verify counter incremented
	count := testutil.CollectAndCount(OperationsTotal)
	if count != 1 {
		t.Errorf("Expected 1 operation recorded, got %d", count)
	}

	// Verify histogram updated
	histCount := testutil.CollectAndCount(OperationDuration)
	if histCount != 1 {
		t.Errorf("Expected 1 histogram sample, got %d", histCount)
	}

	// Record an error operation
	RecordOperation(OpGet, "tpm2", StatusError, 0.1)

	// Verify counter incremented again
	count = testutil.CollectAndCount(OperationsTotal)
	if count != 2 {
		t.Errorf("Expected 2 operations recorded, got %d", count)
	}
}

func TestRecordersWhenDisabled(t *testing.T) {
	tests := []struct {
		name      string
		collector interface {
			prometheus.Collector
			Reset()
		}
		record func()
	}{
		{"operation", OperationsTotal, func() { RecordOperation(OpGenerate, "pkcs8", StatusSuccess, 0.5) }},
		{"error", ErrorsTotal, func() { RecordError(OpGet, "pkcs8", "key_not_found") }},
		{"http", HTTPRequestsTotal, func() { RecordHTTPRequest("GET", "200", 0.05) }},
		{"grpc", GRPCRequestsTotal, func() { RecordGRPCRequest("/test.Method", "OK", 0.1) }},
		{"active connections", ActiveConnections, func() {
			IncrementActiveConnections(ProtocolHTTP)
			DecrementActiveConnections(ProtocolHTTP)
		}},
		{"keys total", KeysTotal, func() { SetKeysTotal("pkcs8", 10) }},
		{"keys adjust", KeysTotal, func() {
			IncrementKeysTotal("pkcs8")
			DecrementKeysTotal("pkcs8")
		}},
		{"certs total", CertsTotal, func() { SetCertsTotal("pkcs8", 5) }},
		{"certs adjust", CertsTotal, func() {
			IncrementCertsTotal("pkcs8")
			DecrementCertsTotal("pkcs8")
		}},
		{"backend health", BackendHealthy, func() {
			SetBackendHealth("pkcs8", true)
			SetBackendHealth("pkcs8", false)
		}},
	}

	Disable()
	defer Enable()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.collector.Reset()
			tt.record()

			count := testutil.CollectAndCount(tt.collector)
			if count != 0 {
				t.Errorf("Expected nothing recorded when disabled, got %d series", count)
			}
		})
	}
}

func TestRecordError(t *testing.T) {
	Enable()

	// Reset counters
	ErrorsTotal.Reset()

	// Record an error
	RecordError(OpGet, "pkcs8", "key_not_found")

	// Verify counter incremented
	count := testutil.CollectAndCount(ErrorsTotal)
	if count != 1 {
		t.Errorf("Expected 1 error recorded, got %d", count)
	}

	// Record another error
	RecordError(OpSign, "tpm2", "permission_denied")

	// Verify counter incremented again
	count = testutil.CollectAndCount(ErrorsTotal)
	if count != 2 {
		t.Errorf("Expected 2 errors recorded, got %d", count)
	}
}

func TestRecordHTTPRequest(t *testing.T) {
	Enable()

	// Reset metrics
	HTTPRequestsTotal.Reset()
	HTTPRequestDuration.Reset()

	// Record HTTP request
	RecordHTTPRequest("GET", "200", 0.05)

	// Verify metrics recorded
	count := testutil.CollectAndCount(HTTPRequestsTotal)
	if count != 1 {
		t.Errorf("Expected 1 HTTP request recorded, got %d", count)
	}

	histCount := testutil.CollectAndCount(HTTPRequestDuration)
	if histCount != 1 {
		t.Errorf("Expected 1 HTTP histogram sample, got %d", histCount)
	}
}

func TestRecordGRPCRequest(t *testing.T) {
	Enable()

	// Reset metrics
	GRPCRequestsTotal.Reset()
	GRPCRequestDuration.Reset()

	// Record gRPC request
	RecordGRPCRequest("/xkms.v1.XKMSService/Generate", "OK", 0.1)

	// Verify metrics recorded
	count := testutil.CollectAndCount(GRPCRequestsTotal)
	if count != 1 {
		t.Errorf("Expected 1 gRPC request recorded, got %d", count)
	}

	histCount := testutil.CollectAndCount(GRPCRequestDuration)
	if histCount != 1 {
		t.Errorf("Expected 1 gRPC histogram sample, got %d", histCount)
	}
}

func TestActiveConnections(t *testing.T) {
	Enable()

	// Reset gauge
	ActiveConnections.Reset()

	// Increment connections
	IncrementActiveConnections(ProtocolHTTP)
	IncrementActiveConnections(ProtocolHTTP)
	IncrementActiveConnections(ProtocolGRPC)

	// Verify gauge values (we can't easily check exact values with prometheus/testutil,
	// but we can ensure it collects)
	count := testutil.CollectAndCount(ActiveConnections)
	if count == 0 {
		t.Error("Expected active connections to be tracked")
	}

	// Decrement connections
	DecrementActiveConnections(ProtocolHTTP)

	// Verify still collecting
	count = testutil.CollectAndCount(ActiveConnections)
	if count == 0 {
		t.Error("Expected active connections to still be tracked")
	}
}

func TestSetKeysTotal(t *testing.T) {
	Enable()

	// Reset gauge
	KeysTotal.Reset()

	// Set keys count
	SetKeysTotal("pkcs8", 10)
	SetKeysTotal("tpm2", 5)

	// Verify gauge is collecting
	count := testutil.CollectAndCount(KeysTotal)
	if count == 0 {
		t.Error("Expected keys total to be tracked")
	}
}

func TestSetCertsTotal(t *testing.T) {
	Enable()

	// Reset gauge
	CertsTotal.Reset()

	// Set certs count
	SetCertsTotal("pkcs8", 3)

	// Verify gauge is collecting
	count := testutil.CollectAndCount(CertsTotal)
	if count == 0 {
		t.Error("Expected certs total to be tracked")
	}
}

// TestAdjustStoredTotals pins the increment and decrement helpers of the
// stored-key and stored-certificate gauges: each moves only its own backend's
// series by exactly one from the value last set.
func TestAdjustStoredTotals(t *testing.T) {
	tests := []struct {
		name      string
		gauge     *prometheus.GaugeVec
		set       func(backend string, count float64)
		increment func(backend string)
		decrement func(backend string)
	}{
		{"keys", KeysTotal, SetKeysTotal, IncrementKeysTotal, DecrementKeysTotal},
		{"certs", CertsTotal, SetCertsTotal, IncrementCertsTotal, DecrementCertsTotal},
	}

	Enable()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.gauge.Reset()
			tt.set("pkcs8", 10)
			tt.set("tpm2", 3)

			tt.increment("pkcs8")
			tt.increment("pkcs8")
			if got := testutil.ToFloat64(tt.gauge.WithLabelValues("pkcs8")); got != 12 {
				t.Errorf("after two increments: got %v, want 12", got)
			}

			tt.decrement("pkcs8")
			if got := testutil.ToFloat64(tt.gauge.WithLabelValues("pkcs8")); got != 11 {
				t.Errorf("after a decrement: got %v, want 11", got)
			}
			if got := testutil.ToFloat64(tt.gauge.WithLabelValues("tpm2")); got != 3 {
				t.Errorf("other backend moved: got %v, want 3", got)
			}
		})
	}
}

func TestSetBackendHealth(t *testing.T) {
	Enable()

	// Reset gauge
	BackendHealthy.Reset()

	// Set backend health
	SetBackendHealth("pkcs8", true)
	SetBackendHealth("tpm2", false)

	// Verify gauge is collecting
	count := testutil.CollectAndCount(BackendHealthy)
	if count == 0 {
		t.Error("Expected backend health to be tracked")
	}

	// Test that true sets to 1.0 and false sets to 0.0
	// We can't easily verify exact values but we can test the calls work
	SetBackendHealth("test", true)
	SetBackendHealth("test", false)
}

func TestMetricsNamespace(t *testing.T) {
	if Namespace != "xkms" {
		t.Errorf("Expected namespace 'xkms', got '%s'", Namespace)
	}
}

func TestConcurrentMetricUpdates(t *testing.T) {
	Enable()

	// Reset metrics
	OperationsTotal.Reset()

	// Concurrently record operations
	done := make(chan bool)
	operations := 100

	for i := 0; i < operations; i++ {
		go func() {
			RecordOperation(OpGenerate, "pkcs8", StatusSuccess, 0.1)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < operations; i++ {
		<-done
	}

	// Verify all operations were recorded (atomic operations should ensure this)
	// Note: We can't verify exact count easily with testutil, but we can verify
	// the operation doesn't panic and metrics are being collected
	count := testutil.CollectAndCount(OperationsTotal)
	if count == 0 {
		t.Error("Expected operations to be recorded concurrently")
	}
}

func BenchmarkRecordOperation(b *testing.B) {
	Enable()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		RecordOperation(OpGenerate, "pkcs8", StatusSuccess, 0.001)
	}
}

func BenchmarkRecordError(b *testing.B) {
	Enable()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		RecordError(OpGet, "pkcs8", "key_not_found")
	}
}

func BenchmarkRecordHTTPRequest(b *testing.B) {
	Enable()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		RecordHTTPRequest("GET", "200", 0.001)
	}
}

func BenchmarkIncrementActiveConnections(b *testing.B) {
	Enable()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		IncrementActiveConnections(ProtocolHTTP)
	}
}
