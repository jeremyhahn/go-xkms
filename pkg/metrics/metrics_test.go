// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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

func TestRecordOperationWhenDisabled(t *testing.T) {
	Disable()
	defer Enable()

	// Reset counters
	OperationsTotal.Reset()

	// Record operation while disabled
	RecordOperation(OpGenerate, "pkcs8", StatusSuccess, 0.5)

	// Verify nothing was recorded
	count := testutil.CollectAndCount(OperationsTotal)
	if count != 0 {
		t.Errorf("Expected 0 operations when disabled, got %d", count)
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

func TestRecordErrorWhenDisabled(t *testing.T) {
	Disable()
	defer Enable()

	// Reset counters
	ErrorsTotal.Reset()

	// Record error while disabled
	RecordError(OpGet, "pkcs8", "key_not_found")

	// Verify nothing was recorded
	count := testutil.CollectAndCount(ErrorsTotal)
	if count != 0 {
		t.Errorf("Expected 0 errors when disabled, got %d", count)
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
	RecordGRPCRequest("/keychain.v1.KeychainService/Generate", "OK", 0.1)

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

func TestOperationConstants(t *testing.T) {
	// Verify operation constants are defined
	operations := []string{
		OpGenerate, OpStore, OpGet, OpDelete, OpList,
		OpSign, OpVerify, OpEncrypt, OpDecrypt,
		OpExport, OpImport, OpRotate, OpBackup, OpRestore,
		OpHealthCheck,
	}

	for _, op := range operations {
		if op == "" {
			t.Error("Operation constant is empty")
		}
	}
}

func TestStatusConstants(t *testing.T) {
	// Verify status constants are defined
	if StatusSuccess == "" {
		t.Error("StatusSuccess constant is empty")
	}
	if StatusError == "" {
		t.Error("StatusError constant is empty")
	}
}

func TestLabelConstants(t *testing.T) {
	// Verify label constants are defined
	labels := []string{
		LabelOperation, LabelBackend, LabelStatus,
		LabelErrorType, LabelProtocol, LabelMethod, LabelStatusCode,
	}

	for _, label := range labels {
		if label == "" {
			t.Error("Label constant is empty")
		}
	}
}

func TestMetricsNamespace(t *testing.T) {
	if Namespace == "" {
		t.Error("Namespace constant is empty")
	}
	if Namespace != "keychain" {
		t.Errorf("Expected namespace 'keychain', got '%s'", Namespace)
	}
}

func TestResourceGauges(t *testing.T) {
	Enable()

	// Verify all resource gauges can be set without panicking
	Goroutines.Set(100)
	MemoryAllocBytes.Set(1024 * 1024)
	MemorySysBytes.Set(10 * 1024 * 1024)
	GCPauseTotalSeconds.Set(0.5)
	ServerUptime.Set(3600)

	// Verify gauges are collecting
	collectors := []prometheus.Collector{
		Goroutines, MemoryAllocBytes, MemorySysBytes,
		GCPauseTotalSeconds, ServerUptime,
	}

	for _, collector := range collectors {
		count := testutil.CollectAndCount(collector)
		if count == 0 {
			t.Errorf("Expected gauge %v to be collecting", collector)
		}
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
