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

//go:build integration

package metrics

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetricsOperationRecordingIntegration tests recording operations
func TestMetricsOperationRecordingIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Record some operations
	metrics.RecordOperation(metrics.OpGenerate, "software", metrics.StatusSuccess, 0.123)
	metrics.RecordOperation(metrics.OpSign, "tpm2", metrics.StatusSuccess, 0.456)
	metrics.RecordOperation(metrics.OpEncrypt, "pkcs11", metrics.StatusError, 0.789)

	// Scrape metrics
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	// Verify operations_total counter
	var foundOperationsTotal bool
	for _, mf := range metricFamilies {
		if mf.GetName() == "keychain_operations_total" {
			foundOperationsTotal = true
			assert.Greater(t, len(mf.GetMetric()), 0, "Should have recorded operations")
		}
	}
	assert.True(t, foundOperationsTotal, "Should find operations_total metric")

	// Verify operation_duration_seconds histogram
	var foundOperationDuration bool
	for _, mf := range metricFamilies {
		if mf.GetName() == "keychain_operation_duration_seconds" {
			foundOperationDuration = true
			assert.Greater(t, len(mf.GetMetric()), 0, "Should have recorded durations")
		}
	}
	assert.True(t, foundOperationDuration, "Should find operation_duration_seconds metric")
}

// TestMetricsErrorRecordingIntegration tests recording errors
func TestMetricsErrorRecordingIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Record some errors
	metrics.RecordError(metrics.OpGet, "software", "key_not_found")
	metrics.RecordError(metrics.OpDecrypt, "tpm2", "permission_denied")
	metrics.RecordError(metrics.OpSign, "pkcs11", "timeout")

	// Scrape metrics
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	// Verify errors_total counter
	var foundErrorsTotal bool
	for _, mf := range metricFamilies {
		if mf.GetName() == "keychain_errors_total" {
			foundErrorsTotal = true
			assert.Greater(t, len(mf.GetMetric()), 0, "Should have recorded errors")

			// Verify error labels
			for _, m := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, l := range m.GetLabel() {
					labels[l.GetName()] = l.GetValue()
				}

				// Check that error_type label exists
				_, hasErrorType := labels["error_type"]
				assert.True(t, hasErrorType, "Error metric should have error_type label")
			}
		}
	}
	assert.True(t, foundErrorsTotal, "Should find errors_total metric")
}

// TestMetricsHTTPRequestRecordingIntegration tests HTTP request metrics
func TestMetricsHTTPRequestRecordingIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Record some HTTP requests
	metrics.RecordHTTPRequest("GET", "200", 0.100)
	metrics.RecordHTTPRequest("POST", "201", 0.200)
	metrics.RecordHTTPRequest("DELETE", "404", 0.050)

	// Scrape metrics
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	// Verify HTTP metrics
	var foundHTTPRequests bool
	var foundHTTPDuration bool

	for _, mf := range metricFamilies {
		switch mf.GetName() {
		case "keychain_http_requests_total":
			foundHTTPRequests = true
			assert.Greater(t, len(mf.GetMetric()), 0, "Should have recorded HTTP requests")
		case "keychain_http_request_duration_seconds":
			foundHTTPDuration = true
			assert.Greater(t, len(mf.GetMetric()), 0, "Should have recorded HTTP durations")
		}
	}

	assert.True(t, foundHTTPRequests, "Should find http_requests_total metric")
	assert.True(t, foundHTTPDuration, "Should find http_request_duration_seconds metric")
}

// TestMetricsGRPCRequestRecordingIntegration tests gRPC request metrics
func TestMetricsGRPCRequestRecordingIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Record some gRPC requests
	metrics.RecordGRPCRequest("/keychain.v1.KeychainService/Generate", "0", 0.150)
	metrics.RecordGRPCRequest("/keychain.v1.KeychainService/Sign", "0", 0.250)
	metrics.RecordGRPCRequest("/keychain.v1.KeychainService/Get", "5", 0.100)

	// Scrape metrics
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	// Verify gRPC metrics
	var foundGRPCRequests bool
	var foundGRPCDuration bool

	for _, mf := range metricFamilies {
		switch mf.GetName() {
		case "keychain_grpc_requests_total":
			foundGRPCRequests = true
			assert.Greater(t, len(mf.GetMetric()), 0, "Should have recorded gRPC requests")
		case "keychain_grpc_request_duration_seconds":
			foundGRPCDuration = true
			assert.Greater(t, len(mf.GetMetric()), 0, "Should have recorded gRPC durations")
		}
	}

	assert.True(t, foundGRPCRequests, "Should find grpc_requests_total metric")
	assert.True(t, foundGRPCDuration, "Should find grpc_request_duration_seconds metric")
}

// TestMetricsActiveConnectionsIntegration tests connection tracking
func TestMetricsActiveConnectionsIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Track connections
	metrics.IncrementActiveConnections("rest")
	metrics.IncrementActiveConnections("grpc")
	metrics.IncrementActiveConnections("quic")

	// Verify connections increased
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	var foundActiveConnections bool
	for _, mf := range metricFamilies {
		if mf.GetName() == "keychain_active_connections" {
			foundActiveConnections = true
			assert.Greater(t, len(mf.GetMetric()), 0, "Should have active connections")
		}
	}
	assert.True(t, foundActiveConnections, "Should find active_connections metric")

	// Decrement connections
	metrics.DecrementActiveConnections("rest")
	metrics.DecrementActiveConnections("grpc")
	metrics.DecrementActiveConnections("quic")
}

// TestMetricsBackendHealthIntegration tests backend health tracking
func TestMetricsBackendHealthIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Set backend health
	metrics.SetBackendHealth("software", true)
	metrics.SetBackendHealth("tpm2", false)
	metrics.SetBackendHealth("pkcs11", true)

	// Scrape metrics
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	// Verify backend_healthy gauge
	var foundBackendHealthy bool
	for _, mf := range metricFamilies {
		if mf.GetName() == "keychain_backend_healthy" {
			foundBackendHealthy = true
			assert.Equal(t, 3, len(mf.GetMetric()), "Should have 3 backend health metrics")

			// Verify values
			for _, m := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, l := range m.GetLabel() {
					labels[l.GetName()] = l.GetValue()
				}

				backend := labels["backend"]
				value := m.GetGauge().GetValue()

				switch backend {
				case "software":
					assert.Equal(t, 1.0, value, "software backend should be healthy")
				case "tpm2":
					assert.Equal(t, 0.0, value, "tpm2 backend should be unhealthy")
				case "pkcs11":
					assert.Equal(t, 1.0, value, "pkcs11 backend should be healthy")
				}
			}
		}
	}
	assert.True(t, foundBackendHealthy, "Should find backend_healthy metric")
}

// TestMetricsKeyAndCertCountsIntegration tests key and certificate counting
func TestMetricsKeyAndCertCountsIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Set key counts
	metrics.SetKeysTotal("software", 10)
	metrics.SetKeysTotal("tpm2", 5)
	metrics.SetKeysTotal("pkcs11", 15)

	// Set cert counts
	metrics.SetCertsTotal("software", 8)
	metrics.SetCertsTotal("tpm2", 3)
	metrics.SetCertsTotal("pkcs11", 12)

	// Scrape metrics
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	// Verify keys_total gauge
	var foundKeysTotal bool
	var foundCertsTotal bool

	for _, mf := range metricFamilies {
		switch mf.GetName() {
		case "keychain_keys_total":
			foundKeysTotal = true
			assert.Equal(t, 3, len(mf.GetMetric()), "Should have 3 key count metrics")
		case "keychain_certs_total":
			foundCertsTotal = true
			assert.Equal(t, 3, len(mf.GetMetric()), "Should have 3 cert count metrics")
		}
	}

	assert.True(t, foundKeysTotal, "Should find keys_total metric")
	assert.True(t, foundCertsTotal, "Should find certs_total metric")
}

// TestMetricsEnableDisableIntegration tests enabling/disabling metrics
func TestMetricsEnableDisableIntegration(t *testing.T) {
	// Initially enabled
	metrics.Enable()
	assert.True(t, metrics.IsEnabled(), "Metrics should be enabled")

	// Record an operation
	metrics.RecordOperation(metrics.OpGenerate, "test", metrics.StatusSuccess, 0.1)

	// Disable metrics
	metrics.Disable()
	assert.False(t, metrics.IsEnabled(), "Metrics should be disabled")

	// Operations should be ignored when disabled
	metrics.RecordOperation(metrics.OpSign, "test", metrics.StatusSuccess, 0.1)
	metrics.RecordError(metrics.OpGet, "test", "test_error")

	// Re-enable
	metrics.Enable()
	assert.True(t, metrics.IsEnabled(), "Metrics should be enabled again")
}

// TestMetricsPrometheusEndpointIntegration tests serving metrics via HTTP
func TestMetricsPrometheusEndpointIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Record some test data
	metrics.RecordOperation(metrics.OpGenerate, "software", metrics.StatusSuccess, 0.123)
	metrics.RecordError(metrics.OpGet, "tpm2", "key_not_found")
	metrics.SetBackendHealth("software", true)

	// Create HTTP handler
	handler := promhttp.Handler()

	// Create test server
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	// Serve metrics
	handler.ServeHTTP(w, req)

	// Verify response
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Should return 200 OK")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response body")

	bodyStr := string(body)

	// Verify metrics are present in Prometheus format
	assert.Contains(t, bodyStr, "keychain_operations_total", "Should contain operations metric")
	assert.Contains(t, bodyStr, "keychain_errors_total", "Should contain errors metric")
	assert.Contains(t, bodyStr, "keychain_backend_healthy", "Should contain health metric")
}

// TestMetricsConcurrentRecordingIntegration tests concurrent metric recording
func TestMetricsConcurrentRecordingIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Number of concurrent operations
	numOps := 1000
	var wg sync.WaitGroup

	// Launch concurrent operations
	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func(iteration int) {
			defer wg.Done()

			// Record various metrics concurrently
			backend := fmt.Sprintf("backend-%d", iteration%5)
			duration := float64(iteration%100) / 1000.0

			metrics.RecordOperation(metrics.OpSign, backend, metrics.StatusSuccess, duration)
			metrics.RecordError(metrics.OpGet, backend, "test_error")
			metrics.SetBackendHealth(backend, iteration%2 == 0)
			metrics.IncrementActiveConnections("rest")
			metrics.DecrementActiveConnections("rest")
		}(i)
	}

	// Wait for all operations to complete
	wg.Wait()

	// Verify metrics were recorded
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	assert.Greater(t, len(metricFamilies), 0, "Should have recorded metrics")
}

// TestMetricsHistogramBucketsIntegration tests histogram bucket distribution
func TestMetricsHistogramBucketsIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Record operations with various durations across bucket ranges
	durations := []float64{
		0.0005, // < 1ms
		0.003,  // 1-5ms
		0.008,  // 5-10ms
		0.020,  // 10-25ms
		0.040,  // 25-50ms
		0.075,  // 50-100ms
		0.150,  // 100-250ms
		0.350,  // 250-500ms
		0.750,  // 500ms-1s
		1.500,  // 1-2.5s
		3.000,  // 2.5-5s
		7.000,  // 5-10s
	}

	for _, duration := range durations {
		metrics.RecordOperation(metrics.OpSign, "test", metrics.StatusSuccess, duration)
	}

	// Scrape metrics
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	// Find histogram metric
	for _, mf := range metricFamilies {
		if mf.GetName() == "keychain_operation_duration_seconds" {
			for _, m := range mf.GetMetric() {
				histogram := m.GetHistogram()
				if histogram != nil {
					// Verify we have samples in buckets
					assert.Greater(t, histogram.GetSampleCount(), uint64(0),
						"Histogram should have samples")
					assert.Greater(t, len(histogram.GetBucket()), 0,
						"Histogram should have buckets")
				}
			}
		}
	}
}

// TestMetricsLabelConsistencyIntegration tests that labels are consistent across operations
func TestMetricsLabelConsistencyIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Record operations with consistent labels
	backend := "software"
	for i := 0; i < 10; i++ {
		metrics.RecordOperation(metrics.OpGenerate, backend, metrics.StatusSuccess, 0.1)
		metrics.RecordOperation(metrics.OpSign, backend, metrics.StatusSuccess, 0.1)
	}

	// Scrape metrics
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	// Verify label consistency
	for _, mf := range metricFamilies {
		if mf.GetName() == "keychain_operations_total" {
			for _, m := range mf.GetMetric() {
				// Verify all expected labels are present
				labels := make(map[string]string)
				for _, l := range m.GetLabel() {
					labels[l.GetName()] = l.GetValue()
				}

				_, hasOperation := labels["operation"]
				_, hasBackend := labels["backend"]
				_, hasStatus := labels["status"]

				assert.True(t, hasOperation, "Should have operation label")
				assert.True(t, hasBackend, "Should have backend label")
				assert.True(t, hasStatus, "Should have status label")
			}
		}
	}
}

// TestMetricsNamespaceIntegration tests that all metrics use the correct namespace
func TestMetricsNamespaceIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Record various metrics
	metrics.RecordOperation(metrics.OpGenerate, "test", metrics.StatusSuccess, 0.1)
	metrics.RecordHTTPRequest("GET", "200", 0.1)
	metrics.RecordGRPCRequest("/test", "0", 0.1)

	// Scrape metrics
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	// Verify all keychain metrics have the correct namespace
	for _, mf := range metricFamilies {
		name := mf.GetName()
		if strings.HasPrefix(name, "keychain") {
			assert.True(t, strings.HasPrefix(name, "keychain_") ||
				strings.HasPrefix(name, "keychain_http_") ||
				strings.HasPrefix(name, "keychain_grpc_"),
				"Metric %s should use keychain namespace", name)
		}
	}
}

// TestMetricsConstantsIntegration tests that metrics constants are correct
func TestMetricsConstantsIntegration(t *testing.T) {
	// Verify namespace
	assert.Equal(t, "keychain", metrics.Namespace)

	// Verify label names
	assert.Equal(t, "operation", metrics.LabelOperation)
	assert.Equal(t, "backend", metrics.LabelBackend)
	assert.Equal(t, "status", metrics.LabelStatus)
	assert.Equal(t, "error_type", metrics.LabelErrorType)
	assert.Equal(t, "protocol", metrics.LabelProtocol)
	assert.Equal(t, "method", metrics.LabelMethod)
	assert.Equal(t, "status_code", metrics.LabelStatusCode)

	// Verify status values
	assert.Equal(t, "success", metrics.StatusSuccess)
	assert.Equal(t, "error", metrics.StatusError)

	// Verify operation names
	assert.Equal(t, "generate", metrics.OpGenerate)
	assert.Equal(t, "store", metrics.OpStore)
	assert.Equal(t, "get", metrics.OpGet)
	assert.Equal(t, "delete", metrics.OpDelete)
	assert.Equal(t, "list", metrics.OpList)
	assert.Equal(t, "sign", metrics.OpSign)
	assert.Equal(t, "verify", metrics.OpVerify)
	assert.Equal(t, "encrypt", metrics.OpEncrypt)
	assert.Equal(t, "decrypt", metrics.OpDecrypt)
	assert.Equal(t, "export", metrics.OpExport)
	assert.Equal(t, "import", metrics.OpImport)
	assert.Equal(t, "rotate", metrics.OpRotate)
	assert.Equal(t, "backup", metrics.OpBackup)
	assert.Equal(t, "restore", metrics.OpRestore)
	assert.Equal(t, "health_check", metrics.OpHealthCheck)
}

// TestMetricsRealWorldScenarioIntegration simulates a real-world metrics scenario
func TestMetricsRealWorldScenarioIntegration(t *testing.T) {
	// Enable metrics
	metrics.Enable()
	defer metrics.Disable()

	// Simulate a keychain service lifecycle
	start := time.Now()

	// 1. Generate keys
	for i := 0; i < 5; i++ {
		duration := time.Since(start).Seconds()
		metrics.RecordOperation(metrics.OpGenerate, "software", metrics.StatusSuccess, duration)
		metrics.SetKeysTotal("software", float64(i+1))
	}

	// 2. Some operations succeed, some fail
	metrics.RecordOperation(metrics.OpSign, "software", metrics.StatusSuccess, 0.050)
	metrics.RecordOperation(metrics.OpSign, "tpm2", metrics.StatusError, 0.100)
	metrics.RecordError(metrics.OpSign, "tpm2", "timeout")

	// 3. Handle HTTP requests
	metrics.IncrementActiveConnections("rest")
	metrics.RecordHTTPRequest("POST", "201", 0.150)
	metrics.RecordHTTPRequest("GET", "200", 0.030)
	metrics.RecordHTTPRequest("DELETE", "404", 0.020)
	metrics.DecrementActiveConnections("rest")

	// 4. Handle gRPC requests
	metrics.IncrementActiveConnections("grpc")
	metrics.RecordGRPCRequest("/keychain.v1.KeychainService/Generate", "0", 0.200)
	metrics.RecordGRPCRequest("/keychain.v1.KeychainService/Sign", "0", 0.080)
	metrics.DecrementActiveConnections("grpc")

	// 5. Update backend health
	metrics.SetBackendHealth("software", true)
	metrics.SetBackendHealth("tpm2", false)

	// 6. Scrape and verify metrics
	registry := prometheus.DefaultGatherer
	metricFamilies, err := registry.Gather()
	require.NoError(t, err, "Failed to gather metrics")

	// Verify we have a comprehensive set of metrics
	metricNames := make(map[string]bool)
	for _, mf := range metricFamilies {
		metricNames[mf.GetName()] = true
	}

	// Check for expected metrics
	expectedMetrics := []string{
		"keychain_operations_total",
		"keychain_operation_duration_seconds",
		"keychain_errors_total",
		"keychain_active_connections",
		"keychain_http_requests_total",
		"keychain_http_request_duration_seconds",
		"keychain_grpc_requests_total",
		"keychain_grpc_request_duration_seconds",
		"keychain_keys_total",
		"keychain_backend_healthy",
	}

	for _, expected := range expectedMetrics {
		assert.True(t, metricNames[expected],
			"Should have %s metric in real-world scenario", expected)
	}
}
