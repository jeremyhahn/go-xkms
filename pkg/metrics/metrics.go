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

// Package metrics provides Prometheus instrumentation for go-keychain operations.
// It exposes operational metrics, performance histograms, error counters, and resource
// gauges to enable comprehensive monitoring of keychain server health and performance.
package metrics

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// Namespace is the Prometheus namespace for all keychain metrics
	Namespace = "keychain"

	// Label names
	LabelOperation  = "operation"
	LabelBackend    = "backend"
	LabelStatus     = "status"
	LabelErrorType  = "error_type"
	LabelProtocol   = "protocol"
	LabelMethod     = "method"
	LabelStatusCode = "status_code"

	// Status values
	StatusSuccess = "success"
	StatusError   = "error"

	// Operation names
	OpGenerate    = "generate"
	OpStore       = "store"
	OpGet         = "get"
	OpDelete      = "delete"
	OpList        = "list"
	OpSign        = "sign"
	OpVerify      = "verify"
	OpEncrypt     = "encrypt"
	OpDecrypt     = "decrypt"
	OpExport      = "export"
	OpImport      = "import"
	OpRotate      = "rotate"
	OpBackup      = "backup"
	OpRestore     = "restore"
	OpHealthCheck = "health_check"
)

var (
	// OperationsTotal tracks the total number of keychain operations by type, backend, and status.
	// Use RecordOperation to increment this counter with the appropriate labels.
	OperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "operations_total",
			Help:      "Total number of keychain operations by type, backend, and status",
		},
		[]string{LabelOperation, LabelBackend, LabelStatus},
	)

	// OperationDuration tracks the duration of keychain operations in seconds.
	// Buckets are optimized for typical cryptographic operation latencies.
	OperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "operation_duration_seconds",
			Help:      "Duration of keychain operations in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{LabelOperation, LabelBackend},
	)

	// ErrorsTotal tracks the total number of errors by operation, backend, and error type.
	// Error types should be specific (e.g., "key_not_found", "permission_denied", "timeout").
	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "errors_total",
			Help:      "Total number of errors by operation, backend, and error type",
		},
		[]string{LabelOperation, LabelBackend, LabelErrorType},
	)

	// ActiveConnections tracks the number of active connections by protocol (REST, gRPC, QUIC, MCP).
	ActiveConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "active_connections",
			Help:      "Number of active connections by protocol",
		},
		[]string{LabelProtocol},
	)

	// HTTPRequestsTotal tracks the total number of HTTP requests by method and status code.
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests by method and status code",
		},
		[]string{LabelMethod, LabelStatusCode},
	)

	// HTTPRequestDuration tracks the duration of HTTP requests in seconds.
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "Duration of HTTP requests in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{LabelMethod},
	)

	// GRPCRequestsTotal tracks the total number of gRPC requests by method and status code.
	GRPCRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "grpc",
			Name:      "requests_total",
			Help:      "Total number of gRPC requests by method and status code",
		},
		[]string{LabelMethod, LabelStatusCode},
	)

	// GRPCRequestDuration tracks the duration of gRPC requests in seconds.
	GRPCRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: "grpc",
			Name:      "request_duration_seconds",
			Help:      "Duration of gRPC requests in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{LabelMethod},
	)

	// Goroutines tracks the current number of goroutines in the keychain server.
	// Updated periodically by the resource collector.
	Goroutines = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "goroutines",
			Help:      "Current number of goroutines",
		},
	)

	// MemoryAllocBytes tracks the current bytes of allocated heap objects.
	// Updated periodically by the resource collector.
	MemoryAllocBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "memory_alloc_bytes",
			Help:      "Current bytes of allocated heap objects",
		},
	)

	// MemorySysBytes tracks the total bytes of memory obtained from the OS.
	// Updated periodically by the resource collector.
	MemorySysBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "memory_sys_bytes",
			Help:      "Total bytes of memory obtained from the OS",
		},
	)

	// GCPauseTotalSeconds tracks the cumulative time spent in GC stop-the-world pauses.
	// Updated periodically by the resource collector.
	GCPauseTotalSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "gc_pause_total_seconds",
			Help:      "Cumulative time spent in GC stop-the-world pauses",
		},
	)

	// KeysTotal tracks the total number of keys stored in each backend.
	KeysTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "keys_total",
			Help:      "Total number of keys stored in each backend",
		},
		[]string{LabelBackend},
	)

	// CertsTotal tracks the total number of certificates stored in each backend.
	CertsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "certs_total",
			Help:      "Total number of certificates stored in each backend",
		},
		[]string{LabelBackend},
	)

	// BackendHealthy indicates whether a backend is healthy (1) or unhealthy (0).
	BackendHealthy = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "backend_healthy",
			Help:      "Indicates whether a backend is healthy (1) or unhealthy (0)",
		},
		[]string{LabelBackend},
	)

	// ServerUptime tracks the server uptime in seconds since startup.
	ServerUptime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "server_uptime_seconds",
			Help:      "Server uptime in seconds since startup",
		},
	)

	// enabled tracks whether metrics collection is enabled
	enabled atomic.Bool
)

func init() {
	// Metrics are enabled by default
	enabled.Store(true)
}

// RecordOperation records a keychain operation with its duration and status.
// This is the primary function for tracking operational metrics.
//
// Parameters:
//   - operation: The operation name (use Op* constants)
//   - backend: The backend identifier (e.g., "pkcs8", "tpm2", "aws-kms")
//   - status: The operation status (use Status* constants)
//   - duration: The operation duration in seconds
//
// Example:
//
//	start := time.Now()
//	err := keystore.Generate(ctx, params)
//	duration := time.Since(start).Seconds()
//	if err != nil {
//	    RecordOperation(OpGenerate, "pkcs8", StatusError, duration)
//	} else {
//	    RecordOperation(OpGenerate, "pkcs8", StatusSuccess, duration)
//	}
func RecordOperation(operation, backend, status string, duration float64) {
	if !enabled.Load() {
		return
	}
	OperationsTotal.WithLabelValues(operation, backend, status).Inc()
	OperationDuration.WithLabelValues(operation, backend).Observe(duration)
}

// RecordError records an error event with context about where it occurred.
//
// Parameters:
//   - operation: The operation during which the error occurred (use Op* constants)
//   - backend: The backend where the error occurred
//   - errorType: A specific error type identifier (e.g., "key_not_found", "permission_denied")
//
// Example:
//
//	if errors.Is(err, keychain.ErrKeyNotFound) {
//	    RecordError(OpGet, "pkcs8", "key_not_found")
//	}
func RecordError(operation, backend, errorType string) {
	if !enabled.Load() {
		return
	}
	ErrorsTotal.WithLabelValues(operation, backend, errorType).Inc()
}

// RecordHTTPRequest records an HTTP request with its duration and status.
//
// Parameters:
//   - method: The HTTP method (GET, POST, etc.)
//   - statusCode: The HTTP status code as a string
//   - duration: The request duration in seconds
func RecordHTTPRequest(method, statusCode string, duration float64) {
	if !enabled.Load() {
		return
	}
	HTTPRequestsTotal.WithLabelValues(method, statusCode).Inc()
	HTTPRequestDuration.WithLabelValues(method).Observe(duration)
}

// RecordGRPCRequest records a gRPC request with its duration and status.
//
// Parameters:
//   - method: The full gRPC method name (e.g., "/keychain.v1.KeychainService/Generate")
//   - statusCode: The gRPC status code as a string
//   - duration: The request duration in seconds
func RecordGRPCRequest(method, statusCode string, duration float64) {
	if !enabled.Load() {
		return
	}
	GRPCRequestsTotal.WithLabelValues(method, statusCode).Inc()
	GRPCRequestDuration.WithLabelValues(method).Observe(duration)
}

// IncrementActiveConnections increments the active connection count for a protocol.
func IncrementActiveConnections(protocol string) {
	if !enabled.Load() {
		return
	}
	ActiveConnections.WithLabelValues(protocol).Inc()
}

// DecrementActiveConnections decrements the active connection count for a protocol.
func DecrementActiveConnections(protocol string) {
	if !enabled.Load() {
		return
	}
	ActiveConnections.WithLabelValues(protocol).Dec()
}

// SetKeysTotal sets the total number of keys for a backend.
func SetKeysTotal(backend string, count float64) {
	if !enabled.Load() {
		return
	}
	KeysTotal.WithLabelValues(backend).Set(count)
}

// SetCertsTotal sets the total number of certificates for a backend.
func SetCertsTotal(backend string, count float64) {
	if !enabled.Load() {
		return
	}
	CertsTotal.WithLabelValues(backend).Set(count)
}

// SetBackendHealth sets the health status of a backend.
// healthy=true sets the gauge to 1, healthy=false sets it to 0.
func SetBackendHealth(backend string, healthy bool) {
	if !enabled.Load() {
		return
	}
	value := 0.0
	if healthy {
		value = 1.0
	}
	BackendHealthy.WithLabelValues(backend).Set(value)
}

// Enable enables metrics collection.
func Enable() {
	enabled.Store(true)
}

// Disable disables metrics collection.
// Useful for testing or when metrics are not desired.
func Disable() {
	enabled.Store(false)
}

// IsEnabled returns whether metrics collection is currently enabled.
func IsEnabled() bool {
	return enabled.Load()
}
