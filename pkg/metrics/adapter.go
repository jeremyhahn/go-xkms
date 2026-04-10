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

// Package metrics provides an adapter interface for metrics and telemetry,
// allowing calling applications to implement custom metrics collection strategies.
//
// This follows the same pattern as auth and logger adapters - providing
// a clean interface that applications can implement while offering sensible
// defaults for common use cases.
package metrics

import (
	"context"
	"time"
)

// Standard metric names used throughout the xkms system
const (
	// Key Management Operations
	MetricKeyGenerate    = "xkms.key.generate"
	MetricKeyImport      = "xkms.key.import"
	MetricKeyExport      = "xkms.key.export"
	MetricKeyRotate      = "xkms.key.rotate"
	MetricKeyDelete      = "xkms.key.delete"
	MetricKeyList        = "xkms.key.list"
	MetricKeyGet         = "xkms.key.get"
	MetricKeyStoreCount  = "xkms.key.store.count"
	MetricKeyActiveCount = "xkms.key.active.count"

	// Cryptographic Operations
	MetricSign            = "xkms.crypto.sign"
	MetricVerify          = "xkms.crypto.verify"
	MetricEncrypt         = "xkms.crypto.encrypt"
	MetricDecrypt         = "xkms.crypto.decrypt"
	MetricEncryptionBytes = "xkms.crypto.encrypt.bytes"
	MetricDecryptionBytes = "xkms.crypto.decrypt.bytes"

	// Certificate Operations
	MetricCertCreate = "xkms.cert.create"
	MetricCertSign   = "xkms.cert.sign"
	MetricCertVerify = "xkms.cert.verify"
	MetricCertRevoke = "xkms.cert.revoke"
	MetricCertRenew  = "xkms.cert.renew"
	MetricCertImport = "xkms.cert.import"
	MetricCertExport = "xkms.cert.export"
	MetricCertDelete = "xkms.cert.delete"
	MetricCertList   = "xkms.cert.list"
	MetricCertGet    = "xkms.cert.get"
	MetricCertCount  = "xkms.cert.count"

	// Error Metrics
	MetricErrorTotal          = "xkms.error.total"
	MetricErrorKeyNotFound    = "xkms.error.key.not_found"
	MetricErrorCertNotFound   = "xkms.error.cert.not_found"
	MetricErrorInvalidInput   = "xkms.error.invalid_input"
	MetricErrorUnauthorized   = "xkms.error.unauthorized"
	MetricErrorBackendFailure = "xkms.error.backend_failure"

	// Latency/Duration Metrics
	MetricLatencyKeyGenerate = "xkms.latency.key.generate"
	MetricLatencyKeyExport   = "xkms.latency.key.export"
	MetricLatencyKeyImport   = "xkms.latency.key.import"
	MetricLatencySign        = "xkms.latency.crypto.sign"
	MetricLatencyVerify      = "xkms.latency.crypto.verify"
	MetricLatencyEncrypt     = "xkms.latency.crypto.encrypt"
	MetricLatencyDecrypt     = "xkms.latency.crypto.decrypt"
	MetricLatencyCertCreate  = "xkms.latency.cert.create"
	MetricLatencyBackend     = "xkms.latency.backend"

	// Backend Metrics
	MetricBackendOperations   = "xkms.backend.operations"
	MetricBackendErrors       = "xkms.backend.errors"
	MetricBackendLatency      = "xkms.latency.backend"
	MetricBackendConnections  = "xkms.backend.connections"
	MetricBackendHealthChecks = "xkms.backend.health_checks"

	// Server/API Metrics
	MetricRequestsTotal   = "xkms.requests.total"
	MetricRequestsActive  = "xkms.requests.active"
	MetricRequestsLatency = "xkms.latency.requests"
	MetricResponsesTotal  = "xkms.responses.total"
	MetricResponseErrors  = "xkms.responses.errors"

	// Cache Metrics
	MetricCacheHits      = "xkms.cache.hits"
	MetricCacheMisses    = "xkms.cache.misses"
	MetricCacheEvictions = "xkms.cache.evictions"
)

// MetricsAdapter provides metrics and telemetry collection capabilities.
//
// Applications can implement this interface to provide custom metrics
// strategies (e.g., Prometheus, StatsD, DataDog, OpenTelemetry integration).
type MetricsAdapter interface {
	// RecordCounter increments a counter metric by 1
	RecordCounter(ctx context.Context, name string, tags map[string]string) error

	// RecordCounterWithValue increments a counter metric by a specific value
	RecordCounterWithValue(ctx context.Context, name string, value int64, tags map[string]string) error

	// RecordGauge sets a gauge metric to a specific value
	RecordGauge(ctx context.Context, name string, value float64, tags map[string]string) error

	// RecordHistogram records a value into a histogram (for distributions)
	RecordHistogram(ctx context.Context, name string, value float64, tags map[string]string) error

	// RecordTimer measures the duration of an operation and records it
	RecordTimer(ctx context.Context, name string, duration time.Duration, tags map[string]string) error

	// Name returns the metrics adapter name for logging/debugging
	Name() string
}

// ContextKey is the type for context keys used by the metrics package
type ContextKey string

const (
	// MetricsContextKey is the context key for storing metrics adapter
	MetricsContextKey ContextKey = "metrics.adapter"
)

// GetMetrics extracts the metrics adapter from a context
func GetMetrics(ctx context.Context) MetricsAdapter {
	if metrics, ok := ctx.Value(MetricsContextKey).(MetricsAdapter); ok {
		return metrics
	}
	return nil
}

// WithMetrics adds a metrics adapter to a context
func WithMetrics(ctx context.Context, metrics MetricsAdapter) context.Context {
	return context.WithValue(ctx, MetricsContextKey, metrics)
}

// RecordCounter is a convenience function to record a counter from context
func RecordCounter(ctx context.Context, name string, tags map[string]string) error {
	metrics := GetMetrics(ctx)
	if metrics == nil {
		return nil
	}
	return metrics.RecordCounter(ctx, name, tags)
}

// RecordCounterWithValue is a convenience function to record a counter with value from context
func RecordCounterWithValue(ctx context.Context, name string, value int64, tags map[string]string) error {
	metrics := GetMetrics(ctx)
	if metrics == nil {
		return nil
	}
	return metrics.RecordCounterWithValue(ctx, name, value, tags)
}

// RecordGauge is a convenience function to record a gauge from context
func RecordGauge(ctx context.Context, name string, value float64, tags map[string]string) error {
	metrics := GetMetrics(ctx)
	if metrics == nil {
		return nil
	}
	return metrics.RecordGauge(ctx, name, value, tags)
}

// RecordHistogram is a convenience function to record a histogram from context
func RecordHistogram(ctx context.Context, name string, value float64, tags map[string]string) error {
	metrics := GetMetrics(ctx)
	if metrics == nil {
		return nil
	}
	return metrics.RecordHistogram(ctx, name, value, tags)
}

// RecordTimer is a convenience function to record a timer from context
func RecordTimer(ctx context.Context, name string, duration time.Duration, tags map[string]string) error {
	metrics := GetMetrics(ctx)
	if metrics == nil {
		return nil
	}
	return metrics.RecordTimer(ctx, name, duration, tags)
}

// WithTimer measures the duration of an operation and records it automatically
func WithTimer(ctx context.Context, name string, tags map[string]string, fn func() error) error {
	start := time.Now()
	err := fn()
	duration := time.Since(start)

	if recordErr := RecordTimer(ctx, name, duration, tags); recordErr != nil && err == nil {
		err = recordErr
	}

	return err
}
