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

// Standard metric names used throughout the keychain system
const (
	// Key Management Operations
	MetricKeyGenerate    = "keychain.key.generate"
	MetricKeyImport      = "keychain.key.import"
	MetricKeyExport      = "keychain.key.export"
	MetricKeyRotate      = "keychain.key.rotate"
	MetricKeyDelete      = "keychain.key.delete"
	MetricKeyList        = "keychain.key.list"
	MetricKeyGet         = "keychain.key.get"
	MetricKeyStoreCount  = "keychain.key.store.count"
	MetricKeyActiveCount = "keychain.key.active.count"

	// Cryptographic Operations
	MetricSign            = "keychain.crypto.sign"
	MetricVerify          = "keychain.crypto.verify"
	MetricEncrypt         = "keychain.crypto.encrypt"
	MetricDecrypt         = "keychain.crypto.decrypt"
	MetricEncryptionBytes = "keychain.crypto.encrypt.bytes"
	MetricDecryptionBytes = "keychain.crypto.decrypt.bytes"

	// Certificate Operations
	MetricCertCreate = "keychain.cert.create"
	MetricCertSign   = "keychain.cert.sign"
	MetricCertVerify = "keychain.cert.verify"
	MetricCertRevoke = "keychain.cert.revoke"
	MetricCertRenew  = "keychain.cert.renew"
	MetricCertImport = "keychain.cert.import"
	MetricCertExport = "keychain.cert.export"
	MetricCertDelete = "keychain.cert.delete"
	MetricCertList   = "keychain.cert.list"
	MetricCertGet    = "keychain.cert.get"
	MetricCertCount  = "keychain.cert.count"

	// Error Metrics
	MetricErrorTotal          = "keychain.error.total"
	MetricErrorKeyNotFound    = "keychain.error.key.not_found"
	MetricErrorCertNotFound   = "keychain.error.cert.not_found"
	MetricErrorInvalidInput   = "keychain.error.invalid_input"
	MetricErrorUnauthorized   = "keychain.error.unauthorized"
	MetricErrorBackendFailure = "keychain.error.backend_failure"

	// Latency/Duration Metrics
	MetricLatencyKeyGenerate = "keychain.latency.key.generate"
	MetricLatencyKeyExport   = "keychain.latency.key.export"
	MetricLatencyKeyImport   = "keychain.latency.key.import"
	MetricLatencySign        = "keychain.latency.crypto.sign"
	MetricLatencyVerify      = "keychain.latency.crypto.verify"
	MetricLatencyEncrypt     = "keychain.latency.crypto.encrypt"
	MetricLatencyDecrypt     = "keychain.latency.crypto.decrypt"
	MetricLatencyCertCreate  = "keychain.latency.cert.create"
	MetricLatencyBackend     = "keychain.latency.backend"

	// Backend Metrics
	MetricBackendOperations   = "keychain.backend.operations"
	MetricBackendErrors       = "keychain.backend.errors"
	MetricBackendLatency      = "keychain.latency.backend"
	MetricBackendConnections  = "keychain.backend.connections"
	MetricBackendHealthChecks = "keychain.backend.health_checks"

	// Server/API Metrics
	MetricRequestsTotal   = "keychain.requests.total"
	MetricRequestsActive  = "keychain.requests.active"
	MetricRequestsLatency = "keychain.latency.requests"
	MetricResponsesTotal  = "keychain.responses.total"
	MetricResponseErrors  = "keychain.responses.errors"

	// Cache Metrics
	MetricCacheHits      = "keychain.cache.hits"
	MetricCacheMisses    = "keychain.cache.misses"
	MetricCacheEvictions = "keychain.cache.evictions"
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
