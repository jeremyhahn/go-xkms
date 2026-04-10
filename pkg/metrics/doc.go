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

/*
Package metrics provides an adapter pattern for metrics and telemetry collection in go-xkms.

# Overview

The metrics adapter pattern allows applications to implement custom metrics collection
strategies while maintaining a consistent interface throughout go-xkms. This enables
integration with various telemetry systems without creating hard dependencies on specific
monitoring platforms.

This follows the same design principles as the auth and logger adapters.

# Architecture

The metrics system consists of:

1. MetricsAdapter Interface - Defines the contract for metrics implementations
2. Standard Metric Names - Predefined constants for common operations
3. Context Integration - Support for passing metrics through context
4. Convenience Functions - Helper functions for common metrics operations

# Metric Types

Four core metric types are supported:

1. Counter - Monotonically increasing values (operations count)
2. Gauge - Point-in-time values (active keys, memory usage)
3. Histogram - Distribution of values (key sizes, message lengths)
4. Timer - Duration measurements (operation latencies)

# Standard Metric Names

The package provides standard metric names for consistency across implementations:

Key Management:
  - xkms.key.generate - Key generation operations
  - xkms.key.import - Key import operations
  - xkms.key.export - Key export operations
  - xkms.key.rotate - Key rotation operations
  - xkms.key.delete - Key deletion operations
  - xkms.key.list - Key listing operations
  - xkms.key.get - Key retrieval operations
  - xkms.key.store.count - Total keys stored
  - xkms.key.active.count - Currently active keys

Cryptographic Operations:
  - xkms.crypto.sign - Signing operations
  - xkms.crypto.verify - Verification operations
  - xkms.crypto.encrypt - Encryption operations
  - xkms.crypto.decrypt - Decryption operations
  - xkms.crypto.encrypt.bytes - Bytes encrypted
  - xkms.crypto.decrypt.bytes - Bytes decrypted

Certificate Operations:
  - xkms.cert.create - Certificate creation
  - xkms.cert.sign - Certificate signing
  - xkms.cert.verify - Certificate verification
  - xkms.cert.revoke - Certificate revocation
  - xkms.cert.renew - Certificate renewal
  - xkms.cert.import - Certificate import
  - xkms.cert.export - Certificate export
  - xkms.cert.delete - Certificate deletion
  - xkms.cert.count - Total certificates

Error Metrics:
  - xkms.error.total - Total errors
  - xkms.error.key.not_found - Key not found errors
  - xkms.error.cert.not_found - Certificate not found errors
  - xkms.error.invalid_input - Invalid input errors
  - xkms.error.unauthorized - Unauthorized errors
  - xkms.error.backend_failure - Backend errors

Latency Metrics:
  - xkms.latency.* - Duration of operations

Backend Metrics:
  - xkms.backend.operations - Backend operation count
  - xkms.backend.errors - Backend error count
  - xkms.backend.latency - Backend operation duration
  - xkms.backend.connections - Active connections
  - xkms.backend.health_checks - Health check count

# Implementations

# NoOpMetrics

The package includes a no-op implementation suitable for:

  - Development and testing
  - Scenarios where metrics collection is disabled
  - Applications not yet integrated with telemetry

The no-op implementation does nothing but allows consistent code paths
without conditional logic throughout the application.

# Custom Implementations

Applications can implement the MetricsAdapter interface to provide:

  - Prometheus metrics
  - StatsD/Grafana integration
  - DataDog metrics
  - OpenTelemetry integration
  - Custom in-memory metrics
  - Cloud provider metrics (CloudWatch, Stackdriver, etc.)

# Usage Examples

Basic Usage:

	import (
		"context"
		"github.com/jeremyhahn/go-xkms/pkg/metrics"
	)

	// Create a metrics adapter (or use your custom implementation)
	adapter := metrics.NewNoOpMetrics()

	// Add to context
	ctx := metrics.WithMetrics(context.Background(), adapter)

	// Record a counter
	metrics.RecordCounter(ctx, metrics.MetricKeyGenerate, map[string]string{
		"algorithm": "RSA",
		"bits":      "2048",
	})

Recording Different Metric Types:

	// Counter - increment by 1
	metrics.RecordCounter(ctx, "operations.total", nil)

	// Counter with value - increment by specific amount
	metrics.RecordCounterWithValue(ctx, "keys.imported", 5, nil)

	// Gauge - set point value
	metrics.RecordGauge(ctx, "active.keys", float64(42), nil)

	// Histogram - record value for distribution analysis
	metrics.RecordHistogram(ctx, "key.size.bytes", 2048.0, nil)

	// Timer - record duration
	duration := time.Since(start)
	metrics.RecordTimer(ctx, metrics.MetricLatencySign, duration, nil)

Automatic Timing:

	// WithTimer automatically measures and records operation duration
	err := metrics.WithTimer(ctx, metrics.MetricLatencyKeyGenerate,
		map[string]string{"algorithm": "RSA"},
		func() error {
			// Generate key here
			return nil
		})

Tags and Labels:

	// Use tags for additional metadata
	tags := map[string]string{
		"backend":   "pkcs11",
		"algorithm": "ECDSA",
		"status":    "success",
	}

	metrics.RecordCounter(ctx, "operations.total", tags)

# Custom Implementation Example

	type PrometheusMetrics struct {
		// Your implementation fields
	}

	func (m *PrometheusMetrics) RecordCounter(ctx context.Context,
		name string, tags map[string]string) error {
		// Implement counter recording
		return nil
	}

	func (m *PrometheusMetrics) RecordGauge(ctx context.Context,
		name string, value float64, tags map[string]string) error {
		// Implement gauge recording
		return nil
	}

	// Implement other required methods...

	func (m *PrometheusMetrics) Name() string {
		return "prometheus"
	}

	// Use in application
	metrics := &PrometheusMetrics{}
	ctx := metrics.WithMetrics(context.Background(), metrics)

# Context Integration

The package provides context-based integration:

	// Store metrics in context
	ctx = metrics.WithMetrics(ctx, adapter)

	// Retrieve metrics from context
	retrieved := metrics.GetMetrics(ctx)

	// Convenience functions use context automatically
	metrics.RecordCounter(ctx, "my.metric", nil)

If metrics are not in context, the convenience functions silently do nothing,
allowing safe usage without explicit nil checks.

# Error Handling

Metrics operations should not block critical paths:

	// Errors from metrics recording are separate from operation errors
	if err := metrics.RecordCounter(ctx, "operation.count", nil); err != nil {
		log.Printf("Warning: failed to record metric: %v", err)
		// Operation continues despite metrics error
	}

	// WithTimer returns operation error, metrics errors are internal
	err := metrics.WithTimer(ctx, "operation.duration", nil, func() error {
		// Do work
		return nil
	})
	// err is the operation result, not metrics recording result

# Tags and Labeling

Most metrics support tags for dimensional analysis:

	tags := map[string]string{
		"environment": "production",
		"service":     "xkms",
		"version":     "1.0",
	}

	metrics.RecordCounter(ctx, "requests.total", tags)

# Performance Considerations

The metrics adapter pattern is designed for minimal overhead:

1. No-op implementation has nearly zero cost
2. Recording operations are typically fire-and-forget
3. No synchronous blocking in critical paths
4. Custom implementations should be async-safe
5. Context operations have minimal overhead

# Best Practices

1. Use consistent metric names from the package constants
2. Include relevant tags for filtering and grouping
3. Separate success/failure metrics for clear analysis
4. Record both operation count and latency
5. Use meaningful tag values for analysis
6. Avoid high-cardinality labels (user IDs, request IDs)
7. Implement custom adapters asynchronously
8. Monitor the metrics system itself

# Thread Safety

All MetricsAdapter implementations must be thread-safe and support
concurrent access from multiple goroutines.

# Integration

The metrics adapter integrates with go-xkms's middleware and
backend operations to automatically collect metrics throughout
the system.
*/
package metrics
