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
	"context"
	"fmt"
	"time"
)

// Example_noOp demonstrates using the no-op metrics adapter
// for when metrics collection is disabled.
func Example_noOp() {
	metrics := NewNoOpMetrics()
	ctx := context.Background()

	// Record various metrics - they will all be no-ops
	metrics.RecordCounter(ctx, "operations.total", nil)
	metrics.RecordGauge(ctx, "keys.active", 42.0, nil)
	metrics.RecordHistogram(ctx, "key.size.bytes", 256.0, nil)
	metrics.RecordTimer(ctx, "operation.latency", 100*time.Millisecond, nil)

	fmt.Printf("Adapter: %s\n", metrics.Name())
	// Output: Adapter: noop
}

// Example_withMetrics demonstrates adding metrics to a context.
func Example_withMetrics() {
	ctx := context.Background()
	metrics := NewNoOpMetrics()

	// Add metrics to context
	ctxWithMetrics := WithMetrics(ctx, metrics)

	// Retrieve metrics from context
	retrieved := GetMetrics(ctxWithMetrics)
	if retrieved != nil {
		fmt.Printf("Retrieved metrics adapter: %s\n", retrieved.Name())
	}
	// Output: Retrieved metrics adapter: noop
}

// Example_recordCounter demonstrates recording a counter metric.
func Example_recordCounter() {
	ctx := WithMetrics(context.Background(), NewNoOpMetrics())

	// Record a simple counter increment
	RecordCounter(ctx, MetricKeyGenerate, map[string]string{
		"algorithm": "RSA",
		"size":      "2048",
	})

	// Also works when no metrics are configured (silently ignored)
	RecordCounter(context.Background(), MetricKeyGenerate, nil)
	// Output:
}

// Example_recordCounterWithValue demonstrates recording a counter with a custom value.
func Example_recordCounterWithValue() {
	ctx := WithMetrics(context.Background(), NewNoOpMetrics())

	// Record multiple keys imported at once
	RecordCounterWithValue(ctx, MetricKeyImport, 5, map[string]string{
		"backend": "pkcs11",
	})

	fmt.Println("Recorded 5 key imports")
	// Output: Recorded 5 key imports
}

// Example_recordGauge demonstrates recording a gauge metric.
func Example_recordGauge() {
	ctx := WithMetrics(context.Background(), NewNoOpMetrics())

	// Record the number of active keys
	RecordGauge(ctx, MetricKeyActiveCount, 128, map[string]string{
		"backend": "software",
	})

	// Record memory usage
	RecordGauge(ctx, "memory.usage.mb", 1024.5, nil)

	fmt.Println("Gauge metrics recorded")
	// Output: Gauge metrics recorded
}

// Example_recordHistogram demonstrates recording a histogram metric.
func Example_recordHistogram() {
	ctx := WithMetrics(context.Background(), NewNoOpMetrics())

	// Record key size distribution
	for _, size := range []float64{256, 512, 1024, 2048} {
		RecordHistogram(ctx, "key.size.bytes", size, nil)
	}

	// Record signature sizes
	RecordHistogram(ctx, "signature.size.bytes", 384, map[string]string{
		"algorithm": "ECDSA",
	})

	fmt.Println("Histogram metrics recorded")
	// Output: Histogram metrics recorded
}

// Example_recordTimer demonstrates recording a timer/duration metric.
func Example_recordTimer() {
	ctx := WithMetrics(context.Background(), NewNoOpMetrics())

	// Record operation latency
	duration := 150 * time.Millisecond
	RecordTimer(ctx, MetricLatencyKeyGenerate, duration, map[string]string{
		"algorithm": "RSA",
	})

	RecordTimer(ctx, MetricLatencySign, 25*time.Millisecond, nil)

	fmt.Println("Timer metrics recorded")
	// Output: Timer metrics recorded
}

// Example_withTimer demonstrates automatically measuring and recording operation duration.
func Example_withTimer() {
	ctx := WithMetrics(context.Background(), NewNoOpMetrics())

	// Simulate an operation
	err := WithTimer(ctx, MetricLatencyEncrypt, map[string]string{
		"algorithm": "AES-256-GCM",
	}, func() error {
		// Simulate encryption work
		time.Sleep(50 * time.Millisecond)
		return nil
	})

	if err == nil {
		fmt.Println("Encryption operation timed and recorded")
	}
	// Output: Encryption operation timed and recorded
}

// Example_customAdapter demonstrates implementing a custom metrics adapter.
// This is a simple example that stores metrics in memory.
func Example_customAdapter() {
	// In a real application, you would implement a custom adapter
	// that integrates with your metrics system (Prometheus, StatsD, etc.)

	ctx := WithMetrics(context.Background(), NewNoOpMetrics())

	// Use the adapter
	retrieved := GetMetrics(ctx)
	if retrieved != nil {
		retrieved.RecordCounter(ctx, "test.counter", nil)
	}

	fmt.Println("Custom metrics adapter example")
	// Output: Custom metrics adapter example
}

// Example_errorHandling demonstrates handling metrics recording errors.
func Example_errorHandling() {
	ctx := WithMetrics(context.Background(), NewNoOpMetrics())

	// When metrics is not configured, RecordCounter returns nil (no error)
	if err := RecordCounter(ctx, MetricKeyGenerate, nil); err != nil {
		fmt.Printf("Error recording counter: %v\n", err)
	}

	// Always check for errors when recording metrics
	if err := RecordTimer(ctx, MetricLatencySign, 100*time.Millisecond, nil); err != nil {
		fmt.Printf("Error recording timer: %v\n", err)
	}

	fmt.Println("Metrics recording completed")
	// Output: Metrics recording completed
}

// Example_standardNames demonstrates the standard metric names available.
func Example_standardNames() {
	// Key management metrics
	fmt.Println(MetricKeyGenerate) // keychain.key.generate
	fmt.Println(MetricKeyImport)   // keychain.key.import
	fmt.Println(MetricKeyExport)   // keychain.key.export
	fmt.Println(MetricSign)        // keychain.crypto.sign
	fmt.Println(MetricErrorTotal)  // keychain.error.total
	fmt.Println(MetricLatencySign) // keychain.latency.crypto.sign

	// Output:
	// keychain.key.generate
	// keychain.key.import
	// keychain.key.export
	// keychain.crypto.sign
	// keychain.error.total
	// keychain.latency.crypto.sign
}

// Example_contextUsage demonstrates using metrics with context.
func Example_contextUsage() {
	// Create a context with metrics
	ctx := WithMetrics(context.Background(), NewNoOpMetrics())

	// Use convenience functions that automatically use the metrics from context
	RecordCounter(ctx, MetricKeyGenerate, map[string]string{
		"algorithm": "RSA",
	})

	RecordCounterWithValue(ctx, "batch.operations", 10, map[string]string{
		"operation": "import",
	})

	// If metrics adapter is not in context, these are silently ignored
	RecordCounter(context.Background(), MetricKeyGenerate, nil)

	fmt.Println("Contextual metrics recorded")
	// Output: Contextual metrics recorded
}
