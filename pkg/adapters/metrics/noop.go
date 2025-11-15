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
	"time"
)

// NoOpMetrics is a metrics adapter that performs no operations.
// Use this for development or when metrics collection is disabled.
type NoOpMetrics struct{}

// NewNoOpMetrics creates a new no-op metrics adapter
func NewNoOpMetrics() *NoOpMetrics {
	return &NoOpMetrics{}
}

// RecordCounter does nothing
func (m *NoOpMetrics) RecordCounter(ctx context.Context, name string, tags map[string]string) error {
	return nil
}

// RecordCounterWithValue does nothing
func (m *NoOpMetrics) RecordCounterWithValue(ctx context.Context, name string, value int64, tags map[string]string) error {
	return nil
}

// RecordGauge does nothing
func (m *NoOpMetrics) RecordGauge(ctx context.Context, name string, value float64, tags map[string]string) error {
	return nil
}

// RecordHistogram does nothing
func (m *NoOpMetrics) RecordHistogram(ctx context.Context, name string, value float64, tags map[string]string) error {
	return nil
}

// RecordTimer does nothing
func (m *NoOpMetrics) RecordTimer(ctx context.Context, name string, duration time.Duration, tags map[string]string) error {
	return nil
}

// Name returns the metrics adapter name
func (m *NoOpMetrics) Name() string {
	return "noop"
}
