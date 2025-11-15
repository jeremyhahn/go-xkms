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
	"errors"
	"testing"
	"time"
)

func TestGetMetrics(t *testing.T) {
	tests := []struct {
		name    string
		ctx     context.Context
		want    MetricsAdapter
		wantNil bool
	}{
		{
			name:    "with metrics adapter",
			ctx:     WithMetrics(context.Background(), NewNoOpMetrics()),
			want:    &NoOpMetrics{},
			wantNil: false,
		},
		{
			name:    "without metrics adapter",
			ctx:     context.Background(),
			want:    nil,
			wantNil: true,
		},
		{
			name:    "with wrong type",
			ctx:     context.WithValue(context.Background(), MetricsContextKey, "not a metrics adapter"),
			want:    nil,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetMetrics(tt.ctx)

			if tt.wantNil && got != nil {
				t.Errorf("GetMetrics() = %v, want nil", got)
			}

			if !tt.wantNil && got == nil {
				t.Error("GetMetrics() returned nil, want non-nil")
			}
		})
	}
}

func TestWithMetrics(t *testing.T) {
	metrics := NewNoOpMetrics()
	ctx := context.Background()

	ctxWithMetrics := WithMetrics(ctx, metrics)
	retrieved := GetMetrics(ctxWithMetrics)

	if retrieved == nil {
		t.Fatal("GetMetrics() returned nil after WithMetrics()")
	}

	if retrieved.Name() != "noop" {
		t.Errorf("Name() = %v, want noop", retrieved.Name())
	}
}

func TestNoOpMetrics_RecordCounter(t *testing.T) {
	m := NewNoOpMetrics()
	ctx := context.Background()

	err := m.RecordCounter(ctx, "test.metric", nil)
	if err != nil {
		t.Errorf("RecordCounter() returned error: %v", err)
	}

	err = m.RecordCounter(ctx, "test.metric", map[string]string{"tag": "value"})
	if err != nil {
		t.Errorf("RecordCounter() with tags returned error: %v", err)
	}
}

func TestNoOpMetrics_RecordCounterWithValue(t *testing.T) {
	m := NewNoOpMetrics()
	ctx := context.Background()

	tests := []struct {
		name  string
		value int64
	}{
		{
			name:  "positive value",
			value: 42,
		},
		{
			name:  "zero value",
			value: 0,
		},
		{
			name:  "negative value",
			value: -1,
		},
		{
			name:  "large value",
			value: 1_000_000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.RecordCounterWithValue(ctx, "test.metric", tt.value, nil)
			if err != nil {
				t.Errorf("RecordCounterWithValue() returned error: %v", err)
			}
		})
	}
}

func TestNoOpMetrics_RecordGauge(t *testing.T) {
	m := NewNoOpMetrics()
	ctx := context.Background()

	tests := []struct {
		name  string
		value float64
	}{
		{
			name:  "positive value",
			value: 42.5,
		},
		{
			name:  "zero value",
			value: 0.0,
		},
		{
			name:  "negative value",
			value: -15.3,
		},
		{
			name:  "very small value",
			value: 0.000001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.RecordGauge(ctx, "test.gauge", tt.value, nil)
			if err != nil {
				t.Errorf("RecordGauge() returned error: %v", err)
			}

			err = m.RecordGauge(ctx, "test.gauge", tt.value, map[string]string{"tag": "value"})
			if err != nil {
				t.Errorf("RecordGauge() with tags returned error: %v", err)
			}
		})
	}
}

func TestNoOpMetrics_RecordHistogram(t *testing.T) {
	m := NewNoOpMetrics()
	ctx := context.Background()

	tests := []struct {
		name  string
		value float64
	}{
		{
			name:  "positive value",
			value: 1024.5,
		},
		{
			name:  "zero value",
			value: 0.0,
		},
		{
			name:  "large value",
			value: 1_000_000.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.RecordHistogram(ctx, "test.histogram", tt.value, nil)
			if err != nil {
				t.Errorf("RecordHistogram() returned error: %v", err)
			}

			err = m.RecordHistogram(ctx, "test.histogram", tt.value, map[string]string{"tag": "value"})
			if err != nil {
				t.Errorf("RecordHistogram() with tags returned error: %v", err)
			}
		})
	}
}

func TestNoOpMetrics_RecordTimer(t *testing.T) {
	m := NewNoOpMetrics()
	ctx := context.Background()

	tests := []struct {
		name     string
		duration time.Duration
	}{
		{
			name:     "milliseconds",
			duration: 100 * time.Millisecond,
		},
		{
			name:     "microseconds",
			duration: 500 * time.Microsecond,
		},
		{
			name:     "nanoseconds",
			duration: 100 * time.Nanosecond,
		},
		{
			name:     "seconds",
			duration: 5 * time.Second,
		},
		{
			name:     "zero duration",
			duration: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.RecordTimer(ctx, "test.timer", tt.duration, nil)
			if err != nil {
				t.Errorf("RecordTimer() returned error: %v", err)
			}

			err = m.RecordTimer(ctx, "test.timer", tt.duration, map[string]string{"tag": "value"})
			if err != nil {
				t.Errorf("RecordTimer() with tags returned error: %v", err)
			}
		})
	}
}

func TestNoOpMetrics_Name(t *testing.T) {
	m := NewNoOpMetrics()
	name := m.Name()

	if name != "noop" {
		t.Errorf("Name() = %v, want noop", name)
	}
}

func TestNewNoOpMetrics(t *testing.T) {
	m := NewNoOpMetrics()

	if m == nil {
		t.Fatal("NewNoOpMetrics() returned nil")
	}

	if m.Name() != "noop" {
		t.Errorf("Name() = %v, want noop", m.Name())
	}
}

func TestRecordCounter(t *testing.T) {
	tests := []struct {
		name    string
		ctx     context.Context
		wantErr bool
	}{
		{
			name:    "with metrics adapter",
			ctx:     WithMetrics(context.Background(), NewNoOpMetrics()),
			wantErr: false,
		},
		{
			name:    "without metrics adapter",
			ctx:     context.Background(),
			wantErr: false, // Should silently do nothing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RecordCounter(tt.ctx, "test.counter", nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("RecordCounter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRecordCounterWithValue(t *testing.T) {
	tests := []struct {
		name    string
		ctx     context.Context
		value   int64
		wantErr bool
	}{
		{
			name:    "with metrics adapter and positive value",
			ctx:     WithMetrics(context.Background(), NewNoOpMetrics()),
			value:   10,
			wantErr: false,
		},
		{
			name:    "without metrics adapter",
			ctx:     context.Background(),
			value:   5,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RecordCounterWithValue(tt.ctx, "test.counter", tt.value, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("RecordCounterWithValue() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRecordGauge(t *testing.T) {
	tests := []struct {
		name    string
		ctx     context.Context
		value   float64
		wantErr bool
	}{
		{
			name:    "with metrics adapter",
			ctx:     WithMetrics(context.Background(), NewNoOpMetrics()),
			value:   42.5,
			wantErr: false,
		},
		{
			name:    "without metrics adapter",
			ctx:     context.Background(),
			value:   100.0,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RecordGauge(tt.ctx, "test.gauge", tt.value, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("RecordGauge() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRecordHistogram(t *testing.T) {
	tests := []struct {
		name    string
		ctx     context.Context
		value   float64
		wantErr bool
	}{
		{
			name:    "with metrics adapter",
			ctx:     WithMetrics(context.Background(), NewNoOpMetrics()),
			value:   256.0,
			wantErr: false,
		},
		{
			name:    "without metrics adapter",
			ctx:     context.Background(),
			value:   512.0,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RecordHistogram(tt.ctx, "test.histogram", tt.value, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("RecordHistogram() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRecordTimer(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		duration time.Duration
		wantErr  bool
	}{
		{
			name:     "with metrics adapter",
			ctx:      WithMetrics(context.Background(), NewNoOpMetrics()),
			duration: 100 * time.Millisecond,
			wantErr:  false,
		},
		{
			name:     "without metrics adapter",
			ctx:      context.Background(),
			duration: 500 * time.Millisecond,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RecordTimer(tt.ctx, "test.timer", tt.duration, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("RecordTimer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWithTimer(t *testing.T) {
	tests := []struct {
		name       string
		ctx        context.Context
		fnErr      error
		wantErr    bool
		shouldWait bool
		waitTime   time.Duration
	}{
		{
			name:       "successful operation",
			ctx:        WithMetrics(context.Background(), NewNoOpMetrics()),
			fnErr:      nil,
			wantErr:    false,
			shouldWait: true,
			waitTime:   50 * time.Millisecond,
		},
		{
			name:       "operation with error",
			ctx:        WithMetrics(context.Background(), NewNoOpMetrics()),
			fnErr:      errors.New("operation failed"),
			wantErr:    true,
			shouldWait: true,
			waitTime:   30 * time.Millisecond,
		},
		{
			name:       "without metrics adapter",
			ctx:        context.Background(),
			fnErr:      nil,
			wantErr:    false,
			shouldWait: false,
			waitTime:   0,
		},
		{
			name:       "without metrics adapter with error",
			ctx:        context.Background(),
			fnErr:      errors.New("operation failed"),
			wantErr:    true,
			shouldWait: false,
			waitTime:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WithTimer(tt.ctx, "test.timer", nil, func() error {
				if tt.shouldWait {
					time.Sleep(tt.waitTime)
				}
				return tt.fnErr
			})

			if (err != nil) != tt.wantErr {
				t.Errorf("WithTimer() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != tt.fnErr {
				t.Errorf("WithTimer() error = %v, want %v", err, tt.fnErr)
			}
		})
	}
}

func TestWithTimer_MeasuresDuration(t *testing.T) {
	ctx := context.Background()
	expectedDuration := 100 * time.Millisecond

	start := time.Now()
	err := WithTimer(ctx, "test.timer", nil, func() error {
		time.Sleep(expectedDuration)
		return nil
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("WithTimer() returned error: %v", err)
	}

	// Allow some tolerance for timing variations (20ms buffer)
	tolerance := 20 * time.Millisecond
	if elapsed < expectedDuration-tolerance || elapsed > expectedDuration+tolerance {
		t.Errorf("WithTimer() measured %v, expected approximately %v", elapsed, expectedDuration)
	}
}

// TestStandardMetricNames verifies all standard metric names are defined
func TestStandardMetricNames(t *testing.T) {
	// This is a compilation test - if any constants are missing, the test won't compile
	metrics := map[string]string{
		// Key Management Operations
		"KeyGenerate":    MetricKeyGenerate,
		"KeyImport":      MetricKeyImport,
		"KeyExport":      MetricKeyExport,
		"KeyRotate":      MetricKeyRotate,
		"KeyDelete":      MetricKeyDelete,
		"KeyList":        MetricKeyList,
		"KeyGet":         MetricKeyGet,
		"KeyStoreCount":  MetricKeyStoreCount,
		"KeyActiveCount": MetricKeyActiveCount,

		// Cryptographic Operations
		"Sign":            MetricSign,
		"Verify":          MetricVerify,
		"Encrypt":         MetricEncrypt,
		"Decrypt":         MetricDecrypt,
		"EncryptionBytes": MetricEncryptionBytes,
		"DecryptionBytes": MetricDecryptionBytes,

		// Certificate Operations
		"CertCreate": MetricCertCreate,
		"CertSign":   MetricCertSign,
		"CertVerify": MetricCertVerify,
		"CertRevoke": MetricCertRevoke,
		"CertRenew":  MetricCertRenew,
		"CertImport": MetricCertImport,
		"CertExport": MetricCertExport,
		"CertDelete": MetricCertDelete,
		"CertList":   MetricCertList,
		"CertGet":    MetricCertGet,
		"CertCount":  MetricCertCount,

		// Error Metrics
		"ErrorTotal":          MetricErrorTotal,
		"ErrorKeyNotFound":    MetricErrorKeyNotFound,
		"ErrorCertNotFound":   MetricErrorCertNotFound,
		"ErrorInvalidInput":   MetricErrorInvalidInput,
		"ErrorUnauthorized":   MetricErrorUnauthorized,
		"ErrorBackendFailure": MetricErrorBackendFailure,

		// Latency/Duration Metrics
		"LatencyKeyGenerate": MetricLatencyKeyGenerate,
		"LatencyKeyExport":   MetricLatencyKeyExport,
		"LatencyKeyImport":   MetricLatencyKeyImport,
		"LatencySign":        MetricLatencySign,
		"LatencyVerify":      MetricLatencyVerify,
		"LatencyEncrypt":     MetricLatencyEncrypt,
		"LatencyDecrypt":     MetricLatencyDecrypt,
		"LatencyCertCreate":  MetricLatencyCertCreate,
		"LatencyBackend":     MetricLatencyBackend,

		// Backend Metrics
		"BackendOperations":   MetricBackendOperations,
		"BackendErrors":       MetricBackendErrors,
		"BackendLatency":      MetricBackendLatency,
		"BackendConnections":  MetricBackendConnections,
		"BackendHealthChecks": MetricBackendHealthChecks,

		// Server/API Metrics
		"RequestsTotal":   MetricRequestsTotal,
		"RequestsActive":  MetricRequestsActive,
		"RequestsLatency": MetricRequestsLatency,
		"ResponsesTotal":  MetricResponsesTotal,
		"ResponseErrors":  MetricResponseErrors,

		// Cache Metrics
		"CacheHits":      MetricCacheHits,
		"CacheMisses":    MetricCacheMisses,
		"CacheEvictions": MetricCacheEvictions,
	}

	for name, metric := range metrics {
		if metric == "" {
			t.Errorf("Metric %s is empty", name)
		}
	}
}
