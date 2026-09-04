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
	"context"
	"errors"
	"sync"
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

// recordingMetrics is a MetricsAdapter that captures the timers recorded
// through it, so a test can assert on the duration WithTimer actually reported
// rather than on its own wall clock. It is mutex-guarded because the race
// detector job exercises this package.
type recordingMetrics struct {
	mu     sync.Mutex
	timers []recordedTimer
}

// recordedTimer is one captured RecordTimer call.
type recordedTimer struct {
	name     string
	duration time.Duration
	tags     map[string]string
}

func (m *recordingMetrics) RecordCounter(context.Context, string, map[string]string) error {
	return nil
}

func (m *recordingMetrics) RecordCounterWithValue(context.Context, string, int64, map[string]string) error {
	return nil
}

func (m *recordingMetrics) RecordGauge(context.Context, string, float64, map[string]string) error {
	return nil
}

func (m *recordingMetrics) RecordHistogram(context.Context, string, float64, map[string]string) error {
	return nil
}

func (m *recordingMetrics) RecordTimer(_ context.Context, name string, duration time.Duration, tags map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.timers = append(m.timers, recordedTimer{name: name, duration: duration, tags: tags})
	return nil
}

func (m *recordingMetrics) Name() string { return "recording" }

// recorded returns a copy of the captured timers.
func (m *recordingMetrics) recorded() []recordedTimer {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]recordedTimer, len(m.timers))
	copy(out, m.timers)
	return out
}

// TestWithTimer_MeasuresDuration asserts that the duration WithTimer reports
// covers the work it wrapped.
//
// It asserts a LOWER BOUND ONLY, and it reads the recorded duration rather
// than the caller's wall clock. The previous version did neither: it installed
// no adapter, so nothing was recorded and the assertion was really about
// time.Sleep; and it required the elapsed time to land within 20ms on BOTH
// sides of 100ms. time.Sleep guarantees a minimum, never a maximum, so the
// upper bound asserted something Go does not provide — it failed in CI at
// 120.167ms, missing by 0.167ms, purely because the runner was busy (#243).
//
// The lower bound is the whole property WithTimer can guarantee, and it holds
// deterministically: WithTimer brackets fn() with time.Now()/time.Since, so
// the recorded duration cannot be shorter than a sleep that ran inside it.
func TestWithTimer_MeasuresDuration(t *testing.T) {
	const (
		workDuration = 100 * time.Millisecond

		// A hang detector, not a timing assertion. It is three orders of
		// magnitude above the work so scheduling noise can never reach it;
		// only a WithTimer that never returned or ran fn twice would.
		runawayCeiling = 30 * time.Second
	)

	adapter := &recordingMetrics{}
	ctx := WithMetrics(context.Background(), adapter)

	err := WithTimer(ctx, "test.timer", map[string]string{"op": "measure"}, func() error {
		time.Sleep(workDuration)
		return nil
	})
	if err != nil {
		t.Fatalf("WithTimer() returned error: %v", err)
	}

	recorded := adapter.recorded()
	if len(recorded) != 1 {
		t.Fatalf("WithTimer() recorded %d timers, want exactly 1", len(recorded))
	}

	timer := recorded[0]
	if timer.name != "test.timer" {
		t.Errorf("WithTimer() recorded name %q, want %q", timer.name, "test.timer")
	}
	if got := timer.tags["op"]; got != "measure" {
		t.Errorf("WithTimer() recorded tag op=%q, want %q", got, "measure")
	}
	if timer.duration < workDuration {
		t.Errorf("WithTimer() recorded %v, want at least the %v the work took",
			timer.duration, workDuration)
	}
	if timer.duration > runawayCeiling {
		t.Errorf("WithTimer() recorded %v, beyond the %v runaway ceiling",
			timer.duration, runawayCeiling)
	}
}

// TestWithTimer_RecordsDurationOnError verifies the timer is recorded even when
// the wrapped work fails: a failed operation's latency is exactly the latency
// an operator needs. Lower bound only, for the same reason as above.
func TestWithTimer_RecordsDurationOnError(t *testing.T) {
	const workDuration = 20 * time.Millisecond

	adapter := &recordingMetrics{}
	ctx := WithMetrics(context.Background(), adapter)
	wantErr := errors.New("operation failed")

	err := WithTimer(ctx, "test.timer.error", nil, func() error {
		time.Sleep(workDuration)
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WithTimer() error = %v, want %v", err, wantErr)
	}

	recorded := adapter.recorded()
	if len(recorded) != 1 {
		t.Fatalf("WithTimer() recorded %d timers, want exactly 1", len(recorded))
	}
	if recorded[0].duration < workDuration {
		t.Errorf("WithTimer() recorded %v, want at least the %v the work took",
			recorded[0].duration, workDuration)
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
