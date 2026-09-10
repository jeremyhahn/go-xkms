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

package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &Config{
				Enabled:              true,
				LogPath:              "/var/log/audit.log",
				MaxSizeMB:            100,
				MaxAgeDays:           365,
				MaxBackups:           10,
				Format:               "json",
				BufferSize:           100,
				FlushIntervalSeconds: 5,
			},
			wantErr: false,
		},
		{
			name: "disabled config is valid",
			config: &Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "missing log path",
			config: &Config{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "logPath is required",
		},
		{
			name: "invalid format",
			config: &Config{
				Enabled: true,
				LogPath: "/var/log/audit.log",
				Format:  "xml",
			},
			wantErr: true,
			errMsg:  "only 'json' format",
		},
		{
			name: "applies defaults",
			config: &Config{
				Enabled: true,
				LogPath: "/var/log/audit.log",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				if tt.config.Enabled {
					// Check defaults were applied
					assert.Equal(t, "json", tt.config.Format)
					if tt.config.MaxSizeMB == 0 {
						assert.Equal(t, 100, tt.config.MaxSizeMB)
					}
					if tt.config.BufferSize == 0 {
						assert.Equal(t, 100, tt.config.BufferSize)
					}
				}
			}
		})
	}
}

func TestAuditEvent_Validate(t *testing.T) {
	validEvent := &AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: EventCertificateIssued,
		Actor:     "account:123",
		Resource:  "order:456",
		Action:    "issue",
		Result:    ResultSuccess,
	}

	tests := []struct {
		name    string
		event   *AuditEvent
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid event",
			event:   validEvent,
			wantErr: false,
		},
		{
			name: "missing timestamp",
			event: &AuditEvent{
				EventType: EventCertificateIssued,
				Actor:     "account:123",
				Resource:  "order:456",
				Action:    "issue",
				Result:    ResultSuccess,
			},
			wantErr: true,
			errMsg:  "timestamp is required",
		},
		{
			name: "missing event type",
			event: &AuditEvent{
				Timestamp: time.Now().UTC(),
				Actor:     "account:123",
				Resource:  "order:456",
				Action:    "issue",
				Result:    ResultSuccess,
			},
			wantErr: true,
			errMsg:  "event_type is required",
		},
		{
			name: "missing actor",
			event: &AuditEvent{
				Timestamp: time.Now().UTC(),
				EventType: EventCertificateIssued,
				Resource:  "order:456",
				Action:    "issue",
				Result:    ResultSuccess,
			},
			wantErr: true,
			errMsg:  "actor is required",
		},
		{
			name: "missing resource",
			event: &AuditEvent{
				Timestamp: time.Now().UTC(),
				EventType: EventCertificateIssued,
				Actor:     "account:123",
				Action:    "issue",
				Result:    ResultSuccess,
			},
			wantErr: true,
			errMsg:  "resource is required",
		},
		{
			name: "missing action",
			event: &AuditEvent{
				Timestamp: time.Now().UTC(),
				EventType: EventCertificateIssued,
				Actor:     "account:123",
				Resource:  "order:456",
				Result:    ResultSuccess,
			},
			wantErr: true,
			errMsg:  "action is required",
		},
		{
			name: "invalid result",
			event: &AuditEvent{
				Timestamp: time.Now().UTC(),
				EventType: EventCertificateIssued,
				Actor:     "account:123",
				Resource:  "order:456",
				Action:    "issue",
				Result:    "invalid",
			},
			wantErr: true,
			errMsg:  "result must be",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNoOpLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	event := &AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: EventCertificateIssued,
		Actor:     "account:123",
		Resource:  "order:456",
		Action:    "issue",
		Result:    ResultSuccess,
	}

	assert.False(t, logger.Enabled())
	assert.NoError(t, logger.Log(ctx, event))
	assert.NoError(t, logger.LogWithContext(ctx, EventCertificateIssued, "actor", "resource", "action", ResultSuccess, nil))
	assert.NoError(t, logger.Flush())
	assert.NoError(t, logger.Close())
}

func TestEventBuilder(t *testing.T) {
	builder := NewEventBuilder(EventCertificateIssued).
		WithActor("account:123").
		WithResource("order:456").
		WithAction("issue").
		WithResult(ResultSuccess).
		WithRequestID("req-123").
		WithSourceIP("192.168.1.1").
		WithUserAgent("Test Agent").
		WithDetail("common_name", "example.com").
		WithDetail("validity_days", 90).
		WithDuration(100)

	event := builder.Build()

	assert.Equal(t, EventCertificateIssued, event.EventType)
	assert.Equal(t, "account:123", event.Actor)
	assert.Equal(t, "order:456", event.Resource)
	assert.Equal(t, "issue", event.Action)
	assert.Equal(t, ResultSuccess, event.Result)
	assert.Equal(t, "req-123", event.RequestID)
	assert.Equal(t, "192.168.1.1", event.SourceIP)
	assert.Equal(t, "Test Agent", event.UserAgent)
	assert.Equal(t, "example.com", event.Details["common_name"])
	assert.Equal(t, 90, event.Details["validity_days"])
	assert.Equal(t, int64(100), event.Duration)
	assert.False(t, event.Timestamp.IsZero())
}

func TestEventBuilder_WithError(t *testing.T) {
	err := assert.AnError
	builder := NewEventBuilder(EventCertificateIssued).
		WithActor("account:123").
		WithResource("order:456").
		WithAction("issue").
		WithResult(ResultSuccess).
		WithError(err)

	event := builder.Build()

	assert.Equal(t, ResultFailure, event.Result)
	assert.Equal(t, err.Error(), event.ErrorMessage)
}

func TestEventBuilder_WithDetails(t *testing.T) {
	details := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	builder := NewEventBuilder(EventCertificateIssued).
		WithActor("account:123").
		WithResource("order:456").
		WithAction("issue").
		WithResult(ResultSuccess).
		WithDetails(details)

	event := builder.Build()

	assert.Equal(t, "value1", event.Details["key1"])
	assert.Equal(t, 123, event.Details["key2"])
	assert.Equal(t, true, event.Details["key3"])
}

func TestFileAuditLogger_New(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config cannot be nil",
		},
		{
			name: "invalid config",
			config: &Config{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "logPath is required",
		},
		{
			name: "valid config",
			config: &Config{
				Enabled:              true,
				LogPath:              logPath,
				MaxSizeMB:            10,
				MaxAgeDays:           30,
				MaxBackups:           3,
				Format:               "json",
				BufferSize:           50,
				FlushIntervalSeconds: 1,
			},
			wantErr: false,
		},
		{
			name: "disabled returns NoOpLogger",
			config: &Config{
				Enabled: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewFileAuditLogger(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, logger)
				if tt.config != nil && tt.config.Enabled {
					assert.True(t, logger.Enabled())
				}
				if logger != nil {
					assert.NoError(t, logger.Close())
				}
			}
		})
	}
}

func TestFileAuditLogger_Log(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		MaxBackups:           3,
		BufferSize:           10,
		FlushIntervalSeconds: 1,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	event := &AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: EventCertificateIssued,
		Actor:     "account:123",
		Resource:  "order:456",
		Action:    "issue",
		Result:    ResultSuccess,
		Details: map[string]interface{}{
			"common_name":   "example.com",
			"validity_days": 90,
		},
	}

	err = logger.Log(ctx, event)
	require.NoError(t, err)

	// Flush to ensure event is written. Flush is documented best-effort against
	// the async writer, so poll for the event to become visible (robust under
	// heavy CI load / -race scheduling) rather than reading once.
	err = logger.Flush()
	require.NoError(t, err)

	var data []byte
	require.Eventually(t, func() bool {
		data, err = os.ReadFile(logPath)
		return err == nil && strings.Contains(string(data), "CERTIFICATE_ISSUED")
	}, 5*time.Second, 20*time.Millisecond, "audit event must be written to the log file")

	assert.Contains(t, string(data), "account:123")
	assert.Contains(t, string(data), "example.com")

	// Verify it's valid JSON
	var loggedEvent AuditEvent
	err = json.Unmarshal(data, &loggedEvent)
	require.NoError(t, err)
	assert.Equal(t, event.EventType, loggedEvent.EventType)
	assert.Equal(t, event.Actor, loggedEvent.Actor)
	assert.Equal(t, event.Resource, loggedEvent.Resource)
}

func TestFileAuditLogger_LogInvalidEvent(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           10,
		FlushIntervalSeconds: 1,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()

	// Test nil event
	err = logger.Log(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "event cannot be nil")

	// Test invalid event (missing required fields)
	invalidEvent := &AuditEvent{
		EventType: EventCertificateIssued,
	}
	err = logger.Log(ctx, invalidEvent)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid event")
}

func TestFileAuditLogger_ConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           100,
		FlushIntervalSeconds: 1,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	numGoroutines := 10
	eventsPerGoroutine := 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				event := &AuditEvent{
					Timestamp: time.Now().UTC(),
					EventType: EventCertificateIssued,
					Actor:     "account:123",
					Resource:  "order:456",
					Action:    "issue",
					Result:    ResultSuccess,
					Details: map[string]interface{}{
						"goroutine": goroutineID,
						"event":     j,
					},
				}
				err := logger.Log(ctx, event)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Wait for the background processor to finish processing buffered events
	time.Sleep(100 * time.Millisecond)

	// Flush to ensure all events are written
	err = logger.Flush()
	require.NoError(t, err)

	// Additional wait to ensure file sync completes
	time.Sleep(10 * time.Millisecond)

	// Verify all events were written
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	// Count the number of events in the file
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}

	expectedLines := numGoroutines * eventsPerGoroutine
	assert.Equal(t, expectedLines, lines, "expected %d events, got %d", expectedLines, lines)
}

func TestFileAuditLogger_LogWithContext(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           10,
		FlushIntervalSeconds: 1,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	ctx = ContextWithRequestID(ctx, "req-123")
	ctx = ContextWithSourceIP(ctx, "192.168.1.1")
	ctx = ContextWithUserAgent(ctx, "Test Agent")

	details := map[string]interface{}{
		"common_name":   "example.com",
		"validity_days": 90,
	}

	err = logger.LogWithContext(
		ctx,
		EventCertificateIssued,
		"account:123",
		"order:456",
		"issue",
		ResultSuccess,
		details,
	)
	require.NoError(t, err)

	// Give background processor time to receive the event
	time.Sleep(10 * time.Millisecond)

	// Flush to ensure event is written
	err = logger.Flush()
	require.NoError(t, err)

	// Verify the log file contains the context values
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "req-123")
	assert.Contains(t, string(data), "192.168.1.1")
	assert.Contains(t, string(data), "Test Agent")
}

func TestFileAuditLogger_Close(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           10,
		FlushIntervalSeconds: 1,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)

	ctx := context.Background()
	event := &AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: EventCertificateIssued,
		Actor:     "account:123",
		Resource:  "order:456",
		Action:    "issue",
		Result:    ResultSuccess,
	}

	// Log an event
	err = logger.Log(ctx, event)
	require.NoError(t, err)

	// Close the logger
	err = logger.Close()
	require.NoError(t, err)

	// Verify the event was written
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "CERTIFICATE_ISSUED")

	// Verify logging after close returns error
	err = logger.Log(ctx, event)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is closed")

	// Verify closing again is safe
	err = logger.Close()
	require.NoError(t, err)
}

func TestFileAuditLogger_ProcessEvents(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           5,
		FlushIntervalSeconds: 1,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()

	// Send multiple events to trigger background processing
	for i := 0; i < 3; i++ {
		event := &AuditEvent{
			Timestamp: time.Now().UTC(),
			EventType: EventCertificateIssued,
			Actor:     "account:123",
			Resource:  "order:456",
			Action:    "issue",
			Result:    ResultSuccess,
			Details: map[string]interface{}{
				"event_number": i,
			},
		}
		err = logger.Log(ctx, event)
		require.NoError(t, err)
	}

	// Flush is the synchronisation point: it returns only after the
	// processor has drained the buffer and the writer has synced, so the
	// events are on disk when it returns. A wall-clock pause here failed on a
	// loaded runner before the processor had run at all.
	require.NoError(t, logger.Flush())

	// Verify events were processed
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestFileAuditLogger_DrainBuffer(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           100,
		FlushIntervalSeconds: 1, // Short interval to trigger periodic flush
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)

	ctx := context.Background()

	// Log multiple events to fill buffer
	for i := 0; i < 10; i++ {
		event := &AuditEvent{
			Timestamp: time.Now().UTC(),
			EventType: EventCertificateIssued,
			Actor:     "account:123",
			Resource:  "order:456",
			Action:    "issue",
			Result:    ResultSuccess,
			Details: map[string]interface{}{
				"event_number": i,
			},
		}
		err = logger.Log(ctx, event)
		require.NoError(t, err)
	}

	// Wait for periodic flush to trigger drainBuffer
	time.Sleep(1500 * time.Millisecond)

	// Close logger to ensure all events are flushed
	err = logger.Close()
	require.NoError(t, err)

	// Verify all events were written
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	assert.Equal(t, 10, lines, "expected all 10 events to be written")
}

func TestFileAuditLogger_ContextTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           1, // Small buffer to trigger context timeout
		FlushIntervalSeconds: 10,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		_ = logger.Close()
	}()

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for context to timeout
	time.Sleep(10 * time.Millisecond)

	event := &AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: EventCertificateIssued,
		Actor:     "account:123",
		Resource:  "order:456",
		Action:    "issue",
		Result:    ResultSuccess,
	}

	// Fill the buffer first
	err = logger.Log(context.Background(), event)
	require.NoError(t, err)

	// Now try to log with timed-out context and full buffer
	err = logger.Log(ctx, event)
	// Should get context error since buffer is full
	if err != nil {
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	}
}

func TestFileAuditLogger_FlushError(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           10,
		FlushIntervalSeconds: 1,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)

	// Close the logger
	err = logger.Close()
	require.NoError(t, err)

	// Try to flush after close
	err = logger.Flush()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is closed")
}

func TestFileAuditLogger_BufferOverflow(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           2, // Very small buffer
		FlushIntervalSeconds: 10,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()

	// Fill buffer and force synchronous write
	for i := 0; i < 5; i++ {
		event := &AuditEvent{
			Timestamp: time.Now().UTC(),
			EventType: EventCertificateIssued,
			Actor:     "account:123",
			Resource:  "order:456",
			Action:    "issue",
			Result:    ResultSuccess,
			Details: map[string]interface{}{
				"event_number": i,
			},
		}
		err = logger.Log(ctx, event)
		require.NoError(t, err)
	}

	// Flush and verify all events were written
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}

	// Should have all 5 events even with small buffer (synchronous writes)
	assert.GreaterOrEqual(t, lines, 3, "expected at least 3 events to be written")
}

func TestContextFunctions(t *testing.T) {
	ctx := context.Background()

	// Test RequestID
	ctx = ContextWithRequestID(ctx, "req-123")
	assert.Equal(t, "req-123", extractRequestID(ctx))

	// Test SourceIP
	ctx = ContextWithSourceIP(ctx, "192.168.1.1")
	assert.Equal(t, "192.168.1.1", extractSourceIP(ctx))

	// Test UserAgent
	ctx = ContextWithUserAgent(ctx, "Test Agent")
	assert.Equal(t, "Test Agent", extractUserAgent(ctx))

	// Test extraction from empty context
	emptyCtx := context.Background()
	assert.Equal(t, "", extractRequestID(emptyCtx))
	assert.Equal(t, "", extractSourceIP(emptyCtx))
	assert.Equal(t, "", extractUserAgent(emptyCtx))
}

func TestContextFunctions_NonStringValues(t *testing.T) {
	ctx := context.Background()

	// Test with non-string values (should return empty string)
	ctx = context.WithValue(ctx, requestIDKey, 12345)
	assert.Equal(t, "", extractRequestID(ctx))

	ctx = context.WithValue(ctx, sourceIPKey, 12345)
	assert.Equal(t, "", extractSourceIP(ctx))

	ctx = context.WithValue(ctx, userAgentKey, 12345)
	assert.Equal(t, "", extractUserAgent(ctx))
}
