// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
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
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-codec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

// TestFileAuditLogger_FlushSync verifies that Flush() properly syncs data to disk
// This test ensures that data is immediately readable after Flush() returns
func TestFileAuditLogger_FlushSync(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           50,
		FlushIntervalSeconds: 10, // Long interval to ensure manual flush is tested
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()

	// Log multiple events rapidly
	expectedEvents := 10
	for i := 0; i < expectedEvents; i++ {
		event := &AuditEvent{
			Timestamp: time.Now().UTC(),
			EventType: EventCertificateIssued,
			Actor:     "account:123",
			Resource:  "order:456",
			Action:    "issue",
			Result:    ResultSuccess,
			Details: map[string]interface{}{
				"test_number": i,
			},
		}
		err = logger.Log(ctx, event)
		require.NoError(t, err)
	}

	// Give the background processor a moment to receive the events
	time.Sleep(10 * time.Millisecond)

	// Immediately flush and verify data is readable
	err = logger.Flush()
	require.NoError(t, err)

	// Read the file immediately - this should NOT be empty due to Flush()
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.NotEmpty(t, data, "log file should not be empty after flush")

	// Count the number of events written
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	actualEvents := 0
	for _, line := range lines {
		if line != "" {
			actualEvents++
			// Verify it's valid JSON
			var event AuditEvent
			err := json.Unmarshal([]byte(line), &event)
			require.NoError(t, err, "each line should be valid JSON")
		}
	}

	assert.Equal(t, expectedEvents, actualEvents,
		"all events should be written and readable immediately after flush")
}

// TestFileAuditLogger_LogWithContextSync specifically tests the scenario
// from the original bug report where context values weren't appearing in logs
func TestFileAuditLogger_LogWithContextSync(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit-context.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           10,
		FlushIntervalSeconds: 10,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		_ = logger.Close()
	}()

	// Create context with all values
	ctx := context.Background()
	ctx = ContextWithRequestID(ctx, "req-sync-test-123")
	ctx = ContextWithSourceIP(ctx, "10.0.0.1")
	ctx = ContextWithUserAgent(ctx, "Go-Test-Agent/1.0")

	// Log event with context
	err = logger.LogWithContext(
		ctx,
		EventCertificateIssued,
		"account:test",
		"order:test-order",
		"issue",
		ResultSuccess,
		map[string]interface{}{
			"common_name": "test.example.com",
		},
	)
	require.NoError(t, err)

	// Give background processor time to receive the event
	time.Sleep(10 * time.Millisecond)

	// Flush and verify immediately
	err = logger.Flush()
	require.NoError(t, err)

	// Read and verify - this is the critical test that was failing
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logContent := string(data)

	// These assertions should all pass thanks to Flush()
	assert.Contains(t, logContent, "req-sync-test-123",
		"request ID should be present in log")
	assert.Contains(t, logContent, "10.0.0.1",
		"source IP should be present in log")
	assert.Contains(t, logContent, "Go-Test-Agent/1.0",
		"user agent should be present in log")
	assert.Contains(t, logContent, "test.example.com",
		"detail values should be present in log")

	// Verify JSON structure
	var event AuditEvent
	err = json.Unmarshal([]byte(strings.TrimSpace(logContent)), &event)
	require.NoError(t, err)

	assert.Equal(t, "req-sync-test-123", event.RequestID)
	assert.Equal(t, "10.0.0.1", event.SourceIP)
	assert.Equal(t, "Go-Test-Agent/1.0", event.UserAgent)
	assert.Equal(t, "test.example.com", event.Details["common_name"])
}

// TestFileAuditLogger_RapidFlushCycles tests multiple rapid flush cycles
// to ensure the sync mechanism is robust under stress
func TestFileAuditLogger_RapidFlushCycles(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit-rapid.log")

	config := &Config{
		Enabled:              true,
		LogPath:              logPath,
		MaxSizeMB:            10,
		MaxAgeDays:           30,
		BufferSize:           5,
		FlushIntervalSeconds: 10,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	totalEvents := 0

	// Perform multiple rapid write-flush cycles
	for cycle := 0; cycle < 5; cycle++ {
		// Write events
		for i := 0; i < 3; i++ {
			event := &AuditEvent{
				Timestamp: time.Now().UTC(),
				EventType: EventCertificateIssued,
				Actor:     "account:rapid",
				Resource:  "order:rapid",
				Action:    "issue",
				Result:    ResultSuccess,
				Details: map[string]interface{}{
					"cycle": cycle,
					"event": i,
				},
			}
			err = logger.Log(ctx, event)
			require.NoError(t, err)
			totalEvents++
		}

		// Give background processor time to receive events
		time.Sleep(10 * time.Millisecond)

		// Flush immediately
		err = logger.Flush()
		require.NoError(t, err)

		// Verify data is readable
		data, err := os.ReadFile(logPath)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		// Count events written so far
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		actualEvents := 0
		for _, line := range lines {
			if line != "" {
				actualEvents++
			}
		}

		// Should have all events from this cycle and previous cycles
		expectedSoFar := (cycle + 1) * 3
		assert.Equal(t, expectedSoFar, actualEvents,
			"cycle %d: should have %d events written", cycle, expectedSoFar)
	}
}

// TestNewCodec tests the NewCodec function with various codec types
func TestNewCodec(t *testing.T) {
	tests := []struct {
		name      string
		codecType codec.Type
		expected  codec.Type
	}{
		{
			name:      "JSON codec",
			codecType: codec.JSON,
			expected:  codec.JSON,
		},
		{
			name:      "CBOR codec",
			codecType: codec.CBOR,
			expected:  codec.CBOR,
		},
		{
			name:      "MsgPack codec",
			codecType: codec.MsgPack,
			expected:  codec.MsgPack,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCodec(tt.codecType)
			require.NotNil(t, c)
			assert.Equal(t, tt.expected, c.Type())
		})
	}
}

// TestCodec_MarshalUnmarshal tests Marshal and Unmarshal for all codec types
func TestCodec_MarshalUnmarshal(t *testing.T) {
	testEvent := &AuditEvent{
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		EventType: EventCertificateIssued,
		Actor:     "account:test",
		Resource:  "order:test-order",
		Action:    "issue",
		Result:    ResultSuccess,
		RequestID: "req-123",
		SourceIP:  "192.168.1.1",
		UserAgent: "TestAgent/1.0",
		Details: map[string]interface{}{
			"common_name": "test.example.com",
		},
	}

	tests := []struct {
		name      string
		codecType codec.Type
	}{
		{
			name:      "JSON codec marshal/unmarshal",
			codecType: codec.JSON,
		},
		{
			name:      "CBOR codec marshal/unmarshal",
			codecType: codec.CBOR,
		},
		{
			name:      "MsgPack codec marshal/unmarshal",
			codecType: codec.MsgPack,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCodec(tt.codecType)

			// Marshal
			data, err := c.Marshal(testEvent)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal
			var decoded AuditEvent
			err = c.Unmarshal(data, &decoded)
			require.NoError(t, err)

			// Verify
			assert.Equal(t, testEvent.EventType, decoded.EventType)
			assert.Equal(t, testEvent.Actor, decoded.Actor)
			assert.Equal(t, testEvent.Resource, decoded.Resource)
			assert.Equal(t, testEvent.Action, decoded.Action)
			assert.Equal(t, testEvent.Result, decoded.Result)
			assert.Equal(t, testEvent.RequestID, decoded.RequestID)
			assert.Equal(t, testEvent.SourceIP, decoded.SourceIP)
		})
	}
}

// TestCodec_DefaultFallback tests that unknown codec types fall back to JSON
func TestCodec_DefaultFallback(t *testing.T) {
	// Use an invalid codec type string
	c := NewCodec(codec.Type("unknown_codec"))

	testData := map[string]string{"key": "value"}

	// Marshal should fallback to JSON
	data, err := c.Marshal(testData)
	require.NoError(t, err)

	// Verify it's valid JSON
	var decoded map[string]string
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "value", decoded["key"])

	// Unmarshal should also fallback to JSON
	jsonData := []byte(`{"key":"value2"}`)
	var decoded2 map[string]string
	err = c.Unmarshal(jsonData, &decoded2)
	require.NoError(t, err)
	assert.Equal(t, "value2", decoded2["key"])
}

// TestCodec_CBORDirectMarshalUnmarshal verifies CBOR codec works correctly
func TestCodec_CBORDirectMarshalUnmarshal(t *testing.T) {
	c := NewCodec(codec.CBOR)

	// Create test data
	original := map[string]interface{}{
		"string":  "test",
		"number":  42,
		"boolean": true,
	}

	// Marshal with our codec
	data, err := c.Marshal(original)
	require.NoError(t, err)

	// Verify it's valid CBOR by unmarshaling with the cbor library directly
	var directDecoded map[string]interface{}
	err = cbor.Unmarshal(data, &directDecoded)
	require.NoError(t, err)
	assert.Equal(t, "test", directDecoded["string"])

	// Unmarshal with our codec
	var codecDecoded map[string]interface{}
	err = c.Unmarshal(data, &codecDecoded)
	require.NoError(t, err)
	assert.Equal(t, "test", codecDecoded["string"])
}

// TestCodec_MsgPackDirectMarshalUnmarshal verifies MsgPack codec works correctly
func TestCodec_MsgPackDirectMarshalUnmarshal(t *testing.T) {
	c := NewCodec(codec.MsgPack)

	// Create test data
	original := map[string]interface{}{
		"string":  "test",
		"number":  42,
		"boolean": true,
	}

	// Marshal with our codec
	data, err := c.Marshal(original)
	require.NoError(t, err)

	// Verify it's valid MsgPack by unmarshaling with the msgpack library directly
	var directDecoded map[string]interface{}
	err = msgpack.Unmarshal(data, &directDecoded)
	require.NoError(t, err)
	assert.Equal(t, "test", directDecoded["string"])

	// Unmarshal with our codec
	var codecDecoded map[string]interface{}
	err = c.Unmarshal(data, &codecDecoded)
	require.NoError(t, err)
	assert.Equal(t, "test", codecDecoded["string"])
}

// TestDefaultCodec tests the DefaultCodec function
func TestDefaultCodec(t *testing.T) {
	c := DefaultCodec()
	require.NotNil(t, c)
	assert.Equal(t, codec.JSON, c.Type())

	// Verify it works
	data, err := c.Marshal(map[string]string{"test": "value"})
	require.NoError(t, err)

	var decoded map[string]string
	err = c.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "value", decoded["test"])
}

// TestAuditEvent_ValidatePendingResult tests validation with pending result
func TestAuditEvent_ValidatePendingResult(t *testing.T) {
	event := &AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: EventOrderCreated,
		Actor:     "account:123",
		Resource:  "order:456",
		Action:    "create",
		Result:    ResultPending, // Test the pending result
	}

	err := event.Validate()
	require.NoError(t, err, "pending result should be valid")
}

// TestConfig_ValidateDefaults tests that Config.Validate sets proper defaults
func TestConfig_ValidateDefaults(t *testing.T) {
	config := &Config{
		Enabled: true,
		LogPath: "/tmp/audit.log",
		// All other fields left at zero values
	}

	err := config.Validate()
	require.NoError(t, err)

	// Verify defaults were set
	assert.Equal(t, 100, config.MaxSizeMB)
	assert.Equal(t, 365, config.MaxAgeDays)
	assert.Equal(t, 10, config.MaxBackups)
	assert.Equal(t, "json", config.Format)
	assert.Equal(t, 100, config.BufferSize)
	assert.Equal(t, 5, config.FlushIntervalSeconds)
}

// TestConfig_ValidateNegativeMaxBackups tests MaxBackups with negative value
func TestConfig_ValidateNegativeMaxBackups(t *testing.T) {
	config := &Config{
		Enabled:    true,
		LogPath:    "/tmp/audit.log",
		MaxBackups: -5, // Negative value
	}

	err := config.Validate()
	require.NoError(t, err)

	// Should be set to default
	assert.Equal(t, 10, config.MaxBackups)
}
