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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPMiddleware(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "OK")
	})

	middleware := HTTPMiddleware(logger)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "test-req-123")
	req.Header.Set("User-Agent", "Test Agent")
	req.RemoteAddr = "192.168.1.1:12345"

	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Flush and verify the log
	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var event AuditEvent
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, "test-req-123", event.RequestID)
	assert.Contains(t, event.SourceIP, "192.168.1.1")
	assert.Equal(t, "Test Agent", event.UserAgent)
	assert.Equal(t, "/test", event.Resource)
	assert.Equal(t, "GET", event.Action)
	assert.Equal(t, ResultSuccess, event.Result)
	assert.Equal(t, float64(200), event.Details["status_code"])
}

func TestHTTPMiddleware_WithError(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintln(w, "Error")
	})

	middleware := HTTPMiddleware(logger)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("POST", "/api/error", nil)
	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	// Flush and verify the log
	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var event AuditEvent
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, ResultFailure, event.Result)
	assert.Equal(t, float64(500), event.Details["status_code"])
}

func TestHTTPMiddleware_Disabled(t *testing.T) {
	logger := NewNoOpLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "OK")
	})

	middleware := HTTPMiddleware(logger)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// mustAuditTrustedProxies parses a trusted-proxy list for a test, failing the
// test on a malformed entry.
func mustAuditTrustedProxies(t *testing.T, entries ...string) *ratelimit.TrustedProxies {
	t.Helper()
	proxies, err := ratelimit.ParseTrustedProxies(entries)
	require.NoError(t, err)
	return proxies
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name     string
		proxies  *ratelimit.TrustedProxies
		headers  map[string]string
		remoteIP string
		expected string
	}{
		{
			name: "untrusted peer forged X-Forwarded-For is ignored",
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			remoteIP: "192.168.1.1:12345",
			expected: "192.168.1.1",
		},
		{
			name: "untrusted peer forged X-Real-IP is ignored",
			headers: map[string]string{
				"X-Real-IP": "10.0.0.2",
			},
			remoteIP: "192.168.1.1:12345",
			expected: "192.168.1.1",
		},
		{
			name:     "RemoteAddr fallback, port dropped",
			headers:  map[string]string{},
			remoteIP: "192.168.1.1:12345",
			expected: "192.168.1.1",
		},
		{
			name:    "trusted proxy's X-Forwarded-For is believed",
			proxies: mustAuditTrustedProxies(t, "192.168.1.1"),
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
				"X-Real-IP":       "10.0.0.2",
			},
			remoteIP: "192.168.1.1:12345",
			expected: "10.0.0.1",
		},
		{
			name:    "untrusted proxy's X-Forwarded-For is still ignored",
			proxies: mustAuditTrustedProxies(t, "192.168.1.2"),
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			remoteIP: "192.168.1.1:12345",
			expected: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldProxies := trustedProxies
			defer func() { trustedProxies = oldProxies }()
			trustedProxies = tt.proxies

			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteIP
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := extractClientIP(req)
			assert.Equal(t, tt.expected, ip)
		})
	}
}

func TestSetTrustedProxies(t *testing.T) {
	oldProxies := trustedProxies
	defer func() { trustedProxies = oldProxies }()

	proxies := mustAuditTrustedProxies(t, "192.0.2.1")
	SetTrustedProxies(proxies)
	assert.Same(t, proxies, trustedProxies)

	SetTrustedProxies(nil)
	assert.Nil(t, trustedProxies)
}

func TestExtractActorFromRequest(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name: "with X-Account-ID header",
			headers: map[string]string{
				"X-Account-ID": "user123",
			},
			expected: "account:user123",
		},
		{
			name:     "without X-Account-ID header defaults to system",
			headers:  map[string]string{},
			expected: "system",
		},
		{
			name: "empty X-Account-ID header defaults to system",
			headers: map[string]string{
				"X-Account-ID": "",
			},
			expected: "system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			actor := extractActorFromRequest(req)
			assert.Equal(t, tt.expected, actor)
		})
	}
}

func TestAuditableOperation(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	details := map[string]interface{}{
		"test_key": "test_value",
	}

	t.Run("successful operation", func(t *testing.T) {
		err := AuditableOperation(
			ctx,
			logger,
			EventCertificateIssued,
			"account:123",
			"certificate:456",
			"issue",
			details,
			func() error {
				// Simulate successful operation
				time.Sleep(10 * time.Millisecond)
				return nil
			},
		)
		require.NoError(t, err)
	})

	t.Run("failed operation", func(t *testing.T) {
		expectedErr := errors.New("operation failed")
		err := AuditableOperation(
			ctx,
			logger,
			EventCertificateIssued,
			"account:123",
			"certificate:456",
			"issue",
			details,
			func() error {
				return expectedErr
			},
		)
		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	// Flush and verify logs
	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	// Should have 2 events
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	assert.Equal(t, 2, lines)
}

func TestAuditableOperation_DisabledLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	callCount := 0
	err := AuditableOperation(
		ctx,
		logger,
		EventCertificateIssued,
		"account:123",
		"certificate:456",
		"issue",
		nil,
		func() error {
			callCount++
			return nil
		},
	)

	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "operation should still be called when logger is disabled")
}

func TestLogCertificateIssued(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	err = LogCertificateIssued(ctx, logger, "123", "456", "example.com", 90, "ABC123")
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var event AuditEvent
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, EventCertificateIssued, event.EventType)
	assert.Equal(t, "account:123", event.Actor)
	assert.Equal(t, "order:456", event.Resource)
	assert.Equal(t, "issue", event.Action)
	assert.Equal(t, ResultSuccess, event.Result)
	assert.Equal(t, "example.com", event.Details["common_name"])
	assert.Equal(t, float64(90), event.Details["validity_days"])
	assert.Equal(t, "ABC123", event.Details["serial_number"])
}

func TestLogCertificateIssued_DisabledLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	err := LogCertificateIssued(ctx, logger, "123", "456", "example.com", 90, "ABC123")
	require.NoError(t, err)
}

func TestLogCertificateRevoked(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	err = LogCertificateRevoked(ctx, logger, "123", "ABC123", 1)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var event AuditEvent
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, EventCertificateRevoked, event.EventType)
	assert.Equal(t, "account:123", event.Actor)
	assert.Equal(t, "certificate:ABC123", event.Resource)
	assert.Equal(t, "revoke", event.Action)
	assert.Equal(t, "ABC123", event.Details["serial_number"])
	assert.Equal(t, float64(1), event.Details["reason_code"])
}

func TestLogCertificateRevoked_DisabledLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	err := LogCertificateRevoked(ctx, logger, "123", "ABC123", 1)
	require.NoError(t, err)
}

func TestLogAccountCreated(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	contact := []string{"mailto:admin@example.com"}
	err = LogAccountCreated(ctx, logger, "123", contact, true)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var event AuditEvent
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, EventAccountCreated, event.EventType)
	assert.Equal(t, "system", event.Actor)
	assert.Equal(t, "account:123", event.Resource)
	assert.Equal(t, "create", event.Action)
}

func TestLogAccountCreated_DisabledLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	err := LogAccountCreated(ctx, logger, "123", []string{"mailto:test@example.com"}, false)
	require.NoError(t, err)
}

func TestLogOrderCreated(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	identifiers := []string{"example.com", "www.example.com"}
	err = LogOrderCreated(ctx, logger, "123", "456", identifiers)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var event AuditEvent
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, EventOrderCreated, event.EventType)
	assert.Equal(t, "account:123", event.Actor)
	assert.Equal(t, "order:456", event.Resource)
	assert.Equal(t, "create", event.Action)
}

func TestLogOrderCreated_DisabledLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	err := LogOrderCreated(ctx, logger, "123", "456", []string{"example.com"})
	require.NoError(t, err)
}

func TestLogOrderFinalized(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	err = LogOrderFinalized(ctx, logger, "123", "456", "https://example.com/cert/abc")
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var event AuditEvent
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, EventOrderFinalized, event.EventType)
	assert.Equal(t, "account:123", event.Actor)
	assert.Equal(t, "order:456", event.Resource)
	assert.Equal(t, "finalize", event.Action)
	assert.Equal(t, "https://example.com/cert/abc", event.Details["certificate_url"])
}

func TestLogOrderFinalized_DisabledLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	err := LogOrderFinalized(ctx, logger, "123", "456", "https://example.com/cert/abc")
	require.NoError(t, err)
}

func TestLogChallengeCompleted(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()

	t.Run("successful challenge", func(t *testing.T) {
		err = LogChallengeCompleted(ctx, logger, "123", "789", "http-01", true)
		require.NoError(t, err)
	})

	t.Run("failed challenge", func(t *testing.T) {
		err = LogChallengeCompleted(ctx, logger, "123", "790", "http-01", false)
		require.NoError(t, err)
	})

	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	// Should have 2 events
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	assert.Equal(t, 2, lines)
}

func TestLogChallengeCompleted_DisabledLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	err := LogChallengeCompleted(ctx, logger, "123", "789", "http-01", true)
	require.NoError(t, err)
}

func TestLogKeyChange(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	err = LogKeyChange(ctx, logger, "123", "old-fp", "new-fp")
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var event AuditEvent
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, EventAccountKeyChanged, event.EventType)
	assert.Equal(t, "account:123", event.Actor)
	assert.Equal(t, "key_rollover", event.Action)
	assert.Equal(t, "old-fp", event.Details["old_key_fingerprint"])
	assert.Equal(t, "new-fp", event.Details["new_key_fingerprint"])
}

func TestLogKeyChange_DisabledLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	err := LogKeyChange(ctx, logger, "123", "old-fp", "new-fp")
	require.NoError(t, err)
}

func TestLogAuthenticationFailed(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	err = LogAuthenticationFailed(ctx, logger, "invalid signature")
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var event AuditEvent
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, EventAuthenticationFailed, event.EventType)
	assert.Equal(t, "unknown", event.Actor)
	assert.Equal(t, ResultFailure, event.Result)
	assert.Equal(t, "invalid signature", event.Details["reason"])
}

func TestLogAuthenticationFailed_DisabledLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	err := LogAuthenticationFailed(ctx, logger, "invalid signature")
	require.NoError(t, err)
}

func TestLogTPMEnrollment(t *testing.T) {
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
	defer func() {
		_ = logger.Close()
	}()

	ctx := context.Background()
	err = LogTPMEnrollment(ctx, logger, "123", "device-456", "ek-cert-abc", "ak-cert-xyz")
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	err = logger.Flush()
	require.NoError(t, err)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var event AuditEvent
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, EventTPMEnrollment, event.EventType)
	assert.Equal(t, "account:123", event.Actor)
	assert.Equal(t, "device:device-456", event.Resource)
	assert.Equal(t, "enroll", event.Action)
	assert.Equal(t, "device-456", event.Details["device_id"])
}

func TestLogTPMEnrollment_DisabledLogger(t *testing.T) {
	logger := NewNoOpLogger()
	ctx := context.Background()

	err := LogTPMEnrollment(ctx, logger, "123", "device-456", "ek-cert-abc", "ak-cert-xyz")
	require.NoError(t, err)
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	// Request IDs should not be empty
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)

	// Request IDs should be unique
	assert.NotEqual(t, id1, id2)

	// Request IDs should start with "req-"
	assert.Contains(t, id1, "req-")
	assert.Contains(t, id2, "req-")
}
