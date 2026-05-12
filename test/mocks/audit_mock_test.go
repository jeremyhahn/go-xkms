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

package mocks

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestMockAuditLogger_Log tests the Log method mock
func TestMockAuditLogger_Log(t *testing.T) {
	mockLogger := new(MockAuditLogger)
	ctx := context.Background()
	event := &audit.AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: audit.EventCertificateIssued,
		Actor:     "account:12345",
		Resource:  "certificate:abc123",
		Action:    "create",
		Result:    audit.ResultSuccess,
		Details:   make(map[string]interface{}),
	}

	// Setup expectations
	mockLogger.On("Log", ctx, event).Return(nil)

	// Execute
	err := mockLogger.Log(ctx, event)

	// Assert
	assert.NoError(t, err)
	mockLogger.AssertExpectations(t)
}

// TestMockAuditLogger_Log_Error tests the Log method mock with error
func TestMockAuditLogger_Log_Error(t *testing.T) {
	mockLogger := new(MockAuditLogger)
	ctx := context.Background()
	event := &audit.AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: audit.EventCertificateIssued,
		Actor:     "account:12345",
		Resource:  "certificate:abc123",
		Action:    "create",
		Result:    audit.ResultSuccess,
		Details:   make(map[string]interface{}),
	}
	expectedErr := errors.New("log write failed")

	// Setup expectations
	mockLogger.On("Log", ctx, event).Return(expectedErr)

	// Execute
	err := mockLogger.Log(ctx, event)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockLogger.AssertExpectations(t)
}

// TestMockAuditLogger_LogWithContext tests the LogWithContext method mock
func TestMockAuditLogger_LogWithContext(t *testing.T) {
	mockLogger := new(MockAuditLogger)
	ctx := context.Background()
	eventType := audit.EventAccountCreated
	actor := "system"
	resource := "account:67890"
	action := "create"
	result := audit.ResultSuccess
	details := map[string]interface{}{
		"email": "user@example.com",
	}

	// Setup expectations
	mockLogger.On("LogWithContext", ctx, eventType, actor, resource, action, result, details).Return(nil)

	// Execute
	err := mockLogger.LogWithContext(ctx, eventType, actor, resource, action, result, details)

	// Assert
	assert.NoError(t, err)
	mockLogger.AssertExpectations(t)
}

// TestMockAuditLogger_LogWithContext_Error tests the LogWithContext method mock with error
func TestMockAuditLogger_LogWithContext_Error(t *testing.T) {
	mockLogger := new(MockAuditLogger)
	ctx := context.Background()
	eventType := audit.EventAccountCreated
	actor := "system"
	resource := "account:67890"
	action := "create"
	result := audit.ResultSuccess
	details := map[string]interface{}{
		"email": "user@example.com",
	}
	expectedErr := audit.ErrWriteFailed

	// Setup expectations
	mockLogger.On("LogWithContext", ctx, eventType, actor, resource, action, result, details).Return(expectedErr)

	// Execute
	err := mockLogger.LogWithContext(ctx, eventType, actor, resource, action, result, details)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockLogger.AssertExpectations(t)
}

// TestMockAuditLogger_Flush tests the Flush method mock
func TestMockAuditLogger_Flush(t *testing.T) {
	mockLogger := new(MockAuditLogger)

	// Setup expectations
	mockLogger.On("Flush").Return(nil)

	// Execute
	err := mockLogger.Flush()

	// Assert
	assert.NoError(t, err)
	mockLogger.AssertExpectations(t)
}

// TestMockAuditLogger_Flush_Error tests the Flush method mock with error
func TestMockAuditLogger_Flush_Error(t *testing.T) {
	mockLogger := new(MockAuditLogger)
	expectedErr := errors.New("flush failed")

	// Setup expectations
	mockLogger.On("Flush").Return(expectedErr)

	// Execute
	err := mockLogger.Flush()

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockLogger.AssertExpectations(t)
}

// TestMockAuditLogger_Close tests the Close method mock
func TestMockAuditLogger_Close(t *testing.T) {
	mockLogger := new(MockAuditLogger)

	// Setup expectations
	mockLogger.On("Close").Return(nil)

	// Execute
	err := mockLogger.Close()

	// Assert
	assert.NoError(t, err)
	mockLogger.AssertExpectations(t)
}

// TestMockAuditLogger_Close_Error tests the Close method mock with error
func TestMockAuditLogger_Close_Error(t *testing.T) {
	mockLogger := new(MockAuditLogger)
	expectedErr := audit.ErrLoggerClosed

	// Setup expectations
	mockLogger.On("Close").Return(expectedErr)

	// Execute
	err := mockLogger.Close()

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockLogger.AssertExpectations(t)
}

// TestMockAuditLogger_Enabled tests the Enabled method mock
func TestMockAuditLogger_Enabled(t *testing.T) {
	mockLogger := new(MockAuditLogger)

	// Setup expectations
	mockLogger.On("Enabled").Return(true)

	// Execute
	enabled := mockLogger.Enabled()

	// Assert
	assert.True(t, enabled)
	mockLogger.AssertExpectations(t)
}

// TestMockAuditLogger_Enabled_False tests the Enabled method mock when disabled
func TestMockAuditLogger_Enabled_False(t *testing.T) {
	mockLogger := new(MockAuditLogger)

	// Setup expectations
	mockLogger.On("Enabled").Return(false)

	// Execute
	enabled := mockLogger.Enabled()

	// Assert
	assert.False(t, enabled)
	mockLogger.AssertExpectations(t)
}

// TestMockAuditLogger_MultipleMethodCalls tests multiple method calls on the same mock
func TestMockAuditLogger_MultipleMethodCalls(t *testing.T) {
	mockLogger := new(MockAuditLogger)
	ctx := context.Background()

	// Setup expectations
	mockLogger.On("Enabled").Return(true)
	mockLogger.On("Log", ctx, mock.AnythingOfType("*audit.AuditEvent")).Return(nil)
	mockLogger.On("Flush").Return(nil)
	mockLogger.On("Close").Return(nil)

	// Execute
	assert.True(t, mockLogger.Enabled())

	event := &audit.AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: audit.EventCertificateIssued,
		Actor:     "test-actor",
		Resource:  "test-resource",
		Action:    "test-action",
		Result:    audit.ResultSuccess,
		Details:   make(map[string]interface{}),
	}
	assert.NoError(t, mockLogger.Log(ctx, event))
	assert.NoError(t, mockLogger.Flush())
	assert.NoError(t, mockLogger.Close())

	// Assert all expectations were met
	mockLogger.AssertExpectations(t)
}
