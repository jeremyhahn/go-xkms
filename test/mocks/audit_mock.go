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

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/stretchr/testify/mock"
)

// MockAuditLogger is a testify mock implementation of the audit.AuditLogger interface.
// It provides mock implementations of all AuditLogger methods for use in testing.
type MockAuditLogger struct {
	mock.Mock
}

// Ensure MockAuditLogger implements audit.AuditLogger interface
var _ audit.AuditLogger = (*MockAuditLogger)(nil)

// Log mocks the Log method of AuditLogger.
// It records an audit event and returns any configured error.
func (m *MockAuditLogger) Log(ctx context.Context, event *audit.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

// LogWithContext mocks the LogWithContext method of AuditLogger.
// It logs an event with context extracted from the provided context.Context.
func (m *MockAuditLogger) LogWithContext(
	ctx context.Context,
	eventType audit.EventType,
	actor string,
	resource string,
	action string,
	result audit.Result,
	details map[string]interface{},
) error {
	args := m.Called(ctx, eventType, actor, resource, action, result, details)
	return args.Error(0)
}

// Flush mocks the Flush method of AuditLogger.
// It ensures all buffered events are written to storage.
func (m *MockAuditLogger) Flush() error {
	args := m.Called()
	return args.Error(0)
}

// Close mocks the Close method of AuditLogger.
// It flushes remaining events and closes the logger.
func (m *MockAuditLogger) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Enabled mocks the Enabled method of AuditLogger.
// It returns true if audit logging is enabled.
func (m *MockAuditLogger) Enabled() bool {
	args := m.Called()
	return args.Bool(0)
}
