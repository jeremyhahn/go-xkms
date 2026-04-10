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

package agent

import (
	"errors"
	"testing"
)

func TestAgentError_Error(t *testing.T) {
	err := &AgentError{
		Operation: "test_op",
		Err:       ErrServerNotStarted,
	}
	expected := "agent: test_op: agent: server not started"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestAgentError_Unwrap(t *testing.T) {
	inner := ErrEnrollmentFailed
	err := &AgentError{
		Operation: "enroll",
		Err:       inner,
	}
	if !errors.Is(err, inner) {
		t.Error("errors.Is should find the wrapped error")
	}
}

func TestAgentError_As(t *testing.T) {
	err := &AgentError{
		Operation: "connect",
		Err:       ErrClientNotConnected,
	}
	var agentErr *AgentError
	if !errors.As(err, &agentErr) {
		t.Error("errors.As should succeed for *AgentError")
	}
	if agentErr.Operation != "connect" {
		t.Errorf("expected operation 'connect', got %q", agentErr.Operation)
	}
}

func TestSentinelErrors(t *testing.T) {
	// Verify all sentinel errors are distinct and non-nil.
	sentinels := []error{
		ErrServerNotStarted,
		ErrServerAlreadyRunning,
		ErrClientNotConnected,
		ErrClientAlreadyConnected,
		ErrEnrollmentFailed,
		ErrEnrollmentCodeExpired,
		ErrEnrollmentCodeInvalid,
		ErrEnrollmentPending,
		ErrEnrollmentRejected,
		ErrEnrollmentMethodNotAllowed,
		ErrMaxAgentsReached,
		ErrCertificateInvalid,
		ErrCertificateExpired,
		ErrCertificateRevoked,
		ErrPolicyViolation,
		ErrTouchRequired,
		ErrNilConfig,
		ErrNilLogger,
		ErrNilCAService,
		ErrNilEnrollmentStore,
		ErrNilEnrollmentService,
		ErrNilClient,
		ErrInvalidAddress,
		ErrInvalidCSR,
		ErrInvalidRequestID,
		ErrRequestNotFound,
		ErrAgentNotFound,
		ErrStoreDir,
		ErrStoreMarshal,
		ErrStoreUnmarshal,
		ErrStoreWrite,
		ErrStoreRead,
		ErrStoreDelete,
		ErrSocketPath,
	}

	seen := make(map[string]struct{}, len(sentinels))
	for _, err := range sentinels {
		if err == nil {
			t.Error("sentinel error should not be nil")
			continue
		}
		msg := err.Error()
		if _, ok := seen[msg]; ok {
			t.Errorf("duplicate sentinel error message: %q", msg)
		}
		seen[msg] = struct{}{}
	}
}

func TestAgentError_NestedUnwrap(t *testing.T) {
	inner := &AgentError{
		Operation: "inner",
		Err:       ErrEnrollmentCodeExpired,
	}
	outer := &AgentError{
		Operation: "outer",
		Err:       inner,
	}

	if !errors.Is(outer, ErrEnrollmentCodeExpired) {
		t.Error("nested unwrap should find deeply wrapped error")
	}
}
