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

package errors

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestTrustedCAError_GRPCStatus(t *testing.T) {
	tests := []struct {
		name         string
		err          *TrustedCAError
		expectedCode codes.Code
	}{
		{
			name:         "InternalServer",
			err:          &TrustedCAError{Type: InternalServer, Detail: "internal error"},
			expectedCode: codes.Internal,
		},
		{
			name:         "Malformed",
			err:          &TrustedCAError{Type: Malformed, Detail: "malformed request"},
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "Unauthorized",
			err:          &TrustedCAError{Type: Unauthorized, Detail: "unauthorized"},
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "NotFound",
			err:          &TrustedCAError{Type: NotFound, Detail: "not found"},
			expectedCode: codes.NotFound,
		},
		{
			name:         "RateLimit",
			err:          &TrustedCAError{Type: RateLimit, Detail: "rate limited"},
			expectedCode: codes.ResourceExhausted,
		},
		{
			name:         "ConnectionFailure",
			err:          &TrustedCAError{Type: ConnectionFailure, Detail: "connection failed"},
			expectedCode: codes.Unavailable,
		},
		{
			name:         "CAA",
			err:          &TrustedCAError{Type: CAA, Detail: "caa check failed"},
			expectedCode: codes.FailedPrecondition,
		},
		{
			name:         "Duplicate",
			err:          &TrustedCAError{Type: Duplicate, Detail: "duplicate"},
			expectedCode: codes.AlreadyExists,
		},
		{
			name:         "OrderNotReady",
			err:          &TrustedCAError{Type: OrderNotReady, Detail: "order not ready"},
			expectedCode: codes.FailedPrecondition,
		},
		{
			name:         "InvalidToken",
			err:          &TrustedCAError{Type: InvalidToken, Detail: "invalid token"},
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "ChallengeTimeout",
			err:          &TrustedCAError{Type: ChallengeTimeout, Detail: "timeout"},
			expectedCode: codes.DeadlineExceeded,
		},
		{
			name:         "Unknown type",
			err:          &TrustedCAError{Type: ErrorType(999), Detail: "unknown"},
			expectedCode: codes.Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.err.GRPCStatus()
			if s.Code() != tt.expectedCode {
				t.Errorf("GRPCStatus().Code() = %v, want %v", s.Code(), tt.expectedCode)
			}
			if s.Message() != tt.err.Detail {
				t.Errorf("GRPCStatus().Message() = %q, want %q", s.Message(), tt.err.Detail)
			}
		})
	}
}

func TestGRPCCodeMapping(t *testing.T) {
	// Test all error types have valid gRPC code mappings
	errorTypes := []ErrorType{
		InternalServer, Malformed, Unauthorized, NotFound, RateLimit,
		RejectedIdentifier, InvalidEmail, ConnectionFailure, CAA, MissingSCTs,
		Duplicate, OrderNotReady, DNS, BadPublicKey, BadCSR, AlreadyRevoked,
		BadRevocationReason, UnsupportedContact, UnknownSerial, Conflict,
		InvalidProfile, AlreadyReplaced, BadSignatureAlgorithm, AccountDoesNotExist,
		BadNonce, ExternalAccountRequired, IncorrectResponse, InvalidContact,
		TLSError, UnsupportedIdentifier, UserActionRequired, AccountExists,
		CompoundError, BadAttestationStatement, StorageFailure, SerializationFailure,
		TenantNotFound, TenantSuspended, TenantQuotaExceeded, CertificateExpired,
		CertificateNotYetValid, SigningFailure, VerificationFailure,
		KeyGenerationFailure, TPMError, OCSPFailure, CRLFailure, PolicyViolation,
		AuthorizationExpired, ChallengeTimeout, InvalidToken,
	}

	for _, et := range errorTypes {
		err := &TrustedCAError{Type: et, Detail: "test"}
		s := err.GRPCStatus()
		if s == nil {
			t.Errorf("GRPCStatus() returned nil for %v", et)
		}
		// Just ensure it doesn't panic and returns a valid status
		_ = s.Code()
	}
}

func TestToGRPCMetadata(t *testing.T) {
	err := &TrustedCAError{
		Type:       RateLimit,
		Detail:     "too many requests",
		RetryAfter: 60 * time.Second,
		Instance:   "https://example.com/limits",
		SubErrors: []SubError{
			{
				TrustedCAError: &TrustedCAError{
					Type:   RejectedIdentifier,
					Detail: "domain blocked",
				},
				Identifier: ACMEIdentifier{Type: "dns", Value: "blocked.com"},
			},
		},
	}

	data, marshalErr := err.ToGRPCMetadata()
	if marshalErr != nil {
		t.Fatalf("ToGRPCMetadata() error = %v", marshalErr)
	}

	if len(data) == 0 {
		t.Error("ToGRPCMetadata() returned empty data")
	}

	// Round-trip test
	decoded, decodeErr := FromGRPCMetadata(data)
	if decodeErr != nil {
		t.Fatalf("FromGRPCMetadata() error = %v", decodeErr)
	}

	if decoded.Type != err.Type {
		t.Errorf("Type = %v, want %v", decoded.Type, err.Type)
	}
	if decoded.Detail != err.Detail {
		t.Errorf("Detail = %q, want %q", decoded.Detail, err.Detail)
	}
	if decoded.RetryAfter != err.RetryAfter {
		t.Errorf("RetryAfter = %v, want %v", decoded.RetryAfter, err.RetryAfter)
	}
	if decoded.Instance != err.Instance {
		t.Errorf("Instance = %q, want %q", decoded.Instance, err.Instance)
	}
	if len(decoded.SubErrors) != 1 {
		t.Fatalf("SubErrors len = %d, want 1", len(decoded.SubErrors))
	}
	if decoded.SubErrors[0].Identifier.Value != "blocked.com" {
		t.Errorf("SubErrors[0].Identifier.Value = %q, want 'blocked.com'",
			decoded.SubErrors[0].Identifier.Value)
	}
}

func TestToGRPCMetadata_Empty(t *testing.T) {
	err := &TrustedCAError{
		Type:   Malformed,
		Detail: "simple error",
	}

	data, marshalErr := err.ToGRPCMetadata()
	if marshalErr != nil {
		t.Fatalf("ToGRPCMetadata() error = %v", marshalErr)
	}

	decoded, decodeErr := FromGRPCMetadata(data)
	if decodeErr != nil {
		t.Fatalf("FromGRPCMetadata() error = %v", decodeErr)
	}

	if decoded.Type != Malformed {
		t.Errorf("Type = %v, want %v", decoded.Type, Malformed)
	}
	if len(decoded.SubErrors) != 0 {
		t.Errorf("SubErrors len = %d, want 0", len(decoded.SubErrors))
	}
}

func TestFromGRPCMetadata_InvalidJSON(t *testing.T) {
	_, err := FromGRPCMetadata([]byte("invalid json"))
	if err == nil {
		t.Error("FromGRPCMetadata() expected error for invalid JSON")
	}
}

func TestFromGRPCMetadata_NilSubError(t *testing.T) {
	// Test that nil TrustedCAError in SubError is handled
	err := &TrustedCAError{
		Type:   CompoundError,
		Detail: "compound",
		SubErrors: []SubError{
			{
				TrustedCAError: nil, // This should be skipped
				Identifier:     ACMEIdentifier{Type: "dns", Value: "test.com"},
			},
		},
	}

	data, marshalErr := err.ToGRPCMetadata()
	if marshalErr != nil {
		t.Fatalf("ToGRPCMetadata() error = %v", marshalErr)
	}

	decoded, decodeErr := FromGRPCMetadata(data)
	if decodeErr != nil {
		t.Fatalf("FromGRPCMetadata() error = %v", decodeErr)
	}

	// Should have no sub-errors since the nil one was skipped
	if len(decoded.SubErrors) != 0 {
		t.Errorf("SubErrors len = %d, want 0", len(decoded.SubErrors))
	}
}

func TestGRPCMetadataKey(t *testing.T) {
	key := GRPCMetadataKey()
	if key != "trustedca-error-bin" {
		t.Errorf("GRPCMetadataKey() = %q, want 'trustedca-error-bin'", key)
	}
}

func TestFromGRPCStatus(t *testing.T) {
	tests := []struct {
		name         string
		status       *status.Status
		expectedType ErrorType
		expectedNil  bool
	}{
		{
			name:        "nil status",
			status:      nil,
			expectedNil: true,
		},
		{
			name:         "InvalidArgument",
			status:       status.New(codes.InvalidArgument, "bad input"),
			expectedType: Malformed,
		},
		{
			name:         "PermissionDenied",
			status:       status.New(codes.PermissionDenied, "denied"),
			expectedType: Unauthorized,
		},
		{
			name:         "NotFound",
			status:       status.New(codes.NotFound, "not found"),
			expectedType: NotFound,
		},
		{
			name:         "ResourceExhausted",
			status:       status.New(codes.ResourceExhausted, "exhausted"),
			expectedType: RateLimit,
		},
		{
			name:         "Unavailable",
			status:       status.New(codes.Unavailable, "unavailable"),
			expectedType: ConnectionFailure,
		},
		{
			name:         "FailedPrecondition",
			status:       status.New(codes.FailedPrecondition, "precondition"),
			expectedType: OrderNotReady,
		},
		{
			name:         "AlreadyExists",
			status:       status.New(codes.AlreadyExists, "exists"),
			expectedType: Duplicate,
		},
		{
			name:         "Unauthenticated",
			status:       status.New(codes.Unauthenticated, "unauthenticated"),
			expectedType: InvalidToken,
		},
		{
			name:         "DeadlineExceeded",
			status:       status.New(codes.DeadlineExceeded, "timeout"),
			expectedType: ChallengeTimeout,
		},
		{
			name:         "Internal",
			status:       status.New(codes.Internal, "internal"),
			expectedType: InternalServer,
		},
		{
			name:         "Unknown maps to InternalServer",
			status:       status.New(codes.Unknown, "unknown"),
			expectedType: InternalServer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromGRPCStatus(tt.status)
			if tt.expectedNil {
				if result != nil {
					t.Errorf("FromGRPCStatus() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatal("FromGRPCStatus() returned nil, want error")
			}
			if result.Type != tt.expectedType {
				t.Errorf("Type = %v, want %v", result.Type, tt.expectedType)
			}
			if result.Detail != tt.status.Message() {
				t.Errorf("Detail = %q, want %q", result.Detail, tt.status.Message())
			}
		})
	}
}

func TestGRPCCodeToErrorType(t *testing.T) {
	// Test all mapped codes
	mappings := map[codes.Code]ErrorType{
		codes.InvalidArgument:    Malformed,
		codes.PermissionDenied:   Unauthorized,
		codes.NotFound:           NotFound,
		codes.ResourceExhausted:  RateLimit,
		codes.Unavailable:        ConnectionFailure,
		codes.FailedPrecondition: OrderNotReady,
		codes.AlreadyExists:      Duplicate,
		codes.Unauthenticated:    InvalidToken,
		codes.DeadlineExceeded:   ChallengeTimeout,
		codes.Internal:           InternalServer,
	}

	for code, expectedType := range mappings {
		result := grpcCodeToErrorType(code)
		if result != expectedType {
			t.Errorf("grpcCodeToErrorType(%v) = %v, want %v", code, result, expectedType)
		}
	}
}

func TestGRPCRoundTrip(t *testing.T) {
	// Create a complex error and verify it survives gRPC serialization
	original := &TrustedCAError{
		Type:       CompoundError,
		Detail:     "multiple validation errors",
		RetryAfter: 30 * time.Second,
		Instance:   "https://example.com/errors/12345",
		SubErrors: []SubError{
			{
				TrustedCAError: &TrustedCAError{
					Type:   BadCSR,
					Detail: "CSR missing required fields",
				},
				Identifier: ACMEIdentifier{Type: "dns", Value: "example.com"},
			},
			{
				TrustedCAError: &TrustedCAError{
					Type:   RejectedIdentifier,
					Detail: "domain on blocklist",
				},
				Identifier: ACMEIdentifier{Type: "dns", Value: "blocked.com"},
			},
		},
	}

	// Serialize
	data, err := original.ToGRPCMetadata()
	if err != nil {
		t.Fatalf("ToGRPCMetadata() error = %v", err)
	}

	// Deserialize
	restored, err := FromGRPCMetadata(data)
	if err != nil {
		t.Fatalf("FromGRPCMetadata() error = %v", err)
	}

	// Verify all fields
	if restored.Type != original.Type {
		t.Errorf("Type mismatch: got %v, want %v", restored.Type, original.Type)
	}
	if restored.Detail != original.Detail {
		t.Errorf("Detail mismatch: got %q, want %q", restored.Detail, original.Detail)
	}
	if restored.RetryAfter != original.RetryAfter {
		t.Errorf("RetryAfter mismatch: got %v, want %v", restored.RetryAfter, original.RetryAfter)
	}
	if restored.Instance != original.Instance {
		t.Errorf("Instance mismatch: got %q, want %q", restored.Instance, original.Instance)
	}
	if len(restored.SubErrors) != len(original.SubErrors) {
		t.Fatalf("SubErrors count mismatch: got %d, want %d",
			len(restored.SubErrors), len(original.SubErrors))
	}

	for i, se := range restored.SubErrors {
		orig := original.SubErrors[i]
		if se.TrustedCAError.Type != orig.TrustedCAError.Type {
			t.Errorf("SubError[%d].Type mismatch", i)
		}
		if se.TrustedCAError.Detail != orig.TrustedCAError.Detail {
			t.Errorf("SubError[%d].Detail mismatch", i)
		}
		if se.Identifier.Type != orig.Identifier.Type {
			t.Errorf("SubError[%d].Identifier.Type mismatch", i)
		}
		if se.Identifier.Value != orig.Identifier.Value {
			t.Errorf("SubError[%d].Identifier.Value mismatch", i)
		}
	}
}
