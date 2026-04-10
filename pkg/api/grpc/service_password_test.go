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

package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMapPasswordError(t *testing.T) {
	tests := []struct {
		name         string
		inputErr     error
		expectedCode codes.Code
		expectedMsg  string
	}{
		{
			name:         "nil error returns nil",
			inputErr:     nil,
			expectedCode: codes.OK,
			expectedMsg:  "",
		},
		{
			name:         "password not found",
			inputErr:     staticpw.ErrPasswordNotFound,
			expectedCode: codes.NotFound,
			expectedMsg:  "password not found",
		},
		{
			name:         "password exists",
			inputErr:     staticpw.ErrPasswordExists,
			expectedCode: codes.AlreadyExists,
			expectedMsg:  "password with this name already exists",
		},
		{
			name:         "store not locked",
			inputErr:     staticpw.ErrStoreNotLocked,
			expectedCode: codes.FailedPrecondition,
			expectedMsg:  "store is already unlocked",
		},
		{
			name:         "store already locked",
			inputErr:     staticpw.ErrStoreAlreadyLocked,
			expectedCode: codes.FailedPrecondition,
			expectedMsg:  "store is already locked",
		},
		{
			name:         "invalid name",
			inputErr:     staticpw.ErrInvalidName,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "name is required",
		},
		{
			name:         "empty password",
			inputErr:     staticpw.ErrEmptyPassword,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "password is required",
		},
		{
			name:         "invalid length",
			inputErr:     staticpw.ErrInvalidLength,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "invalid password length (min 8, max 128)",
		},
		{
			name:         "invalid scope",
			inputErr:     staticpw.ErrInvalidScope,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "invalid scope (use personal, shared, or all)",
		},
		{
			name:         "invalid tenant ID",
			inputErr:     staticpw.ErrInvalidTenantID,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "invalid tenant ID",
		},
		{
			name:         "invalid user ID",
			inputErr:     staticpw.ErrInvalidUserID,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "invalid user identity",
		},
		{
			name:         "invalid folder path",
			inputErr:     staticpw.ErrInvalidFolderPath,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "invalid folder path",
		},
		{
			name:         "folder path too deep",
			inputErr:     staticpw.ErrFolderPathTooDeep,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "folder path exceeds maximum depth",
		},
		{
			name:         "password read only",
			inputErr:     staticpw.ErrPasswordReadOnly,
			expectedCode: codes.PermissionDenied,
			expectedMsg:  "password is read-only",
		},
		{
			name:         "not owner",
			inputErr:     staticpw.ErrNotOwner,
			expectedCode: codes.PermissionDenied,
			expectedMsg:  "not the owner of this password",
		},
		{
			name:         "store closed",
			inputErr:     staticpw.ErrStoreClosed,
			expectedCode: codes.Unavailable,
			expectedMsg:  "password store is closed",
		},
		{
			name:         "store locked",
			inputErr:     staticpw.ErrStoreLocked,
			expectedCode: codes.FailedPrecondition,
			expectedMsg:  "password store is locked",
		},
		{
			name:         "not configured",
			inputErr:     staticpw.ErrNotConfigured,
			expectedCode: codes.Unavailable,
			expectedMsg:  "password store not configured",
		},
		{
			name:         "tenant sealed",
			inputErr:     seal.ErrTenantSealed,
			expectedCode: codes.Unavailable,
			expectedMsg:  "tenant barrier is sealed",
		},
		{
			name:         "tenant not found",
			inputErr:     seal.ErrTenantNotFound,
			expectedCode: codes.NotFound,
			expectedMsg:  "tenant not found",
		},
		{
			name:         "nil store",
			inputErr:     staticpw.ErrNilStore,
			expectedCode: codes.Internal,
			expectedMsg:  "password store not initialized",
		},
		{
			name:         "nil encrypter",
			inputErr:     staticpw.ErrNilEncrypter,
			expectedCode: codes.Internal,
			expectedMsg:  "encrypter not configured",
		},
		{
			name:         "nil barrier registry",
			inputErr:     staticpw.ErrNilBarrierRegistry,
			expectedCode: codes.Internal,
			expectedMsg:  "barrier registry not configured",
		},
		{
			name:         "xkms not configured",
			inputErr:     xkms.ErrNotConfigured,
			expectedCode: codes.Unavailable,
			expectedMsg:  "password store not configured",
		},
		{
			name:         "xkms operation not supported",
			inputErr:     xkms.ErrOperationNotSupported,
			expectedCode: codes.Unimplemented,
			expectedMsg:  "operation not supported",
		},
		{
			name:         "xkms nil request",
			inputErr:     xkms.ErrNilRequest,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "request is required",
		},
		{
			name:         "unknown error with 'not found'",
			inputErr:     errors.New("some resource not found"),
			expectedCode: codes.NotFound,
			expectedMsg:  "some resource not found",
		},
		{
			name:         "unknown error with 'already exists'",
			inputErr:     errors.New("item already exists"),
			expectedCode: codes.AlreadyExists,
			expectedMsg:  "item already exists",
		},
		{
			name:         "unknown error with 'locked'",
			inputErr:     errors.New("resource is locked"),
			expectedCode: codes.FailedPrecondition,
			expectedMsg:  "resource is locked",
		},
		{
			name:         "unknown error",
			inputErr:     errors.New("some other error"),
			expectedCode: codes.Internal,
			expectedMsg:  "some other error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapPasswordError(tt.inputErr)

			if tt.inputErr == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			st, ok := status.FromError(result)
			if !ok {
				t.Fatalf("expected gRPC status error, got %v", result)
			}

			if st.Code() != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, st.Code())
			}

			if st.Message() != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, st.Message())
			}
		})
	}
}

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		wantTime time.Time
	}{
		{
			name:    "empty string",
			input:   "",
			wantNil: true,
		},
		{
			name:     "valid RFC3339",
			input:    "2025-01-15T10:30:00Z",
			wantNil:  false,
			wantTime: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		},
		{
			name:    "invalid format",
			input:   "not-a-timestamp",
			wantNil: true,
		},
		{
			name:     "RFC3339 with timezone",
			input:    "2025-03-03T15:00:00-08:00",
			wantNil:  false,
			wantTime: time.Date(2025, 3, 3, 23, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseTimestamp(tt.input)

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil timestamp")
			}

			resultTime := result.AsTime()
			if !resultTime.Equal(tt.wantTime) {
				t.Errorf("expected time %v, got %v", tt.wantTime, resultTime)
			}
		})
	}
}

func TestPasswordAdd_Validation(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	tests := []struct {
		name         string
		req          *pb.PasswordAddRequest
		expectedCode codes.Code
		expectedMsg  string
	}{
		{
			name:         "nil request",
			req:          nil,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "request is required",
		},
		{
			name:         "empty name",
			req:          &pb.PasswordAddRequest{Name: "", Password: "secret"},
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "name is required",
		},
		{
			name:         "empty password",
			req:          &pb.PasswordAddRequest{Name: "test", Password: ""},
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "password is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.PasswordAdd(ctx, tt.req)

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %v", err)
			}

			if st.Code() != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, st.Code())
			}

			if st.Message() != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, st.Message())
			}
		})
	}
}

func TestPasswordGet_Validation(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	tests := []struct {
		name         string
		req          *pb.PasswordGetRequest
		expectedCode codes.Code
		expectedMsg  string
	}{
		{
			name:         "nil request",
			req:          nil,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "request is required",
		},
		{
			name:         "empty id",
			req:          &pb.PasswordGetRequest{Id: ""},
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.PasswordGet(ctx, tt.req)

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %v", err)
			}

			if st.Code() != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, st.Code())
			}

			if st.Message() != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, st.Message())
			}
		})
	}
}

func TestPasswordUpdate_Validation(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	tests := []struct {
		name         string
		req          *pb.PasswordUpdateRequest
		expectedCode codes.Code
		expectedMsg  string
	}{
		{
			name:         "nil request",
			req:          nil,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "request is required",
		},
		{
			name:         "empty id",
			req:          &pb.PasswordUpdateRequest{Id: ""},
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.PasswordUpdate(ctx, tt.req)

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %v", err)
			}

			if st.Code() != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, st.Code())
			}

			if st.Message() != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, st.Message())
			}
		})
	}
}

func TestPasswordDelete_Validation(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	tests := []struct {
		name         string
		req          *pb.PasswordDeleteRequest
		expectedCode codes.Code
		expectedMsg  string
	}{
		{
			name:         "nil request",
			req:          nil,
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "request is required",
		},
		{
			name:         "empty id",
			req:          &pb.PasswordDeleteRequest{Id: ""},
			expectedCode: codes.InvalidArgument,
			expectedMsg:  "id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.PasswordDelete(ctx, tt.req)

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %v", err)
			}

			if st.Code() != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, st.Code())
			}

			if st.Message() != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, st.Message())
			}
		})
	}
}

func TestPasswordList_NilRequest(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	// PasswordList should accept nil request (uses defaults)
	_, err := svc.PasswordList(ctx, nil)

	// Without xkms initialized, we expect an unavailable error
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}

	if st.Code() != codes.Unavailable {
		t.Errorf("expected code Unavailable, got %v", st.Code())
	}
}

func TestPasswordGenerate_NilRequest(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	// PasswordGenerate should accept nil request (uses defaults)
	_, err := svc.PasswordGenerate(ctx, nil)

	// Without xkms initialized, we expect an unavailable error
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}

	if st.Code() != codes.Unavailable {
		t.Errorf("expected code Unavailable, got %v", st.Code())
	}
}

func TestPasswordStoreUnlock_NilRequest(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	// PasswordStoreUnlock should accept nil request
	_, err := svc.PasswordStoreUnlock(ctx, nil)

	// Without xkms initialized, we expect an unavailable error
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}

	if st.Code() != codes.Unavailable {
		t.Errorf("expected code Unavailable, got %v", st.Code())
	}
}

func TestPasswordStoreLock_NilRequest(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	// PasswordStoreLock accepts nil request (no parameters)
	_, err := svc.PasswordStoreLock(ctx, nil)

	// Without xkms initialized, we expect an unavailable error
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}

	if st.Code() != codes.Unavailable {
		t.Errorf("expected code Unavailable, got %v", st.Code())
	}
}

func TestPasswordStoreStatus_NilRequest(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	// PasswordStoreStatus accepts nil request (no parameters)
	_, err := svc.PasswordStoreStatus(ctx, nil)

	// Without xkms initialized, we expect an unavailable error
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}

	if st.Code() != codes.Unavailable {
		t.Errorf("expected code Unavailable, got %v", st.Code())
	}
}
