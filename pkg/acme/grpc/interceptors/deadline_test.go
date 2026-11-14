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

package interceptors

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestDeadlineConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *DeadlineConfig
		wantErr bool
	}{
		{
			name: "zero values are valid",
			config: &DeadlineConfig{
				ReturnOverhead:   0,
				MinimumRemaining: 0,
			},
			wantErr: false,
		},
		{
			name: "negative return overhead",
			config: &DeadlineConfig{
				ReturnOverhead:   -1 * time.Millisecond,
				MinimumRemaining: 100 * time.Millisecond,
			},
			wantErr: true,
		},
		{
			name: "negative minimum remaining",
			config: &DeadlineConfig{
				ReturnOverhead:   20 * time.Millisecond,
				MinimumRemaining: -1 * time.Millisecond,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultDeadlineConfig(t *testing.T) {
	config := DefaultDeadlineConfig()

	assert.Equal(t, DefaultReturnOverhead, config.ReturnOverhead)
	assert.Equal(t, MinimumRemainingTime, config.MinimumRemaining)
	assert.NoError(t, config.Validate())
}

func TestDeadlineInterceptor_SufficientTime(t *testing.T) {
	interceptor := DeadlineInterceptor(20 * time.Millisecond)

	// Set deadline with plenty of time
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	handlerCalled := false
	var handlerDeadline time.Time

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		deadline, ok := ctx.Deadline()
		assert.True(t, ok)
		handlerDeadline = deadline
		return "result", nil
	}

	originalDeadline, _ := ctx.Deadline()
	result, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, "result", result)

	// Handler should have received adjusted deadline (earlier than original)
	assert.True(t, handlerDeadline.Before(originalDeadline),
		"handler deadline should be before original deadline")
}

func TestDeadlineInterceptor_InsufficientTime(t *testing.T) {
	interceptor := DeadlineInterceptor(20 * time.Millisecond)

	// Set deadline with very little time (less than minimum + overhead)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "result", nil
	}

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.Error(t, err)
	assert.False(t, handlerCalled, "handler should not be called when insufficient time")

	// Should be DeadlineExceeded status
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
	assert.Contains(t, st.Message(), "insufficient time")
}

func TestDeadlineInterceptor_ExactMinimum(t *testing.T) {
	overhead := 20 * time.Millisecond
	interceptor := DeadlineInterceptor(overhead)

	// Set deadline at exactly minimum + overhead + small buffer
	ctx, cancel := context.WithTimeout(context.Background(), MinimumRemainingTime+overhead+10*time.Millisecond)
	defer cancel()

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "result", nil
	}

	result, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, "result", result)
}

func TestDeadlineInterceptorWithConfig_NilConfig(t *testing.T) {
	interceptor := DeadlineInterceptorWithConfig(nil)

	ctx := context.Background()
	handlerCalled := false

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		_, ok := ctx.Deadline()
		assert.False(t, ok, "no deadline should be set when context has none")
		return "result", nil
	}

	result, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, "result", result)
}

func TestDeadlineInterceptor_CustomConfig(t *testing.T) {
	config := &DeadlineConfig{
		ReturnOverhead:   50 * time.Millisecond,
		MinimumRemaining: 200 * time.Millisecond,
	}
	interceptor := DeadlineInterceptorWithConfig(config)

	// Should reject with 200ms remaining (need 200ms min + 50ms overhead)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "result", nil
	})

	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

func TestDeadlineInterceptor_ContextCancellation(t *testing.T) {
	interceptor := DeadlineInterceptor(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		// Verify context can be cancelled
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return "result", nil
		}
	}

	result, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, "result", result)
}

func TestStreamDeadlineInterceptor_SufficientTime(t *testing.T) {
	interceptor := StreamDeadlineInterceptor(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	mockStream := newMockServerStream(ctx)
	handlerCalled := false
	var streamDeadline time.Time

	originalDeadline, _ := ctx.Deadline()

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		deadline, ok := stream.Context().Deadline()
		assert.True(t, ok)
		streamDeadline = deadline
		return nil
	}

	err := interceptor(nil, mockStream, &grpc.StreamServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.True(t, streamDeadline.Before(originalDeadline))
}

func TestStreamDeadlineInterceptor_InsufficientTime(t *testing.T) {
	interceptor := StreamDeadlineInterceptor(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	mockStream := newMockServerStream(ctx)
	handlerCalled := false

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := interceptor(nil, mockStream, &grpc.StreamServerInfo{}, handler)

	require.Error(t, err)
	assert.False(t, handlerCalled)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

func TestStreamDeadlineInterceptorWithConfig_NilConfig(t *testing.T) {
	interceptor := StreamDeadlineInterceptorWithConfig(nil)

	mockStream := newMockServerStream(context.Background())
	handlerCalled := false

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		_, ok := stream.Context().Deadline()
		assert.False(t, ok, "no deadline should be set when context has none")
		return nil
	}

	err := interceptor(nil, mockStream, &grpc.StreamServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestChainedDeadlineInterceptor(t *testing.T) {
	nextInterceptorCalled := false
	nextInterceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		nextInterceptorCalled = true
		return handler(ctx, req)
	}

	chained := ChainedDeadlineInterceptor(20*time.Millisecond, nextInterceptor)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "result", nil
	}

	result, err := chained(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, nextInterceptorCalled)
	assert.True(t, handlerCalled)
	assert.Equal(t, "result", result)
}

func TestChainedDeadlineInterceptor_NilNext(t *testing.T) {
	chained := ChainedDeadlineInterceptor(20*time.Millisecond, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "result", nil
	}

	result, err := chained(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, "result", result)
}

func TestChainedDeadlineInterceptor_InsufficientTime(t *testing.T) {
	nextInterceptorCalled := false
	nextInterceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		nextInterceptorCalled = true
		return handler(ctx, req)
	}

	chained := ChainedDeadlineInterceptor(20*time.Millisecond, nextInterceptor)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := chained(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "result", nil
	})

	require.Error(t, err)
	assert.False(t, nextInterceptorCalled, "next interceptor should not be called when insufficient time")
}

func TestChainedDeadlineInterceptorWithConfig_NilConfig(t *testing.T) {
	chained := ChainedDeadlineInterceptorWithConfig(nil, nil)

	ctx := context.Background()
	handlerCalled := false

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "result", nil
	}

	result, err := chained(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, "result", result)
}

func TestChainedStreamDeadlineInterceptor(t *testing.T) {
	nextInterceptorCalled := false
	nextInterceptor := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		nextInterceptorCalled = true
		return handler(srv, ss)
	}

	chained := ChainedStreamDeadlineInterceptor(20*time.Millisecond, nextInterceptor)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	mockStream := newMockServerStream(ctx)
	handlerCalled := false

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := chained(nil, mockStream, &grpc.StreamServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, nextInterceptorCalled)
	assert.True(t, handlerCalled)
}

func TestChainedStreamDeadlineInterceptor_NilNext(t *testing.T) {
	chained := ChainedStreamDeadlineInterceptor(20*time.Millisecond, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	mockStream := newMockServerStream(ctx)
	handlerCalled := false

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := chained(nil, mockStream, &grpc.StreamServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestChainedStreamDeadlineInterceptor_InsufficientTime(t *testing.T) {
	nextInterceptorCalled := false
	nextInterceptor := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		nextInterceptorCalled = true
		return handler(srv, ss)
	}

	chained := ChainedStreamDeadlineInterceptor(20*time.Millisecond, nextInterceptor)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	mockStream := newMockServerStream(ctx)
	handlerCalled := false

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := chained(nil, mockStream, &grpc.StreamServerInfo{}, handler)

	require.Error(t, err)
	assert.False(t, nextInterceptorCalled, "next interceptor should not be called when insufficient time")
	assert.False(t, handlerCalled)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

func TestChainedStreamDeadlineInterceptorWithConfig_NilConfig(t *testing.T) {
	chained := ChainedStreamDeadlineInterceptorWithConfig(nil, nil)

	mockStream := newMockServerStream(context.Background())
	handlerCalled := false

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := chained(nil, mockStream, &grpc.StreamServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestRemainingTime(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		overhead time.Duration
		wantZero bool
	}{
		{
			name:     "no deadline",
			ctx:      context.Background(),
			overhead: 20 * time.Millisecond,
			wantZero: true,
		},
		{
			name: "deadline with overhead",
			ctx: func() context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				_ = cancel // Don't call yet, but keep reference
				return ctx
			}(),
			overhead: 20 * time.Millisecond,
			wantZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remaining := RemainingTime(tt.ctx, tt.overhead)
			if tt.wantZero {
				assert.Zero(t, remaining)
			} else {
				assert.Greater(t, remaining, time.Duration(0))
			}
		})
	}
}

func TestRemainingTime_Expired(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	remaining := RemainingTime(ctx, 0)
	assert.Zero(t, remaining)
}

func TestHasSufficientTime(t *testing.T) {
	tests := []struct {
		name     string
		timeout  time.Duration
		overhead time.Duration
		minimum  time.Duration
		want     bool
	}{
		{
			name:     "sufficient time",
			timeout:  500 * time.Millisecond,
			overhead: 20 * time.Millisecond,
			minimum:  100 * time.Millisecond,
			want:     true,
		},
		{
			name:     "insufficient time",
			timeout:  50 * time.Millisecond,
			overhead: 20 * time.Millisecond,
			minimum:  100 * time.Millisecond,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			result := HasSufficientTime(ctx, tt.overhead, tt.minimum)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestHasSufficientTime_NoDeadline(t *testing.T) {
	// No deadline means unlimited time
	result := HasSufficientTime(context.Background(), 20*time.Millisecond, 100*time.Millisecond)
	assert.True(t, result)
}

func TestDeadlineServerStream_Context(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	originalStream := newMockServerStream(context.Background())
	wrappedStream := &deadlineServerStream{
		ServerStream: originalStream,
		ctx:          ctx,
	}

	// Wrapped stream should return the custom context
	assert.Equal(t, ctx, wrappedStream.Context())

	// Verify deadline is accessible
	deadline, ok := wrappedStream.Context().Deadline()
	assert.True(t, ok)
	assert.False(t, deadline.IsZero())
}

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	ctx context.Context
}

func newMockServerStream(ctx context.Context) *mockServerStream {
	return &mockServerStream{ctx: ctx}
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SetHeader(md metadata.MD) error {
	return nil
}

func (m *mockServerStream) SendHeader(md metadata.MD) error {
	return nil
}

func (m *mockServerStream) SetTrailer(md metadata.MD) {
}

func (m *mockServerStream) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockServerStream) RecvMsg(msg interface{}) error {
	return nil
}
