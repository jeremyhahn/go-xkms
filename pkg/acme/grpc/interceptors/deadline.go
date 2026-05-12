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

package interceptors

import (
	"context"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// DefaultReturnOverhead is the default time subtracted from deadline
	// to account for network return overhead.
	DefaultReturnOverhead = 20 * time.Millisecond

	// MinimumRemainingTime is the minimum time required to process a request.
	// Requests with less remaining time are rejected immediately.
	MinimumRemainingTime = 100 * time.Millisecond
)

// DeadlineConfig contains configuration for deadline interceptors.
type DeadlineConfig struct {
	// ReturnOverhead is the time to subtract from the deadline to account
	// for network overhead when sending the response back to the client.
	ReturnOverhead time.Duration

	// MinimumRemaining is the minimum time that must remain after subtracting
	// the return overhead for a request to be processed.
	MinimumRemaining time.Duration
}

// DefaultDeadlineConfig returns a DeadlineConfig with default values.
func DefaultDeadlineConfig() *DeadlineConfig {
	return &DeadlineConfig{
		ReturnOverhead:   DefaultReturnOverhead,
		MinimumRemaining: MinimumRemainingTime,
	}
}

// Validate validates the deadline configuration.
func (c *DeadlineConfig) Validate() error {
	if c.ReturnOverhead < 0 {
		return ErrInvalidOverhead
	}
	if c.MinimumRemaining < 0 {
		return caerrors.MalformedError("interceptors: minimum remaining must be >= 0")
	}
	return nil
}

// DeadlineInterceptor creates a unary server interceptor that properly manages
// client deadlines by subtracting return overhead. This ensures that handlers
// complete before the client's deadline, accounting for network latency.
//
// The interceptor:
//   - Subtracts returnOverhead from the client's deadline
//   - Rejects requests if remaining time < MinimumRemainingTime
//   - Passes through requests without deadlines unchanged
//
// Example:
//
//	server := grpc.NewServer(
//	    grpc.UnaryInterceptor(interceptors.DeadlineInterceptor(20*time.Millisecond)),
//	)
func DeadlineInterceptor(returnOverhead time.Duration) grpc.UnaryServerInterceptor {
	config := &DeadlineConfig{
		ReturnOverhead:   returnOverhead,
		MinimumRemaining: MinimumRemainingTime,
	}
	return DeadlineInterceptorWithConfig(config)
}

// DeadlineInterceptorWithConfig creates a unary server interceptor with
// custom configuration for deadline management.
func DeadlineInterceptorWithConfig(config *DeadlineConfig) grpc.UnaryServerInterceptor {
	if config == nil {
		config = DefaultDeadlineConfig()
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			// No deadline set - pass through unchanged
			return handler(ctx, req)
		}

		remaining := time.Until(deadline) - config.ReturnOverhead
		if remaining < config.MinimumRemaining {
			return nil, status.Errorf(
				codes.DeadlineExceeded,
				"insufficient time for request processing: %v remaining, %v minimum required",
				remaining,
				config.MinimumRemaining,
			)
		}

		// Create new context with adjusted deadline
		ctx, cancel := context.WithTimeout(ctx, remaining)
		defer cancel()

		return handler(ctx, req)
	}
}

// StreamDeadlineInterceptor creates a stream server interceptor that properly
// manages client deadlines by subtracting return overhead.
//
// For streaming RPCs, the deadline is applied to the entire stream lifecycle.
// Individual message sends/receives within the stream will inherit this deadline.
func StreamDeadlineInterceptor(returnOverhead time.Duration) grpc.StreamServerInterceptor {
	config := &DeadlineConfig{
		ReturnOverhead:   returnOverhead,
		MinimumRemaining: MinimumRemainingTime,
	}
	return StreamDeadlineInterceptorWithConfig(config)
}

// StreamDeadlineInterceptorWithConfig creates a stream server interceptor with
// custom configuration for deadline management.
func StreamDeadlineInterceptorWithConfig(config *DeadlineConfig) grpc.StreamServerInterceptor {
	if config == nil {
		config = DefaultDeadlineConfig()
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		deadline, ok := ctx.Deadline()
		if !ok {
			// No deadline set - pass through unchanged
			return handler(srv, ss)
		}

		remaining := time.Until(deadline) - config.ReturnOverhead
		if remaining < config.MinimumRemaining {
			return status.Errorf(
				codes.DeadlineExceeded,
				"insufficient time for request processing: %v remaining, %v minimum required",
				remaining,
				config.MinimumRemaining,
			)
		}

		// Wrap the stream with adjusted deadline context
		ctx, cancel := context.WithTimeout(ctx, remaining)
		defer cancel()

		wrappedStream := &deadlineServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		return handler(srv, wrappedStream)
	}
}

// deadlineServerStream wraps a grpc.ServerStream with a modified context.
type deadlineServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context with adjusted deadline.
func (s *deadlineServerStream) Context() context.Context {
	return s.ctx
}

// ChainedDeadlineInterceptor chains deadline management with another interceptor.
// The deadline adjustment happens before the next interceptor is called.
func ChainedDeadlineInterceptor(returnOverhead time.Duration, next grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	config := &DeadlineConfig{
		ReturnOverhead:   returnOverhead,
		MinimumRemaining: MinimumRemainingTime,
	}
	return ChainedDeadlineInterceptorWithConfig(config, next)
}

// ChainedDeadlineInterceptorWithConfig chains deadline management with another
// interceptor using custom configuration.
func ChainedDeadlineInterceptorWithConfig(config *DeadlineConfig, next grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	if config == nil {
		config = DefaultDeadlineConfig()
	}

	deadlineInterceptor := DeadlineInterceptorWithConfig(config)

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Apply deadline adjustment first
		return deadlineInterceptor(ctx, req, info, func(adjustedCtx context.Context, req interface{}) (interface{}, error) {
			if next != nil {
				// Chain to next interceptor
				return next(adjustedCtx, req, info, handler)
			}
			return handler(adjustedCtx, req)
		})
	}
}

// ChainedStreamDeadlineInterceptor chains deadline management with another
// stream interceptor.
func ChainedStreamDeadlineInterceptor(returnOverhead time.Duration, next grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	config := &DeadlineConfig{
		ReturnOverhead:   returnOverhead,
		MinimumRemaining: MinimumRemainingTime,
	}
	return ChainedStreamDeadlineInterceptorWithConfig(config, next)
}

// ChainedStreamDeadlineInterceptorWithConfig chains deadline management with
// another stream interceptor using custom configuration.
func ChainedStreamDeadlineInterceptorWithConfig(config *DeadlineConfig, next grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	if config == nil {
		config = DefaultDeadlineConfig()
	}

	deadlineInterceptor := StreamDeadlineInterceptorWithConfig(config)

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Create a wrapper handler that applies deadline adjustment
		return deadlineInterceptor(srv, ss, info, func(srv interface{}, adjustedStream grpc.ServerStream) error {
			if next != nil {
				// Chain to next interceptor
				return next(srv, adjustedStream, info, handler)
			}
			return handler(srv, adjustedStream)
		})
	}
}

// RemainingTime returns the remaining time from the context deadline minus
// the specified overhead. Returns 0 if no deadline is set.
func RemainingTime(ctx context.Context, overhead time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	remaining := time.Until(deadline) - overhead
	if remaining < 0 {
		return 0
	}
	return remaining
}

// HasSufficientTime checks if the context has sufficient time remaining
// (after subtracting overhead) to meet the minimum requirement.
func HasSufficientTime(ctx context.Context, overhead, minimum time.Duration) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true // No deadline means unlimited time
	}
	remaining := time.Until(deadline) - overhead
	return remaining >= minimum
}
