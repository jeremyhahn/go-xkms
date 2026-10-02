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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/correlation"

// Request correlation. Every xkmsd transport stamps a correlation ID on each
// request and echoes it to the client; a host that composes xkms surfaces
// installs the same middleware so one ID follows a request across layers.

const (
	// CorrelationIDHeader is the HTTP header carrying a correlation ID.
	CorrelationIDHeader = correlation.CorrelationIDHeader
	// CorrelationRequestIDHeader is the HTTP header read when
	// CorrelationIDHeader is absent.
	CorrelationRequestIDHeader = correlation.RequestIDHeader
	// CorrelationGRPCIDKey is the gRPC metadata key carrying a correlation ID.
	CorrelationGRPCIDKey = correlation.GRPCCorrelationIDKey
	// CorrelationGRPCRequestIDKey is the gRPC metadata key read when
	// CorrelationGRPCIDKey is absent.
	CorrelationGRPCRequestIDKey = correlation.GRPCRequestIDKey
)

// WithCorrelationID returns a context carrying a correlation ID.
var WithCorrelationID = correlation.WithCorrelationID

// CorrelationIDFromContext returns the correlation ID a context carries, or
// "".
var CorrelationIDFromContext = correlation.GetCorrelationID

// NewCorrelationID returns a fresh correlation ID (a UUID v4).
var NewCorrelationID = correlation.NewID

// CorrelationIDOrNew returns the context's correlation ID, or a fresh one.
var CorrelationIDOrNew = correlation.GetOrGenerate

// CorrelationMiddleware returns HTTP middleware that reads or generates a
// request's correlation ID, stores it in the request context and echoes it in
// the X-Correlation-ID response header.
var CorrelationMiddleware = correlation.Middleware

// CorrelationUnaryServerInterceptor is the gRPC unary form of
// CorrelationMiddleware. A failure to send the response header is logged to
// the given logger (slog.Default when nil) and does not fail the call.
var CorrelationUnaryServerInterceptor = correlation.UnaryServerInterceptor

// CorrelationStreamServerInterceptor is the gRPC stream form of
// CorrelationMiddleware.
var CorrelationStreamServerInterceptor = correlation.StreamServerInterceptor
