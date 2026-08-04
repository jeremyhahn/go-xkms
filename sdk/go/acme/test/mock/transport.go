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

// Package mock provides test doubles for the Trusted CA SDK.
package mock

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// Compile-time interface check.
var _ transport.Transport = (*Transport)(nil)

// Transport is a mock transport for testing SDK clients.
// Each method delegates to a configurable function field, allowing
// tests to control transport behavior per-call.
type Transport struct {
	// RequestFunc is called by Request. If nil, returns (nil, nil).
	RequestFunc func(ctx context.Context, service, method string, req interface{}) (interface{}, error)

	// RequestStreamFunc is called by RequestStream. If nil, returns (nil, nil).
	RequestStreamFunc func(ctx context.Context, service, method string, req interface{}) (transport.Stream, error)

	// CloseFunc is called by Close. If nil, returns nil.
	CloseFunc func() error

	// HealthyFunc is called by Healthy. If nil, returns true.
	HealthyFunc func() bool

	// ConnFunc is called by Conn. If nil, returns nil.
	ConnFunc func() interface{}
}

// Request sends a unary request using the configured RequestFunc.
func (m *Transport) Request(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
	if m.RequestFunc != nil {
		return m.RequestFunc(ctx, service, method, req)
	}
	return nil, nil
}

// RequestStream initiates a streaming request using the configured RequestStreamFunc.
func (m *Transport) RequestStream(ctx context.Context, service, method string, req interface{}) (transport.Stream, error) {
	if m.RequestStreamFunc != nil {
		return m.RequestStreamFunc(ctx, service, method, req)
	}
	return nil, nil
}

// Close closes the mock transport using the configured CloseFunc.
func (m *Transport) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

// Healthy returns the health status using the configured HealthyFunc.
func (m *Transport) Healthy() bool {
	if m.HealthyFunc != nil {
		return m.HealthyFunc()
	}
	return true
}

// Conn returns the underlying connection using the configured ConnFunc.
func (m *Transport) Conn() interface{} {
	if m.ConnFunc != nil {
		return m.ConnFunc()
	}
	return nil
}
