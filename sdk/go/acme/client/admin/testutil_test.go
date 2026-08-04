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

package admin

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// Shared sentinel errors for transport-failure test scenarios.
var (
	errTestUnavailable      = errors.New("unavailable")
	errTestNotFound         = errors.New("not found")
	errTestForbidden        = errors.New("forbidden")
	errTestConnRefused      = errors.New("connection refused")
	errTestConflict         = errors.New("conflict")
	errTestServerError      = errors.New("server error")
	errTestInternalError    = errors.New("internal error")
	errTestRevocationFailed = errors.New("revocation failed")

	// errMockNoRequestFunc is returned by mockTransport when no request
	// function is configured.
	errMockNoRequestFunc = errors.New("mock: no request function configured")

	// errMockStreamingUnsupported is returned by mockTransport for streaming requests.
	errMockStreamingUnsupported = errors.New("mock: streaming not supported")
)

// mockTransport implements transport.Transport for testing.
type mockTransport struct {
	requestFunc func(ctx context.Context, service, method string, req interface{}) (interface{}, error)
}

func (m *mockTransport) Request(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
	if m.requestFunc != nil {
		return m.requestFunc(ctx, service, method, req)
	}
	return nil, errMockNoRequestFunc
}

func (m *mockTransport) RequestStream(_ context.Context, _, _ string, _ interface{}) (transport.Stream, error) {
	return nil, errMockStreamingUnsupported
}

func (m *mockTransport) Conn() interface{} { return nil }
func (m *mockTransport) Close() error      { return nil }
func (m *mockTransport) Healthy() bool     { return true }

// newMockTransportWithResponse creates a mock transport that returns the given
// value as JSON-marshaled map (simulating a REST-like transport response).
func newMockTransportWithResponse(response interface{}) *mockTransport {
	return &mockTransport{
		requestFunc: func(_ context.Context, _, _ string, _ interface{}) (interface{}, error) {
			jsonBytes, err := json.Marshal(response)
			if err != nil {
				return nil, err
			}
			var result map[string]interface{}
			if err := json.Unmarshal(jsonBytes, &result); err != nil {
				return nil, err
			}
			return result, nil
		},
	}
}

// newMockTransportWithError creates a mock transport that returns an error.
func newMockTransportWithError(err error) *mockTransport {
	return &mockTransport{
		requestFunc: func(_ context.Context, _, _ string, _ interface{}) (interface{}, error) {
			return nil, err
		},
	}
}

// newMockTransportNilResponse creates a mock transport that returns nil.
func newMockTransportNilResponse() *mockTransport {
	return &mockTransport{
		requestFunc: func(_ context.Context, _, _ string, _ interface{}) (interface{}, error) {
			return nil, nil
		},
	}
}
