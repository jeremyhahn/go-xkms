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

package admin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// mockTransport implements transport.Transport for testing.
type mockTransport struct {
	requestFunc func(ctx context.Context, service, method string, req interface{}) (interface{}, error)
}

func (m *mockTransport) Request(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
	if m.requestFunc != nil {
		return m.requestFunc(ctx, service, method, req)
	}
	return nil, fmt.Errorf("mock: no request function configured")
}

func (m *mockTransport) RequestStream(_ context.Context, _, _ string, _ interface{}) (transport.Stream, error) {
	return nil, fmt.Errorf("mock: streaming not supported")
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

// newMockTransportWithServiceRouter creates a mock transport that routes
// based on service/method and returns the configured responses.
func newMockTransportWithServiceRouter(routes map[string]interface{}) *mockTransport {
	return &mockTransport{
		requestFunc: func(_ context.Context, service, method string, _ interface{}) (interface{}, error) {
			key := service + "/" + method
			resp, ok := routes[key]
			if !ok {
				return nil, fmt.Errorf("mock: no route for %s", key)
			}
			jsonBytes, err := json.Marshal(resp)
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
