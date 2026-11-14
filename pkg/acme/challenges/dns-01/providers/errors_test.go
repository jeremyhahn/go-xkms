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

package providers

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProviderError(t *testing.T) {
	tests := []struct {
		name      string
		provider  string
		operation string
		domain    string
		err       error
		expected  string
	}{
		{
			name:      "with domain",
			provider:  "route53",
			operation: "create record",
			domain:    "example.com",
			err:       errors.New("API error"),
			expected:  "route53: create record for example.com: API error",
		},
		{
			name:      "without domain",
			provider:  "cloudflare",
			operation: "authenticate",
			domain:    "",
			err:       errors.New("invalid token"),
			expected:  "cloudflare: authenticate: invalid token",
		},
		{
			name:      "with sentinel error",
			provider:  "azure",
			operation: "get zone",
			domain:    "test.com",
			err:       ErrZoneNotFound,
			expected:  "azure: get zone for test.com: dns01: zone not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewProviderError(tt.provider, tt.operation, tt.domain, tt.err)
			assert.Equal(t, tt.expected, err.Error())
			assert.ErrorIs(t, err, tt.err)
			assert.Equal(t, tt.err, errors.Unwrap(err))
			assert.NotErrorIs(t, err, ErrRecordNotFound)
		})
	}
}

func TestConfigError(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		field    string
		message  string
		expected string
	}{
		{
			name:     "missing field",
			provider: "route53",
			field:    "access_key_id",
			message:  "is required",
			expected: "route53: configuration error: access_key_id: is required",
		},
		{
			name:     "invalid value",
			provider: "cloudflare",
			field:    "api_token",
			message:  "contains invalid characters",
			expected: "cloudflare: configuration error: api_token: contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewConfigError(tt.provider, tt.field, tt.message)
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestAPIError(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		statusCode int
		message    string
		requestID  string
		expected   string
	}{
		{
			name:       "with all fields",
			provider:   "route53",
			statusCode: 400,
			message:    "Invalid parameter",
			requestID:  "abc123",
			expected:   "route53: API error (status (: Invalid parameter [request_id=abc123]",
		},
		{
			name:       "message only",
			provider:   "cloudflare",
			statusCode: 0,
			message:    "Rate limited",
			requestID:  "",
			expected:   "cloudflare: API error: Rate limited",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAPIError(tt.provider, tt.statusCode, tt.message, tt.requestID)
			assert.NotEmpty(t, err.Error())
			assert.Equal(t, tt.provider, err.Provider)
			assert.Equal(t, tt.statusCode, err.StatusCode)
			assert.Equal(t, tt.message, err.Message)
			assert.Equal(t, tt.requestID, err.RequestID)
		})
	}
}
