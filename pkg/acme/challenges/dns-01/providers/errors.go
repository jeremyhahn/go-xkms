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

package providers

import "errors"

// Sentinel errors for DNS provider operations
var (
	// ErrProviderNotFound is returned when a requested provider is not registered.
	ErrProviderNotFound = errors.New("dns01: provider not found")

	// ErrInvalidConfig is returned when provider configuration is invalid.
	ErrInvalidConfig = errors.New("dns01: invalid provider configuration")

	// ErrMissingCredentials is returned when required credentials are not provided.
	ErrMissingCredentials = errors.New("dns01: missing credentials")

	// ErrAmbientCredentialsDisabled is returned when ambient credentials are required but disabled.
	ErrAmbientCredentialsDisabled = errors.New("dns01: ambient credentials are disabled")

	// ErrZoneNotFound is returned when the DNS zone cannot be found.
	ErrZoneNotFound = errors.New("dns01: zone not found")

	// ErrRecordNotFound is returned when the DNS record cannot be found.
	ErrRecordNotFound = errors.New("dns01: record not found")

	// ErrRecordCreateFailed is returned when creating a DNS record fails.
	ErrRecordCreateFailed = errors.New("dns01: failed to create record")

	// ErrRecordDeleteFailed is returned when deleting a DNS record fails.
	ErrRecordDeleteFailed = errors.New("dns01: failed to delete record")

	// ErrPropagationTimeout is returned when DNS propagation takes too long.
	ErrPropagationTimeout = errors.New("dns01: propagation timeout")

	// ErrAPIError is returned when the DNS provider API returns an error.
	ErrAPIError = errors.New("dns01: API error")

	// ErrInvalidCredentials is returned when credentials are invalid or malformed.
	ErrInvalidCredentials = errors.New("dns01: invalid credentials")

	// ErrRateLimited is returned when the provider API rate limits requests.
	ErrRateLimited = errors.New("dns01: rate limited")
)

// ProviderError wraps an error with additional context about the provider operation.
type ProviderError struct {
	Provider  string
	Operation string
	Domain    string
	Err       error
}

// Error implements the error interface.
func (e *ProviderError) Error() string {
	if e.Domain != "" {
		return e.Provider + ": " + e.Operation + " for " + e.Domain + ": " + e.Err.Error()
	}
	return e.Provider + ": " + e.Operation + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ProviderError) Unwrap() error {
	return e.Err
}

// NewProviderError creates a new ProviderError.
func NewProviderError(provider, operation, domain string, err error) *ProviderError {
	return &ProviderError{
		Provider:  provider,
		Operation: operation,
		Domain:    domain,
		Err:       err,
	}
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Provider string
	Field    string
	Message  string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return e.Provider + ": configuration error: " + e.Field + ": " + e.Message
}

// NewConfigError creates a new ConfigError.
func NewConfigError(provider, field, message string) *ConfigError {
	return &ConfigError{
		Provider: provider,
		Field:    field,
		Message:  message,
	}
}

// APIError represents an error returned by a DNS provider API.
type APIError struct {
	Provider   string
	StatusCode int
	Message    string
	RequestID  string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	msg := e.Provider + ": API error"
	if e.StatusCode != 0 {
		msg += " (status " + string(rune(e.StatusCode+'0')) + ")"
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.RequestID != "" {
		msg += " [request_id=" + e.RequestID + "]"
	}
	return msg
}

// NewAPIError creates a new APIError.
func NewAPIError(provider string, statusCode int, message, requestID string) *APIError {
	return &APIError{
		Provider:   provider,
		StatusCode: statusCode,
		Message:    message,
		RequestID:  requestID,
	}
}
