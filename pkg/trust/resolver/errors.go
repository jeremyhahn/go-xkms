// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package resolver

import (
	"fmt"
	"strings"
)

// ErrNilConfig indicates a nil *Config was passed to New.
type ErrNilConfig struct{}

func (e ErrNilConfig) Error() string {
	return "trust resolver: config is required"
}

// ErrScopeNotConfigured indicates the requested scope has no ScopeConfig.
type ErrScopeNotConfigured struct {
	Scope string
}

func (e *ErrScopeNotConfigured) Error() string {
	return fmt.Sprintf("trust resolver: scope %q is not configured", e.Scope)
}

// ErrInvalidConfig indicates a scope configuration field is missing or
// malformed.
type ErrInvalidConfig struct {
	Scope  string
	Field  string
	Reason string
}

func (e *ErrInvalidConfig) Error() string {
	if e.Scope == "" {
		return fmt.Sprintf("trust resolver: invalid config field %q: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("trust resolver: invalid config for scope %q field %q: %s", e.Scope, e.Field, e.Reason)
}

// ErrFetchFailed indicates a CA bundle fetch strategy failed.
type ErrFetchFailed struct {
	Strategy Strategy
	Cause    error
}

func (e *ErrFetchFailed) Error() string {
	return fmt.Sprintf("trust resolver: fetch via strategy %q failed: %v", e.Strategy, e.Cause)
}

// Unwrap returns the underlying fetch error.
func (e *ErrFetchFailed) Unwrap() error {
	return e.Cause
}

// ErrCABundleEmpty indicates a fetched or provided CA bundle contained
// no data.
type ErrCABundleEmpty struct{}

func (e ErrCABundleEmpty) Error() string {
	return "trust resolver: CA bundle is empty"
}

// ErrCABundleParse indicates a CA bundle contained no parseable PEM
// certificates.
type ErrCABundleParse struct{}

func (e ErrCABundleParse) Error() string {
	return "trust resolver: CA bundle contains no valid PEM certificates"
}

// ErrWriteFailed indicates a filesystem write failed while installing
// a CA bundle.
type ErrWriteFailed struct {
	Path string
	Err  error
}

func (e *ErrWriteFailed) Error() string {
	return fmt.Sprintf("trust resolver: write failed for %s: %v", e.Path, e.Err)
}

// Unwrap returns the underlying filesystem error.
func (e *ErrWriteFailed) Unwrap() error {
	return e.Err
}

// ErrProviderCAUnavailable indicates the provider-ca strategy was
// requested but no CABundleProvider was injected.
type ErrProviderCAUnavailable struct{}

func (e ErrProviderCAUnavailable) Error() string {
	return "trust resolver: provider-ca strategy requires a CA bundle provider"
}

// ErrPinNotFound indicates no SPKI pin is available for the endpoint:
// the PinStore has no entry and the scope carries no static pin.
type ErrPinNotFound struct {
	Endpoint string
}

func (e *ErrPinNotFound) Error() string {
	if e.Endpoint == "" {
		return "trust resolver: no SPKI pin configured"
	}
	return fmt.Sprintf("trust resolver: no SPKI pin found for endpoint %q", e.Endpoint)
}

// ErrCAFileRead indicates the ca-file strategy could not read its CA
// bundle file.
type ErrCAFileRead struct {
	Path string
	Err  error
}

func (e *ErrCAFileRead) Error() string {
	return fmt.Sprintf("trust resolver: could not read CA file %s: %v", e.Path, e.Err)
}

// Unwrap returns the underlying filesystem error.
func (e *ErrCAFileRead) Unwrap() error {
	return e.Err
}

// ErrEndpointInvalid indicates the caller-supplied endpoint (or the
// scope's server-url fallback) could not be parsed into host and port.
type ErrEndpointInvalid struct {
	Endpoint string
	Reason   string
}

func (e *ErrEndpointInvalid) Error() string {
	return fmt.Sprintf("trust resolver: invalid endpoint %q: %s", e.Endpoint, e.Reason)
}

// ErrTOFUPinStoreRequired indicates the tofu strategy was configured but
// no TOFUPinStore was injected at construction time.
type ErrTOFUPinStoreRequired struct{}

func (e ErrTOFUPinStoreRequired) Error() string {
	return "trust resolver: tofu strategy requires a TOFU pin store (use WithTOFUPinStore)"
}

// Attempt records the outcome of a single strategy attempt within a
// resolution chain.
type Attempt struct {
	Strategy Strategy
	Err      error
}

// ErrNoStrategySucceeded indicates every strategy in a scope's chain
// failed. Attempts records each failure in chain order.
type ErrNoStrategySucceeded struct {
	Scope    string
	Endpoint string
	Attempts []Attempt
}

func (e *ErrNoStrategySucceeded) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "trust resolver: no strategy succeeded for scope %q", e.Scope)
	if e.Endpoint != "" {
		fmt.Fprintf(&b, " endpoint %q", e.Endpoint)
	}
	for _, attempt := range e.Attempts {
		fmt.Fprintf(&b, "; %s: %v", attempt.Strategy, attempt.Err)
	}
	return b.String()
}

// Unwrap returns each attempt's error so errors.Is and errors.As
// traverse the full chain.
func (e *ErrNoStrategySucceeded) Unwrap() []error {
	errs := make([]error, 0, len(e.Attempts))
	for _, attempt := range e.Attempts {
		if attempt.Err != nil {
			errs = append(errs, attempt.Err)
		}
	}
	return errs
}
